package nats

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// fakeAckMsg records which ack verb processMsg chose.
type fakeAckMsg struct {
	delivered  uint64
	metadataOK bool
	acked      bool
	termed     bool
	naked      bool
	nakDelay   time.Duration
}

func (f *fakeAckMsg) Ack() error { f.acked = true; return nil }
func (f *fakeAckMsg) NakWithDelay(d time.Duration) error {
	f.naked = true
	f.nakDelay = d
	return nil
}
func (f *fakeAckMsg) Term() error { f.termed = true; return nil }
func (f *fakeAckMsg) NumDelivered() (uint64, bool) {
	return f.delivered, f.metadataOK
}

func testSubscriber(cfg SubscriberConfig) *Subscriber {
	cfg.setDefaults()
	return &Subscriber{
		cfg: cfg,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func validBatch(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(FlowBatch{Cluster: "prod", Node: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The original subscriber Nak()ed every failure with no delay and no
// delivery cap: a poison message or a persistently failing handler
// redelivered in a hot loop forever. This table pins the policy that
// replaces it.
func TestProcessMsg_RedeliveryPolicy(t *testing.T) {
	handlerErr := errors.New("downstream unavailable")

	tests := []struct {
		name       string
		data       []byte
		handler    Handler
		delivered  uint64
		metadataOK bool
		wantAck    bool
		wantTerm   bool
		wantNak    bool
		wantDelay  time.Duration
	}{
		{
			name:       "success acks",
			handler:    func(FlowBatch) error { return nil },
			delivered:  1,
			metadataOK: true,
			wantAck:    true,
		},
		{
			name:       "malformed JSON is poison: Term, never Nak",
			data:       []byte("{not json"),
			handler:    func(FlowBatch) error { t.Fatal("handler must not run for poison"); return nil },
			delivered:  1,
			metadataOK: true,
			wantTerm:   true,
		},
		{
			name:       "first failure naks with base delay",
			handler:    func(FlowBatch) error { return handlerErr },
			delivered:  1,
			metadataOK: true,
			wantNak:    true,
			wantDelay:  time.Second,
		},
		{
			name:       "third failure naks with doubled backoff",
			handler:    func(FlowBatch) error { return handlerErr },
			delivered:  3,
			metadataOK: true,
			wantNak:    true,
			wantDelay:  4 * time.Second,
		},
		{
			name:       "backoff is capped at NakMaxDelay",
			handler:    func(FlowBatch) error { return handlerErr },
			delivered:  4,
			metadataOK: true,
			wantNak:    true,
			wantDelay:  5 * time.Second, // capped below 8s by config
		},
		{
			name:       "max deliveries exhausted terms the message",
			handler:    func(FlowBatch) error { return handlerErr },
			delivered:  5,
			metadataOK: true,
			wantTerm:   true,
		},
		{
			name:       "missing metadata still naks with base delay",
			handler:    func(FlowBatch) error { return handlerErr },
			metadataOK: false,
			wantNak:    true,
			wantDelay:  time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := testSubscriber(SubscriberConfig{
				MaxDeliver:   5,
				NakBaseDelay: time.Second,
				NakMaxDelay:  5 * time.Second,
			})
			data := tc.data
			if data == nil {
				data = validBatch(t)
			}
			msg := &fakeAckMsg{delivered: tc.delivered, metadataOK: tc.metadataOK}
			s.processMsg(data, msg, tc.handler)

			if msg.acked != tc.wantAck {
				t.Errorf("acked = %v, want %v", msg.acked, tc.wantAck)
			}
			if msg.termed != tc.wantTerm {
				t.Errorf("termed = %v, want %v", msg.termed, tc.wantTerm)
			}
			if msg.naked != tc.wantNak {
				t.Errorf("naked = %v, want %v", msg.naked, tc.wantNak)
			}
			if tc.wantNak && msg.nakDelay != tc.wantDelay {
				t.Errorf("nak delay = %v, want %v", msg.nakDelay, tc.wantDelay)
			}
			if msg.naked && msg.nakDelay == 0 {
				t.Error("nak with zero delay reintroduces the redelivery hot loop")
			}
		})
	}
}

// fakeJetStream simulates the server side of the durable-upgrade dance:
// one stored consumer config, nats.go's checkConfig MaxDeliver rule, and
// the two JetStreamManager verbs the upgrade path uses.
type fakeJetStream struct {
	consumer     *nats.ConsumerConfig // nil = durable does not exist yet
	infoErr      error                // forced ConsumerInfo failure
	updateErr    error                // forced UpdateConsumer failure
	subscribeErr error                // forced Subscribe failure (e.g. server down)
	updateCalls  int
	binds        []bool // withMaxDeliver of each successful bind
}

func (f *fakeJetStream) ConsumerInfo(stream, consumer string, opts ...nats.JSOpt) (*nats.ConsumerInfo, error) {
	if f.infoErr != nil {
		return nil, f.infoErr
	}
	if f.consumer == nil {
		return nil, nats.ErrConsumerNotFound
	}
	return &nats.ConsumerInfo{Stream: stream, Name: consumer, Config: *f.consumer}, nil
}

func (f *fakeJetStream) UpdateConsumer(stream string, cfg *nats.ConsumerConfig, opts ...nats.JSOpt) (*nats.ConsumerInfo, error) {
	f.updateCalls++
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	c := *cfg
	f.consumer = &c
	return &nats.ConsumerInfo{Stream: stream, Name: cfg.Durable, Config: c}, nil
}

// subscribe mimics js.Subscribe's durable handling: create the consumer
// when absent; when it exists, reject a MaxDeliver mismatch exactly the
// way nats.go's checkConfig does (only a requested MaxDeliver > 0 is
// compared, so binding without the option always succeeds).
func (f *fakeJetStream) subscribe(withMaxDeliver bool, maxDeliver int) (*nats.Subscription, error) {
	if f.subscribeErr != nil {
		return nil, f.subscribeErr
	}
	if f.consumer == nil {
		cfg := &nats.ConsumerConfig{Durable: "tollwing-server", MaxDeliver: -1}
		if withMaxDeliver {
			cfg.MaxDeliver = maxDeliver
		}
		f.consumer = cfg
		f.binds = append(f.binds, withMaxDeliver)
		return &nats.Subscription{}, nil
	}
	if withMaxDeliver && f.consumer.MaxDeliver != maxDeliver {
		return nil, fmt.Errorf("nats: configuration requests max deliver to be %d, but consumer's value is %d",
			maxDeliver, f.consumer.MaxDeliver)
	}
	f.binds = append(f.binds, withMaxDeliver)
	return &nats.Subscription{}, nil
}

// Adding nats.MaxDeliver to the subscribe options used to brick every
// already-deployed installation: the durable consumer created by the
// previous version has no MaxDeliver, nats.go refuses to bind a durable
// with a mismatched option, and the error was only logged — flow
// ingestion silently stopped after the upgrade. This pins the recovery
// ladder: upgrade the existing consumer in place, and if that is
// impossible, bind without the cap (loudly) rather than not at all.
func TestSubscribeWithDurableUpgrade(t *testing.T) {
	const maxDeliver = 5

	preExisting := func(maxDeliver int) *nats.ConsumerConfig {
		return &nats.ConsumerConfig{
			Durable:       "tollwing-server",
			AckWait:       42 * time.Second, // sentinel: must survive the upgrade untouched
			MaxAckPending: 1234,             // sentinel
			MaxDeliver:    maxDeliver,
		}
	}

	tests := []struct {
		name            string
		fake            *fakeJetStream
		wantErr         bool
		wantMaxDeliver  int // final server-side consumer MaxDeliver
		wantUpdates     int
		wantLastBindCap bool   // withMaxDeliver of the successful bind
		wantLogSub      string // substring the log output must contain
	}{
		{
			name:            "fresh install creates consumer with the cap",
			fake:            &fakeJetStream{},
			wantMaxDeliver:  maxDeliver,
			wantUpdates:     0,
			wantLastBindCap: true,
		},
		{
			name:            "already-upgraded consumer binds directly",
			fake:            &fakeJetStream{consumer: preExisting(maxDeliver)},
			wantMaxDeliver:  maxDeliver,
			wantUpdates:     0,
			wantLastBindCap: true,
		},
		{
			name:            "pre-existing durable without the cap is upgraded in place",
			fake:            &fakeJetStream{consumer: preExisting(-1)},
			wantMaxDeliver:  maxDeliver,
			wantUpdates:     1,
			wantLastBindCap: true,
		},
		{
			name: "update refused: bind without the cap and log the CLI fix",
			fake: &fakeJetStream{
				consumer:  preExisting(-1),
				updateErr: errors.New("nats: consumer update not permitted"),
			},
			wantMaxDeliver:  -1,
			wantUpdates:     1,
			wantLastBindCap: false,
			wantLogSub:      "nats consumer edit TOLLWING tollwing-server --max-deliver=5",
		},
		{
			name: "server unreachable surfaces the subscribe error",
			fake: &fakeJetStream{
				subscribeErr: errors.New("nats: timeout"),
				infoErr:      errors.New("nats: timeout"),
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&logBuf, nil))

			sub, err := subscribeWithDurableUpgrade(log, tc.fake,
				func(withMaxDeliver bool) (*nats.Subscription, error) {
					return tc.fake.subscribe(withMaxDeliver, maxDeliver)
				},
				StreamName, "tollwing-server", maxDeliver)

			if tc.wantErr {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("subscribeWithDurableUpgrade: %v (flow ingestion would halt after upgrade)", err)
			}
			if sub == nil {
				t.Fatal("nil subscription without error")
			}
			if got := tc.fake.consumer.MaxDeliver; got != tc.wantMaxDeliver {
				t.Errorf("server-side MaxDeliver = %d, want %d", got, tc.wantMaxDeliver)
			}
			if tc.fake.updateCalls != tc.wantUpdates {
				t.Errorf("UpdateConsumer calls = %d, want %d", tc.fake.updateCalls, tc.wantUpdates)
			}
			if n := len(tc.fake.binds); n == 0 || tc.fake.binds[n-1] != tc.wantLastBindCap {
				t.Errorf("successful binds = %v, want last bind withMaxDeliver=%v", tc.fake.binds, tc.wantLastBindCap)
			}
			if tc.wantLogSub != "" && !strings.Contains(logBuf.String(), tc.wantLogSub) {
				t.Errorf("log output missing actionable fix %q; got:\n%s", tc.wantLogSub, logBuf.String())
			}
			// An in-place upgrade must change MaxDeliver and nothing else.
			if tc.wantUpdates > 0 && tc.fake.consumer.MaxDeliver == maxDeliver {
				if tc.fake.consumer.AckWait != 42*time.Second || tc.fake.consumer.MaxAckPending != 1234 {
					t.Errorf("upgrade did not preserve unrelated consumer fields: %+v", tc.fake.consumer)
				}
			}
		})
	}
}

// The concrete JetStream context must satisfy the seam the upgrade path
// is tested through; if this stops compiling, the fake diverged from
// the real API.
var _ jsConsumerManager = nats.JetStreamContext(nil)

func TestSubscriberConfig_SetDefaults(t *testing.T) {
	var cfg SubscriberConfig
	cfg.setDefaults()
	if cfg.MaxDeliver != 5 {
		t.Errorf("MaxDeliver default = %d, want 5", cfg.MaxDeliver)
	}
	if cfg.NakBaseDelay != time.Second {
		t.Errorf("NakBaseDelay default = %v, want 1s", cfg.NakBaseDelay)
	}
	if cfg.NakMaxDelay != 30*time.Second {
		t.Errorf("NakMaxDelay default = %v, want 30s", cfg.NakMaxDelay)
	}
}
