package nats

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
)

// SubscriberConfig controls the NATS subscriber.
type SubscriberConfig struct {
	// URL is the NATS server URL. Default: "nats://localhost:4222".
	URL string

	// ConsumerGroup is the durable consumer name. Default: "tollwing-server".
	ConsumerGroup string

	// MaxDeliver caps how many times JetStream redelivers a failing
	// message before it is dropped. Without a cap, a poison message
	// (or a persistently failing handler) is redelivered forever.
	// Default: 5.
	MaxDeliver int

	// NakBaseDelay is the redelivery delay after the first failure;
	// it doubles per delivery attempt up to NakMaxDelay. Without a
	// delay, Nak() redelivers immediately and a failing batch spins
	// the subscriber in a hot loop. Defaults: 1s base, 30s max.
	NakBaseDelay time.Duration
	NakMaxDelay  time.Duration
}

func (c *SubscriberConfig) setDefaults() {
	if c.URL == "" {
		c.URL = nats.DefaultURL
	}
	if c.ConsumerGroup == "" {
		c.ConsumerGroup = "tollwing-server"
	}
	if c.MaxDeliver <= 0 {
		c.MaxDeliver = 5
	}
	if c.NakBaseDelay <= 0 {
		c.NakBaseDelay = time.Second
	}
	if c.NakMaxDelay <= 0 {
		c.NakMaxDelay = 30 * time.Second
	}
}

// Handler is called for each received flow batch.
type Handler func(batch FlowBatch) error

// Subscriber consumes flow batches from NATS JetStream.
type Subscriber struct {
	cfg SubscriberConfig
	log *slog.Logger
	nc  *nats.Conn
	js  nats.JetStreamContext
	sub *nats.Subscription
}

// NewSubscriber connects to NATS and prepares to consume.
func NewSubscriber(cfg SubscriberConfig, log *slog.Logger) (*Subscriber, error) {
	cfg.setDefaults()

	nc, err := nats.Connect(cfg.URL,
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}

	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream: %w", err)
	}

	return &Subscriber{
		cfg: cfg,
		log: log,
		nc:  nc,
		js:  js,
	}, nil
}

// ackMsg abstracts the JetStream ack verbs (plus delivery metadata) so
// the redelivery policy in processMsg is unit-testable without a live
// NATS server. *nats.Msg is adapted by natsAckMsg.
type ackMsg interface {
	Ack() error
	NakWithDelay(delay time.Duration) error
	Term() error
	// NumDelivered returns how many times this message has been
	// delivered (1 = first delivery). ok=false when metadata is
	// unavailable.
	NumDelivered() (n uint64, ok bool)
}

// natsAckMsg adapts *nats.Msg to ackMsg.
type natsAckMsg struct{ m *nats.Msg }

func (a natsAckMsg) Ack() error                         { return a.m.Ack() }
func (a natsAckMsg) NakWithDelay(d time.Duration) error { return a.m.NakWithDelay(d) }
func (a natsAckMsg) Term() error                        { return a.m.Term() }
func (a natsAckMsg) NumDelivered() (uint64, bool) {
	md, err := a.m.Metadata()
	if err != nil {
		return 0, false
	}
	return md.NumDelivered, true
}

// processMsg applies the redelivery policy to one message:
//
//   - malformed JSON is poison — no redelivery can ever fix it, so it
//     is Term()ed (dropped permanently) instead of Nak()ed into a
//     redelivery hot loop;
//   - handler errors are presumed transient and Nak()ed with
//     exponential backoff (base·2^(attempt−1), capped) so a struggling
//     downstream (ClickHouse, registry cap) is not hammered;
//   - once MaxDeliver attempts are exhausted the message is Term()ed
//     with an explicit log line — dropped data is logged, never silent.
func (s *Subscriber) processMsg(data []byte, msg ackMsg, handler Handler) {
	var batch FlowBatch
	if err := json.Unmarshal(data, &batch); err != nil {
		s.log.Error("unmarshal flow batch: poison message, dropping (Term)", "err", err)
		msg.Term()
		return
	}

	if err := handler(batch); err != nil {
		delivered, ok := msg.NumDelivered()
		if ok && delivered >= uint64(s.cfg.MaxDeliver) {
			s.log.Error("handle flow batch: giving up after max deliveries, dropping (Term)",
				"err", err, "cluster", batch.Cluster, "node", batch.Node,
				"deliveries", delivered, "max_deliver", s.cfg.MaxDeliver)
			msg.Term()
			return
		}
		delay := s.nakDelay(delivered)
		s.log.Error("handle flow batch: scheduling redelivery",
			"err", err, "cluster", batch.Cluster, "node", batch.Node,
			"deliveries", delivered, "nak_delay", delay)
		msg.NakWithDelay(delay)
		return
	}

	msg.Ack()
	s.log.Debug("processed flow batch", "cluster", batch.Cluster, "node", batch.Node, "flows", len(batch.Flows))
}

// nakDelay computes the exponential redelivery backoff for a message on
// its delivered-th attempt (1-based). Unknown attempt counts get the
// base delay.
func (s *Subscriber) nakDelay(delivered uint64) time.Duration {
	delay := s.cfg.NakBaseDelay
	for i := uint64(1); i < delivered; i++ {
		delay *= 2
		if delay >= s.cfg.NakMaxDelay {
			return s.cfg.NakMaxDelay
		}
	}
	if delay > s.cfg.NakMaxDelay {
		return s.cfg.NakMaxDelay
	}
	return delay
}

// Subscribe starts consuming flow batches. Blocks until ctx is cancelled.
func (s *Subscriber) Subscribe(ctx context.Context, handler Handler) error {
	cb := func(msg *nats.Msg) {
		s.processMsg(msg.Data, natsAckMsg{m: msg}, handler)
	}
	sub, err := subscribeWithDurableUpgrade(s.log, s.js,
		func(withMaxDeliver bool) (*nats.Subscription, error) {
			return s.js.Subscribe(FlowSubject+".>", cb, s.subOpts(withMaxDeliver)...)
		},
		StreamName, s.cfg.ConsumerGroup, s.cfg.MaxDeliver)
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	s.sub = sub

	<-ctx.Done()
	return sub.Drain()
}

// subOpts assembles the durable consumer options. withMaxDeliver=false
// is the degraded fallback for a pre-existing durable that could not be
// upgraded in place — see subscribeWithDurableUpgrade.
func (s *Subscriber) subOpts(withMaxDeliver bool) []nats.SubOpt {
	opts := []nats.SubOpt{
		nats.Durable(s.cfg.ConsumerGroup),
		nats.DeliverNew(),
		nats.AckExplicit(),
		nats.ManualAck(),
	}
	if withMaxDeliver {
		// Server-side redelivery cap — belt to processMsg's braces:
		// even if the client never Term()s, JetStream stops
		// redelivering after MaxDeliver attempts.
		opts = append(opts, nats.MaxDeliver(s.cfg.MaxDeliver))
	}
	return opts
}

// jsConsumerManager is the subset of nats.JetStreamManager the durable-
// upgrade path needs, abstracted (like ackMsg) so the upgrade policy is
// unit-testable without a live NATS server. nats.JetStreamContext
// satisfies it.
type jsConsumerManager interface {
	ConsumerInfo(stream, consumer string, opts ...nats.JSOpt) (*nats.ConsumerInfo, error)
	UpdateConsumer(stream string, cfg *nats.ConsumerConfig, opts ...nats.JSOpt) (*nats.ConsumerInfo, error)
}

// subscribeWithDurableUpgrade binds the durable consumer, upgrading a
// pre-existing consumer's config in place when it predates MaxDeliver.
//
// nats.go refuses to bind a durable whose server-side config mismatches
// the requested options, so a deployment whose consumer was created
// before the MaxDeliver cap existed would fail the subscribe on every
// restart after an upgrade — halting flow ingestion entirely. Per P8
// (failures must be loud, with a way back), the recovery ladder is:
//
//  1. subscribe with MaxDeliver — fresh installs and already-upgraded
//     consumers bind here;
//  2. on failure, update the existing durable's server-side config to
//     the desired MaxDeliver (preserving every other field verbatim)
//     and retry once;
//  3. if the update cannot be applied, subscribe WITHOUT the cap and
//     log the exact CLI fix — degraded ingestion (processMsg's
//     client-side Term still bounds redelivery) beats none, and the
//     failure mode is loud and actionable, never silent.
func subscribeWithDurableUpgrade(
	log *slog.Logger,
	mgr jsConsumerManager,
	subscribe func(withMaxDeliver bool) (*nats.Subscription, error),
	stream, durable string,
	maxDeliver int,
) (*nats.Subscription, error) {
	sub, err := subscribe(true)
	if err == nil {
		return sub, nil
	}

	if upErr := upgradeDurableMaxDeliver(mgr, stream, durable, maxDeliver); upErr == nil {
		sub, retryErr := subscribe(true)
		if retryErr == nil {
			log.Info("upgraded existing durable consumer to the configured max_deliver",
				"stream", stream, "consumer", durable, "max_deliver", maxDeliver)
			return sub, nil
		}
		err = retryErr
	} else {
		log.Warn("existing durable consumer could not be upgraded in place",
			"stream", stream, "consumer", durable, "err", upErr, "subscribe_err", err)
	}

	sub, fbErr := subscribe(false)
	if fbErr != nil {
		// Both shapes failed — the cause is not a MaxDeliver mismatch
		// (server down, stream missing, ...). Surface the original error.
		return nil, err
	}
	log.Error("subscribed WITHOUT the server-side MaxDeliver cap: the existing durable consumer "+
		"conflicts and could not be updated; redelivery is bounded only client-side until the "+
		"consumer is fixed manually and the server restarted",
		"stream", stream, "consumer", durable, "want_max_deliver", maxDeliver,
		"fix", fmt.Sprintf("nats consumer edit %s %s --max-deliver=%d -f", stream, durable, maxDeliver),
		"subscribe_err", err)
	return sub, nil
}

// upgradeDurableMaxDeliver updates an existing durable consumer's
// MaxDeliver to the desired value. It starts from the server's own
// config and changes only MaxDeliver, so every other field is preserved
// verbatim and the update cannot introduce a new config mismatch.
func upgradeDurableMaxDeliver(mgr jsConsumerManager, stream, durable string, maxDeliver int) error {
	info, err := mgr.ConsumerInfo(stream, durable)
	if err != nil {
		return fmt.Errorf("consumer info: %w", err)
	}
	if info.Config.MaxDeliver == maxDeliver {
		return fmt.Errorf("consumer %q already has max_deliver=%d; the subscribe failure has another cause",
			durable, maxDeliver)
	}
	cfg := info.Config
	cfg.MaxDeliver = maxDeliver
	if _, err := mgr.UpdateConsumer(stream, &cfg); err != nil {
		return fmt.Errorf("update consumer: %w", err)
	}
	return nil
}

// Close disconnects from NATS.
func (s *Subscriber) Close() {
	if s.sub != nil {
		s.sub.Drain()
	}
	if s.nc != nil {
		s.nc.Drain()
	}
}
