// Package nats provides NATS JetStream publisher and subscriber for
// shipping flow records from agents to the control plane.
package nats

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/tollwing/tollwing/pkg/cost"
)

// Stream and subject constants.
const (
	StreamName  = "TOLLWING"
	FlowSubject = "tollwing.flows" // tollwing.flows.{cluster}.{node}
)

// PublisherConfig controls the NATS publisher.
type PublisherConfig struct {
	// URL is the NATS server URL. Default: "nats://localhost:4222".
	URL string

	// Cluster is this agent's cluster name.
	Cluster string

	// Node is this agent's node name.
	Node string

	// StreamReplicas is the JetStream replication factor. Production
	// clusters should use 3; single-node dev uses 1. Default: 1.
	StreamReplicas int

	// StreamMaxAge caps how long un-acked messages are retained.
	// Default: 24h. Beyond this, old messages are discarded even if
	// no consumer has processed them — prevents unbounded disk growth.
	StreamMaxAge time.Duration

	// StreamMaxBytes caps total stream size. 0 = unlimited (not recommended).
	// Default: 10 GiB.
	StreamMaxBytes int64
}

func (c *PublisherConfig) setDefaults() {
	if c.URL == "" {
		c.URL = nats.DefaultURL
	}
	if c.StreamReplicas == 0 {
		c.StreamReplicas = 1
	}
	if c.StreamMaxAge == 0 {
		c.StreamMaxAge = 24 * time.Hour
	}
	if c.StreamMaxBytes == 0 {
		c.StreamMaxBytes = 10 << 30 // 10 GiB
	}
}

// Publisher sends flow batches to NATS JetStream.
type Publisher struct {
	cfg PublisherConfig
	log *slog.Logger
	nc  *nats.Conn
	js  nats.JetStreamContext
}

// NewPublisher connects to NATS and ensures the JetStream stream exists.
func NewPublisher(cfg PublisherConfig, log *slog.Logger) (*Publisher, error) {
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

	// Ensure stream exists with production-grade durability: file-backed,
	// replicated, bounded by both time and size so disk can't fill up.
	streamCfg := &nats.StreamConfig{
		Name:      StreamName,
		Subjects:  []string{"tollwing.>"},
		Storage:   nats.FileStorage,
		Retention: nats.WorkQueuePolicy, // messages removed after ack
		Replicas:  cfg.StreamReplicas,
		MaxAge:    cfg.StreamMaxAge,
		MaxBytes:  cfg.StreamMaxBytes,
		Discard:   nats.DiscardOld, // prefer losing old data vs blocking
	}
	if _, err := js.StreamInfo(StreamName); err != nil {
		if _, err := js.AddStream(streamCfg); err != nil {
			nc.Close()
			return nil, fmt.Errorf("create stream: %w", err)
		}
	} else {
		// Stream already exists — update settings (safe no-op if unchanged).
		if _, err := js.UpdateStream(streamCfg); err != nil {
			log.Warn("update nats stream config (continuing with old settings)", "err", err)
		}
	}

	return &Publisher{
		cfg: cfg,
		log: log,
		nc:  nc,
		js:  js,
	}, nil
}

// FlowBatch is the wire format for a batch of flow records.
type FlowBatch struct {
	Cluster string            `json:"cluster"`
	Node    string            `json:"node"`
	Flows   []cost.CostResult `json:"flows"`
	SentAt  time.Time         `json:"sent_at"`
}

// ToFlowRecords converts the batch's cost results to flow records.
func (b *FlowBatch) ToFlowRecords() []cost.FlowRecord {
	records := make([]cost.FlowRecord, len(b.Flows))
	for i, f := range b.Flows {
		records[i] = f.FlowRecord
	}
	return records
}

// Publish sends a batch of cost results to NATS JetStream.
func (p *Publisher) Publish(results []cost.CostResult) error {
	batch := FlowBatch{
		Cluster: p.cfg.Cluster,
		Node:    p.cfg.Node,
		Flows:   results,
		SentAt:  time.Now(),
	}

	data, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	subject := fmt.Sprintf("%s.%s.%s", FlowSubject, p.cfg.Cluster, p.cfg.Node)
	_, err = p.js.Publish(subject, data)
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}

	p.log.Debug("published flow batch", "subject", subject, "flows", len(results))
	return nil
}

// Close disconnects from NATS.
func (p *Publisher) Close() {
	if p.nc != nil {
		p.nc.Drain()
	}
}
