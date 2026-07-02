// Package nats provides NATS JetStream publisher and subscriber for
// shipping flow records from agents to the control plane.
package nats

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
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

// validate rejects config values that would build an unpublishable subject.
// An empty Cluster or Node used to produce "tollwing.flows..host", which NATS
// rejects on EVERY publish — the agent then warn-and-dropped each batch
// forever. Failing here, at construction, makes the misconfiguration loud
// exactly once instead of a silent per-poll data loss.
func (c *PublisherConfig) validate() error {
	if err := ValidateSubjectToken(c.Cluster); err != nil {
		return fmt.Errorf("cluster: %w", err)
	}
	if err := ValidateSubjectToken(c.Node); err != nil {
		return fmt.Errorf("node: %w", err)
	}
	return nil
}

// ValidateSubjectToken checks that a value can be embedded in a NATS subject.
// It rejects values that make the composed subject invalid for publishing:
// empty values, empty dot-delimited parts (leading/trailing/double dots),
// whitespace or control characters, and the subscription wildcards "*"/">".
// Interior dots are permitted — they add subject tokens, which the
// "tollwing.flows.>" consumers still match, and batch identity travels in the
// JSON body — so dotted hostnames (e.g. "ip-10-0-1-5.ec2.internal") keep working.
func ValidateSubjectToken(v string) error {
	if v == "" {
		return fmt.Errorf("empty subject token")
	}
	for _, part := range strings.Split(v, ".") {
		if part == "" {
			return fmt.Errorf("subject token %q has an empty dot-delimited part", v)
		}
		for _, r := range part {
			switch {
			case r == '*' || r == '>':
				return fmt.Errorf("subject token %q contains NATS wildcard %q", v, string(r))
			case r == ' ' || r == '\t' || r == '\n' || r == '\r' || r < 0x20 || r == 0x7f:
				return fmt.Errorf("subject token %q contains whitespace or a control character", v)
			}
		}
	}
	return nil
}

// Publisher sends flow batches to NATS JetStream.
type Publisher struct {
	cfg     PublisherConfig
	log     *slog.Logger
	nc      *nats.Conn
	js      nats.JetStreamContext
	subject string // fixed at construction; tokens validated by cfg.validate
}

// NewPublisher connects to NATS and ensures the JetStream stream exists.
// It fails fast on config that would build an invalid publish subject
// (empty cluster/node tokens) — see PublisherConfig.validate.
func NewPublisher(cfg PublisherConfig, log *slog.Logger) (*Publisher, error) {
	cfg.setDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("nats publisher config: %w", err)
	}

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
		cfg:     cfg,
		log:     log,
		nc:      nc,
		js:      js,
		subject: fmt.Sprintf("%s.%s.%s", FlowSubject, cfg.Cluster, cfg.Node),
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

	if _, err := p.js.Publish(p.subject, data); err != nil {
		return fmt.Errorf("publish: %w", err)
	}

	p.log.Debug("published flow batch", "subject", p.subject, "flows", len(results))
	return nil
}

// Close disconnects from NATS.
func (p *Publisher) Close() {
	if p.nc != nil {
		p.nc.Drain()
	}
}
