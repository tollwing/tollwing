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
}

func (c *SubscriberConfig) setDefaults() {
	if c.URL == "" {
		c.URL = nats.DefaultURL
	}
	if c.ConsumerGroup == "" {
		c.ConsumerGroup = "tollwing-server"
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

// Subscribe starts consuming flow batches. Blocks until ctx is cancelled.
func (s *Subscriber) Subscribe(ctx context.Context, handler Handler) error {
	sub, err := s.js.Subscribe(
		FlowSubject+".>",
		func(msg *nats.Msg) {
			var batch FlowBatch
			if err := json.Unmarshal(msg.Data, &batch); err != nil {
				s.log.Error("unmarshal flow batch", "err", err)
				msg.Nak()
				return
			}

			if err := handler(batch); err != nil {
				s.log.Error("handle flow batch", "err", err, "cluster", batch.Cluster, "node", batch.Node)
				msg.Nak()
				return
			}

			msg.Ack()
			s.log.Debug("processed flow batch", "cluster", batch.Cluster, "node", batch.Node, "flows", len(batch.Flows))
		},
		nats.Durable(s.cfg.ConsumerGroup),
		nats.DeliverNew(),
		nats.AckExplicit(),
		nats.ManualAck(),
	)
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	s.sub = sub

	<-ctx.Done()
	return sub.Drain()
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
