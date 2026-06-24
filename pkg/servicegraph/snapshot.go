package servicegraph

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// SnapshotConfig controls the periodic rebuild.
type SnapshotConfig struct {
	// Window is the lookback each snapshot aggregates over. Default 1h.
	Window time.Duration
	// Interval is the rebuild cadence. Default 5m.
	Interval time.Duration
}

func (c *SnapshotConfig) setDefaults() {
	if c.Window <= 0 {
		c.Window = time.Hour
	}
	if c.Interval <= 0 {
		c.Interval = 5 * time.Minute
	}
}

// Snapshotter periodically rebuilds the graph from an EdgeSource and serves the
// latest snapshot via an atomic pointer, so readers (API handlers, other
// recommenders) never block the rebuild and vice versa. Mirrors the
// ticker+goroutine lifecycle of alert.Engine and the ClickHouse writer.
type Snapshotter struct {
	src     EdgeSource
	cfg     SnapshotConfig
	log     *slog.Logger
	current atomic.Pointer[ServiceGraph]
	now     func() time.Time // injectable for tests
}

// NewSnapshotter wires a snapshotter. log may be nil (a discard logger is used).
func NewSnapshotter(src EdgeSource, cfg SnapshotConfig, log *slog.Logger) *Snapshotter {
	cfg.setDefaults()
	if log == nil {
		log = slog.New(slog.NewTextHandler(noopWriter{}, nil))
	}
	return &Snapshotter{src: src, cfg: cfg, log: log, now: time.Now}
}

// Graph returns the latest snapshot, or nil if none has been built yet.
// Callers must treat the returned graph as read-only.
func (s *Snapshotter) Graph() *ServiceGraph { return s.current.Load() }

// Refresh builds one snapshot now and swaps it in atomically.
func (s *Snapshotter) Refresh(ctx context.Context) (*ServiceGraph, error) {
	rows, err := s.src.Edges(ctx, s.cfg.Window)
	if err != nil {
		return nil, err
	}
	g := Build(rows, s.now(), s.cfg.Window)
	s.current.Store(g)
	return g, nil
}

// Start runs the refresh loop until ctx is cancelled. Non-blocking; an initial
// snapshot is built immediately so Graph() is populated without waiting a tick.
func (s *Snapshotter) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(s.cfg.Interval)
		defer ticker.Stop()
		if _, err := s.Refresh(ctx); err != nil {
			s.log.Warn("servicegraph initial snapshot failed", "err", err)
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := s.Refresh(ctx); err != nil {
					s.log.Warn("servicegraph snapshot failed", "err", err)
				}
			}
		}
	}()
}

type noopWriter struct{}

func (noopWriter) Write(p []byte) (int, error) { return len(p), nil }
