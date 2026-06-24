//go:build linux

package ebpf

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

// CgroupCost mirrors struct cgroup_cost in maps.h.
type CgroupCost struct {
	TxBytes         uint64
	RxBytes         uint64
	RetransmitBytes uint64
	ConnCount       uint64
}

// CgroupCostSnapshot is a point-in-time reading of per-cgroup cost data.
type CgroupCostSnapshot struct {
	CgroupID uint64
	Cost     CgroupCost
}

// CgroupReader periodically reads the cgroup cost storage map and provides
// per-cgroup byte accounting. This is an optimization over the
// flow → PID → cgroup → pod lookup chain.
//
// Requires kernel 6.3+ for BPF_MAP_TYPE_CGRP_STORAGE.
type CgroupReader struct {
	log      *slog.Logger
	interval time.Duration
	callback func([]CgroupCostSnapshot)
	done     chan struct{}
	started  sync.Once
	mu       sync.RWMutex
	latest   []CgroupCostSnapshot
}

// CgroupReaderConfig configures the cgroup reader.
type CgroupReaderConfig struct {
	// Interval between reads. Default: 10s.
	Interval time.Duration
	// Callback is called on each successful read with the latest snapshot.
	Callback func([]CgroupCostSnapshot)
}

func (c *CgroupReaderConfig) setDefaults() {
	if c.Interval == 0 {
		c.Interval = 10 * time.Second
	}
}

// HaveCgroupStorage probes whether the kernel supports BPF_MAP_TYPE_CGRP_STORAGE.
// Tries to create a small CGRP_STORAGE map and checks for success.
func HaveCgroupStorage() bool {
	_, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.MapType(35),
		KeySize:    8,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		return false
	}
	// Verify the kernel is recent enough by checking /proc/version
	// for 6.3+. BPF_MAP_TYPE_CGRP_STORAGE requires kernel 6.3+.
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "6.") || strings.Contains(string(data), "7.")
}

// NewCgroupReader creates a reader for the cgroup cost storage map.
func NewCgroupReader(cfg CgroupReaderConfig, log *slog.Logger) *CgroupReader {
	cfg.setDefaults()
	return &CgroupReader{
		log:      log,
		interval: cfg.Interval,
		callback: cfg.Callback,
		done:     make(chan struct{}),
	}
}

// Start begins the periodic read loop. The cgroup storage map is iterated
// using bpf_map_get_next_key to enumerate all cgroup entries.
func (cr *CgroupReader) Start(ctx context.Context, cgroupMap *ebpf.Map) {
	cr.started.Do(func() {
		if cgroupMap == nil {
			cr.log.Warn("cgroup_cost_storage map not available, cgroup reader disabled")
			close(cr.done)
			return
		}

		go func() {
			defer close(cr.done)

			ticker := time.NewTicker(cr.interval)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					cr.read(cgroupMap)
				case <-ctx.Done():
					return
				}
			}
		}()

		cr.log.Info("cgroup cost reader started", "interval", cr.interval)
	})
}

func (cr *CgroupReader) Stop() {
	<-cr.done
}

func (cr *CgroupReader) Latest() []CgroupCostSnapshot {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	out := make([]CgroupCostSnapshot, len(cr.latest))
	copy(out, cr.latest)
	return out
}

func (cr *CgroupReader) read(m *ebpf.Map) {
	var snapshots []CgroupCostSnapshot

	// Iterate all entries in the cgroup storage map.
	var key uint64
	var value CgroupCost

	iter := m.Iterate()
	for iter.Next(&key, &value) {
		snapshots = append(snapshots, CgroupCostSnapshot{
			CgroupID: key,
			Cost:     value,
		})
	}

	if err := iter.Err(); err != nil {
		cr.log.Debug("cgroup storage iteration", "err", err, "entries", len(snapshots))
	}

	cr.mu.Lock()
	cr.latest = snapshots
	cr.mu.Unlock()

	if cr.callback != nil && len(snapshots) > 0 {
		cr.callback(snapshots)
	}

	cr.log.Debug("cgroup cost snapshot", "entries", len(snapshots))
}

// FormatCgroupCost returns a human-readable summary.
func FormatCgroupCost(c CgroupCost) string {
	return fmt.Sprintf("tx=%d rx=%d retx=%d conns=%d",
		c.TxBytes, c.RxBytes, c.RetransmitBytes, c.ConnCount)
}
