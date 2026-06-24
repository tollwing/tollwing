//go:build linux

package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// IterOutput mirrors struct iter_output in iter.bpf.c.
type IterOutput struct {
	FK              FlowKey
	TxBytes         uint64
	RxBytes         uint64
	RetransmitBytes uint64
	CgroupID        uint64
	StartNs         uint64
	SnapshotNs      uint64
}

// CostSnapshot is a processed iterator output for userspace consumption.
type CostSnapshot struct {
	FlowKey         FlowKey
	TxBytes         uint64
	RxBytes         uint64
	RetransmitBytes uint64
	CgroupID        uint64
	ActiveSince     time.Duration // time since connection start
}

// Iterator reads per-socket cost state via BPF iterators for consistent
// snapshots. Eliminates race conditions from polling BPF hash maps.
//
// Requires kernel 5.15+ for iterators, 6.4+ for sk_storage iterators.
type Iterator struct {
	log      *slog.Logger
	interval time.Duration
	callback func([]CostSnapshot)
	done     chan struct{}
	started  sync.Once
	mu       sync.RWMutex
	latest   []CostSnapshot
}

// IteratorConfig configures the BPF iterator.
type IteratorConfig struct {
	// Interval between snapshots. Default: 15s.
	Interval time.Duration
	// Callback receives each snapshot.
	Callback func([]CostSnapshot)
}

func (c *IteratorConfig) setDefaults() {
	if c.Interval == 0 {
		c.Interval = 15 * time.Second
	}
}

// NewIterator creates a BPF sk_storage iterator reader.
func NewIterator(cfg IteratorConfig, log *slog.Logger) *Iterator {
	cfg.setDefaults()
	return &Iterator{
		log:      log,
		interval: cfg.Interval,
		callback: cfg.Callback,
		done:     make(chan struct{}),
	}
}

// Start begins the periodic iterator loop. The iterator program must be
// loaded in the BPF collection and the sk_cost_storage map must be available.
func (it *Iterator) Start(ctx context.Context, iterProg *ebpf.Program, skStorageMap *ebpf.Map) {
	it.started.Do(func() {
		if iterProg == nil || skStorageMap == nil {
			it.log.Warn("sk_storage iterator not available, falling back to map polling")
			close(it.done)
			return
		}

		go func() {
			defer close(it.done)

			ticker := time.NewTicker(it.interval)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					it.snapshot(iterProg, skStorageMap)
				case <-ctx.Done():
					return
				}
			}
		}()

		it.log.Info("BPF iterator started", "interval", it.interval)
	})
}

func (it *Iterator) Stop() {
	<-it.done
}

func (it *Iterator) Latest() []CostSnapshot {
	it.mu.RLock()
	defer it.mu.RUnlock()
	out := make([]CostSnapshot, len(it.latest))
	copy(out, it.latest)
	return out
}

func (it *Iterator) snapshot(prog *ebpf.Program, storageMap *ebpf.Map) {
	// Attach the iterator to the sk_cost_storage map.
	iter, err := link.AttachIter(link.IterOptions{
		Program: prog,
		Map:     storageMap,
	})
	if err != nil {
		it.log.Error("attach iterator", "err", err)
		return
	}
	defer iter.Close()

	// Open the iterator fd and read all records.
	rd, err := iter.Open()
	if err != nil {
		it.log.Error("open iterator", "err", err)
		return
	}
	defer rd.Close()

	recordSize := int(unsafe.Sizeof(IterOutput{}))
	var snapshots []CostSnapshot

	for {
		var rec IterOutput
		if err := binary.Read(rd, binary.NativeEndian, &rec); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			it.log.Warn("read iterator record", "err", err, "record_size", recordSize)
			break
		}

		snapshots = append(snapshots, CostSnapshot{
			FlowKey:         rec.FK,
			TxBytes:         rec.TxBytes,
			RxBytes:         rec.RxBytes,
			RetransmitBytes: rec.RetransmitBytes,
			CgroupID:        rec.CgroupID,
			ActiveSince:     time.Duration(rec.SnapshotNs-rec.StartNs) * time.Nanosecond,
		})
	}

	it.mu.Lock()
	it.latest = snapshots
	it.mu.Unlock()

	if it.callback != nil && len(snapshots) > 0 {
		it.callback(snapshots)
	}

	it.log.Debug("iterator snapshot", "entries", len(snapshots))
}

// FormatSnapshot returns a human-readable summary.
func FormatSnapshot(s CostSnapshot) string {
	return fmt.Sprintf("src=%s dst=%s tx=%d rx=%d retx=%d cgroup=%d active=%s",
		FormatIPPort(s.FlowKey.SrcIP, s.FlowKey.SrcPort),
		FormatIPPort(s.FlowKey.DstIP, s.FlowKey.DstPort),
		s.TxBytes, s.RxBytes, s.RetransmitBytes,
		s.CgroupID, s.ActiveSince)
}
