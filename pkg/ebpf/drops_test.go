//go:build linux

package ebpf

import (
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
)

// TestReadDropCounters verifies the per-CPU drop counter sums against a
// real PERCPU_ARRAY shaped like drop_counters. Skips without CAP_BPF.
func TestReadDropCounters(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 4, // DROP_SLOT_MAX
	})
	if err != nil {
		t.Skipf("cannot create BPF map (need CAP_BPF): %v", err)
	}
	defer m.Close()

	ncpu := runtime.NumCPU()
	fill := func(slot uint32, perCPUVal uint64) {
		vals := make([]uint64, ncpu)
		for i := range vals {
			vals[i] = perCPUVal
		}
		if err := m.Put(&slot, vals); err != nil {
			t.Fatalf("put slot %d: %v", slot, err)
		}
	}
	fill(dropSlotEventsRingbuf, 3)
	fill(dropSlotFlowAggregates, 5)
	fill(dropSlotDNSRingbuf, 7)
	fill(dropSlotQuicFlows, 11)

	dc, err := ReadDropCounters(m)
	if err != nil {
		t.Fatalf("ReadDropCounters: %v", err)
	}

	n := uint64(ncpu)
	tests := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"EventsRingbuf", dc.EventsRingbuf, 3 * n},
		{"FlowAggregates", dc.FlowAggregates, 5 * n},
		{"DNSRingbuf", dc.DNSRingbuf, 7 * n},
		{"QuicFlows", dc.QuicFlows, 11 * n},
		{"RingbufDrops", dc.RingbufDrops(), (3 + 7) * n},
		{"MapUpdateDrops", dc.MapUpdateDrops(), (5 + 11) * n},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

// TestDropCountersTotals covers the metric aggregation helpers without
// needing BPF privileges.
func TestDropCountersTotals(t *testing.T) {
	dc := DropCounters{EventsRingbuf: 1, FlowAggregates: 2, DNSRingbuf: 4, QuicFlows: 8}
	if got := dc.RingbufDrops(); got != 5 {
		t.Errorf("RingbufDrops() = %d, want 5", got)
	}
	if got := dc.MapUpdateDrops(); got != 10 {
		t.Errorf("MapUpdateDrops() = %d, want 10", got)
	}
}
