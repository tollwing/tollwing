//go:build linux

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// Drop counter slots — must match enum drop_slot in bpf/maps.h.
const (
	dropSlotEventsRingbuf  = 0 // events ringbuf reserve failures
	dropSlotFlowAggregates = 1 // flow_aggregates map-full update failures
	dropSlotDNSRingbuf     = 2 // dns_events ringbuf reserve failures
	dropSlotQuicFlows      = 3 // quic_flows map-full update failures
)

// DropCounters mirrors the kernel drop_counters PERCPU_ARRAY summed across
// CPUs. All values are cumulative since program load. They exist so the
// exporter's drop metrics report what the kernel actually failed to record
// instead of reading 0 forever (P4 — cost figures must be honest about
// their gaps).
type DropCounters struct {
	EventsRingbuf  uint64 // lost connection lifecycle events
	FlowAggregates uint64 // lost byte deltas (flow_aggregates full)
	DNSRingbuf     uint64 // lost DNS response captures
	QuicFlows      uint64 // lost QUIC packet accounting (quic_flows full)
}

// RingbufDrops is the total of ring-buffer reserve failures (lifecycle
// events + DNS captures) — the value behind tollwing_ringbuf_drops_total.
func (d DropCounters) RingbufDrops() uint64 {
	return d.EventsRingbuf + d.DNSRingbuf
}

// MapUpdateDrops is the total of map-full update failures — the value
// behind tollwing_map_update_drops_total.
func (d DropCounters) MapUpdateDrops() uint64 {
	return d.FlowAggregates + d.QuicFlows
}

// ReadDropCounters reads the drop_counters PERCPU_ARRAY and sums the
// per-CPU values for each slot.
func ReadDropCounters(m *ebpf.Map) (DropCounters, error) {
	var dc DropCounters
	slots := []struct {
		slot uint32
		dst  *uint64
	}{
		{dropSlotEventsRingbuf, &dc.EventsRingbuf},
		{dropSlotFlowAggregates, &dc.FlowAggregates},
		{dropSlotDNSRingbuf, &dc.DNSRingbuf},
		{dropSlotQuicFlows, &dc.QuicFlows},
	}
	for _, s := range slots {
		var perCPU []uint64
		if err := m.Lookup(&s.slot, &perCPU); err != nil {
			return DropCounters{}, fmt.Errorf("lookup drop_counters slot %d: %w", s.slot, err)
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		*s.dst = sum
	}
	return dc, nil
}
