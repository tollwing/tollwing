//go:build linux

package poller

import (
	"log/slog"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"

	bpf "github.com/tollwing/tollwing/pkg/ebpf"
)

// newFlowAggMap creates a PERCPU_HASH map shaped like flow_aggregates.
// Skips the test when BPF map creation is unavailable (no privileges or no
// BPF support) — CI without CAP_BPF skips, privileged runs exercise it.
func newFlowAggMap(t *testing.T, maxEntries uint32) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.PerCPUHash,
		KeySize:    20, // sizeof(struct flow_key)
		ValueSize:  48, // sizeof(struct flow_metrics)
		MaxEntries: maxEntries,
	})
	if err != nil {
		t.Skipf("cannot create BPF map (need CAP_BPF): %v", err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func putFlow(t *testing.T, m *ebpf.Map, key bpf.FlowKey, txPerCPU uint64) {
	t.Helper()
	perCPU := make([]bpf.FlowMetrics, runtime.NumCPU())
	for i := range perCPU {
		perCPU[i] = bpf.FlowMetrics{TxBytes: txPerCPU, ConnCount: 1}
	}
	if err := m.Put(&key, perCPU); err != nil {
		t.Fatalf("put flow entry: %v", err)
	}
}

func mapLen(t *testing.T, m *ebpf.Map) int {
	t.Helper()
	var (
		key  bpf.FlowKey
		vals []bpf.FlowMetrics
		n    int
	)
	iter := m.Iterate()
	for iter.Next(&key, &vals) {
		n++
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}
	return n
}

// TestPollIterateDrains verifies the non-batch fallback path returns every
// entry exactly once and leaves the map empty. It exercises the
// LookupAndDelete drain that replaced the lossy read-then-delete (which
// destroyed increments landing between the read and the delete).
func TestPollIterateDrains(t *testing.T) {
	m := newFlowAggMap(t, 64)

	keys := []bpf.FlowKey{
		{SrcIP: 0x0100000A, DstIP: 0x0200000A, SrcPort: 1000, DstPort: 80, PID: 1, Protocol: 6},
		{SrcIP: 0x0100000A, DstIP: 0x0300000A, SrcPort: 1001, DstPort: 443, PID: 2, Protocol: 6},
		{DstIP: 0x0400000A, DstPort: 53, PID: 3, Protocol: protoUDP},
	}
	for i, k := range keys {
		putFlow(t, m, k, uint64(100*(i+1)))
	}

	p := New(Config{}, m, nil, slog.Default())
	p.useBatch = false // force the fallback path under test

	flows := p.pollIterate()
	if len(flows) != len(keys) {
		t.Fatalf("pollIterate returned %d flows, want %d", len(flows), len(keys))
	}
	// Per-CPU values are summed: entry i carries 100*(i+1) per CPU.
	want := map[uint32]uint64{
		0x0200000A: 100 * uint64(runtime.NumCPU()),
		0x0300000A: 200 * uint64(runtime.NumCPU()),
		0x0400000A: 300 * uint64(runtime.NumCPU()),
	}
	for _, f := range flows {
		if f.TxBytes != want[f.DstIP] {
			t.Errorf("dst %#x: TxBytes = %d, want %d", f.DstIP, f.TxBytes, want[f.DstIP])
		}
	}

	if n := mapLen(t, m); n != 0 {
		t.Errorf("map has %d entries after drain, want 0", n)
	}

	// A second drain must return nothing (each delta accounted exactly once).
	if flows := p.pollIterate(); len(flows) != 0 {
		t.Errorf("second pollIterate returned %d flows, want 0", len(flows))
	}
}

// TestPollBatchDrains covers the batch path with the same
// exactly-once-and-empty contract.
func TestPollBatchDrains(t *testing.T) {
	m := newFlowAggMap(t, 64)

	key := bpf.FlowKey{SrcIP: 0x0100000A, DstIP: 0x0200000A, SrcPort: 1000, DstPort: 80, PID: 1, Protocol: 6}
	putFlow(t, m, key, 100)

	p := New(Config{}, m, nil, slog.Default())
	if !p.useBatch {
		t.Skip("kernel lacks batch map ops")
	}

	flows := p.pollBatch()
	if len(flows) != 1 {
		t.Fatalf("pollBatch returned %d flows, want 1", len(flows))
	}
	if want := 100 * uint64(runtime.NumCPU()); flows[0].TxBytes != want {
		t.Errorf("TxBytes = %d, want %d", flows[0].TxBytes, want)
	}
	if n := mapLen(t, m); n != 0 {
		t.Errorf("map has %d entries after drain, want 0", n)
	}
}

// TestPollQuicDrains verifies the QUIC drain path returns entries exactly
// once, sums per-CPU packet bytes, and empties the map.
func TestPollQuicDrains(t *testing.T) {
	quicMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.PerCPUHash,
		KeySize:    12, // sizeof(struct quic_flow_key)
		ValueSize:  40, // sizeof(struct quic_flow_metrics)
		MaxEntries: 16,
	})
	if err != nil {
		t.Skipf("cannot create BPF map (need CAP_BPF): %v", err)
	}
	defer quicMap.Close()

	key := bpf.QuicFlowKey{SrcIP: 0x0100000A, DstIP: 0x0200000A, SrcPort: 51820, DstPort: 443}
	perCPU := make([]bpf.QuicFlowMetrics, runtime.NumCPU())
	for i := range perCPU {
		perCPU[i] = bpf.QuicFlowMetrics{TxBytes: 500, PktCount: 2}
	}
	if err := quicMap.Put(&key, perCPU); err != nil {
		t.Fatalf("put quic entry: %v", err)
	}

	flowAgg := newFlowAggMap(t, 16)
	p := New(Config{}, flowAgg, nil, slog.Default())
	p.SetQuicMap(quicMap)

	flows := p.pollQuic()
	if len(flows) != 1 {
		t.Fatalf("pollQuic returned %d flows, want 1", len(flows))
	}
	f := flows[0]
	if f.Protocol != protoUDP {
		t.Errorf("Protocol = %d, want %d", f.Protocol, protoUDP)
	}
	if want := 500 * uint64(runtime.NumCPU()); f.TxBytes != want {
		t.Errorf("TxBytes = %d, want %d", f.TxBytes, want)
	}
	if want := 2 * uint64(runtime.NumCPU()); f.PacketCount != want {
		t.Errorf("PacketCount = %d, want %d", f.PacketCount, want)
	}

	if flows := p.pollQuic(); len(flows) != 0 {
		t.Errorf("second pollQuic returned %d flows, want 0", len(flows))
	}
}

// newQuicMap creates a PERCPU_HASH map shaped like quic_flows.
func newQuicMap(t *testing.T, maxEntries uint32) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.PerCPUHash,
		KeySize:    12, // sizeof(struct quic_flow_key)
		ValueSize:  40, // sizeof(struct quic_flow_metrics)
		MaxEntries: maxEntries,
	})
	if err != nil {
		t.Skipf("cannot create BPF map (need CAP_BPF): %v", err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func putQuic(t *testing.T, m *ebpf.Map, key bpf.QuicFlowKey, txPerCPU uint64) {
	t.Helper()
	perCPU := make([]bpf.QuicFlowMetrics, runtime.NumCPU())
	for i := range perCPU {
		perCPU[i] = bpf.QuicFlowMetrics{TxBytes: txPerCPU, PktCount: 1}
	}
	if err := m.Put(&key, perCPU); err != nil {
		t.Fatalf("put quic entry: %v", err)
	}
}

// TestPollMergesQuicWithoutDedup is the map-level regression test for the
// QUIC merge undercount: the old poller joined quic_flows against socket
// flows on (dst_ip, dst_port) alone, so ONE pod's connected-socket UDP flow
// silently discarded EVERY other pod's TC-observed QUIC bytes to the same
// destination. The two sources are now disjoint by construction kernel-side
// (see bpf/quic.bpf.c), and poll() must deliver every entry of both maps.
//
// Fails on the old code: it returned 1 flow here instead of 3.
func TestPollMergesQuicWithoutDedup(t *testing.T) {
	const (
		cdnIP   = uint32(0x0100000A)
		cdnPort = uint16(443)
	)

	flowAgg := newFlowAggMap(t, 16)
	// Socket-path UDP flow: created by cgroup/connect4 before the local
	// address is bound — src_ip/src_port zero, destination is the connect()
	// target. Coexists with quic entries only when the sources are disjoint
	// (e.g. it carries RX bytes counted by fexit/udp_recvmsg).
	putFlow(t, flowAgg, bpf.FlowKey{
		DstIP: cdnIP, DstPort: cdnPort, PID: 42, Protocol: protoUDP,
	}, 100)

	quicMap := newQuicMap(t, 16)
	// Two other pods' QUIC egress to the SAME destination.
	putQuic(t, quicMap, bpf.QuicFlowKey{
		SrcIP: 0x0300000A, DstIP: cdnIP, SrcPort: 51821, DstPort: cdnPort,
	}, 700)
	putQuic(t, quicMap, bpf.QuicFlowKey{
		SrcIP: 0x0400000A, DstIP: cdnIP, SrcPort: 51822, DstPort: cdnPort,
	}, 900)

	p := New(Config{}, flowAgg, nil, slog.Default())
	p.useBatch = false // deterministic drain path; the merge under test is shared
	p.SetQuicMap(quicMap)

	flows := p.poll()
	if len(flows) != 3 {
		t.Fatalf("poll returned %d flows, want 3 (socket flow + 2 pods' QUIC)", len(flows))
	}

	// Each source's bytes must arrive exactly once (per-CPU values summed).
	want := (100 + 700 + 900) * uint64(runtime.NumCPU())
	var got uint64
	for _, f := range flows {
		got += f.TxBytes
	}
	if got != want {
		t.Errorf("total TxBytes = %d, want %d", got, want)
	}
}
