//go:build linux

// Package poller periodically reads BPF maps to produce flow snapshots.
// Uses BatchLookupAndDelete on the flow_aggregates PERCPU_HASH map for
// efficient bulk reads. Falls back to Iterate on kernels < 5.6 that
// don't support batch operations.
package poller

import (
	"context"
	"errors"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	bpf "github.com/tollwing/tollwing/pkg/ebpf"
)

// FlowSnapshot is an aggregated flow from the flow_aggregates PERCPU_HASH map.
// Per-CPU values are summed before delivery.
type FlowSnapshot struct {
	SrcIP           uint32
	DstIP           uint32
	SrcPort         uint16
	DstPort         uint16
	PID             uint32
	Protocol        uint8
	Direction       uint8
	TxBytes         uint64
	RxBytes         uint64
	ConnCount       uint64
	PacketCount     uint64 // QUIC/UDP packet count (0 for TCP — use ConnCount instead)
	RetransmitBytes uint64
	RetransmitCount uint64
	Domain          string // DNS-resolved domain name (filled by agent)
	CloudService    string // Cloud service name (filled by agent)
}

// Handler processes a batch of flow snapshots on each poll tick.
type Handler func(flows []FlowSnapshot)

// Config controls the poller behavior.
type Config struct {
	// Interval between poll ticks. Default: 5s.
	Interval time.Duration

	// BatchSize is the number of entries to read per batch call. Default: 256.
	BatchSize int

	// OnDrops, when set together with SetDropCountersMap, receives the
	// cumulative kernel-side drop counters once per poll tick. Wire it to
	// exporter.SetKernelDropStats so tollwing_ringbuf_drops_total and
	// tollwing_map_update_drops_total report real kernel drops (P4).
	OnDrops func(bpf.DropCounters)
}

func (c *Config) setDefaults() {
	if c.Interval == 0 {
		c.Interval = 5 * time.Second
	}
	if c.BatchSize == 0 {
		c.BatchSize = 256
	}
}

// Poller reads BPF maps on a configurable interval.
type Poller struct {
	cfg        Config
	log        *slog.Logger
	flowAggMap *ebpf.Map // flow_aggregates PERCPU_HASH
	quicMap    *ebpf.Map // quic_flows PERCPU_HASH (optional)
	dropMap    *ebpf.Map // drop_counters PERCPU_ARRAY (optional)
	handler    Handler
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	useBatch   bool
	numCPU     int

	// lossyFallbackOnce gates the warning for kernels without
	// BPF_MAP_LOOKUP_AND_DELETE_ELEM on hash maps (< 5.14).
	lossyFallbackOnce sync.Once

	// Pre-allocated batch buffers — reused across poll ticks to avoid GC
	// pressure. batchValues is FLAT: cilium/ebpf batch ops on per-CPU maps
	// require a single []FlowMetrics of length BatchSize×PossibleCPU()
	// (entry i occupies [i*numCPU, (i+1)*numCPU)). The previous
	// [][]FlowMetrics shape made every batch call fail unmarshalling, so
	// the batch probe reported "unsupported" on every kernel and the
	// poller silently ran the fallback path forever.
	batchKeys   []bpf.FlowKey
	batchValues []bpf.FlowMetrics

	// Pre-allocated flows slice — reused across polls, reset to len 0 each tick.
	flows []FlowSnapshot
}

// New creates a Poller. flowAggMap is the "flow_aggregates" BPF map.
func New(cfg Config, flowAggMap *ebpf.Map, handler Handler, log *slog.Logger) *Poller {
	cfg.setDefaults()

	p := &Poller{
		cfg:        cfg,
		log:        log,
		flowAggMap: flowAggMap,
		handler:    handler,
		numCPU:     possibleCPUs(log),
	}

	// Pre-allocate batch buffers (flat per-CPU layout — see field comment).
	p.batchKeys = make([]bpf.FlowKey, cfg.BatchSize)
	p.batchValues = make([]bpf.FlowMetrics, cfg.BatchSize*p.numCPU)

	// Probe batch support. BatchLookupAndDelete requires kernel 5.6+.
	if flowAggMap != nil {
		p.useBatch = probeBatchSupport(flowAggMap, p.numCPU)
		if p.useBatch {
			log.Info("poller using BatchLookupAndDelete (kernel 5.6+)")
		} else {
			log.Info("poller using Iterate fallback (batch ops unavailable)")
		}
	}

	return p
}

// SetQuicMap sets the optional quic_flows PERCPU_HASH map for QUIC flow polling.
func (p *Poller) SetQuicMap(m *ebpf.Map) {
	p.quicMap = m
}

// SetDropCountersMap sets the optional drop_counters PERCPU_ARRAY map.
// When set (and Config.OnDrops is non-nil), cumulative kernel drop counters
// are read and delivered once per poll tick.
func (p *Poller) SetDropCountersMap(m *ebpf.Map) {
	p.dropMap = m
}

// Start begins the poll loop. Non-blocking.
func (p *Poller) Start(ctx context.Context) {
	ctx, p.cancel = context.WithCancel(ctx)
	p.wg.Add(1)
	go p.loop(ctx)
}

// Stop cancels the poll loop, performs a final flush to avoid losing
// in-flight flow data, and waits for it to exit.
func (p *Poller) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()

	// Final flush: drain remaining entries so byte counters aren't lost.
	flows := p.poll()
	if len(flows) > 0 && p.handler != nil {
		p.log.Info("final flush on shutdown", "flows", len(flows))
		p.handler(flows)
	}
}

func (p *Poller) loop(ctx context.Context) {
	defer p.wg.Done()

	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			flows := p.poll()
			if len(flows) > 0 && p.handler != nil {
				p.handler(flows)
			}
		}
	}
}

func (p *Poller) poll() []FlowSnapshot {
	var flows []FlowSnapshot
	if p.useBatch {
		flows = p.pollBatch()
	} else {
		flows = p.pollIterate()
	}

	// Merge QUIC flows if the quic_flows map is available.
	if p.quicMap != nil {
		flows = appendQuicFlows(flows, p.pollQuic())
	}

	// Deliver cumulative kernel drop counters once per tick.
	if p.dropMap != nil && p.cfg.OnDrops != nil {
		if dc, err := bpf.ReadDropCounters(p.dropMap); err != nil {
			p.log.Warn("read drop_counters", "err", err)
		} else {
			p.cfg.OnDrops(dc)
		}
	}

	return flows
}

// appendQuicFlows merges QUIC snapshots from the TC egress hook into the
// main flow list — with NO deduplication, on purpose.
//
// This is the seam where the two UDP byte sources meet, and they are
// disjoint BY CONSTRUCTION in the kernel, not deduplicated here:
// tollwing_quic_egress (bpf/quic.bpf.c) records nothing whenever
// agent_config.udp_socket_tx is set — i.e. -udp is on AND fentry/udp_sendmsg
// actually attached, making the socket path (flow_aggregates) the sole owner
// of UDP TX bytes. So any entry that reaches quic_flows was, by contract,
// NOT counted by the socket path.
//
// The dedup heuristic that used to live here — drop QUIC snapshots whose
// (dst_ip, dst_port) matched a socket-level UDP flow — was doubly broken:
// the socket path stores the PRE-DNAT connect() destination while the TC
// hook sees the POST-DNAT wire destination, so DNATed QUIC never matched
// and stayed double counted; and the destination-only key made one pod's
// connected-socket flow discard every other pod's TC-observed bytes to the
// same destination (undercount). Per P5, overlap is now eliminated at the
// source instead of joined on lossy keys; the trade-off (unconnected-UDP
// egress uncounted while -udp owns TX) is documented in quic.bpf.c.
func appendQuicFlows(flows, quic []FlowSnapshot) []FlowSnapshot {
	return append(flows, quic...)
}

// pollBatch uses BatchLookupAndDelete to atomically read and clear entries.
// Reuses pre-allocated buffers to avoid per-tick allocations.
func (p *Poller) pollBatch() []FlowSnapshot {
	p.flows = p.flows[:0] // reset, keep backing array
	flows := p.flows

	var cursor ebpf.MapBatchCursor
	for {
		n, err := p.flowAggMap.BatchLookupAndDelete(&cursor, p.batchKeys, p.batchValues, nil)
		for i := 0; i < n; i++ {
			// Entry i's per-CPU values live at [i*numCPU, (i+1)*numCPU).
			snap := sumPerCPU(p.batchKeys[i], p.batchValues[i*p.numCPU:(i+1)*p.numCPU])
			flows = append(flows, snap)
		}

		if errors.Is(err, ebpf.ErrKeyNotExist) || n == 0 {
			break // no more entries
		}
		if err != nil {
			p.log.Warn("batch lookup and delete error", "err", err)
			break
		}
	}

	p.flows = flows // save back in case append grew the backing array
	return flows
}

// pollIterate drains flow_aggregates one key at a time, as fallback for
// kernels without batch map ops. Values are read with LookupAndDelete: the
// kernel performs the read and the delete atomically under the bucket lock,
// so increments landing in between either make this snapshot or survive for
// the next tick. The previous read-then-delete destroyed every increment
// that landed between the iteration read and the delete (P4/P5 — silent
// byte loss on every fallback poll).
func (p *Poller) pollIterate() []FlowSnapshot {
	var (
		key    bpf.FlowKey
		values []bpf.FlowMetrics
		flows  []FlowSnapshot
		keys   []bpf.FlowKey
	)

	// Phase 1: collect keys only. The iterated values are NOT trusted —
	// the authoritative read happens in LookupAndDelete below.
	iter := p.flowAggMap.Iterate()
	for iter.Next(&key, &values) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		p.log.Warn("flow_aggregates iteration error", "err", err)
	}

	// Phase 2: atomically read-and-remove each key.
	for i := range keys {
		var perCPU []bpf.FlowMetrics
		err := p.flowAggMap.LookupAndDelete(&keys[i], &perCPU)
		switch {
		case err == nil:
			flows = append(flows, sumPerCPU(keys[i], perCPU))
		case errors.Is(err, ebpf.ErrKeyNotExist):
			// Removed concurrently; nothing left to account.
		default:
			// Kernels < 5.14 lack LOOKUP_AND_DELETE_ELEM on hash maps.
			// Degrade to the lossy read-then-delete — but say so.
			p.lossyFallbackOnce.Do(func() {
				p.log.Warn("lookup-and-delete unavailable, falling back to lossy read-then-delete",
					"err", err)
			})
			if lerr := p.flowAggMap.Lookup(&keys[i], &perCPU); lerr == nil {
				flows = append(flows, sumPerCPU(keys[i], perCPU))
			}
			p.flowAggMap.Delete(&keys[i])
		}
	}

	return flows
}

// sumPerCPU sums per-CPU FlowMetrics values into a single FlowSnapshot.
func sumPerCPU(key bpf.FlowKey, perCPU []bpf.FlowMetrics) FlowSnapshot {
	snap := FlowSnapshot{
		SrcIP:     key.SrcIP,
		DstIP:     key.DstIP,
		SrcPort:   key.SrcPort,
		DstPort:   key.DstPort,
		PID:       key.PID,
		Protocol:  key.Protocol,
		Direction: key.Direction,
	}
	for _, m := range perCPU {
		snap.TxBytes += m.TxBytes
		snap.RxBytes += m.RxBytes
		snap.ConnCount += m.ConnCount
		snap.RetransmitBytes += m.RetransmitBytes
		snap.RetransmitCount += m.RetransmitCount
	}
	return snap
}

// protoUDP is the IPPROTO_UDP wire value carried in FlowSnapshot.Protocol.
const protoUDP = 17

// pollQuic drains the quic_flows PERCPU_HASH map and converts QUIC entries
// to FlowSnapshots. Same two-phase drain as pollIterate: keys first, then
// an atomic LookupAndDelete per key, so per-packet increments landing
// mid-poll are never destroyed.
func (p *Poller) pollQuic() []FlowSnapshot {
	var (
		key   bpf.QuicFlowKey
		vals  []bpf.QuicFlowMetrics
		flows []FlowSnapshot
		keys  []bpf.QuicFlowKey
	)

	iter := p.quicMap.Iterate()
	for iter.Next(&key, &vals) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		p.log.Warn("quic_flows iteration error", "err", err)
	}

	for i := range keys {
		var perCPU []bpf.QuicFlowMetrics
		err := p.quicMap.LookupAndDelete(&keys[i], &perCPU)
		switch {
		case err == nil:
			// authoritative read below
		case errors.Is(err, ebpf.ErrKeyNotExist):
			continue
		default:
			p.lossyFallbackOnce.Do(func() {
				p.log.Warn("lookup-and-delete unavailable, falling back to lossy read-then-delete",
					"err", err)
			})
			if lerr := p.quicMap.Lookup(&keys[i], &perCPU); lerr != nil {
				p.quicMap.Delete(&keys[i])
				continue
			}
			p.quicMap.Delete(&keys[i])
		}

		snap := FlowSnapshot{
			SrcIP:     keys[i].SrcIP,
			DstIP:     keys[i].DstIP,
			SrcPort:   keys[i].SrcPort,
			DstPort:   keys[i].DstPort,
			Protocol:  protoUDP,
			Direction: 0, // egress (TC egress hook)
		}
		// Sum per-CPU values. QUIC is connectionless so we track packets,
		// not connections — leave ConnCount at zero.
		for _, m := range perCPU {
			snap.TxBytes += m.TxBytes
			snap.PacketCount += m.PktCount
		}
		flows = append(flows, snap)
	}

	return flows
}

// possibleCPUs returns the number of possible CPUs — the per-CPU value
// stride of BPF per-CPU maps. This can exceed runtime.NumCPU() (online
// CPUs) on hotplug-capable hosts; sizing buffers from NumCPU there would
// corrupt batch unmarshalling.
func possibleCPUs(log *slog.Logger) int {
	n, err := ebpf.PossibleCPU()
	if err != nil {
		log.Warn("possible CPU count unavailable, using runtime.NumCPU", "err", err)
		return runtime.NumCPU()
	}
	return n
}

// probeBatchSupport attempts a small batch lookup to detect kernel support
// (BPF_MAP_LOOKUP_BATCH, kernel 5.6+). numCPU must be the possible-CPU
// count so the flat per-CPU buffer has the shape cilium/ebpf requires —
// a mis-shaped buffer fails unmarshalling and masquerades as "batch
// unsupported" (which is exactly the bug that kept the batch path dead).
func probeBatchSupport(m *ebpf.Map, numCPU int) bool {
	keys := make([]bpf.FlowKey, 1)
	// Flat batch×numCPU buffer — see the batchValues field comment.
	values := make([]bpf.FlowMetrics, 1*numCPU)

	var cursor ebpf.MapBatchCursor
	_, err := m.BatchLookup(&cursor, keys, values, nil)
	// ErrKeyNotExist means batch is supported but map is empty — that's fine.
	// ErrNotSupported or EINVAL means batch ops aren't available.
	if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
		return true
	}
	return false
}
