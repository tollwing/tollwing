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
	handler    Handler
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	useBatch   bool
	numCPU     int

	// Pre-allocated batch buffers — reused across poll ticks to avoid GC pressure.
	batchKeys   []bpf.FlowKey
	batchValues [][]bpf.FlowMetrics

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
		numCPU:     runtime.NumCPU(),
	}

	// Pre-allocate batch buffers.
	p.batchKeys = make([]bpf.FlowKey, cfg.BatchSize)
	p.batchValues = make([][]bpf.FlowMetrics, cfg.BatchSize)
	for i := range p.batchValues {
		p.batchValues[i] = make([]bpf.FlowMetrics, p.numCPU)
	}

	// Probe batch support. BatchLookupAndDelete requires kernel 5.6+.
	if flowAggMap != nil {
		p.useBatch = probeBatchSupport(flowAggMap)
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

	// Append QUIC flows if the quic_flows map is available.
	if p.quicMap != nil {
		quicFlows := p.pollQuic()
		flows = append(flows, quicFlows...)
	}

	return flows
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
			snap := sumPerCPU(p.batchKeys[i], p.batchValues[i])
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

// pollIterate uses per-key Iterate + Delete as fallback for kernels < 5.6.
func (p *Poller) pollIterate() []FlowSnapshot {
	var (
		key    bpf.FlowKey
		values []bpf.FlowMetrics
		flows  []FlowSnapshot
		keys   []bpf.FlowKey
	)

	iter := p.flowAggMap.Iterate()
	for iter.Next(&key, &values) {
		snap := sumPerCPU(key, values)
		flows = append(flows, snap)
		keyCopy := key
		keys = append(keys, keyCopy)
	}

	if err := iter.Err(); err != nil {
		p.log.Warn("flow_aggregates iteration error", "err", err)
	}

	// Delete iterated keys to reset counters.
	for _, k := range keys {
		p.flowAggMap.Delete(&k)
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

// pollQuic reads the quic_flows PERCPU_HASH map and converts QUIC entries
// to FlowSnapshots. Uses Iterate + Delete since QUIC flows are typically
// fewer than TCP flows.
func (p *Poller) pollQuic() []FlowSnapshot {
	var (
		key    bpf.QuicFlowKey
		values []bpf.QuicFlowMetrics
		flows  []FlowSnapshot
		keys   []bpf.QuicFlowKey
	)

	iter := p.quicMap.Iterate()
	for iter.Next(&key, &values) {
		snap := FlowSnapshot{
			SrcIP:     key.SrcIP,
			DstIP:     key.DstIP,
			SrcPort:   key.SrcPort,
			DstPort:   key.DstPort,
			Protocol:  17, // UDP
			Direction: 0,  // egress (TC egress hook)
		}
		// Sum per-CPU values. QUIC is connectionless so we track packets,
		// not connections — leave ConnCount at zero.
		for _, m := range values {
			snap.TxBytes += m.TxBytes
			snap.PacketCount += m.PktCount
		}
		flows = append(flows, snap)
		keyCopy := key
		keys = append(keys, keyCopy)
	}

	if err := iter.Err(); err != nil {
		p.log.Warn("quic_flows iteration error", "err", err)
	}

	// Delete iterated keys to reset counters.
	for _, k := range keys {
		p.quicMap.Delete(&k)
	}

	return flows
}

// probeBatchSupport attempts a zero-size batch lookup to detect support.
func probeBatchSupport(m *ebpf.Map) bool {
	keys := make([]bpf.FlowKey, 1)
	values := make([][]bpf.FlowMetrics, 1)
	values[0] = make([]bpf.FlowMetrics, runtime.NumCPU())

	var cursor ebpf.MapBatchCursor
	_, err := m.BatchLookup(&cursor, keys, values, nil)
	// ErrKeyNotExist means batch is supported but map is empty — that's fine.
	// ErrNotSupported or EINVAL means batch ops aren't available.
	if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
		return true
	}
	return false
}
