//go:build linux

// Package exporter exposes tollwing metrics via a Prometheus /metrics endpoint.
package exporter

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tollwing/tollwing/pkg/classifier"
)

// Config controls the Prometheus exporter.
type Config struct {
	// ListenAddr is the HTTP listen address. Default: ":9990".
	ListenAddr string
}

func (c *Config) setDefaults() {
	if c.ListenAddr == "" {
		c.ListenAddr = ":9990"
	}
}

// HealthStats provides agent health info for self-monitoring metrics.
// Populated by a callback to avoid import cycles.
type HealthStats struct {
	EnricherCacheSize int
	DNSCacheSize      int
	PollLatencyUs     int64 // last poll duration in microseconds
	GoroutineCount    int
	HeapAllocBytes    uint64
	HeapSysBytes      uint64
}

// HealthStatsFunc is a callback that returns current agent health stats.
type HealthStatsFunc func() HealthStats

// bufPool reuses bufio.Writers across /metrics scrapes to reduce allocations.
var bufPool = sync.Pool{
	New: func() any { return bufio.NewWriterSize(nil, 4096) },
}

// Exporter serves Prometheus metrics at /metrics.
type Exporter struct {
	cfg         Config
	log         *slog.Logger
	server      *http.Server
	state       metricsState
	healthStats HealthStatsFunc

	// Cached health stats — updated once per poll tick, read on scrape.
	cachedHealth atomic.Pointer[HealthStats]

	// Self-monitoring counters.
	pollCount atomic.Uint64

	// Kernel-side drop totals, mirrored from the BPF drop_counters map via
	// SetKernelDropStats. Cumulative — the kernel owns the counters and
	// userspace only republishes them.
	ringbufDrops   atomic.Uint64
	mapUpdateDrops atomic.Uint64
}

// SetHealthStats sets the callback for agent health metrics.
func (e *Exporter) SetHealthStats(fn HealthStatsFunc) {
	e.healthStats = fn
}

// RecordPoll records a poll tick and refreshes cached health stats.
// Health stats are sampled here (once per poll) instead of on every
// /metrics scrape, avoiding runtime.ReadMemStats STW pauses on scrape.
func (e *Exporter) RecordPoll() {
	e.pollCount.Add(1)
	if e.healthStats != nil {
		h := e.healthStats()
		e.cachedHealth.Store(&h)
	}
}

// SetKernelDropStats publishes the cumulative kernel-side drop counters.
// ringbufDrops is the total of BPF ring-buffer reserve failures (lost
// lifecycle events + DNS captures); mapUpdateDrops is the total of
// map-full update failures (flow_aggregates + quic_flows). Both are
// monotonic totals read from the kernel drop_counters map on each poll
// tick, so this stores rather than increments. It replaces the old
// RecordRingbufDrop, which had no callers — the metric read 0 forever
// while the kernel silently dropped data (P4).
func (e *Exporter) SetKernelDropStats(ringbufDrops, mapUpdateDrops uint64) {
	e.ringbufDrops.Store(ringbufDrops)
	e.mapUpdateDrops.Store(mapUpdateDrops)
}

// podKey identifies a pod for per-pod metrics.
type podKey struct {
	Namespace string
	Pod       string
}

// podMetrics holds accumulated byte counters for a single pod.
type podMetrics struct {
	TxBytes uint64
	RxBytes uint64
}

// metricsState holds the latest aggregated metrics, updated on each poll tick.
type metricsState struct {
	// Per-traffic-type byte counters (monotonically increasing — accumulated across polls).
	txByType [numTrafficTypes]atomic.Uint64
	rxByType [numTrafficTypes]atomic.Uint64

	// Per-traffic-type connection counts (current snapshot).
	connsByType [numTrafficTypes]atomic.Int64

	// Total active connections.
	activeConns atomic.Int64

	// Connection lifecycle counters.
	totalEstablished atomic.Uint64
	totalClosed      atomic.Uint64

	// Retransmission counters (monotonically increasing).
	retransmitBytes atomic.Uint64
	retransmitCount atomic.Uint64

	// Per-pod byte counters (monotonically increasing).
	// Protected by podMu since cardinality is dynamic.
	// Bounded to maxPodMetrics via ring-buffer LRU eviction.
	podMu      sync.Mutex
	podMetrics map[podKey]*podMetrics
	podRing    []podKey // ring buffer for LRU eviction
	podRingPos int      // next write position in ring

	// Per-traffic-type cost in USD (monotonically increasing). Accumulated in
	// full-precision float dollars and rounded to %.6f only at emit time.
	// Stored as float64-bits in an atomic.Uint64 (see addCostUSD) to keep the
	// lock-free scrape read that the byte counters use.
	// Per DEC-011 (P4): never floor per flow — the previous uint64(CostUSD*1e6)
	// truncated every sub-micro-dollar flow (many short-lived connections) to $0.
	costByType [numTrafficTypes]atomic.Uint64

	// Per-pod cost in USD (monotonically increasing). Plain float64 dollars
	// accumulated under podMu; rounded to %.6f only at emit time (DEC-011, P4).
	podCost map[podKey]float64

	// Sidecar dedup counters.
	sidecarSkippedBytes atomic.Uint64
	sidecarSkippedConns atomic.Uint64
}

const (
	numTrafficTypes = 12   // must match classifier.NumTrafficTypes
	maxPodMetrics   = 1000 // max unique pods tracked before LRU eviction
)

// Compile-time assertion: numTrafficTypes matches classifier enum.
var _ [numTrafficTypes - int(classifier.NumTrafficTypes)]struct{} // fails if mismatched

// New creates a Prometheus exporter.
func New(cfg Config, log *slog.Logger) *Exporter {
	cfg.setDefaults()
	e := &Exporter{
		cfg: cfg,
		log: log,
	}
	e.state.podMetrics = make(map[podKey]*podMetrics)
	e.state.podCost = make(map[podKey]float64)
	e.state.podRing = make([]podKey, maxPodMetrics)
	return e
}

// Start begins serving /metrics. Non-blocking.
func (e *Exporter) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", e.handleMetrics)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	e.server = &http.Server{
		Addr:    e.cfg.ListenAddr,
		Handler: mux,
	}

	go func() {
		e.log.Info("prometheus exporter listening", "addr", e.cfg.ListenAddr)
		if err := e.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			e.log.Error("prometheus server error", "err", err)
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		e.server.Shutdown(shutdownCtx)
	}()

	return nil
}

// RecordEstablish increments the established connection counter.
func (e *Exporter) RecordEstablish() {
	e.state.totalEstablished.Add(1)
}

// RecordClose increments the closed connection counter.
func (e *Exporter) RecordClose() {
	e.state.totalClosed.Add(1)
}

// ClassifiedFlow is a flow with its traffic type already resolved.
// Avoids double-classification between agent poll handler and exporter.
type ClassifiedFlow struct {
	TrafficType     int
	TxBytes         uint64
	RxBytes         uint64
	RetransmitBytes uint64
	RetransmitCount uint64
	CostUSD         float64 // calculated cost in USD for this flow
	Namespace       string  // K8s namespace (empty if unknown)
	Pod             string  // K8s pod name (empty if unknown)
	IsSidecar       bool    // true if this is sidecar-internal (skip byte counting)

	// Service-dependency graph enrichment — the source service, both
	// endpoints' zones, and the destination's service identity (resolved
	// from the pre-DNAT ClusterIP intent, falling back to the post-DNAT
	// backend pod). Any field may be empty when K8s metadata is unavailable.
	SrcZone      string
	SrcService   string
	DstNamespace string
	DstPod       string
	DstService   string
	DstZone      string

	// Domain resolution from the DNS tracker — populated by the agent
	// before publishing to the cost engine / NATS so the control plane
	// can perform DNS cascade attribution (cost grouped by destination
	// domain rather than only by destination IP).
	ResolvedDomain string
	CloudService   string
}

// addCostUSD atomically adds delta dollars to a cost counter stored as
// float64-bits in an atomic.Uint64. The poll loop is the only writer, so the
// CAS effectively never contends; the atomic exists only so the /metrics scrape
// can read the counter lock-free (like the byte counters).
//
// Per DEC-011 (P4): cost is accumulated in full-precision float dollars and
// rounded only at emit time. Flooring per flow — uint64(delta*1e6) — truncated
// every sub-micro-dollar flow to $0, so workloads of many small short-lived
// flows reported $0 despite real byte volume.
func addCostUSD(c *atomic.Uint64, delta float64) {
	for {
		old := c.Load()
		next := math.Float64frombits(old) + delta
		if c.CompareAndSwap(old, math.Float64bits(next)) {
			return
		}
	}
}

// UpdateFromPoll updates metrics from pre-classified flow data.
// Byte and retransmit counters are accumulated (monotonically increasing).
// Connection counts reflect the current snapshot.
// Sidecar-internal flows are counted but excluded from byte totals.
func (e *Exporter) UpdateFromPoll(flows []ClassifiedFlow) {
	// Reset per-type connection snapshot.
	for i := 0; i < numTrafficTypes; i++ {
		e.state.connsByType[i].Store(0)
	}

	// Collect per-pod deltas under a single lock acquisition.
	e.state.podMu.Lock()
	for _, f := range flows {
		// Sidecar dedup: skip byte counting for internal sidecar traffic
		// (loopback connections between app and Envoy/Linkerd proxy).
		if f.IsSidecar {
			e.state.sidecarSkippedBytes.Add(f.TxBytes + f.RxBytes)
			e.state.sidecarSkippedConns.Add(1)
			continue
		}

		idx := f.TrafficType
		if idx < 0 || idx >= numTrafficTypes {
			idx = 0
		}

		e.state.txByType[idx].Add(f.TxBytes)
		e.state.rxByType[idx].Add(f.RxBytes)
		e.state.connsByType[idx].Add(1)
		e.state.retransmitBytes.Add(f.RetransmitBytes)
		e.state.retransmitCount.Add(f.RetransmitCount)

		// Per-type cost in USD. Accumulate full-precision float dollars and
		// round once at emit (DEC-011, P4) — flooring here would truncate every
		// sub-micro-dollar flow to $0.
		if f.CostUSD > 0 {
			addCostUSD(&e.state.costByType[idx], f.CostUSD)
		}

		// Per-pod metrics (bounded cardinality with LRU eviction).
		if f.Namespace != "" && f.Pod != "" {
			pk := podKey{Namespace: f.Namespace, Pod: f.Pod}
			pm := e.state.podMetrics[pk]
			if pm == nil {
				// New pod — evict oldest if at capacity.
				if len(e.state.podMetrics) >= maxPodMetrics {
					oldest := e.state.podRing[e.state.podRingPos]
					if oldest.Namespace != "" {
						delete(e.state.podMetrics, oldest)
						delete(e.state.podCost, oldest)
					}
				}
				pm = &podMetrics{}
				e.state.podMetrics[pk] = pm
				e.state.podRing[e.state.podRingPos] = pk
				e.state.podRingPos = (e.state.podRingPos + 1) % len(e.state.podRing)
			}
			pm.TxBytes += f.TxBytes
			pm.RxBytes += f.RxBytes

			// Per-pod cost in USD (float dollars; rounded only at emit — DEC-011, P4).
			if f.CostUSD > 0 {
				e.state.podCost[pk] += f.CostUSD
			}
		}
	}
	e.state.podMu.Unlock()

	e.state.activeConns.Store(int64(len(flows)))
}

// handleMetrics writes Prometheus text format metrics.
// Lock-free: all state is accessed via atomics.
// Uses a pooled bufio.Writer to batch syscalls and reduce allocations.
func (e *Exporter) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	bw := bufPool.Get().(*bufio.Writer)
	bw.Reset(w)
	defer func() {
		bw.Flush()
		bufPool.Put(bw)
	}()

	// Connection lifecycle.
	fmt.Fprintf(bw, "# HELP tollwing_active_connections Number of currently tracked connections.\n")
	fmt.Fprintf(bw, "# TYPE tollwing_active_connections gauge\n")
	fmt.Fprintf(bw, "tollwing_active_connections %d\n", e.state.activeConns.Load())

	fmt.Fprintf(bw, "# HELP tollwing_connections_established_total Total connections established.\n")
	fmt.Fprintf(bw, "# TYPE tollwing_connections_established_total counter\n")
	fmt.Fprintf(bw, "tollwing_connections_established_total %d\n", e.state.totalEstablished.Load())

	fmt.Fprintf(bw, "# HELP tollwing_connections_closed_total Total connections closed.\n")
	fmt.Fprintf(bw, "# TYPE tollwing_connections_closed_total counter\n")
	fmt.Fprintf(bw, "tollwing_connections_closed_total %d\n", e.state.totalClosed.Load())

	// Per-traffic-type byte counters (monotonically increasing).
	fmt.Fprintf(bw, "# HELP tollwing_tx_bytes_total Bytes sent by traffic type.\n")
	fmt.Fprintf(bw, "# TYPE tollwing_tx_bytes_total counter\n")
	for i := 0; i < numTrafficTypes; i++ {
		label := classifier.TrafficType(i).String()
		fmt.Fprintf(bw, "tollwing_tx_bytes_total{traffic_type=%q} %d\n", label, e.state.txByType[i].Load())
	}

	fmt.Fprintf(bw, "# HELP tollwing_rx_bytes_total Bytes received by traffic type.\n")
	fmt.Fprintf(bw, "# TYPE tollwing_rx_bytes_total counter\n")
	for i := 0; i < numTrafficTypes; i++ {
		label := classifier.TrafficType(i).String()
		fmt.Fprintf(bw, "tollwing_rx_bytes_total{traffic_type=%q} %d\n", label, e.state.rxByType[i].Load())
	}

	// Per-traffic-type connection counts (snapshot).
	fmt.Fprintf(bw, "# HELP tollwing_connections_by_type Active connections by traffic type.\n")
	fmt.Fprintf(bw, "# TYPE tollwing_connections_by_type gauge\n")
	for i := 0; i < numTrafficTypes; i++ {
		label := classifier.TrafficType(i).String()
		fmt.Fprintf(bw, "tollwing_connections_by_type{traffic_type=%q} %d\n", label, e.state.connsByType[i].Load())
	}

	// Retransmission counters (monotonically increasing).
	fmt.Fprintf(bw, "# HELP tollwing_retransmit_bytes_total Total retransmitted bytes (wasted bandwidth).\n")
	fmt.Fprintf(bw, "# TYPE tollwing_retransmit_bytes_total counter\n")
	fmt.Fprintf(bw, "tollwing_retransmit_bytes_total %d\n", e.state.retransmitBytes.Load())

	fmt.Fprintf(bw, "# HELP tollwing_retransmit_count_total Total number of retransmissions.\n")
	fmt.Fprintf(bw, "# TYPE tollwing_retransmit_count_total counter\n")
	fmt.Fprintf(bw, "tollwing_retransmit_count_total %d\n", e.state.retransmitCount.Load())

	// ---- Per-traffic-type cost (USD) ----
	fmt.Fprintf(bw, "# HELP tollwing_cost_usd_total Estimated network cost in USD by traffic type.\n")
	fmt.Fprintf(bw, "# TYPE tollwing_cost_usd_total counter\n")
	for i := 0; i < numTrafficTypes; i++ {
		label := classifier.TrafficType(i).String()
		costUSD := math.Float64frombits(e.state.costByType[i].Load())
		fmt.Fprintf(bw, "tollwing_cost_usd_total{traffic_type=%q} %.6f\n", label, costUSD)
	}

	// ---- Per-pod byte counters and cost ----
	e.state.podMu.Lock()
	if len(e.state.podMetrics) > 0 {
		fmt.Fprintf(bw, "# HELP tollwing_pod_tx_bytes_total Bytes sent per pod.\n")
		fmt.Fprintf(bw, "# TYPE tollwing_pod_tx_bytes_total counter\n")
		for pk, pm := range e.state.podMetrics {
			fmt.Fprintf(bw, "tollwing_pod_tx_bytes_total{namespace=%q,pod=%q} %d\n", pk.Namespace, pk.Pod, pm.TxBytes)
		}
		fmt.Fprintf(bw, "# HELP tollwing_pod_rx_bytes_total Bytes received per pod.\n")
		fmt.Fprintf(bw, "# TYPE tollwing_pod_rx_bytes_total counter\n")
		for pk, pm := range e.state.podMetrics {
			fmt.Fprintf(bw, "tollwing_pod_rx_bytes_total{namespace=%q,pod=%q} %d\n", pk.Namespace, pk.Pod, pm.RxBytes)
		}
		fmt.Fprintf(bw, "# HELP tollwing_pod_cost_usd_total Estimated network cost in USD per pod.\n")
		fmt.Fprintf(bw, "# TYPE tollwing_pod_cost_usd_total counter\n")
		for pk, costUSD := range e.state.podCost {
			fmt.Fprintf(bw, "tollwing_pod_cost_usd_total{namespace=%q,pod=%q} %.6f\n", pk.Namespace, pk.Pod, costUSD)
		}
	}
	e.state.podMu.Unlock()

	// ---- Sidecar dedup metrics ----
	fmt.Fprintf(bw, "# HELP tollwing_sidecar_skipped_bytes_total Bytes skipped from sidecar-internal (loopback) traffic.\n")
	fmt.Fprintf(bw, "# TYPE tollwing_sidecar_skipped_bytes_total counter\n")
	fmt.Fprintf(bw, "tollwing_sidecar_skipped_bytes_total %d\n", e.state.sidecarSkippedBytes.Load())

	fmt.Fprintf(bw, "# HELP tollwing_sidecar_skipped_connections_total Connections skipped from sidecar-internal traffic.\n")
	fmt.Fprintf(bw, "# TYPE tollwing_sidecar_skipped_connections_total counter\n")
	fmt.Fprintf(bw, "tollwing_sidecar_skipped_connections_total %d\n", e.state.sidecarSkippedConns.Load())

	// ---- Self-monitoring metrics ----
	fmt.Fprintf(bw, "# HELP tollwing_poll_total Total number of map poll ticks.\n")
	fmt.Fprintf(bw, "# TYPE tollwing_poll_total counter\n")
	fmt.Fprintf(bw, "tollwing_poll_total %d\n", e.pollCount.Load())

	fmt.Fprintf(bw, "# HELP tollwing_ringbuf_drops_total Ring buffer events dropped due to full buffer.\n")
	fmt.Fprintf(bw, "# TYPE tollwing_ringbuf_drops_total counter\n")
	fmt.Fprintf(bw, "tollwing_ringbuf_drops_total %d\n", e.ringbufDrops.Load())

	fmt.Fprintf(bw, "# HELP tollwing_map_update_drops_total BPF map updates dropped because the map was full (flow_aggregates + quic_flows).\n")
	fmt.Fprintf(bw, "# TYPE tollwing_map_update_drops_total counter\n")
	fmt.Fprintf(bw, "tollwing_map_update_drops_total %d\n", e.mapUpdateDrops.Load())

	// Health stats are sampled per poll tick (not per scrape) to avoid
	// runtime.ReadMemStats STW pauses during Prometheus scrapes.
	if h := e.cachedHealth.Load(); h != nil {
		fmt.Fprintf(bw, "# HELP tollwing_enricher_cache_size Current number of entries in the PID enricher cache.\n")
		fmt.Fprintf(bw, "# TYPE tollwing_enricher_cache_size gauge\n")
		fmt.Fprintf(bw, "tollwing_enricher_cache_size %d\n", h.EnricherCacheSize)

		fmt.Fprintf(bw, "# HELP tollwing_dns_cache_size Current number of entries in the DNS cache.\n")
		fmt.Fprintf(bw, "# TYPE tollwing_dns_cache_size gauge\n")
		fmt.Fprintf(bw, "tollwing_dns_cache_size %d\n", h.DNSCacheSize)

		fmt.Fprintf(bw, "# HELP tollwing_goroutines Current number of goroutines.\n")
		fmt.Fprintf(bw, "# TYPE tollwing_goroutines gauge\n")
		fmt.Fprintf(bw, "tollwing_goroutines %d\n", h.GoroutineCount)

		fmt.Fprintf(bw, "# HELP tollwing_heap_alloc_bytes Current heap allocation in bytes.\n")
		fmt.Fprintf(bw, "# TYPE tollwing_heap_alloc_bytes gauge\n")
		fmt.Fprintf(bw, "tollwing_heap_alloc_bytes %d\n", h.HeapAllocBytes)

		fmt.Fprintf(bw, "# HELP tollwing_heap_sys_bytes Total heap memory obtained from OS.\n")
		fmt.Fprintf(bw, "# TYPE tollwing_heap_sys_bytes gauge\n")
		fmt.Fprintf(bw, "tollwing_heap_sys_bytes %d\n", h.HeapSysBytes)
	}
}
