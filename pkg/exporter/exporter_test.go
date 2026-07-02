//go:build linux

package exporter

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tollwing/tollwing/pkg/classifier"
)

func freePort() string {
	return fmt.Sprintf("127.0.0.1:%d", 19990+time.Now().UnixNano()%1000)
}

func TestExporter_HealthEndpoint(t *testing.T) {
	addr := freePort()
	e := New(Config{ListenAddr: addr}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := e.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("healthz request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("healthz status = %d, want 200", resp.StatusCode)
	}
}

func TestExporter_MetricsEndpoint(t *testing.T) {
	addr := freePort()
	e := New(Config{ListenAddr: addr}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := e.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("metrics request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("metrics status = %d, want 200", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}

	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	expected := []string{
		"tollwing_active_connections",
		"tollwing_connections_established_total",
		"tollwing_connections_closed_total",
		"tollwing_tx_bytes_total",
		"tollwing_rx_bytes_total",
		"tollwing_connections_by_type",
		"tollwing_cost_usd_total",
		"tollwing_sidecar_skipped_bytes_total",
		"tollwing_sidecar_skipped_connections_total",
	}

	for _, metric := range expected {
		if !strings.Contains(body, metric) {
			t.Errorf("metrics output missing %q", metric)
		}
	}
}

func TestExporter_RecordCounters(t *testing.T) {
	addr := freePort()
	e := New(Config{ListenAddr: addr}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := e.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	e.RecordEstablish()
	e.RecordEstablish()
	e.RecordClose()

	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("metrics request: %v", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	if !strings.Contains(body, "tollwing_connections_established_total 2") {
		t.Error("expected established_total 2")
	}
	if !strings.Contains(body, "tollwing_connections_closed_total 1") {
		t.Error("expected closed_total 1")
	}
}

func TestExporter_UpdateFromPoll_WithPodMetrics(t *testing.T) {
	addr := freePort()
	e := New(Config{ListenAddr: addr}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := e.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	flows := []ClassifiedFlow{
		{TrafficType: 4, TxBytes: 100, RxBytes: 50, Namespace: "default", Pod: "web-abc"},
		{TrafficType: 4, TxBytes: 200, RxBytes: 150, Namespace: "default", Pod: "web-abc"},
		{TrafficType: 1, TxBytes: 50, RxBytes: 25, Namespace: "kube-system", Pod: "coredns-xyz"},
	}
	e.UpdateFromPoll(flows)

	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("metrics request: %v", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 16384)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	if !strings.Contains(body, "tollwing_active_connections 3") {
		t.Errorf("expected active_connections 3, got:\n%s", body)
	}

	// Check per-pod metrics exist.
	if !strings.Contains(body, `tollwing_pod_tx_bytes_total{namespace="default",pod="web-abc"}`) {
		t.Errorf("missing per-pod tx metric for default/web-abc")
	}
	if !strings.Contains(body, `tollwing_pod_tx_bytes_total{namespace="kube-system",pod="coredns-xyz"}`) {
		t.Errorf("missing per-pod tx metric for kube-system/coredns-xyz")
	}
}

func TestExporter_SidecarDedup(t *testing.T) {
	addr := freePort()
	e := New(Config{ListenAddr: addr}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := e.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	flows := []ClassifiedFlow{
		{TrafficType: 4, TxBytes: 1000, RxBytes: 500, IsSidecar: false},
		{TrafficType: 4, TxBytes: 1000, RxBytes: 500, IsSidecar: true}, // should be skipped
	}
	e.UpdateFromPoll(flows)

	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("metrics request: %v", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 16384)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	// Sidecar bytes should be counted as skipped.
	if !strings.Contains(body, "tollwing_sidecar_skipped_bytes_total 1500") {
		t.Errorf("expected sidecar_skipped_bytes_total 1500, body:\n%s", body)
	}
	if !strings.Contains(body, "tollwing_sidecar_skipped_connections_total 1") {
		t.Errorf("expected sidecar_skipped_connections_total 1")
	}
}

func TestExporter_CostMetrics(t *testing.T) {
	addr := freePort()
	e := New(Config{ListenAddr: addr}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := e.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	flows := []ClassifiedFlow{
		{TrafficType: 4, TxBytes: 1073741824, RxBytes: 0, CostUSD: 0.09},                                       // 1 GB internet egress @ $0.09
		{TrafficType: 2, TxBytes: 1073741824, RxBytes: 0, CostUSD: 0.01, Namespace: "default", Pod: "web-abc"}, // cross-AZ
	}
	e.UpdateFromPoll(flows)

	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("metrics request: %v", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 16384)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	// Check per-type cost metric.
	if !strings.Contains(body, "tollwing_cost_usd_total") {
		t.Error("missing tollwing_cost_usd_total metric")
	}

	// Check per-pod cost metric.
	if !strings.Contains(body, `tollwing_pod_cost_usd_total{namespace="default",pod="web-abc"}`) {
		t.Errorf("missing per-pod cost metric, body:\n%s", body)
	}
}

// TestExporter_CostMetrics_SubMicroDollarFlows is a regression test for the
// per-flow cost-truncation bug (DEC-011, P4): a workload of many small,
// short-lived flows — each costing less than $0.000001 — must still accumulate
// into a non-zero cost counter. The previous code floored every flow with
// uint64(CostUSD * 1e6), so each sub-micro-dollar flow truncated to 0 and both
// tollwing_cost_usd_total and tollwing_pod_cost_usd_total stayed at $0 despite
// real byte volume (observed on the L2b tier: ~376 MB cross_az, cost $0.000000).
func TestExporter_CostMetrics_SubMicroDollarFlows(t *testing.T) {
	e := New(Config{ListenAddr: ":0"}, slog.Default())

	const (
		nFlows      = 1000
		costPerFlow = 0.0000004 // $4e-7: sub-micro-dollar, uint64(*1e6) == 0
	)
	// Guard the premise: each flow must floor to zero under the old integer path.
	// (Use a runtime var — Go forbids converting the non-integer *constant* 0.4 to uint64.)
	perFlow := costPerFlow
	if floor := uint64(perFlow * 1_000_000); floor != 0 {
		t.Fatalf("test premise broken: %.9f floors to %d, not sub-micro-dollar", perFlow, floor)
	}

	// Derive the index/label from the enum — never hardcode "cross_az" (P6).
	crossAZ := int(classifier.CrossAZ)
	flows := make([]ClassifiedFlow, nFlows)
	for i := range flows {
		flows[i] = ClassifiedFlow{
			TrafficType: crossAZ,
			TxBytes:     1024,
			CostUSD:     costPerFlow,
			Namespace:   "default",
			Pod:         "client-loop",
		}
	}
	e.UpdateFromPoll(flows)

	wantUSD := nFlows * costPerFlow // $0.0004 — clearly non-zero at %.6f

	// Per-type counter: the accumulated float must be non-zero and equal the sum.
	gotType := math.Float64frombits(e.state.costByType[crossAZ].Load())
	if gotType == 0 {
		t.Fatalf("per-type %s cost truncated to 0; want ~%.6f", classifier.CrossAZ, wantUSD)
	}
	if math.Abs(gotType-wantUSD) > 1e-9 {
		t.Errorf("per-type %s cost = %.9f, want %.9f", classifier.CrossAZ, gotType, wantUSD)
	}

	// Per-pod counter: same assertion, read under podMu.
	e.state.podMu.Lock()
	gotPod := e.state.podCost[podKey{Namespace: "default", Pod: "client-loop"}]
	e.state.podMu.Unlock()
	if gotPod == 0 {
		t.Fatalf("per-pod cost truncated to 0; want ~%.6f", wantUSD)
	}
	if math.Abs(gotPod-wantUSD) > 1e-9 {
		t.Errorf("per-pod cost = %.9f, want %.9f", gotPod, wantUSD)
	}

	// Contract level: the emitted %.6f lines must show the non-zero value, not
	// the 0.000000 the truncation bug produced.
	rec := httptest.NewRecorder()
	e.handleMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	wantType := fmt.Sprintf("tollwing_cost_usd_total{traffic_type=%q} %.6f", classifier.CrossAZ.String(), wantUSD)
	if !strings.Contains(body, wantType) {
		t.Errorf("missing emitted per-type cost line %q in:\n%s", wantType, body)
	}
	zeroType := fmt.Sprintf("tollwing_cost_usd_total{traffic_type=%q} 0.000000", classifier.CrossAZ.String())
	if strings.Contains(body, zeroType) {
		t.Error("per-type cost emitted as 0.000000 — sub-micro-dollar truncation regression")
	}
	wantPod := fmt.Sprintf("tollwing_pod_cost_usd_total{namespace=%q,pod=%q} %.6f", "default", "client-loop", wantUSD)
	if !strings.Contains(body, wantPod) {
		t.Errorf("missing emitted per-pod cost line %q in:\n%s", wantPod, body)
	}
}

func TestExporter_PodCardinalityBound(t *testing.T) {
	e := New(Config{ListenAddr: ":0"}, slog.Default())

	// Insert more pods than maxPodMetrics (1000).
	for i := 0; i < 1100; i++ {
		flows := []ClassifiedFlow{{
			TrafficType: 1,
			TxBytes:     100,
			RxBytes:     50,
			Namespace:   "default",
			Pod:         fmt.Sprintf("pod-%d", i),
		}}
		e.UpdateFromPoll(flows)
	}

	e.state.podMu.Lock()
	count := len(e.state.podMetrics)
	e.state.podMu.Unlock()

	if count > 1001 { // allow 1 margin for off-by-one
		t.Errorf("pod metrics count %d exceeds max %d", count, 1000)
	}

	// Latest pods should still be present.
	e.state.podMu.Lock()
	_, ok := e.state.podMetrics[podKey{Namespace: "default", Pod: "pod-1099"}]
	e.state.podMu.Unlock()
	if !ok {
		t.Error("latest pod should still be tracked")
	}
}

func TestExporter_Shutdown(t *testing.T) {
	addr := freePort()
	e := New(Config{ListenAddr: addr}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())

	if err := e.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	cancel()
	time.Sleep(100 * time.Millisecond)

	_, err := http.Get("http://" + addr + "/healthz")
	if err == nil {
		t.Error("expected connection error after shutdown")
	}
}

// TestExporter_KernelDropMetrics is the regression test for the lying drop
// instrumentation: tollwing_ringbuf_drops_total had no writers and read 0
// forever. The kernel-mirrored totals must surface in both drop metrics.
func TestExporter_KernelDropMetrics(t *testing.T) {
	addr := freePort()
	e := New(Config{ListenAddr: addr}, slog.Default())

	e.SetKernelDropStats(7, 13)
	// Cumulative kernel counters: a later, larger reading replaces the
	// earlier one rather than accumulating on top of it.
	e.SetKernelDropStats(9, 21)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := e.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("metrics request: %v", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 32768)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	for _, want := range []string{
		"tollwing_ringbuf_drops_total 9\n",
		"tollwing_map_update_drops_total 21\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}
