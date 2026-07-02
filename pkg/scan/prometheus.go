package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// maxResponseBytes caps a Prometheus /api/v1/query response (64 MiB) so a
// misconfigured or hostile endpoint can't exhaust memory.
const maxResponseBytes = 64 << 20

// PromSource reads the agent's cost metrics from a Prometheus HTTP API.
//
// The agent exports cumulative counters, one series per node; the scan wants the
// spend *during* the window, summed across the fleet. So it asks Prometheus for
// the range-increase, aggregated:
//
//	sum by (traffic_type) (increase(tollwing_cost_usd_total[<window>]))
//	sum by (namespace, pod) (increase(tollwing_pod_cost_usd_total[<window>]))
type PromSource struct {
	BaseURL string       // e.g. http://prometheus.monitoring:9090
	Client  *http.Client // nil → a client with a sane timeout
}

// Fetch runs the two aggregation queries for the given PromQL window string
// (e.g. "24h", "7d") and returns per-path and per-pod window spend.
func (p PromSource) Fetch(ctx context.Context, promWindow string) (byPath map[string]float64, pods []PodCost, err error) {
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	pathQ := fmt.Sprintf("sum by (traffic_type) (increase(tollwing_cost_usd_total[%s]))", promWindow)
	pathVec, err := p.query(ctx, client, pathQ)
	if err != nil {
		return nil, nil, fmt.Errorf("query path costs: %w", err)
	}
	byPath = make(map[string]float64, len(pathVec))
	for _, s := range pathVec {
		// A series with no traffic_type label is malformed for this metric;
		// skip it rather than bucketing real spend under "".
		if t := s.Metric["traffic_type"]; t != "" {
			byPath[t] += s.Value
		}
	}

	podQ := fmt.Sprintf("sum by (namespace, pod) (increase(tollwing_pod_cost_usd_total[%s]))", promWindow)
	podVec, err := p.query(ctx, client, podQ)
	if err != nil {
		return nil, nil, fmt.Errorf("query pod costs: %w", err)
	}
	for _, s := range podVec {
		pods = append(pods, PodCost{
			Namespace: s.Metric["namespace"],
			Pod:       s.Metric["pod"],
			USD:       s.Value,
		})
	}

	if len(byPath) == 0 && len(pods) == 0 {
		return nil, nil, fmt.Errorf("no tollwing_* cost metrics found at %s over %s — is the agent deployed and scraped?", p.BaseURL, promWindow)
	}
	return byPath, pods, nil
}

// sample is one Prometheus instant-vector element after decoding.
type sample struct {
	Metric map[string]string
	Value  float64
}

// promResponse mirrors the Prometheus /api/v1/query envelope for a vector.
type promResponse struct {
	Status string `json:"status"`
	Error  string `json:"error"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string  `json:"metric"`
			Value  [2]json.RawMessage `json:"value"` // [ <unix_ts>, "<float-as-string>" ]
		} `json:"result"`
	} `json:"data"`
}

func (p PromSource) query(ctx context.Context, client *http.Client, q string) ([]sample, error) {
	endpoint := p.BaseURL + "/api/v1/query?" + url.Values{"query": {q}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Cap the body so a misconfigured or hostile endpoint can't OOM the scan.
	// A cost vector for a large fleet is well under this.
	var pr promResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&pr); err != nil {
		return nil, fmt.Errorf("decode response (HTTP %d): %w", resp.StatusCode, err)
	}
	if pr.Status != "success" {
		if pr.Error != "" {
			return nil, fmt.Errorf("prometheus error (HTTP %d): %s", resp.StatusCode, pr.Error)
		}
		return nil, fmt.Errorf("prometheus returned status %q (HTTP %d)", pr.Status, resp.StatusCode)
	}
	if pr.Data.ResultType != "vector" {
		return nil, fmt.Errorf("expected a vector result, got %q", pr.Data.ResultType)
	}

	out := make([]sample, 0, len(pr.Data.Result))
	for _, r := range pr.Data.Result {
		// value is [ts, "<float>"]; the sample value is the quoted string.
		var vs string
		if err := json.Unmarshal(r.Value[1], &vs); err != nil {
			return nil, fmt.Errorf("decode sample value: %w", err)
		}
		v, err := strconv.ParseFloat(vs, 64)
		if err != nil {
			return nil, fmt.Errorf("parse sample value %q: %w", vs, err)
		}
		// increase()/rate() over a counter reset (an agent pod restart) can
		// yield NaN or ±Inf, which Prometheus serialises as "NaN"/"+Inf" and
		// ParseFloat accepts. A non-finite value is not a real dollar (P4), so
		// drop the sample rather than poison the sum or crash the report.
		if math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		out = append(out, sample{Metric: r.Metric, Value: v})
	}
	return out, nil
}

// ParseWindow accepts a Go duration ("24h", "90m") or an "Nd" day form ("7d")
// and returns both the time.Duration (for the monthly projection) and the
// PromQL range string (for the increase() query). PromQL accepts h/m/s/d/w, so
// the day form is passed through verbatim.
func ParseWindow(s string) (time.Duration, string, error) {
	if s == "" {
		return 0, "", fmt.Errorf("empty window")
	}
	if s[len(s)-1] == 'd' {
		days, err := strconv.Atoi(s[:len(s)-1])
		if err != nil || days <= 0 {
			return 0, "", fmt.Errorf("invalid day window %q", s)
		}
		return time.Duration(days) * 24 * time.Hour, s, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, "", fmt.Errorf("invalid window %q: %w", s, err)
	}
	if d <= 0 {
		return 0, "", fmt.Errorf("window must be positive, got %q", s)
	}
	return d, s, nil
}
