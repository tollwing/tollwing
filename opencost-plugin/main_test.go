package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/tollwing/tollwing/pkg/classifier"
)

func TestParseWindow(t *testing.T) {
	tests := []struct {
		name    string
		window  string
		want    time.Duration
		wantErr bool
	}{
		{name: "go duration hours", window: "24h", want: 24 * time.Hour},
		{name: "go duration minutes", window: "90m", want: 90 * time.Minute},
		{name: "day suffix", window: "7d", want: 7 * 24 * time.Hour},
		{name: "fractional days", window: "0.5d", want: 12 * time.Hour},
		{name: "garbage", window: "banana", wantErr: true},
		{name: "empty", window: "", wantErr: true},
		{name: "bare day suffix", window: "d", wantErr: true},
		{name: "negative duration", window: "-24h", wantErr: true},
		{name: "negative days", window: "-2d", wantErr: true},
		{name: "zero", window: "0h", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseWindow(tt.window)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseWindow(%q) = %v, want error", tt.window, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseWindow(%q): unexpected error: %v", tt.window, err)
			}
			if got != tt.want {
				t.Errorf("parseWindow(%q) = %v, want %v", tt.window, got, tt.want)
			}
		})
	}
}

// TestHandleCostTotal_WindowHonored is the regression test for the P4
// mislabel bug: the original code silently fell back to 24h for any
// window time.ParseDuration could not parse (e.g. "7d") while echoing
// the requested window string in the response.
func TestHandleCostTotal_WindowHonored(t *testing.T) {
	tests := []struct {
		name         string
		window       string
		wantStatus   int
		wantLookback time.Duration // asserted against the upstream query
		wantWindow   string        // echoed label
	}{
		{name: "default", window: "", wantStatus: http.StatusOK, wantLookback: 24 * time.Hour, wantWindow: "24h"},
		{name: "explicit hours", window: "48h", wantStatus: http.StatusOK, wantLookback: 48 * time.Hour, wantWindow: "48h"},
		{name: "day suffix honored not defaulted", window: "7d", wantStatus: http.StatusOK, wantLookback: 7 * 24 * time.Hour, wantWindow: "7d"},
		{name: "garbage rejected not defaulted", window: "banana", wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotQuery url.Values
			upstreamCalled := false
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalled = true
				gotQuery = r.URL.Query()
				json.NewEncoder(w).Encode(map[string]float64{"total_cost_usd": 12.5})
			}))
			defer upstream.Close()

			p := newExportServer(Config{TollwingAPI: upstream.URL, Log: testLogger()})
			req := httptest.NewRequest("GET", "/cost/total", nil)
			if tt.window != "" {
				req.URL.RawQuery = url.Values{"window": {tt.window}}.Encode()
			}
			rec := httptest.NewRecorder()
			p.handleCostTotal(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantStatus != http.StatusOK {
				if upstreamCalled {
					t.Errorf("upstream queried despite invalid window %q", tt.window)
				}
				return
			}

			start, err := time.Parse(time.RFC3339, gotQuery.Get("start"))
			if err != nil {
				t.Fatalf("upstream start %q not RFC3339: %v", gotQuery.Get("start"), err)
			}
			end, err := time.Parse(time.RFC3339, gotQuery.Get("end"))
			if err != nil {
				t.Fatalf("upstream end %q not RFC3339: %v", gotQuery.Get("end"), err)
			}
			lookback := end.Sub(start)
			// RFC3339 formatting truncates sub-second precision; allow 2s slack.
			if diff := lookback - tt.wantLookback; diff < -2*time.Second || diff > 2*time.Second {
				t.Errorf("queried lookback = %v, want %v", lookback, tt.wantLookback)
			}

			var resp totalCostResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal response: %v", err)
			}
			if resp.Window != tt.wantWindow {
				t.Errorf("response window = %q, want %q", resp.Window, tt.wantWindow)
			}
			if resp.TotalCostUSD != 12.5 {
				t.Errorf("total = %v, want 12.5", resp.TotalCostUSD)
			}
		})
	}
}

// TestHandleCostTotal_AgentMode is the regression test for the P4
// mislabel bug in agent-scrape mode: the original code summed the
// agent's cumulative-since-start counters and labeled the result with
// whatever window the caller asked for.
func TestHandleCostTotal_AgentMode(t *testing.T) {
	// Per P6, derive the traffic-type labels from TrafficType.String()
	// rather than hardcoding the wire strings.
	metrics := fmt.Sprintf(`# HELP tollwing_cost_usd_total Estimated network cost in USD by traffic type.
# TYPE tollwing_cost_usd_total counter
tollwing_cost_usd_total{traffic_type=%q} 3.25
tollwing_cost_usd_total{traffic_type=%q} 1.75
tollwing_flow_bytes_total{direction="tx"} 999999
`, classifier.CrossAZ.String(), classifier.InternetEgress.String())
	tests := []struct {
		name       string
		query      string
		wantStatus int
		wantTotal  float64
		wantWindow string
	}{
		{
			name:       "no window: cumulative total, honestly labeled",
			query:      "",
			wantStatus: http.StatusOK,
			wantTotal:  5.0,
			wantWindow: windowCumulative,
		},
		{
			name:       "windowed query rejected, never mislabeled",
			query:      "window=24h",
			wantStatus: http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/metrics" {
					t.Errorf("agent scrape path = %q, want /metrics", r.URL.Path)
				}
				w.Write([]byte(metrics))
			}))
			defer agent.Close()

			p := newExportServer(Config{AgentMetrics: agent.URL, Log: testLogger()})
			req := httptest.NewRequest("GET", "/cost/total?"+tt.query, nil)
			rec := httptest.NewRecorder()
			p.handleCostTotal(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantStatus != http.StatusOK {
				return
			}

			var resp totalCostResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal response: %v", err)
			}
			if resp.TotalCostUSD != tt.wantTotal {
				t.Errorf("total = %v, want %v", resp.TotalCostUSD, tt.wantTotal)
			}
			if resp.Window != tt.wantWindow {
				t.Errorf("window = %q, want %q", resp.Window, tt.wantWindow)
			}
		})
	}
}

// TestHandleCosts_TimeBounds covers two original bugs: (a) start/end
// were interpolated into the upstream URL unencoded, so an RFC3339
// timezone offset like "+02:00" decoded to a space upstream and
// tollwing-server silently substituted its default window; (b) invalid
// bounds were forwarded instead of rejected.
func TestHandleCosts_TimeBounds(t *testing.T) {
	tests := []struct {
		name       string
		query      url.Values
		wantStatus int
		wantStart  string // exact value the upstream must receive; "" = skip
	}{
		{
			name:       "offset timestamp survives URL encoding",
			query:      url.Values{"start": {"2026-07-01T00:00:00+02:00"}, "end": {"2026-07-02T00:00:00+02:00"}},
			wantStatus: http.StatusOK,
			wantStart:  "2026-07-01T00:00:00+02:00",
		},
		{
			name:       "utc timestamps pass through",
			query:      url.Values{"start": {"2026-07-01T00:00:00Z"}, "end": {"2026-07-02T00:00:00Z"}},
			wantStatus: http.StatusOK,
			wantStart:  "2026-07-01T00:00:00Z",
		},
		{
			name:       "invalid start rejected",
			query:      url.Values{"start": {"yesterday"}},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid end rejected",
			query:      url.Values{"end": {"2026-13-99"}},
			wantStatus: http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotQuery url.Values
			upstreamCalled := false
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalled = true
				gotQuery = r.URL.Query()
				json.NewEncoder(w).Encode(map[string]any{
					"entries": []map[string]any{
						{"key": "checkout", "cost_usd": 4.2, "tx_bytes": 1 << 30, "rx_bytes": 1 << 30, "connections": 7},
					},
					"total_cost_usd": 4.2,
				})
			}))
			defer upstream.Close()

			p := newExportServer(Config{TollwingAPI: upstream.URL, Log: testLogger()})
			req := httptest.NewRequest("GET", "/costs?"+tt.query.Encode(), nil)
			rec := httptest.NewRecorder()
			p.handleCosts(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantStatus != http.StatusOK {
				if upstreamCalled {
					t.Errorf("upstream queried despite invalid bounds %v", tt.query)
				}
				return
			}

			if got := gotQuery.Get("start"); got != tt.wantStart {
				t.Errorf("upstream received start %q, want %q", got, tt.wantStart)
			}
			if _, err := time.Parse(time.RFC3339, gotQuery.Get("start")); err != nil {
				t.Errorf("upstream start %q no longer RFC3339 after transport: %v", gotQuery.Get("start"), err)
			}

			var resp costResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal response: %v", err)
			}
			if len(resp.Costs) != 1 {
				t.Fatalf("got %d cost items, want 1", len(resp.Costs))
			}
			item := resp.Costs[0]
			if item.NetCost != 4.2 || item.ListCost != 4.2 {
				t.Errorf("cost = list %v / net %v, want 4.2", item.ListCost, item.NetCost)
			}
			if item.UsageQuantity != 2.0 { // 1 GiB tx + 1 GiB rx
				t.Errorf("usage = %v GB, want 2.0", item.UsageQuantity)
			}
			// The response must state the window its dollars cover (P4).
			if resp.Window.Start != tt.wantStart {
				t.Errorf("response window start = %q, want %q", resp.Window.Start, tt.wantStart)
			}
		})
	}
}

// TestHandleCosts_DefaultWindow checks the default 24h window is
// generated in UTC and echoed in the response.
func TestHandleCosts_DefaultWindow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, key := range []string{"start", "end"} {
			ts, err := time.Parse(time.RFC3339, r.URL.Query().Get(key))
			if err != nil {
				t.Errorf("default %s %q not RFC3339: %v", key, r.URL.Query().Get(key), err)
				continue
			}
			if _, offset := ts.Zone(); offset != 0 {
				t.Errorf("default %s %q not UTC (offset %d)", key, r.URL.Query().Get(key), offset)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"entries": []any{}, "total_cost_usd": 0.0})
	}))
	defer upstream.Close()

	p := newExportServer(Config{TollwingAPI: upstream.URL, Log: testLogger()})
	rec := httptest.NewRecorder()
	p.handleCosts(rec, httptest.NewRequest("GET", "/costs", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var resp costResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Window.Start == "" || resp.Window.End == "" {
		t.Errorf("response window not echoed: %+v", resp.Window)
	}
}

func TestConfigSetDefaults(t *testing.T) {
	var c Config
	c.setDefaults()
	if c.ListenAddr != defaultListenAddr {
		t.Errorf("ListenAddr = %q, want %q", c.ListenAddr, defaultListenAddr)
	}
	if c.TollwingAPI != defaultTollwingAPI {
		t.Errorf("TollwingAPI = %q, want %q", c.TollwingAPI, defaultTollwingAPI)
	}
	if c.Timeout != defaultTimeout {
		t.Errorf("Timeout = %v, want %v", c.Timeout, defaultTimeout)
	}
	if c.Log == nil {
		t.Error("Log not defaulted")
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
