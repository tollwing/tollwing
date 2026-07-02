// Command opencost-plugin serves Tollwing network-cost data as
// FOCUS-aligned JSON over plain HTTP, for external cost tooling to poll.
//
// Honest scope (per DEC-017): this is NOT an OpenCost plugin. The real
// OpenCost custom-cost contract is a hashicorp/go-plugin gRPC subprocess
// implementing CustomCostSource.GetCustomCosts; this component never
// implemented that contract and OpenCost never calls these endpoints.
// It is a standalone cost-export sidecar that re-exposes tollwing-server's
// REST API (and, optionally, the agent's cumulative Prometheus counters)
// in a FOCUS-aligned JSON shape. See README.md in this directory.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultListenAddr  = ":9992"
	defaultTollwingAPI = "http://tollwing-server:8080"
	defaultTimeout     = 10 * time.Second

	// windowCumulative labels a total derived from the agent's Prometheus
	// counters, which accumulate from agent start. Per P4, a cumulative
	// dollar figure must never be labeled with a requested lookback window.
	windowCumulative = "cumulative_since_agent_start"
)

// Config configures the cost-export server.
type Config struct {
	// ListenAddr is the HTTP listen address. Default ":9992".
	ListenAddr string
	// TollwingAPI is the base URL of the tollwing-server REST API.
	// Default "http://tollwing-server:8080".
	TollwingAPI string
	// AgentMetrics optionally points /cost/total at an agent's Prometheus
	// endpoint instead of the server API. Agent counters are cumulative
	// since agent start, so this mode cannot answer windowed queries.
	AgentMetrics string
	// Timeout bounds each upstream request. Default 10s.
	Timeout time.Duration
	// Log is the structured logger. Default: JSON to stderr.
	Log *slog.Logger
}

func (c *Config) setDefaults() {
	if c.ListenAddr == "" {
		c.ListenAddr = defaultListenAddr
	}
	if c.TollwingAPI == "" {
		c.TollwingAPI = defaultTollwingAPI
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultTimeout
	}
	if c.Log == nil {
		c.Log = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
}

func main() {
	cfg := Config{
		ListenAddr:   strings.TrimSpace(os.Getenv("LISTEN_ADDR")),
		TollwingAPI:  strings.TrimSpace(os.Getenv("TOLLWING_API")),
		AgentMetrics: strings.TrimSpace(os.Getenv("AGENT_METRICS_URL")),
	}
	cfg.setDefaults()

	export := newExportServer(cfg)

	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: export.routes(),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		cfg.Log.Info("cost export listening",
			"addr", cfg.ListenAddr, "tollwing_api", cfg.TollwingAPI)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			cfg.Log.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
}

// exportServer serves Tollwing cost data as FOCUS-aligned JSON.
type exportServer struct {
	cfg Config
	log *slog.Logger
}

func newExportServer(cfg Config) *exportServer {
	cfg.setDefaults()
	return &exportServer{cfg: cfg, log: cfg.Log}
}

func (p *exportServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/costs", p.handleCosts)
	mux.HandleFunc("/cost/total", p.handleCostTotal)
	mux.HandleFunc("/config", p.handleConfig)
	return mux
}

// costWindow echoes the exact time range a response covers, so every
// dollar in the response traces to a stated window (P4).
type costWindow struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type costResponse struct {
	Costs  []costItem `json:"costs"`
	Window costWindow `json:"window"`
}

// costItem is a FOCUS-aligned cost row.
type costItem struct {
	// FOCUS standard fields.
	ResourceName string `json:"resourceName"`
	ResourceType string `json:"resourceType"`
	ProviderName string `json:"providerName"`
	Region       string `json:"region"`
	AccountID    string `json:"accountId"`
	Category     string `json:"category"`
	Service      string `json:"service"`
	// Cost fields.
	ListCost      float64 `json:"listCost"`
	NetCost       float64 `json:"netCost"`
	ListUnitPrice float64 `json:"listUnitPrice"`
	UsageQuantity float64 `json:"usageQuantity"`
	UsageUnit     string  `json:"usageUnit"`
	// Tollwing-specific fields.
	TrafficType  string `json:"trafficType"`
	SrcNamespace string `json:"srcNamespace"`
	DstService   string `json:"dstService"`
	SrcZone      string `json:"srcZone"`
	DstZone      string `json:"dstZone"`
}

type totalCostResponse struct {
	TotalCostUSD float64 `json:"total_cost_usd"`
	Currency     string  `json:"currency"`
	Window       string  `json:"window"`
}

// parseWindow parses a lookback window: Go duration syntax ("24h",
// "90m") plus a day suffix ("7d" = 7×24h), since cost tooling
// conventionally asks in days. Per P4, an unparseable window is an
// error, never a silent default — the dollar returned must be the
// dollar of the window asked.
func parseWindow(s string) (time.Duration, error) {
	var d time.Duration
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.ParseFloat(days, 64)
		if err != nil {
			return 0, fmt.Errorf("parse window %q: %w", s, err)
		}
		d = time.Duration(n * float64(24*time.Hour))
	} else {
		var err error
		d, err = time.ParseDuration(s)
		if err != nil {
			return 0, fmt.Errorf("parse window %q: %w", s, err)
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("window %q must be positive", s)
	}
	return d, nil
}

func (p *exportServer) handleCosts(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	start := now.Add(-24 * time.Hour).Format(time.RFC3339)
	end := now.Format(time.RFC3339)

	// Per P4, reject malformed bounds instead of forwarding them:
	// tollwing-server silently substitutes its own default window for an
	// unparseable timestamp, which would mislabel the returned dollars.
	if s := r.URL.Query().Get("start"); s != "" {
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("invalid start %q: want RFC3339", s))
			return
		}
		start = s
	}
	if e := r.URL.Query().Get("end"); e != "" {
		if _, err := time.Parse(time.RFC3339, e); err != nil {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("invalid end %q: want RFC3339", e))
			return
		}
		end = e
	}

	q := url.Values{}
	q.Set("start", start)
	q.Set("end", end)
	q.Set("group_by", "service")

	body, err := p.get(r.Context(), "/api/v1/cost/breakdown?"+q.Encode())
	if err != nil {
		writeError(w, http.StatusBadGateway, "tollwing API unavailable: "+err.Error())
		return
	}

	var breakdown struct {
		Entries []struct {
			Key         string  `json:"key"`
			CostUSD     float64 `json:"cost_usd"`
			TxBytes     uint64  `json:"tx_bytes"`
			RxBytes     uint64  `json:"rx_bytes"`
			Connections uint32  `json:"connections"`
		} `json:"entries"`
		TotalCostUSD float64 `json:"total_cost_usd"`
	}
	if err := json.Unmarshal(body, &breakdown); err != nil {
		writeError(w, http.StatusInternalServerError, "parse tollwing response: "+err.Error())
		return
	}

	// Convert to FOCUS-aligned rows.
	var items []costItem
	for _, e := range breakdown.Entries {
		totalBytes := float64(e.TxBytes + e.RxBytes)
		totalGB := totalBytes / (1024 * 1024 * 1024)

		items = append(items, costItem{
			ResourceName:  e.Key,
			ResourceType:  "NetworkTraffic",
			Category:      "Network",
			Service:       e.Key,
			ListCost:      e.CostUSD,
			NetCost:       e.CostUSD,
			UsageQuantity: totalGB,
			UsageUnit:     "GB",
			DstService:    e.Key,
		})
	}

	writeJSON(w, http.StatusOK, costResponse{
		Costs:  items,
		Window: costWindow{Start: start, End: end},
	})
}

func (p *exportServer) handleCostTotal(w http.ResponseWriter, r *http.Request) {
	window := r.URL.Query().Get("window")

	// Agent scrape mode: the agent's tollwing_cost_usd_total counters
	// accumulate from agent start, so there is no windowed dollar to
	// derive from them. Per P4, refuse a windowed request rather than
	// return a cumulative figure labeled with the requested window.
	if p.cfg.AgentMetrics != "" {
		if window != "" {
			writeError(w, http.StatusBadRequest,
				"agent scrape mode reports cumulative cost since agent start and cannot answer a windowed query; drop the window parameter or query tollwing-server instead")
			return
		}
		total, err := p.scrapeAgentCostTotal(r.Context())
		if err != nil {
			writeError(w, http.StatusBadGateway, "agent metrics unavailable: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, totalCostResponse{
			TotalCostUSD: total,
			Currency:     "USD",
			Window:       windowCumulative,
		})
		return
	}

	if window == "" {
		window = "24h"
	}
	duration, err := parseWindow(window)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	end := time.Now().UTC()
	start := end.Add(-duration)

	q := url.Values{}
	q.Set("start", start.Format(time.RFC3339))
	q.Set("end", end.Format(time.RFC3339))

	body, err := p.get(r.Context(), "/api/v1/overview?"+q.Encode())
	if err != nil {
		writeError(w, http.StatusBadGateway, "tollwing API unavailable: "+err.Error())
		return
	}

	var overview struct {
		TotalCostUSD float64 `json:"total_cost_usd"`
	}
	if err := json.Unmarshal(body, &overview); err != nil {
		writeError(w, http.StatusInternalServerError, "parse response: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, totalCostResponse{
		TotalCostUSD: overview.TotalCostUSD,
		Currency:     "USD",
		Window:       window,
	})
}

// get issues a GET against the tollwing-server API and returns the body.
func (p *exportServer) get(ctx context.Context, path string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", p.cfg.TollwingAPI+path, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return body, nil
}

// scrapeAgentCostTotal scrapes the agent's /metrics endpoint and sums
// tollwing_cost_usd_total values across all traffic types. The result
// is cumulative since agent start (Prometheus counter semantics).
func (p *exportServer) scrapeAgentCostTotal(ctx context.Context) (float64, error) {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()

	url := p.cfg.AgentMetrics + "/metrics"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, err
	}

	// Parse Prometheus text format — sum all tollwing_cost_usd_total lines.
	var total float64
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "tollwing_cost_usd_total{") {
			// Extract the numeric value after the last space.
			idx := strings.LastIndex(line, " ")
			if idx >= 0 {
				var val float64
				if _, err := fmt.Sscanf(line[idx+1:], "%f", &val); err == nil {
					total += val
				}
			}
		}
	}
	return total, nil
}

// handleConfig describes this endpoint for pollers. Per DEC-017 this is
// self-description of a plain HTTP cost export, not OpenCost plugin
// discovery — OpenCost has no such HTTP discovery mechanism.
func (p *exportServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	config := map[string]any{
		"name":        "tollwing",
		"version":     "1.1.0",
		"description": "Tollwing network cost export: FOCUS-aligned JSON over HTTP (not an OpenCost plugin; see DEC-017)",
		"endpoints": map[string]string{
			"costs":     "/costs",
			"costTotal": "/cost/total",
			"health":    "/healthz",
		},
		"capabilities": []string{
			"network-cost",
			"per-pod-cost",
			"traffic-classification",
		},
	}
	writeJSON(w, http.StatusOK, config)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
