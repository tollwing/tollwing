// OpenCost plugin for Tollwing — exposes network cost data in the
// OpenCost custom cost plugin format conforming to the FOCUS spec.
//
// This is a standalone binary that queries Tollwing's REST API and
// serves network cost data at the OpenCost plugin endpoints.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	defaultListenAddr      = ":9992"
	defaultTollwingAPI     = "http://tollwing-server:8080"
	defaultRefreshInterval = 5 * time.Minute
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	listenAddr := envOrDefault("LISTEN_ADDR", defaultListenAddr)
	tollwingAPI := envOrDefault("TOLLWING_API", defaultTollwingAPI)
	agentMetrics := envOrDefault("AGENT_METRICS_URL", "") // direct agent scrape mode

	plugin := &Plugin{
		log:          log,
		tollwingAPI:  tollwingAPI,
		agentMetrics: agentMetrics,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	// OpenCost custom cost plugin endpoints.
	mux.HandleFunc("/costs", plugin.handleCosts)
	mux.HandleFunc("/cost/total", plugin.handleCostTotal)
	// OpenCost plugin discovery endpoint.
	mux.HandleFunc("/config", plugin.handleConfig)

	server := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Info("opencost plugin listening", "addr", listenAddr, "tollwing_api", tollwingAPI)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
}

// Plugin implements the OpenCost custom cost plugin interface.
type Plugin struct {
	log          *slog.Logger
	tollwingAPI  string
	agentMetrics string // optional: scrape agent /metrics directly instead of server API
}

// OpenCost custom cost response types (FOCUS-aligned).
type costResponse struct {
	Costs []costItem `json:"costs"`
}

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

func (p *Plugin) handleCosts(w http.ResponseWriter, r *http.Request) {
	start := r.URL.Query().Get("start")
	end := r.URL.Query().Get("end")

	if start == "" {
		start = time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	}
	if end == "" {
		end = time.Now().Format(time.RFC3339)
	}

	// Query Tollwing API for cost breakdown.
	url := fmt.Sprintf("%s/api/v1/cost/breakdown?start=%s&end=%s&group_by=service",
		p.tollwingAPI, start, end)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "tollwing API unavailable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
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

	// Convert to OpenCost format.
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(costResponse{Costs: items})
}

func (p *Plugin) handleCostTotal(w http.ResponseWriter, r *http.Request) {
	window := r.URL.Query().Get("window")
	if window == "" {
		window = "24h"
	}

	// If agent metrics URL is configured, scrape directly from agent Prometheus.
	if p.agentMetrics != "" {
		total, err := p.scrapeAgentCostTotal(r.Context())
		if err != nil {
			writeError(w, http.StatusBadGateway, "agent metrics unavailable: "+err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(totalCostResponse{
			TotalCostUSD: total,
			Currency:     "USD",
			Window:       window,
		})
		return
	}

	duration, err := time.ParseDuration(window)
	if err != nil {
		duration = 24 * time.Hour
	}

	end := time.Now()
	start := end.Add(-duration)

	url := fmt.Sprintf("%s/api/v1/overview?start=%s&end=%s",
		p.tollwingAPI, start.Format(time.RFC3339), end.Format(time.RFC3339))

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "tollwing API unavailable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var overview struct {
		TotalCostUSD float64 `json:"total_cost_usd"`
	}
	if err := json.Unmarshal(body, &overview); err != nil {
		writeError(w, http.StatusInternalServerError, "parse response: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(totalCostResponse{
		TotalCostUSD: overview.TotalCostUSD,
		Currency:     "USD",
		Window:       window,
	})
}

// scrapeAgentCostTotal scrapes the agent's /metrics endpoint and sums
// tollwing_cost_usd_total values across all traffic types.
func (p *Plugin) scrapeAgentCostTotal(ctx context.Context) (float64, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	url := p.agentMetrics + "/metrics"
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

// handleConfig returns plugin configuration for OpenCost discovery.
func (p *Plugin) handleConfig(w http.ResponseWriter, r *http.Request) {
	config := map[string]any{
		"name":        "tollwing",
		"version":     "1.0.0",
		"description": "Tollwing eBPF network cost attribution plugin",
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return strings.TrimSpace(v)
	}
	return def
}
