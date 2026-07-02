// Command tollwing-scan reads the free agent's exported cost metrics and prints
// a one-shot network data-transfer waste report: spend by AWS billing path,
// projected to a month, the addressable slice, and the top cost-driving pods.
//
// Usage:
//
//	tollwing-scan --demo                                  # synthetic, no cluster
//	tollwing-scan --prometheus http://prom:9090           # scan a live fleet
//	tollwing-scan --input scan.json                       # offline, from a file
//	  [--window 24h] [--json] [--top 10]
//
// It talks only to Prometheus (where the agent's tollwing_* metrics are
// scraped) — no cloud credentials, no control plane. Cross-platform,
// CGO_ENABLED=0.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/tollwing/tollwing/pkg/classifier"
	"github.com/tollwing/tollwing/pkg/scan"
)

// fileInput is the offline scan format (--input): pre-aggregated window spend.
type fileInput struct {
	ByPath map[string]float64 `json:"by_path"` // keyed by traffic-type string
	Pods   []scan.PodCost     `json:"pods"`
}

func main() {
	demo := flag.Bool("demo", false, "run a built-in synthetic scenario (no cluster, no Prometheus)")
	promURL := flag.String("prometheus", "", "Prometheus base URL scraping the agent (e.g. http://prometheus:9090)")
	input := flag.String("input", "", "path to a JSON scan input ({by_path, pods})")
	windowStr := flag.String("window", "24h", "scan window: a Go duration (24h, 90m) or day form (7d)")
	asJSON := flag.Bool("json", false, "emit JSON instead of the text report")
	top := flag.Int("top", 10, "how many cost-driving pods to list (0 = all)")
	flag.Parse()

	window, promWindow, err := scan.ParseWindow(*windowStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tollwing-scan: %v\n", err)
		os.Exit(2)
	}

	var byPath map[string]float64
	var pods []scan.PodCost

	switch {
	case *demo:
		byPath, pods = demoScenario()
	case *promURL != "":
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		byPath, pods, err = scan.PromSource{BaseURL: *promURL}.Fetch(ctx, promWindow)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tollwing-scan: %v\n", err)
			os.Exit(1)
		}
	case *input != "":
		byPath, pods, err = readInput(*input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tollwing-scan: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: tollwing-scan (--demo | --prometheus URL | --input file.json) [--window 24h] [--json] [--top N]")
		os.Exit(2)
	}

	rep := scan.AnalyzeTopN(byPath, pods, window, *top)

	if *asJSON {
		if err := rep.WriteJSON(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "tollwing-scan: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := rep.WriteText(os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "tollwing-scan: %v\n", err)
		os.Exit(1)
	}
}

func readInput(path string) (map[string]float64, []scan.PodCost, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var in fileInput
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(in.ByPath) == 0 {
		return nil, nil, fmt.Errorf("%s: by_path is empty", path)
	}
	return in.ByPath, in.Pods, nil
}

// demoScenario is a realistic mid-size cluster's 24h of network spend, built so
// the addressable slice (cross-AZ + NAT) dominates — the story the scan tells.
// Path keys come from classifier.TrafficType.String() so they can't drift (P6).
func demoScenario() (map[string]float64, []scan.PodCost) {
	byPath := map[string]float64{
		classifier.CrossAZ.String():          31.40, // the differentiator: chatty services split across AZs
		classifier.NATGatewayEgress.String(): 18.75, // S3/Dynamo pulls + internal traffic through NAT
		classifier.InternetEgress.String():   12.10,
		classifier.CrossRegion.String():      4.90,
		classifier.VPCPeering.String():       1.20,
		classifier.SameZone.String():         0.00, // free — shown as $0
	}
	pods := []scan.PodCost{
		{Namespace: "checkout", Pod: "checkout-7c9f8b-x2k9", USD: 14.20},
		{Namespace: "search", Pod: "search-indexer-5d4c-qq7", USD: 11.85},
		{Namespace: "checkout", Pod: "cart-6b7a9c-mm3", USD: 9.40},
		{Namespace: "data", Pod: "kafka-broker-2", USD: 8.10},
		{Namespace: "search", Pod: "search-api-84ff-z1", USD: 5.55},
		{Namespace: "ml", Pod: "feature-store-9a-kd", USD: 4.30},
		{Namespace: "data", Pod: "etl-runner-3f2-77", USD: 3.10},
		{Namespace: "web", Pod: "frontend-59dd-bb", USD: 2.05},
	}
	return byPath, pods
}
