// Command demo prints a narrated, engine-priced network-cost report for
// Tollwing's headline scenarios — pure Go, no cloud account, no cluster, no
// kernel, in milliseconds.
//
// It runs the real cost engine (pkg/cost via test/sim.Measure — the same
// classification + dated-rate arithmetic the eBPF agent feeds in production)
// over the declarative scenarios in test/sim/scenarios, and shows per-pod cost
// by AWS billing path — including the cross-AZ attribution that post-DNAT-only
// tools get wrong. Every dollar is bytes × dated-rate (traceable, never
// estimated) and is independently re-derived by the L0 oracle (`make sim`), so
// the demo can never print a number the product doesn't actually produce.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/tollwing/tollwing/test/sim"
	"github.com/tollwing/tollwing/test/sim/scenario"
)

var scenarioDir = "test/sim/scenarios"

func main() {
	if d := os.Getenv("TOLLWING_SCENARIO_DIR"); d != "" {
		scenarioDir = d
	}
	header()
	if !differentiator() {
		os.Exit(1)
	}
	breadth()
	footer()
}

func header() {
	fmt.Print(`
  ┌────────────────────────────────────────────────────────────────────────┐
  │  Tollwing · per-pod Kubernetes network cost, by AWS billing path         │
  └────────────────────────────────────────────────────────────────────────┘

  Pricing real traffic scenarios through the production cost engine, pure Go,
  no cloud account, no cluster, no kernel. Every dollar below is bytes ×
  dated-rate (traceable, never estimated), and an independent oracle re-derives
  each one in ` + "`make sim`" + `.
`)
}

// differentiator renders the headline: cross-AZ cost that post-DNAT-only tools
// misattribute. Returns false if the scenario can't be loaded.
func differentiator() bool {
	s, err := load("cross-az-differentiator.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n  demo: %v\n", err)
		return false
	}
	results := sim.Measure(s)
	r, gib := headline(s, results)

	src, dst := s.Services[r.From], s.Services[r.To]
	clusterIP := ""
	if dst.ClusterIP {
		clusterIP = " (ClusterIP)"
	}
	perGiB := 0.0
	if gib > 0 {
		perGiB = r.CostUSD / gib
	}

	fmt.Printf(`
  ① THE DIFFERENTIATOR: cross-AZ cost that post-DNAT-only tools miss
  ──────────────────────────────────────────────────────────────────────────

     %s [%s/%s]  ──%s──▶  %s%s [%s/%s]

  %s dials the %s ClusterIP, which kube-proxy DNATs to a backend pod in
  a different AZ, so every byte is cross-AZ at %s/GiB. Tollwing recovers the
  pre-DNAT intent, and the backend-node agent prices the cross-AZ movement once:

        billing path     attributed to     cost
        %-15s  %-15s   %s   ◀── correct
        ───────────────────────────────────────
        total                              %s

  Post-DNAT-only tools (Kubecost / OpenCost) see only the rewritten destination
  IP, so they bill this to %s, or miss it. That structural blind spot is the gap
  Tollwing closes.
`,
		r.From, src.Namespace, src.Zone, data(gib), r.To, clusterIP, dst.Namespace, dst.Zone,
		r.From, r.To, money(perGiB),
		r.Type.String(), r.To, money(r.CostUSD),
		money(r.CostUSD),
		r.From,
	)
	return true
}

// breadth prices one scenario per AWS billing path and tabulates the result.
func breadth() {
	fmt.Print(`
  ② THE BREADTH: per-pod cost by AWS billing path
  ──────────────────────────────────────────────────────────────────────────
  (each row is an independent scenario, priced by the same engine)

     billing path          example flow                 data        cost
     ─────────────────────────────────────────────────────────────────────
`)
	for _, f := range []string{
		"same-zone.yaml", "cross-az-differentiator.yaml", "cross-region.yaml",
		"nat-gateway.yaml", "internet-egress.yaml", "vpc-peering.yaml",
		"transit-gateway.yaml", "vpc-endpoint.yaml", "cloud-service-public.yaml",
	} {
		s, err := load(f)
		if err != nil {
			continue
		}
		results := sim.Measure(s)
		if len(results) == 0 {
			continue
		}
		r, gib := headline(s, results)
		flow := fmt.Sprintf("%s → %s", r.From, r.To)
		fmt.Printf("     %-20s  %-26s  %-9s  %8s\n",
			r.Type.String(), trunc(flow, 26), data(gib), money(r.CostUSD))
	}
}

func footer() {
	fmt.Print(`
  ──────────────────────────────────────────────────────────────────────────
  Same engine, on your cluster. One Helm install, no app changes, and an
  overhead budget of 0.1-0.5% of one core (ARCHITECTURE.md §2.4):

      helm install tollwing-agent ./deploy/helm/tollwing-agent \
        --set agent.provider=aws --set agent.region=us-east-1

  The agent then exposes tollwing_* Prometheus metrics on :9990/metrics; point
  Prometheus at it and import the 23-panel Grafana dashboard. No server needed.
  Verify every number independently:  make sim     Full design: ARCHITECTURE.md

`)
}

// headline returns the costliest priced edge of a scenario and its data volume
// in GiB — the row that demonstrates the scenario's billing path. Ties resolve
// to the first edge, so an all-free scenario (same_zone) reports its first edge.
func headline(s *scenario.Scenario, results []sim.EdgeResult) (sim.EdgeResult, float64) {
	best := 0
	for i, r := range results {
		if r.CostUSD > results[best].CostUSD {
			best = i
		}
	}
	r := results[best]
	var gib float64
	for _, e := range s.Traffic {
		if e.From == r.From && e.To == r.To {
			tx, rx := e.Bytes()
			gib = float64(tx+rx) / (1 << 30)
			break
		}
	}
	return r, gib
}

func load(file string) (*scenario.Scenario, error) {
	return scenario.Load(filepath.Join(scenarioDir, file))
}

// money formats a cost, keeping sub-cent precision so small rates stay honest.
func money(f float64) string {
	switch {
	case f == 0:
		return "$0.00"
	case f < 0.01:
		return fmt.Sprintf("$%.4f", f)
	default:
		return fmt.Sprintf("$%.2f", f)
	}
}

func data(gib float64) string {
	if gib >= 1 {
		return fmt.Sprintf("%.1f GiB", gib)
	}
	return fmt.Sprintf("%.0f MiB", gib*1024)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
