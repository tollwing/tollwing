// Package scan turns the tollwing-agent's exported network-cost metrics into a
// one-shot "where is my data-transfer money going" report: the spend by AWS
// billing path over a window, projected to a month, the addressable slice with
// a concrete optimization, and the top cost-driving pods.
//
// It is a read-only consumer of the free agent's Prometheus metrics — no
// control plane, no cloud credentials, no state. Per P4, every figure it prints
// traces back to the agent's `metered bytes × dated rate`; the scan only sums,
// ranks, and projects. The one estimate it introduces — the monthly projection
// — is a linear extrapolation of the window and is always labelled as such.
package scan

import (
	"sort"
	"time"

	"github.com/tollwing/tollwing/pkg/classifier"
)

// monthHours is the projection horizon: a 30-day month.
const monthHours = 30 * 24

// topPodsDefault is how many cost-driving pods the report keeps.
const topPodsDefault = 10

// PodCost is one pod's network cost over the scanned window.
type PodCost struct {
	Namespace  string  `json:"namespace"`
	Pod        string  `json:"pod"`
	USD        float64 `json:"usd"`         // over the window
	MonthlyUSD float64 `json:"monthly_usd"` // projected to 30 days
}

// PathCost is one AWS billing path's spend over the window.
type PathCost struct {
	Path        string  `json:"path"`        // classifier.TrafficType.String()
	USD         float64 `json:"usd"`         // over the window
	MonthlyUSD  float64 `json:"monthly_usd"` // projected to 30 days
	Pct         float64 `json:"pct"`         // share of the total, 0..100
	Addressable bool    `json:"addressable"` // has a known low-effort optimization
}

// Recommendation is a concrete action attached to an addressable path.
type Recommendation struct {
	Path       string  `json:"path"`
	MonthlyUSD float64 `json:"monthly_usd"` // the addressable spend it targets
	Action     string  `json:"action"`
}

// Report is the full scan result.
type Report struct {
	WindowHours     float64          `json:"window_hours"`
	TotalUSD        float64          `json:"total_usd"`       // over the window
	MonthlyUSD      float64          `json:"monthly_usd"`     // projected
	AddressableUSD  float64          `json:"addressable_usd"` // projected, optimizable subset
	ByPath          []PathCost       `json:"by_path"`         // sorted desc by USD
	TopPods         []PodCost        `json:"top_pods"`        // sorted desc, capped
	Recommendations []Recommendation `json:"recommendations"` // sorted desc by targeted spend
}

// addressable maps each optimizable billing path to its recommended action.
// "Addressable" means a known, low-effort fix exists — not a guaranteed saving.
// Scoped to cross-AZ and NAT gateway (DEC-021): the two paths whose spend a
// low-effort change actually converts to cheaper traffic. vpc_endpoint is
// deliberately NOT here — it is already the cheap destination the other fixes
// land on, so counting its spend as "addressable" would overclaim (P5).
// Keyed by classifier.TrafficType.String() so the wire strings stay canonical
// (P6) and can never drift from the agent's own labels.
var addressable = map[string]string{
	classifier.CrossAZ.String():          "co-locate chatty services (topology-aware routing / pod anti-affinity) so cross-AZ hops become same-zone",
	classifier.NATGatewayEgress.String(): "add VPC gateway/interface endpoints for S3, DynamoDB and other AWS services, and check for internal traffic routed through the NAT gateway",
}

// Analyze folds per-path spend and per-pod spend over a window into a Report.
// byPath is keyed by classifier.TrafficType.String(); pods carry window USD
// (MonthlyUSD is filled here). window must be > 0.
func Analyze(byPath map[string]float64, pods []PodCost, window time.Duration) Report {
	return AnalyzeTopN(byPath, pods, window, topPodsDefault)
}

// AnalyzeTopN is Analyze with an explicit cap on the pod list (0 = keep all).
func AnalyzeTopN(byPath map[string]float64, pods []PodCost, window time.Duration, topN int) Report {
	windowHours := window.Hours()
	// A non-positive window can't be projected; treat the factor as 1 so the
	// report still shows the raw window totals rather than dividing by zero.
	factor := 1.0
	if windowHours > 0 {
		factor = monthHours / windowHours
	}

	var total float64
	for _, usd := range byPath {
		total += usd
	}

	rep := Report{
		WindowHours: windowHours,
		TotalUSD:    total,
		MonthlyUSD:  total * factor,
	}

	for path, usd := range byPath {
		// A path with no spend is noise in the breakdown; skip it.
		if usd == 0 {
			continue
		}
		pct := 0.0
		if total > 0 {
			pct = usd / total * 100
		}
		_, isAddr := addressable[path]
		monthly := usd * factor
		rep.ByPath = append(rep.ByPath, PathCost{
			Path:        path,
			USD:         usd,
			MonthlyUSD:  monthly,
			Pct:         pct,
			Addressable: isAddr,
		})
		if isAddr {
			rep.AddressableUSD += monthly
		}
	}
	// Highest spend first; ties broken by path name for a stable order.
	sort.Slice(rep.ByPath, func(i, j int) bool {
		if rep.ByPath[i].USD != rep.ByPath[j].USD {
			return rep.ByPath[i].USD > rep.ByPath[j].USD
		}
		return rep.ByPath[i].Path < rep.ByPath[j].Path
	})

	// Recommendations: one per addressable path actually present, ordered by
	// the spend it targets so the biggest lever is first.
	for _, pc := range rep.ByPath {
		if action, ok := addressable[pc.Path]; ok && pc.MonthlyUSD > 0 {
			rep.Recommendations = append(rep.Recommendations, Recommendation{
				Path:       pc.Path,
				MonthlyUSD: pc.MonthlyUSD,
				Action:     action,
			})
		}
	}

	// Top pods by window spend; project each and cap the list.
	rep.TopPods = make([]PodCost, 0, len(pods))
	for _, p := range pods {
		if p.USD == 0 {
			continue
		}
		p.MonthlyUSD = p.USD * factor
		rep.TopPods = append(rep.TopPods, p)
	}
	sort.Slice(rep.TopPods, func(i, j int) bool {
		if rep.TopPods[i].USD != rep.TopPods[j].USD {
			return rep.TopPods[i].USD > rep.TopPods[j].USD
		}
		if rep.TopPods[i].Namespace != rep.TopPods[j].Namespace {
			return rep.TopPods[i].Namespace < rep.TopPods[j].Namespace
		}
		return rep.TopPods[i].Pod < rep.TopPods[j].Pod
	})
	if topN > 0 && len(rep.TopPods) > topN {
		rep.TopPods = rep.TopPods[:topN]
	}

	return rep
}
