package sim

import (
	"path/filepath"
	"testing"

	"github.com/tollwing/tollwing/pkg/classifier"
	"github.com/tollwing/tollwing/pkg/servicegraph"
	"github.com/tollwing/tollwing/test/sim/scenario"
)

// TestAttribution_Scenarios proves transitive cross-AZ attribution for any
// scenario declaring an expect.attribution block: the REAL pkg/servicegraph
// builds its graph from the scenario's real edges, and AttributeFrom must match
// the pinned direct/induced dollars (DEC-008; the killer cost feature, P5).
func TestAttribution_Scenarios(t *testing.T) {
	paths, _ := filepath.Glob("scenarios/*.yaml")
	ran := 0
	for _, p := range paths {
		s, err := scenario.Load(p)
		if err != nil {
			t.Fatalf("load %s: %v", p, err)
		}
		exp := s.Expect.Attribution
		if exp == nil {
			continue
		}
		ran++
		t.Run(s.Name, func(t *testing.T) {
			g := servicegraph.New()
			for _, row := range GraphEdges(s) {
				g.AddEdgeRow(row)
			}
			a := g.AttributeFrom(ServiceNode(s, exp.From), servicegraph.AttributeOpts{})

			if exp.DirectUSD != nil && !almostEqual(a.DirectCrossZoneUSD, *exp.DirectUSD) {
				t.Errorf("%s direct: got $%.4f want $%.4f", exp.From, a.DirectCrossZoneUSD, *exp.DirectUSD)
			}
			if exp.InducedUSD != nil && !almostEqual(a.InducedCrossZoneUSD, *exp.InducedUSD) {
				t.Errorf("%s induced: got $%.4f want $%.4f", exp.From, a.InducedCrossZoneUSD, *exp.InducedUSD)
			}
			if exp.TotalUSD != nil && !almostEqual(a.TotalCrossZoneUSD, *exp.TotalUSD) {
				t.Errorf("%s total: got $%.4f want $%.4f", exp.From, a.TotalCrossZoneUSD, *exp.TotalUSD)
			}
			if !t.Failed() {
				t.Logf("%s: direct $%.2f + induced $%.2f = $%.2f ✓ (real servicegraph)",
					exp.From, a.DirectCrossZoneUSD, a.InducedCrossZoneUSD, a.TotalCrossZoneUSD)
			}
		})
	}
	if ran == 0 {
		t.Skip("no attribution scenarios")
	}
}

// TestAttribution_ProportionalConservation proves the responsibility split is
// proportional to bytes and conserves dollars: two originators of a shared
// downstream cross-AZ edge split its cost in proportion to their share of the
// shared node's inbound traffic, and those shares sum to exactly the edge cost.
func TestAttribution_ProportionalConservation(t *testing.T) {
	svc := func(n string) servicegraph.NodeID {
		return servicegraph.NodeID{Cluster: "sim", Namespace: "shop", Name: n, Kind: servicegraph.KindService}
	}
	g := servicegraph.New()
	// s→a (100B) and t→a (300B) are same-zone/free; a→b is cross_az and costs $20.
	g.AddEdgeRow(servicegraph.EdgeRow{Src: svc("s"), Dst: svc("a"), TrafficType: classifier.SameZone.String(), Bytes: 100})
	g.AddEdgeRow(servicegraph.EdgeRow{Src: svc("t"), Dst: svc("a"), TrafficType: classifier.SameZone.String(), Bytes: 300})
	g.AddEdgeRow(servicegraph.EdgeRow{Src: svc("a"), Dst: svc("b"), TrafficType: classifier.CrossAZ.String(), Bytes: 100, Cost: 20})

	as := g.AttributeFrom(svc("s"), servicegraph.AttributeOpts{})
	at := g.AttributeFrom(svc("t"), servicegraph.AttributeOpts{})

	// resp_s(a) = 100/400 = 0.25 → $5; resp_t(a) = 300/400 = 0.75 → $15; sum = $20.
	if !almostEqual(as.InducedCrossZoneUSD, 5) {
		t.Errorf("induced(s): got $%.4f want $5", as.InducedCrossZoneUSD)
	}
	if !almostEqual(at.InducedCrossZoneUSD, 15) {
		t.Errorf("induced(t): got $%.4f want $15", at.InducedCrossZoneUSD)
	}
	if sum := as.InducedCrossZoneUSD + at.InducedCrossZoneUSD; !almostEqual(sum, 20) {
		t.Errorf("conservation: induced(s)+induced(t) = $%.4f, want $20 (the full edge cost)", sum)
	}
}
