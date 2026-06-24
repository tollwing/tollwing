package servicegraph

import (
	"math"
	"testing"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func TestAttributeFrom_DirectOnly(t *testing.T) {
	s, a := svc("p", "s"), svc("p", "a")
	g := New()
	g.AddEdgeRow(EdgeRow{Src: s, Dst: a, TrafficType: czAZ, Bytes: 100, Cost: 10})

	got := g.AttributeFrom(s, AttributeOpts{})
	if !approx(got.DirectCrossZoneUSD, 10) || !approx(got.InducedCrossZoneUSD, 0) || !approx(got.TotalCrossZoneUSD, 10) {
		t.Fatalf("direct=%v induced=%v total=%v, want 10/0/10", got.DirectCrossZoneUSD, got.InducedCrossZoneUSD, got.TotalCrossZoneUSD)
	}
	if len(got.TopContributors) != 1 || !approx(got.TopContributors[0].AttributedUSD, 10) {
		t.Errorf("contributors = %+v", got.TopContributors)
	}
}

// The killer feature: s's own edge is free (same-zone), but it drives a
// downstream cross-AZ call a→b. Transitive attribution charges that $20 back
// to s even though s looks cheap when you only read its direct edges.
func TestAttributeFrom_InducedChain(t *testing.T) {
	s, a, b := svc("p", "s"), svc("p", "a"), svc("p", "b")
	g := New()
	g.AddEdgeRow(EdgeRow{Src: s, Dst: a, TrafficType: sameZ, Bytes: 100, Cost: 0})
	g.AddEdgeRow(EdgeRow{Src: a, Dst: b, TrafficType: czAZ, Bytes: 100, Cost: 20})

	fromS := g.AttributeFrom(s, AttributeOpts{})
	if !approx(fromS.DirectCrossZoneUSD, 0) || !approx(fromS.InducedCrossZoneUSD, 20) || !approx(fromS.TotalCrossZoneUSD, 20) {
		t.Fatalf("from s: direct=%v induced=%v total=%v, want 0/20/20",
			fromS.DirectCrossZoneUSD, fromS.InducedCrossZoneUSD, fromS.TotalCrossZoneUSD)
	}
	if len(fromS.TopContributors) == 0 || fromS.TopContributors[0].Src != a || fromS.TopContributors[0].Dst != b {
		t.Errorf("top contributor should be a→b, got %+v", fromS.TopContributors)
	}

	// a is directly responsible for its own cross-AZ edge.
	fromA := g.AttributeFrom(a, AttributeOpts{})
	if !approx(fromA.DirectCrossZoneUSD, 20) || !approx(fromA.InducedCrossZoneUSD, 0) {
		t.Errorf("from a: direct=%v induced=%v, want 20/0", fromA.DirectCrossZoneUSD, fromA.InducedCrossZoneUSD)
	}
}

// Two originators share a downstream service proportionally to their byte
// volume; the downstream cross-AZ cost splits by responsibility share and the
// split conserves dollars (sum of attributions == edge cost).
func TestAttributeFrom_ProportionalConservation(t *testing.T) {
	s1, s2, a, b := svc("p", "s1"), svc("p", "s2"), svc("p", "a"), svc("p", "b")
	g := New()
	g.AddEdgeRow(EdgeRow{Src: s1, Dst: a, TrafficType: sameZ, Bytes: 75})
	g.AddEdgeRow(EdgeRow{Src: s2, Dst: a, TrafficType: sameZ, Bytes: 25})
	g.AddEdgeRow(EdgeRow{Src: a, Dst: b, TrafficType: czAZ, Bytes: 100, Cost: 40})

	from1 := g.AttributeFrom(s1, AttributeOpts{})
	from2 := g.AttributeFrom(s2, AttributeOpts{})
	if !approx(from1.InducedCrossZoneUSD, 30) {
		t.Errorf("s1 induced = %v, want 30 (0.75 × 40)", from1.InducedCrossZoneUSD)
	}
	if !approx(from2.InducedCrossZoneUSD, 10) {
		t.Errorf("s2 induced = %v, want 10 (0.25 × 40)", from2.InducedCrossZoneUSD)
	}
	if sum := from1.InducedCrossZoneUSD + from2.InducedCrossZoneUSD; !approx(sum, 40) {
		t.Errorf("conservation broken: %v != 40", sum)
	}
}

// Cyclic graphs must terminate, flag the cycle, and still produce finite,
// sensible numbers (origin pinned at responsibility 1).
func TestAttributeFrom_Cycle(t *testing.T) {
	a, b, c := svc("p", "a"), svc("p", "b"), svc("p", "c")
	g := New()
	g.AddEdgeRow(EdgeRow{Src: a, Dst: b, TrafficType: czAZ, Bytes: 100, Cost: 10})
	g.AddEdgeRow(EdgeRow{Src: b, Dst: a, TrafficType: sameZ, Bytes: 100, Cost: 0}) // back-edge → cycle
	g.AddEdgeRow(EdgeRow{Src: b, Dst: c, TrafficType: czAZ, Bytes: 100, Cost: 6})

	got := g.AttributeFrom(a, AttributeOpts{})
	if !got.CyclesDetected {
		t.Error("cycle not flagged")
	}
	if !approx(got.DirectCrossZoneUSD, 10) || !approx(got.InducedCrossZoneUSD, 6) || !approx(got.TotalCrossZoneUSD, 16) {
		t.Errorf("direct=%v induced=%v total=%v, want 10/6/16",
			got.DirectCrossZoneUSD, got.InducedCrossZoneUSD, got.TotalCrossZoneUSD)
	}
}

func TestAttributeAll_SortedChargeback(t *testing.T) {
	s1, s2, a, b := svc("p", "s1"), svc("p", "s2"), svc("p", "a"), svc("p", "b")
	g := New()
	g.AddEdgeRow(EdgeRow{Src: s1, Dst: a, TrafficType: sameZ, Bytes: 75})
	g.AddEdgeRow(EdgeRow{Src: s2, Dst: a, TrafficType: sameZ, Bytes: 25})
	g.AddEdgeRow(EdgeRow{Src: a, Dst: b, TrafficType: czAZ, Bytes: 100, Cost: 40})

	all := g.AttributeAll(AttributeOpts{})
	if len(all) != 3 {
		t.Fatalf("want 3 originators (a, s1, s2), got %d: %+v", len(all), all)
	}
	// a is directly responsible ($40) > s1 induced ($30) > s2 induced ($10).
	if all[0].Origin != a || !approx(all[0].TotalCrossZoneUSD, 40) {
		t.Errorf("rank 0 = %+v, want a/40", all[0])
	}
	if all[1].Origin != s1 || !approx(all[1].TotalCrossZoneUSD, 30) {
		t.Errorf("rank 1 = %+v, want s1/30", all[1])
	}
	if all[2].Origin != s2 || !approx(all[2].TotalCrossZoneUSD, 10) {
		t.Errorf("rank 2 = %+v, want s2/10", all[2])
	}
}

func TestChokepoints_RankedByScore(t *testing.T) {
	s1, s2, h, d := svc("p", "s1"), svc("p", "s2"), svc("p", "h"), svc("p", "d")
	g := New()
	g.AddEdgeRow(EdgeRow{Src: s1, Dst: h, TrafficType: czAZ, Bytes: 100, Cost: 10})
	g.AddEdgeRow(EdgeRow{Src: s2, Dst: h, TrafficType: czAZ, Bytes: 100, Cost: 10})
	g.AddEdgeRow(EdgeRow{Src: h, Dst: d, TrafficType: czAZ, Bytes: 100, Cost: 10})

	cps := g.Chokepoints(0)
	if len(cps) != 4 {
		t.Fatalf("want 4 nodes with cross-zone cost, got %d", len(cps))
	}
	top := cps[0]
	// h: incident cross-zone = 10+10 (in) + 10 (out) = 30; degree = 2+1 = 3; score = 90.
	if top.Node != h || !approx(top.CrossZoneThroughUSD, 30) || top.InDegree != 2 || top.OutDegree != 1 || !approx(top.Score, 90) {
		t.Errorf("top chokepoint = %+v, want h through=30 in=2 out=1 score=90", top)
	}
}
