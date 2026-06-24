package servicegraph

import (
	"testing"

	"github.com/tollwing/tollwing/pkg/classifier"
)

var (
	czAZ  = classifier.CrossAZ.String()
	czReg = classifier.CrossRegion.String()
	sameZ = classifier.SameZone.String()
	inet  = classifier.InternetEgress.String()
)

func svc(ns, name string) NodeID { return NodeID{Namespace: ns, Name: name, Kind: KindService} }
func ext(name string) NodeID     { return NodeID{Name: name, Kind: KindExternal} }

func TestAddEdgeRow_MergeAndByType(t *testing.T) {
	g := New()
	s, a := svc("prod", "s"), svc("prod", "a")
	g.AddEdgeRow(EdgeRow{Src: s, Dst: a, TrafficType: czAZ, Bytes: 100, Connections: 2, Cost: 10, SrcZone: "us-east-1a", DstZone: "us-east-1b"})
	g.AddEdgeRow(EdgeRow{Src: s, Dst: a, TrafficType: sameZ, Bytes: 50, Connections: 1, Cost: 0, SrcZone: "us-east-1a", DstZone: "us-east-1a"})

	if g.NumNodes() != 2 || g.NumEdges() != 1 {
		t.Fatalf("want 2 nodes / 1 edge, got %d / %d", g.NumNodes(), g.NumEdges())
	}
	out := g.Out(s)
	if len(out) != 1 {
		t.Fatalf("want 1 outbound edge, got %d", len(out))
	}
	e := out[0]
	if e.Bytes != 150 || e.Connections != 3 || e.Cost != 10 {
		t.Errorf("edge totals: bytes=%d conns=%d cost=%v", e.Bytes, e.Connections, e.Cost)
	}
	if e.ByType[czAZ].Bytes != 100 || e.ByType[czAZ].Cost != 10 {
		t.Errorf("cross_az slice: %+v", e.ByType[czAZ])
	}
	if e.ByType[sameZ].Bytes != 50 {
		t.Errorf("same_zone slice: %+v", e.ByType[sameZ])
	}
	if cz := e.CrossZoneCost(); cz != 10 {
		t.Errorf("CrossZoneCost = %v, want 10", cz)
	}

	if n := g.Node(s); n.BytesOut != 150 || n.CostOut != 10 {
		t.Errorf("src node out: bytes=%d cost=%v", n.BytesOut, n.CostOut)
	}
	if n := g.Node(a); n.BytesIn != 150 || n.CostIn != 10 {
		t.Errorf("dst node in: bytes=%d cost=%v", n.BytesIn, n.CostIn)
	}
	if z := g.Node(a).Zones; z["us-east-1b"] != 100 || z["us-east-1a"] != 50 {
		t.Errorf("dst zones: %+v", z)
	}
}

func TestCrossZoneCost(t *testing.T) {
	e := &Edge{ByType: map[string]EdgeStat{
		czAZ:  {Bytes: 1, Cost: 5},
		czReg: {Bytes: 1, Cost: 7},
		inet:  {Bytes: 1, Cost: 100}, // charged, but not zone-crossing
		sameZ: {Bytes: 1, Cost: 0},
	}}
	if cz := e.CrossZoneCost(); cz != 12 {
		t.Errorf("CrossZoneCost = %v, want 12 (5+7, internet excluded)", cz)
	}
}

func TestDstNode(t *testing.T) {
	if got := dstNode("c", "ns", "svc", "", ""); got != (NodeID{Cluster: "c", Namespace: "ns", Name: "svc", Kind: KindService}) {
		t.Errorf("internal: %+v", got)
	}
	if got := dstNode("c", "", "", "S3", "x.s3.amazonaws.com"); got != (NodeID{Cluster: "c", Name: "S3", Kind: KindExternal}) {
		t.Errorf("cloud-service preferred over domain: %+v", got)
	}
	if got := dstNode("c", "", "", "", "stripe.com"); got != (NodeID{Cluster: "c", Name: "stripe.com", Kind: KindExternal}) {
		t.Errorf("domain fallback: %+v", got)
	}
}

func TestFindService(t *testing.T) {
	g := New()
	a := NodeID{Cluster: "c1", Namespace: "p", Name: "a", Kind: KindService}
	b := NodeID{Cluster: "c1", Namespace: "p", Name: "b", Kind: KindService}
	g.AddEdgeRow(EdgeRow{Src: a, Dst: b, Bytes: 1})

	if id, ok := g.FindService("p", "a"); !ok || id != a {
		t.Errorf("FindService(p,a) = %+v, %v; want %+v, true", id, ok, a)
	}
	if _, ok := g.FindService("p", "missing"); ok {
		t.Error("FindService found a nonexistent service")
	}
}

func TestHasCycle(t *testing.T) {
	a, b, c := svc("p", "a"), svc("p", "b"), svc("p", "c")

	dag := New()
	dag.AddEdgeRow(EdgeRow{Src: a, Dst: b, Bytes: 1})
	dag.AddEdgeRow(EdgeRow{Src: b, Dst: c, Bytes: 1})
	if dag.hasCycle() {
		t.Error("acyclic chain reported as cyclic")
	}

	cyc := New()
	cyc.AddEdgeRow(EdgeRow{Src: a, Dst: b, Bytes: 1})
	cyc.AddEdgeRow(EdgeRow{Src: b, Dst: a, Bytes: 1})
	if !cyc.hasCycle() {
		t.Error("A<->B cycle not detected")
	}

	self := New()
	self.AddEdgeRow(EdgeRow{Src: a, Dst: a, Bytes: 1})
	if !self.hasCycle() {
		t.Error("self-loop not detected")
	}
}
