// Package servicegraph materialises a first-class, in-memory
// service-dependency graph from tollwing's flow records.
//
// Flows are high-volume, but the *aggregated* service graph is tiny (nodes =
// services, tens to low-thousands; edges = service pairs, hundreds to
// low-tens-of-thousands). So the graph is a periodic ROLLUP of ClickHouse edge
// rows into an in-memory snapshot — not a graph database. It exists to answer
// multi-hop / structural questions that a flat GROUP BY can't: transitive
// cross-zone cost attribution, chokepoint ranking, and (later) topology drift
// and dependency cycles.
//
// Every graph-derived finding carries a dollar number — this stays a cost
// tool, not an APM/reliability tool.
package servicegraph

import (
	"math"
	"time"

	"github.com/tollwing/tollwing/pkg/classifier"
)

// NodeKind distinguishes in-cluster services from external destinations.
type NodeKind uint8

const (
	// KindService is an in-cluster Kubernetes service. With the pre-DNAT
	// path it is resolved from the ClusterIP the client dialed (the
	// "service intent"), not the post-DNAT backend pod.
	KindService NodeKind = iota
	// KindExternal is an out-of-cluster destination: a cloud service
	// ("S3", "DynamoDB") or a DNS domain, as resolved by the agent's DNS
	// tracker. It has no namespace.
	KindExternal
)

func (k NodeKind) String() string {
	if k == KindExternal {
		return "external"
	}
	return "service"
}

// NodeID uniquely identifies a graph node. It is a comparable value so it can
// key maps directly (no interning needed at this scale).
type NodeID struct {
	Cluster   string
	Namespace string // empty for KindExternal
	Name      string // service name, or external service/domain
	Kind      NodeKind
}

// String renders a stable, human-readable id.
func (id NodeID) String() string {
	switch {
	case id.Kind == KindExternal:
		return "ext:" + id.Name
	case id.Namespace == "":
		return id.Name
	default:
		return id.Namespace + "/" + id.Name
	}
}

// EdgeStat is the per-traffic-type slice of an edge's totals.
type EdgeStat struct {
	Bytes uint64
	Cost  float64
}

// Edge is an aggregated, directed dependency (service→service or
// service→external). Metrics are summed over the snapshot window.
type Edge struct {
	Src         NodeID
	Dst         NodeID
	Bytes       uint64
	Connections uint64
	Cost        float64
	// ByType breaks the edge down by traffic type, keyed by the canonical
	// storage string (e.g. cross_az) so callers can isolate the
	// zone-crossing charge from free same-zone traffic.
	ByType map[string]EdgeStat
}

// CrossZoneCost is the dollar cost on this edge attributable to zone-crossing
// traffic (cross-AZ + cross-region) — the charge tollwing exists to attack.
func (e *Edge) CrossZoneCost() float64 {
	var c float64
	for t, s := range e.ByType {
		if crossZoneCharged[t] {
			c += s.Cost
		}
	}
	return c
}

// crossZoneCharged is the set of traffic types that incur a zone-crossing
// charge. Keyed by the canonical strings classifier.TrafficType.String()
// produces, which are exactly the values stored in the ClickHouse
// traffic_type enum — so there is a single source of truth and no drift.
var crossZoneCharged = map[string]bool{
	classifier.CrossAZ.String():     true,
	classifier.CrossRegion.String(): true,
}

// Node is a vertex with rolled-up totals.
type Node struct {
	ID       NodeID
	Zones    map[string]uint64 // zone -> bytes observed at this node (informational)
	BytesIn  uint64
	BytesOut uint64
	CostIn   float64
	CostOut  float64
}

// EdgeRow is one aggregated observation fed into the graph — typically one row
// of the ClickHouse rollup (a single src/dst/traffic-type/zone combination).
type EdgeRow struct {
	Src         NodeID
	Dst         NodeID
	SrcZone     string
	DstZone     string
	TrafficType string // canonical storage string, e.g. cross_az
	Bytes       uint64
	Connections uint64
	Cost        float64
}

// ServiceGraph is an in-memory snapshot. Build it via New + AddEdgeRow (or the
// Build helper), then treat it as read-only — the query methods do not mutate.
type ServiceGraph struct {
	SnapshotAt time.Time
	Window     time.Duration

	nodes map[NodeID]*Node
	edges map[edgeKey]*Edge
	out   map[NodeID][]*Edge
	in    map[NodeID][]*Edge
}

type edgeKey struct {
	src NodeID
	dst NodeID
}

// New returns an empty graph ready for AddEdgeRow.
func New() *ServiceGraph {
	return &ServiceGraph{
		nodes: map[NodeID]*Node{},
		edges: map[edgeKey]*Edge{},
		out:   map[NodeID][]*Edge{},
		in:    map[NodeID][]*Edge{},
	}
}

func (g *ServiceGraph) node(id NodeID) *Node {
	n := g.nodes[id]
	if n == nil {
		n = &Node{ID: id, Zones: map[string]uint64{}}
		g.nodes[id] = n
	}
	return n
}

// AddEdgeRow accumulates one observation. Rows sharing a (src,dst) pair merge
// into one edge; per-traffic-type totals accumulate into ByType. Zero-byte
// rows still register the nodes and edge, so a freshly-established but idle
// dependency remains visible in the topology.
func (g *ServiceGraph) AddEdgeRow(r EdgeRow) {
	src := g.node(r.Src)
	dst := g.node(r.Dst)

	src.BytesOut += r.Bytes
	src.CostOut += r.Cost
	dst.BytesIn += r.Bytes
	dst.CostIn += r.Cost
	if r.SrcZone != "" {
		src.Zones[r.SrcZone] += r.Bytes
	}
	if r.DstZone != "" {
		dst.Zones[r.DstZone] += r.Bytes
	}

	k := edgeKey{r.Src, r.Dst}
	e := g.edges[k]
	if e == nil {
		e = &Edge{Src: r.Src, Dst: r.Dst, ByType: map[string]EdgeStat{}}
		g.edges[k] = e
		g.out[r.Src] = append(g.out[r.Src], e)
		g.in[r.Dst] = append(g.in[r.Dst], e)
	}
	e.Bytes += r.Bytes
	e.Connections += r.Connections
	e.Cost += r.Cost
	if r.TrafficType != "" {
		s := e.ByType[r.TrafficType]
		s.Bytes += r.Bytes
		s.Cost += r.Cost
		e.ByType[r.TrafficType] = s
	}
}

// Node returns the node, or nil if absent.
func (g *ServiceGraph) Node(id NodeID) *Node { return g.nodes[id] }

// Out returns the edges leaving id (do not mutate the slice).
func (g *ServiceGraph) Out(id NodeID) []*Edge { return g.out[id] }

// In returns the edges entering id (do not mutate the slice).
func (g *ServiceGraph) In(id NodeID) []*Edge { return g.in[id] }

// NumNodes reports the vertex count.
func (g *ServiceGraph) NumNodes() int { return len(g.nodes) }

// NumEdges reports the distinct (src,dst) edge count.
func (g *ServiceGraph) NumEdges() int { return len(g.edges) }

// Edges returns all edges (unordered).
func (g *ServiceGraph) Edges() []*Edge {
	out := make([]*Edge, 0, len(g.edges))
	for _, e := range g.edges {
		out = append(out, e)
	}
	return out
}

// FindService returns the service node matching namespace+name, ignoring
// cluster — for API callers in the common single-cluster case who don't know
// the cluster name. When several clusters expose the same service it returns
// the one with the lexicographically smallest cluster (deterministic); callers
// that need a specific cluster should construct the NodeID directly.
func (g *ServiceGraph) FindService(namespace, name string) (NodeID, bool) {
	var best NodeID
	found := false
	for id := range g.nodes {
		if id.Kind != KindService || id.Namespace != namespace || id.Name != name {
			continue
		}
		if !found || id.Cluster < best.Cluster {
			best, found = id, true
		}
	}
	return best, found
}

// hasCycle reports whether the directed graph contains a cycle (including
// self-loops). Used only to flag attribution results — the responsibility
// computation tolerates cycles via its iteration cap.
func (g *ServiceGraph) hasCycle() bool {
	const (
		white = iota
		gray
		black
	)
	color := make(map[NodeID]int, len(g.nodes))
	var visit func(NodeID) bool
	visit = func(n NodeID) bool {
		color[n] = gray
		for _, e := range g.out[n] {
			switch color[e.Dst] {
			case gray:
				return true
			case white:
				if visit(e.Dst) {
					return true
				}
			}
		}
		color[n] = black
		return false
	}
	for id := range g.nodes {
		if color[id] == white && visit(id) {
			return true
		}
	}
	return false
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

func absf(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}
