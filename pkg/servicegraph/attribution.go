package servicegraph

import "sort"

// AttributeOpts tunes the transitive attribution.
type AttributeOpts struct {
	// MaxIterations caps the responsibility-propagation iterations. For a
	// DAG the iteration converges in at most (longest-path) rounds; the cap
	// bounds work on cyclic graphs. Default 100.
	MaxIterations int
	// Epsilon is the convergence threshold on the max per-node delta.
	// Default 1e-9.
	Epsilon float64
	// TopN caps the number of contributing downstream edges returned.
	// Default 10. Negative disables the list.
	TopN int
}

func (o *AttributeOpts) setDefaults() {
	if o.MaxIterations <= 0 {
		o.MaxIterations = 100
	}
	if o.Epsilon <= 0 {
		o.Epsilon = 1e-9
	}
	if o.TopN == 0 {
		o.TopN = 10
	}
}

// EdgeContribution is one downstream edge and the dollars attributed to the
// origin through it.
type EdgeContribution struct {
	Src              NodeID  `json:"src"`
	Dst              NodeID  `json:"dst"`
	Responsibility   float64 `json:"responsibility"`      // origin's share of Src's traffic, [0..1]
	EdgeCrossZoneUSD float64 `json:"edge_cross_zone_usd"` // the edge's own cross-zone cost
	AttributedUSD    float64 `json:"attributed_usd"`      // responsibility × edge cross-zone cost
}

// Attribution is the cross-zone cost attributed to one originating service:
// the cost of the downstream cascade its calls induce, not just its own edges.
//
// This is the killer cost feature — a service can look cheap (its own edges are
// same-zone) yet trigger an A→B→C cascade of cross-AZ calls costing real money;
// transitive attribution charges that closure back to the originator.
type Attribution struct {
	Origin              NodeID             `json:"origin"`
	DirectCrossZoneUSD  float64            `json:"direct_cross_zone_usd"`  // origin's own cross-zone edges
	InducedCrossZoneUSD float64            `json:"induced_cross_zone_usd"` // downstream, responsibility-weighted
	TotalCrossZoneUSD   float64            `json:"total_cross_zone_usd"`
	TopContributors     []EdgeContribution `json:"top_contributors,omitempty"`
	CyclesDetected      bool               `json:"cycles_detected"`
}

// AttributeFrom computes the cross-zone cost attributable to origin — both the
// cost of its own cross-zone edges (direct) and a responsibility-weighted share
// of the downstream cross-zone edges its traffic drives (induced).
//
// Model: responsibility(origin, A) is the fraction of A's inbound traffic that
// ultimately originates from origin, via the recurrence
//
//	resp(A) = Σ_{X→A} (bytes(X→A)/inBytes(A)) · resp(X),   resp(origin) = 1
//
// Each cross-zone edge A→B then contributes resp(A)·CrossZoneCost(A→B). This is
// a *responsibility* split, not proven causation (A→B may have other drivers),
// but it is conservative and conserves dollars: summed over every possible
// origin, the attribution of any one edge equals that edge's cross-zone cost.
//
// Nodes with no inbound edges are roots: only origin itself carries weight, so
// a root's downstream is attributed entirely to itself. Cycles are tolerated
// (bounded iteration) and flagged in the result.
func (g *ServiceGraph) AttributeFrom(origin NodeID, opts AttributeOpts) Attribution {
	opts.setDefaults()
	if g.nodes[origin] == nil {
		return Attribution{Origin: origin}
	}

	// Inbound byte totals per node (denominator of the responsibility share).
	inBytes := make(map[NodeID]uint64, len(g.in))
	for id, edges := range g.in {
		var sum uint64
		for _, e := range edges {
			sum += e.Bytes
		}
		inBytes[id] = sum
	}

	cycles := g.hasCycle()

	// Power-iterate responsibility with origin pinned at 1. Values stay in
	// [0,1] and increase monotonically toward the fixed point, so this is
	// stable; the cap guards pathological fully-cyclic graphs.
	resp := map[NodeID]float64{origin: 1}
	for i := 0; i < opts.MaxIterations; i++ {
		next := make(map[NodeID]float64, len(resp))
		next[origin] = 1
		var maxDelta float64
		for id := range g.nodes {
			if id == origin {
				continue
			}
			ib := inBytes[id]
			if ib == 0 {
				continue // root other than origin → responsibility 0
			}
			var r float64
			for _, e := range g.in[id] {
				if e.Bytes == 0 {
					continue
				}
				r += (float64(e.Bytes) / float64(ib)) * resp[e.Src]
			}
			if r != 0 {
				next[id] = r
			}
			if d := absf(r - resp[id]); d > maxDelta {
				maxDelta = d
			}
		}
		resp = next
		if maxDelta < opts.Epsilon {
			break
		}
	}

	// Attribute cross-zone cost across every edge by its source's responsibility.
	var direct, induced float64
	var contribs []EdgeContribution
	for _, e := range g.edges {
		cz := e.CrossZoneCost()
		if cz == 0 {
			continue
		}
		r := resp[e.Src]
		if r == 0 {
			continue
		}
		attr := r * cz
		if e.Src == origin {
			direct += attr
		} else {
			induced += attr
		}
		if opts.TopN >= 0 {
			contribs = append(contribs, EdgeContribution{
				Src:              e.Src,
				Dst:              e.Dst,
				Responsibility:   r,
				EdgeCrossZoneUSD: round2(cz),
				AttributedUSD:    round2(attr),
			})
		}
	}

	sort.Slice(contribs, func(i, j int) bool {
		return contribs[i].AttributedUSD > contribs[j].AttributedUSD
	})
	if opts.TopN > 0 && len(contribs) > opts.TopN {
		contribs = contribs[:opts.TopN]
	}

	return Attribution{
		Origin:              origin,
		DirectCrossZoneUSD:  round2(direct),
		InducedCrossZoneUSD: round2(induced),
		TotalCrossZoneUSD:   round2(direct + induced),
		TopContributors:     contribs,
		CyclesDetected:      cycles,
	}
}

// OriginAttribution is the per-originator summary AttributeAll returns.
type OriginAttribution struct {
	Origin              NodeID  `json:"origin"`
	TotalCrossZoneUSD   float64 `json:"total_cross_zone_usd"`
	DirectCrossZoneUSD  float64 `json:"direct_cross_zone_usd"`
	InducedCrossZoneUSD float64 `json:"induced_cross_zone_usd"`
}

// AttributeAll runs AttributeFrom for every internal service that originates
// traffic and returns them sorted by total cross-zone cost descending — the
// chargeback view ("which team's calls drive the cross-AZ bill"). Cheap at the
// graph's scale; O(V·(V+E)·iters) over a few-thousand-node graph at most.
func (g *ServiceGraph) AttributeAll(opts AttributeOpts) []OriginAttribution {
	opts.TopN = -1 // skip per-origin contributor lists in the bulk view
	var out []OriginAttribution
	for id, n := range g.nodes {
		if n.ID.Kind != KindService || len(g.out[id]) == 0 {
			continue
		}
		a := g.AttributeFrom(id, opts)
		if a.TotalCrossZoneUSD == 0 {
			continue
		}
		out = append(out, OriginAttribution{
			Origin:              id,
			TotalCrossZoneUSD:   a.TotalCrossZoneUSD,
			DirectCrossZoneUSD:  a.DirectCrossZoneUSD,
			InducedCrossZoneUSD: a.InducedCrossZoneUSD,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].TotalCrossZoneUSD > out[j].TotalCrossZoneUSD
	})
	return out
}

// Chokepoint is a node ranked by cross-zone cost flowing through it times its
// connectivity — the cost/blast-radius hubs.
type Chokepoint struct {
	Node                NodeID  `json:"node"`
	CrossZoneThroughUSD float64 `json:"cross_zone_through_usd"` // cross-zone cost on incident edges
	InDegree            int     `json:"in_degree"`
	OutDegree           int     `json:"out_degree"`
	Score               float64 `json:"score"` // CrossZoneThroughUSD × (in+out degree)
}

// Chokepoints ranks nodes by cross-zone cost on incident edges weighted by
// degree (fan-in + fan-out). limit ≤ 0 returns all. Nodes with no cross-zone
// cost are omitted (this is a cost ranking, not a topology dump).
func (g *ServiceGraph) Chokepoints(limit int) []Chokepoint {
	var out []Chokepoint
	for id := range g.nodes {
		var cz float64
		for _, e := range g.in[id] {
			cz += e.CrossZoneCost()
		}
		for _, e := range g.out[id] {
			cz += e.CrossZoneCost()
		}
		if cz == 0 {
			continue
		}
		deg := len(g.in[id]) + len(g.out[id])
		out = append(out, Chokepoint{
			Node:                id,
			CrossZoneThroughUSD: round2(cz),
			InDegree:            len(g.in[id]),
			OutDegree:           len(g.out[id]),
			Score:               round2(cz * float64(deg)),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Score > out[j].Score
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
