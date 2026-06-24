package sim

import (
	"math"
	"net/netip"

	"github.com/tollwing/tollwing/pkg/classifier"
	"github.com/tollwing/tollwing/pkg/cost"
	"github.com/tollwing/tollwing/test/sim/scenario"
)

// Oracle independently re-derives the expected classification and cost for each
// edge of a scenario. It uses its own classification logic and its own tiered
// arithmetic, pricing from the product's dated rate card for the *rates only*
// (P6: one source of truth for the numbers; P4: cost re-derives from
// bytes × dated-rate). It must agree with the real product (Measure) and with
// the scenario's pinned expectations — three independent computations, one
// answer (DEC-008).
//
// Tiered pricing is cumulative within a scenario: edges are processed in order
// and per-type usage accumulates, mirroring the engine (reset per scenario in
// Measure). Single-tier (flat) rates are order-independent.
func Oracle(s *scenario.Scenario) []EdgeResult {
	card := rateCard(s.Provider, s.Region)
	cum := map[classifier.TrafficType]float64{} // cumulative GiB per type
	out := make([]EdgeResult, 0, len(s.Traffic))
	for _, e := range s.Traffic {
		tt := oracleClassify(s, e)
		tx, rx := e.Bytes()
		gib := float64(tx+rx) / (1 << 30) // GiB (2^30), Tx+Rx summed — matches pkg/cost
		cst := oracleCost(card, tt, cum[tt], gib)
		cum[tt] += gib
		out = append(out, EdgeResult{From: e.From, To: e.To, Type: tt, CostUSD: cst})
	}
	return out
}

// oracleClassify derives the expected traffic type from the topology and hints,
// mirroring pkg/classifier.Classify's decision order but implemented
// independently so a bug on either side fails the cross-check.
func oracleClassify(s *scenario.Scenario, e scenario.Edge) classifier.TrafficType {
	// Hint precedence mirrors Classify: sidecar, then intra-node, then the wire.
	if e.Sidecar {
		return classifier.ServiceMeshInternal
	}
	if e.IntraNode {
		return classifier.IntraNode
	}
	if e.CloudServicePublic {
		return classifier.CloudServicePublic
	}
	// In-cluster service destination → zone-based.
	if _, ok := s.Services[e.To]; ok {
		return zoneBased(s, e.From, e.To)
	}
	// External destination, classified by IP.
	dst, ok := s.DstIP(e.To)
	if !ok {
		return classifier.Unknown
	}
	if dst.IsLoopback() {
		return classifier.IntraNode
	}
	if isPrivateOrCluster(s, dst) {
		// classifier checks NAT first inside classifyInternal; a private,
		// non-NAT dst has no zone here → Unknown.
		for _, a := range s.NATAddrs() {
			if a == dst {
				return classifier.NATGatewayEgress
			}
		}
		return classifier.Unknown
	}
	// Public dst → external prefix sets (scenarios keep these non-overlapping).
	switch {
	case prefixContains(s.PeeringPrefixes(), dst):
		return classifier.VPCPeering
	case prefixContains(s.TGWPrefixes(), dst):
		return classifier.TransitGateway
	case prefixContains(s.EndpointPrefixes(), dst):
		return classifier.VPCEndpoint
	default:
		return classifier.InternetEgress
	}
}

// zoneBased classifies an in-cluster service→service flow from its zones.
func zoneBased(s *scenario.Scenario, from, to string) classifier.TrafficType {
	srcZone := s.Services[from].Zone
	dstZone := s.Services[to].Zone
	if srcZone == "" || dstZone == "" {
		return classifier.Unknown
	}
	if srcZone == dstZone {
		return classifier.SameZone
	}
	if s.Zones[srcZone].Region == s.Zones[dstZone].Region {
		return classifier.CrossAZ
	}
	return classifier.CrossRegion
}

func isPrivateOrCluster(s *scenario.Scenario, dst netip.Addr) bool {
	if dst.IsPrivate() || dst.IsLinkLocalUnicast() {
		return true
	}
	return prefixContains(s.ClusterPrefixes(), dst)
}

func prefixContains(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// oracleCost re-derives cost = GiB × rate independently of pkg/cost's engine.
// prevGiB is the cumulative GiB already billed for this type in the scenario.
func oracleCost(card *cost.RateCard, tt classifier.TrafficType, prevGiB, gib float64) float64 {
	if card == nil {
		return 0
	}
	switch tt {
	case classifier.NATGatewayEgress:
		return gib * card.NATGateway.PerGBUSD // per-hour is NOT in flow cost (matches engine)
	case classifier.TransitGateway:
		return gib * card.TransitGW.PerGBUSD
	default:
		rate, ok := card.Rates[tt]
		if !ok {
			return 0 // free / unpriced (IntraNode, ServiceMeshInternal, Unknown)
		}
		switch len(rate.Tiers) {
		case 0:
			return 0
		case 1:
			return gib * rate.Tiers[0].PerGB // flat — order-independent
		default:
			return tieredCost(rate.Tiers, prevGiB, prevGiB+gib)
		}
	}
}

// tieredCost independently mirrors pkg/cost's tiered math: charge each GiB band
// between prevGiB and newGiB at its tier's rate. UpToGB values are cumulative
// absolute ceilings (math.Inf for the last tier).
func tieredCost(tiers []cost.Tier, prevGiB, newGiB float64) float64 {
	var total, tierStart float64
	for _, t := range tiers {
		start := math.Max(prevGiB, tierStart)
		end := math.Min(newGiB, t.UpToGB)
		if end > start {
			total += (end - start) * t.PerGB
		}
		tierStart = t.UpToGB
	}
	return total
}
