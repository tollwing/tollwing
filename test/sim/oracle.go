package sim

import (
	"math"
	"net/netip"

	"github.com/tollwing/tollwing/pkg/classifier"
	"github.com/tollwing/tollwing/test/sim/scenario"
)

// Oracle independently re-derives the expected classification and cost for
// each edge of a scenario. It uses its own classification logic, its own
// tiered arithmetic, AND its own price sheet: the rates below are transcribed
// by hand from the cloud providers' published pricing pages (verified
// 2026-07-02; source URLs in DEC-014) — deliberately NOT from pkg/cost. The
// harness is a three-way differential (DEC-008): if a rate constant, a
// metered direction, or a tier boundary in the product drifts from billing
// truth, the oracle disagrees and the suite fails. Pricing from the product's
// own rate card (as this file once did) would mirror the product's bugs and
// test nothing.
//
// Tiered pricing is cumulative within a scenario in single-meter mode: edges
// are processed in order and egress usage accumulates, mirroring the engine
// (reset per scenario in Measure). The default marginal mode is stateless.
func Oracle(s *scenario.Scenario) []EdgeResult {
	sheet := sheetFor(s.Provider)
	singleMeter := s.PricingMode == "single_meter"
	cumEgressGiB := 0.0 // cumulative internet-egress GiB (single-meter only)

	out := make([]EdgeResult, 0, len(s.Traffic))
	for _, e := range s.Traffic {
		tt := oracleClassify(s, e)
		tx, rx := e.Bytes()
		txGiB := float64(tx) / (1 << 30)
		rxGiB := float64(rx) / (1 << 30)

		cst, egressGiB := oracleCost(sheet, tt, txGiB, rxGiB, singleMeter, cumEgressGiB)
		cumEgressGiB += egressGiB
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
	// Cluster-internal CIDRs win over everything else (mirrors Classify
	// step 3); a non-service member has no zones → Unknown.
	if prefixContains(s.ClusterPrefixes(), dst) {
		return classifier.Unknown
	}
	if dst.IsPrivate() || dst.IsLinkLocalUnicast() {
		// Private branch mirrors classifyPrivate: NAT IPs first, then the
		// topology prefix sets (real VPC peers are RFC 1918), then the
		// zone-based fallback (no zones here → Unknown).
		for _, a := range s.NATAddrs() {
			if a == dst {
				return classifier.NATGatewayEgress
			}
		}
		switch {
		case prefixContains(s.PeeringPrefixes(), dst):
			return classifier.VPCPeering
		case prefixContains(s.TGWPrefixes(), dst):
			return classifier.TransitGateway
		case prefixContains(s.EndpointPrefixes(), dst):
			return classifier.VPCEndpoint
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
	}
	// Route-based NAT detection (DEC-015): internet-bound flows from a
	// NAT-routed subnet are NAT egress.
	if s.DefaultRouteNAT {
		return classifier.NATGatewayEgress
	}
	return classifier.InternetEgress
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

func prefixContains(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// --- The oracle's own price sheet -----------------------------------------
//
// Transcribed from the providers' published pricing pages, as of 2026-07-02
// (full source URLs in DEC-014). Per P4: every dollar below is bytes × one of
// these dated rates. Directions follow each provider's billing semantics
// from the same pages — the metered-direction differential (DEC-014).

// oracleTier is one internet-egress volume band (cumulative ceiling in GiB).
type oracleTier struct {
	upToGiB float64
	perGiB  float64
}

// oracleSheet holds one provider's transcribed rates.
type oracleSheet struct {
	crossAZPerGiB  float64
	crossAZBothDir bool         // both directions billed at the observing node
	crossRegion    float64      // egress side only, all providers
	egressTiers    []oracleTier // internet egress, Tx only
	peeringPerGiB  float64
	peeringBothDir bool
	endpointPerGiB float64 // endpoint data processing, both directions
	natPerGiB      float64 // NAT data processing, both directions
	tgwPerGiB      float64 // TGW data processing, Tx only
}

func sheetFor(provider string) oracleSheet {
	inf := math.Inf(1)
	switch provider {
	case "gcp":
		// cloud.google.com/vpc/network-pricing + network-tiers/pricing +
		// nat/pricing (2026-07-02).
		return oracleSheet{
			crossAZPerGiB:  0.01, // inter-zone, billed to the sender
			crossAZBothDir: false,
			crossRegion:    0.02, // within North America
			egressTiers: []oracleTier{ // Premium Tier, NA destinations
				{1024, 0.12}, {10 * 1024, 0.11}, {inf, 0.08},
			},
			peeringPerGiB:  0.01, // peering bills standard inter-zone rates
			peeringBothDir: false,
			endpointPerGiB: 0.01,  // PSC consumer data processing
			natPerGiB:      0.045, // Cloud NAT processing, both directions
			tgwPerGiB:      0,     // no TGW equivalent modelled
		}
	case "azure":
		// azure.microsoft.com/pricing/details/bandwidth + virtual-network +
		// azure-nat-gateway + private-link (2026-07-02).
		return oracleSheet{
			crossAZPerGiB:  0, // inter-AZ charges retired
			crossAZBothDir: false,
			crossRegion:    0.02, // within North America
			egressTiers: []oracleTier{ // Zone 1, first 100 GB/mo free
				{100, 0}, {10 * 1024, 0.087}, {50 * 1024, 0.083}, {150 * 1024, 0.07}, {inf, 0.05},
			},
			peeringPerGiB:  0.01, // VNet peering: charged inbound AND outbound
			peeringBothDir: true,
			endpointPerGiB: 0.01,  // Private Link, both directions
			natPerGiB:      0.045, // NAT Gateway data processed
			tgwPerGiB:      0,
		}
	default: // "" or "aws"
		// aws.amazon.com/ec2/pricing/on-demand (Data Transfer) +
		// vpc/pricing + transit-gateway/pricing + privatelink/pricing
		// (2026-07-02).
		return oracleSheet{
			crossAZPerGiB:  0.01, // $0.01/GB in EACH direction
			crossAZBothDir: true,
			crossRegion:    0.02, // us-east-1 → other regions
			egressTiers: []oracleTier{ // first 100 GB/mo free (account-wide)
				{100, 0}, {10 * 1024, 0.09}, {50 * 1024, 0.085}, {150 * 1024, 0.07}, {inf, 0.05},
			},
			peeringPerGiB:  0.01, // intra-region peering, each direction
			peeringBothDir: true,
			endpointPerGiB: 0.01,  // PrivateLink interface endpoints
			natPerGiB:      0.045, // NAT data processing
			tgwPerGiB:      0.02,  // data sent into the TGW
		}
	}
}

// oracleCost re-derives an edge's cost from the oracle's own sheet. It
// returns the cost and the internet-egress GiB this edge consumed from the
// single-meter cumulative meter (NAT egress legs feed the same meter, as the
// engine does). Per DEC-015 the NAT/TGW hourly charges are NOT per-flow.
func oracleCost(sheet oracleSheet, tt classifier.TrafficType, txGiB, rxGiB float64, singleMeter bool, cumEgressGiB float64) (cost, egressGiB float64) {
	both := txGiB + rxGiB
	switch tt {
	case classifier.CrossAZ:
		if sheet.crossAZBothDir {
			return both * sheet.crossAZPerGiB, 0
		}
		return txGiB * sheet.crossAZPerGiB, 0
	case classifier.CrossRegion:
		return txGiB * sheet.crossRegion, 0
	case classifier.InternetEgress:
		return egressCost(sheet, txGiB, singleMeter, cumEgressGiB), txGiB
	case classifier.NATGatewayEgress:
		// NAT data processing (both directions) + the internet DTO leg on
		// Tx (DEC-015) — the bytes still leave the cloud after the NAT.
		return both*sheet.natPerGiB + egressCost(sheet, txGiB, singleMeter, cumEgressGiB), txGiB
	case classifier.TransitGateway:
		return txGiB * sheet.tgwPerGiB, 0
	case classifier.VPCPeering:
		if sheet.peeringBothDir {
			return both * sheet.peeringPerGiB, 0
		}
		return txGiB * sheet.peeringPerGiB, 0
	case classifier.VPCEndpoint:
		return both * sheet.endpointPerGiB, 0
	default:
		// SameZone, IntraNode, ServiceMeshInternal, CloudServicePublic,
		// Unknown: $0 (Unknown must never carry an asserted dollar, P4).
		return 0, 0
	}
}

// egressCost prices txGiB of internet egress: marginal (post-free-tier) list
// rate by default, or the cumulative tier walk in single-meter mode (DEC-014).
func egressCost(sheet oracleSheet, txGiB float64, singleMeter bool, cumGiB float64) float64 {
	if !singleMeter {
		return txGiB * marginalEgressRate(sheet)
	}
	return tieredCost(sheet.egressTiers, cumGiB, cumGiB+txGiB)
}

// marginalEgressRate is the first paid egress band — what one more GiB costs
// once the monthly free allowance is spent.
func marginalEgressRate(sheet oracleSheet) float64 {
	for _, t := range sheet.egressTiers {
		if t.perGiB > 0 {
			return t.perGiB
		}
	}
	return 0
}

// tieredCost independently mirrors the cumulative tier walk: charge each GiB
// band between prevGiB and newGiB at its band's rate. upToGiB values are
// cumulative absolute ceilings (math.Inf for the last band).
func tieredCost(tiers []oracleTier, prevGiB, newGiB float64) float64 {
	var total, tierStart float64
	for _, t := range tiers {
		start := math.Max(prevGiB, tierStart)
		end := math.Min(newGiB, t.upToGiB)
		if end > start {
			total += (end - start) * t.perGiB
		}
		tierStart = t.upToGiB
	}
	return total
}
