// Package sim is the proof/simulation harness for Tollwing (DEC-008). It runs
// declarative scenarios through three independent computations that must agree:
// the scenario's self-reported injection, an independent Oracle, and the real
// product path (Measure). Divergence is a bug — the suite asserts exact dollars
// and exact classifications, not "200 OK".
package sim

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net/netip"
	"time"

	"github.com/tollwing/tollwing/pkg/classifier"
	"github.com/tollwing/tollwing/pkg/cost"
	"github.com/tollwing/tollwing/test/sim/scenario"
)

// EdgeResult is the per-edge outcome of a scenario: classification + cost.
type EdgeResult struct {
	From    string
	To      string
	Type    classifier.TrafficType
	CostUSD float64
}

// edgeMeasurement is the full per-edge product output (internal).
type edgeMeasurement struct {
	edge scenario.Edge
	tt   classifier.TrafficType
	cost float64
	tx   uint64
	rx   uint64
}

// measure runs each scenario edge through the REAL product path — the actual
// pkg/classifier and pkg/cost engine, configured exactly as the agent/server
// configure them. This is computation (3) in the three-way differential (DEC-008).
func measure(s *scenario.Scenario) []edgeMeasurement {
	// Discard classifier logs; the zone resolver only logs IMDS/provider noise.
	resolver := classifier.NewZoneResolver(slog.New(slog.NewTextHandler(io.Discard, nil)))
	for name, svc := range s.Services {
		if ip, ok := s.ServiceIP(name); ok {
			// Fake the zone the K8s informer would derive from the node's
			// topology.kubernetes.io/zone label — cross-AZ is just labels (P5).
			resolver.SetIPZone(ip, svc.Zone)
		}
	}
	cls := classifier.New(resolver)
	// Synthetic cloud topology — fed to the classifier exactly as the
	// cloud.TopologyRefresher would (all fakeable locally, no cloud account).
	cls.SetNATGatewayIPs(s.NATAddrs())
	cls.SetVPCPeeringCIDRs(s.PeeringPrefixes())
	cls.SetTransitGatewayCIDRs(s.TGWPrefixes())
	cls.SetVPCEndpointCIDRs(s.EndpointPrefixes())
	cls.SetDefaultRouteNAT(s.DefaultRouteNAT)
	if cps := s.ClusterPrefixes(); len(cps) > 0 {
		cls.SetClusterCIDRs(cps)
	}

	store := cost.NewRateCardStore()
	card := rateCard(s.Provider, s.Region)
	store.Set(card)
	// Default = marginal pricing, exactly as the distributed agents run;
	// scenarios opt into the Enterprise single-meter mode explicitly
	// (DEC-014).
	engine := cost.NewEngineWithConfig(store, cost.EngineConfig{Mode: pricingMode(s)})
	engine.ResetBillingPeriod() // deterministic tiered pricing per scenario run

	out := make([]edgeMeasurement, 0, len(s.Traffic))
	for _, e := range s.Traffic {
		srcIP, _ := s.ServiceIP(e.From)
		dstIP, _ := s.DstIP(e.To)
		res := cls.Classify(classifier.FlowInfo{
			SrcIP:     addrToNBO(srcIP),
			DstIP:     addrToNBO(dstIP),
			IsSidecar: e.Sidecar,
			IntraNode: e.IntraNode,
		})
		tt := res.Type
		if e.CloudServicePublic {
			tt = classifier.CloudServicePublic
		}
		tx, rx := e.Bytes()
		costs := engine.Calculate(card.Provider, card.Region, []cost.FlowRecord{{
			TrafficType: tt, TxBytes: tx, RxBytes: rx,
		}})
		out = append(out, edgeMeasurement{edge: e, tt: tt, cost: costs[0].CostUSD, tx: tx, rx: rx})
	}
	return out
}

// Measure returns the per-edge classification + cost from the real product path.
func Measure(s *scenario.Scenario) []EdgeResult {
	ms := measure(s)
	out := make([]EdgeResult, len(ms))
	for i, m := range ms {
		out[i] = EdgeResult{From: m.edge.From, To: m.edge.To, Type: m.tt, CostUSD: m.cost}
	}
	return out
}

// Flows returns the scenario as the real cost.CostResult records the agent would
// ship and the ClickHouse Writer would persist — full src/dst metadata + cost,
// stamped at ts. Used by L1 to seed real storage. (Callers persisting to the
// `flows` table must drop types beyond CloudServicePublic, which the Enum8 of
// that table does not enumerate.)
func Flows(s *scenario.Scenario, ts time.Time) []cost.CostResult {
	ms := measure(s)
	out := make([]cost.CostResult, 0, len(ms))
	for _, m := range ms {
		src := s.Services[m.edge.From]
		conns := m.edge.Requests
		if conns == 0 {
			conns = 1
		}
		rec := cost.FlowRecord{
			Timestamp:    ts,
			Cluster:      "sim",
			Node:         "sim-node",
			SrcNamespace: src.Namespace,
			SrcPod:       m.edge.From + "-0",
			SrcService:   m.edge.From,
			SrcZone:      src.Zone,
			DstService:   m.edge.To,
			TrafficType:  m.tt,
			TxBytes:      m.tx,
			RxBytes:      m.rx,
			Connections:  uint32(conns),
		}
		if dst, ok := s.Services[m.edge.To]; ok {
			rec.DstNamespace = dst.Namespace
			rec.DstPod = m.edge.To + "-0"
			rec.DstZone = dst.Zone
		}
		if m.tt == classifier.CloudServicePublic {
			rec.CloudService = m.edge.To
		}
		out = append(out, cost.CostResult{FlowRecord: rec, CostUSD: m.cost})
	}
	return out
}

// rateCard returns the product's default dated rate card for the provider —
// the MEASURED side of the differential only. The Oracle deliberately does
// NOT price from these cards: its rates are transcribed independently from
// the provider price sheets (oracle.go), so a wrong constant in pkg/cost
// fails the cross-check instead of being mirrored.
func rateCard(provider, region string) *cost.RateCard {
	switch provider {
	case "gcp":
		return cost.DefaultGCPRateCard(region)
	case "azure":
		return cost.DefaultAzureRateCard(region)
	default: // "" or "aws"
		return cost.DefaultAWSRateCard(region)
	}
}

// pricingMode maps a scenario's pricingMode knob to the engine config
// (DEC-014). Validate() already rejected unknown values.
func pricingMode(s *scenario.Scenario) cost.PricingMode {
	if s.PricingMode == "single_meter" {
		return cost.PricingModeSingleMeter
	}
	return cost.PricingModeMarginal
}

// addrToNBO builds the uint32 the classifier's FlowInfo expects, the way the
// BPF data plane delivers it: network-order bytes loaded native-endian (the
// inverse of pkg/classifier's nboToAddr). Building it native-endian rather than
// big-endian keeps the simulation faithful to the real decode path the L2b tier
// exercises — a big-endian build here would re-mask the cross-AZ
// misclassification bug at L0/L1/L2a. See DEC-009.
func addrToNBO(a netip.Addr) uint32 {
	b := a.As4()
	return binary.NativeEndian.Uint32(b[:])
}
