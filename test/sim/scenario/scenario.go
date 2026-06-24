// Package scenario defines Tollwing's declarative simulation scenario format:
// a topology (zones + services + external endpoints), the traffic driven across
// it, and the expected classification + cost. One Scenario drives every tier of
// the proof suite (L0–L3); see docs/testing/simulation-suite-design.md and DEC-008.
package scenario

import (
	"fmt"
	"net/netip"
	"os"
	"sort"

	"sigs.k8s.io/yaml"
)

// Scenario is a single, self-contained proof: a topology, the traffic on it,
// and the ground-truth expectations the product must reproduce.
type Scenario struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Provider    string              `json:"provider"` // "aws" | "gcp" | "azure" ("" = aws)
	Region      string              `json:"region"`
	Zones       map[string]Zone     `json:"zones"`
	Services    map[string]Service  `json:"services"`
	External    map[string]External `json:"external"`
	Traffic     []Edge              `json:"traffic"`
	Expect      Expect              `json:"expect"`

	// Synthetic cloud topology knobs — all fakeable locally, no cloud account.
	// Fed to the classifier exactly as the cloud.TopologyRefresher would.
	NATGatewayIPs       []string `json:"natGatewayIPs"`
	VPCPeeringCIDRs     []string `json:"vpcPeeringCIDRs"`
	TransitGatewayCIDRs []string `json:"transitGatewayCIDRs"`
	VPCEndpointCIDRs    []string `json:"vpcEndpointCIDRs"`
	ClusterCIDRs        []string `json:"clusterCIDRs"`
}

// Zone is a fake availability zone. At L2 it becomes a node label
// (topology.kubernetes.io/zone); at L0/L1 it seeds the zone resolver. Zone names
// must be real cloud-zone strings (e.g. "us-east-1a") so the classifier's
// regionFromZone() derives the right region.
type Zone struct {
	Region string `json:"region"`
}

// Service is a workload with a home zone. ClusterIP marks a service the client
// dials by its virtual IP (the pre-DNAT intent case, DEC-003).
type Service struct {
	Zone      string `json:"zone"`
	Namespace string `json:"namespace"`
	ClusterIP bool   `json:"clusterIP"`
}

// External is a destination outside the cluster, addressed by a literal IP
// (a public endpoint, a peered-CIDR member, a NAT gateway IP, …).
type External struct {
	IP string `json:"ip"`
}

// Edge is one directed traffic flow from a source service to a destination
// (another service or an external endpoint). Bytes are declared either
// per-request (Requests × {Request,Response}Bytes) or directly (Tx/RxBytes).
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`

	Requests      uint64 `json:"requests"`
	RequestBytes  uint64 `json:"requestBytes"`
	ResponseBytes uint64 `json:"responseBytes"`

	TxBytes uint64 `json:"txBytes"`
	RxBytes uint64 `json:"rxBytes"`

	// Hints the agent's enricher would supply. Sidecar marks an app↔sidecar
	// loopback hop (→ service_mesh_internal); IntraNode marks same-host
	// pod-to-pod (→ intra_node). Both win over zone-based classification,
	// exactly as in pkg/classifier.Classify.
	Sidecar   bool `json:"sidecar"`
	IntraNode bool `json:"intraNode"`

	// Per P4/P6, cloud_service_public is modeled as a DNS/FOCUS-enriched
	// cost path: Classify() does not infer it from an IP prefix, but the real
	// cost engine still prices the canonical TrafficType.
	CloudServicePublic bool `json:"cloudServicePublic"`
}

// Bytes returns the (tx, rx) byte totals for the edge: tx is what the source
// sent (requests), rx is what it received (responses).
func (e Edge) Bytes() (tx, rx uint64) {
	if e.Requests > 0 {
		return e.Requests * e.RequestBytes, e.Requests * e.ResponseBytes
	}
	return e.TxBytes, e.RxBytes
}

// Expect holds the ground-truth assertions for a scenario.
type Expect struct {
	Edges       []EdgeExpect       `json:"edges"`
	Attribution *AttributionExpect `json:"attribution,omitempty"`
}

// AttributionExpect pins the transitive cross-AZ attribution for an origin
// service (the killer cost feature: a service's downstream cascade charged back
// to it). Dollars are pointers so a pinned 0 is distinguishable from unset.
type AttributionExpect struct {
	From       string   `json:"from"`
	DirectUSD  *float64 `json:"directUSD,omitempty"`
	InducedUSD *float64 `json:"inducedUSD,omitempty"`
	TotalUSD   *float64 `json:"totalUSD,omitempty"`
}

// EdgeExpect is the expected classification and (optionally) exact cost for one
// edge. CostUSD is a pointer so a pinned "0" is distinguishable from "unset".
type EdgeExpect struct {
	From    string   `json:"from"`
	To      string   `json:"to"`
	Type    string   `json:"type"`              // classifier TrafficType.String()
	CostUSD *float64 `json:"costUSD,omitempty"` // exact pin, optional
}

// Load reads and validates a scenario from a YAML file.
func Load(path string) (*Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scenario %s: %w", path, err)
	}
	var s Scenario
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse scenario %s: %w", path, err)
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("invalid scenario %s: %w", path, err)
	}
	return &s, nil
}

// Validate checks referential integrity and that every IP/CIDR parses.
func (s *Scenario) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("name is required")
	}
	for name, svc := range s.Services {
		if _, ok := s.Zones[svc.Zone]; !ok {
			return fmt.Errorf("service %q references undeclared zone %q", name, svc.Zone)
		}
	}
	for name, ext := range s.External {
		if _, err := netip.ParseAddr(ext.IP); err != nil {
			return fmt.Errorf("external %q has invalid ip %q: %w", name, ext.IP, err)
		}
	}
	for i, e := range s.Traffic {
		if _, ok := s.Services[e.From]; !ok {
			return fmt.Errorf("traffic[%d] from undeclared service %q", i, e.From)
		}
		if !s.isDestination(e.To) {
			return fmt.Errorf("traffic[%d] to %q is neither a declared service nor external", i, e.To)
		}
	}
	for _, ip := range s.NATGatewayIPs {
		if _, err := netip.ParseAddr(ip); err != nil {
			return fmt.Errorf("invalid natGatewayIP %q: %w", ip, err)
		}
	}
	for _, set := range [][]string{s.VPCPeeringCIDRs, s.TransitGatewayCIDRs, s.VPCEndpointCIDRs, s.ClusterCIDRs} {
		for _, c := range set {
			if _, err := netip.ParsePrefix(c); err != nil {
				return fmt.Errorf("invalid CIDR %q: %w", c, err)
			}
		}
	}
	return nil
}

func (s *Scenario) isDestination(name string) bool {
	if _, ok := s.Services[name]; ok {
		return true
	}
	_, ok := s.External[name]
	return ok
}

// ServiceIP returns a deterministic synthetic IP for a service, placed in the
// RFC-1918 10.0.0.0/8 range so the classifier treats it as cluster-internal.
// Octet 2 is the (sorted) zone index + 1, octet 4 the (sorted) global service
// index + 1 — stable across runs and unique per service. NAT/external IPs use
// octet 2 = 0 (or are public), so they never collide with a service IP.
func (s *Scenario) ServiceIP(name string) (netip.Addr, bool) {
	svc, ok := s.Services[name]
	if !ok {
		return netip.Addr{}, false
	}
	zoneIdx := sortedIndex(mapKeys(s.Zones), svc.Zone)
	svcIdx := sortedIndex(mapKeys(s.Services), name)
	if zoneIdx < 0 || svcIdx < 0 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{10, byte(zoneIdx + 1), 0, byte(svcIdx + 1)}), true
}

// DstIP resolves an edge destination: a declared service (→ synthetic 10.x) or
// a declared external endpoint (→ its literal IP).
func (s *Scenario) DstIP(name string) (netip.Addr, bool) {
	if _, ok := s.Services[name]; ok {
		return s.ServiceIP(name)
	}
	if ext, ok := s.External[name]; ok {
		a, err := netip.ParseAddr(ext.IP)
		return a, err == nil
	}
	return netip.Addr{}, false
}

// Parsed classifier-knob accessors (invalid entries already rejected by Validate).
func (s *Scenario) NATAddrs() []netip.Addr           { return parseAddrs(s.NATGatewayIPs) }
func (s *Scenario) PeeringPrefixes() []netip.Prefix  { return parsePrefixes(s.VPCPeeringCIDRs) }
func (s *Scenario) TGWPrefixes() []netip.Prefix      { return parsePrefixes(s.TransitGatewayCIDRs) }
func (s *Scenario) EndpointPrefixes() []netip.Prefix { return parsePrefixes(s.VPCEndpointCIDRs) }
func (s *Scenario) ClusterPrefixes() []netip.Prefix  { return parsePrefixes(s.ClusterCIDRs) }

func parseAddrs(in []string) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	for _, v := range in {
		if a, err := netip.ParseAddr(v); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func parsePrefixes(in []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(in))
	for _, v := range in {
		if p, err := netip.ParsePrefix(v); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func mapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sortedIndex(keys []string, target string) int {
	sort.Strings(keys)
	for i, k := range keys {
		if k == target {
			return i
		}
	}
	return -1
}
