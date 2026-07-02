// Package classifier determines the traffic type and cost class of network
// flows based on source/destination IPs, zones, and cloud topology.
package classifier

import (
	"encoding/binary"
	"net/netip"
	"sync"
)

// TrafficType describes the cost class of a network flow.
type TrafficType int

const (
	Unknown            TrafficType = iota
	SameZone                       // free on all clouds
	CrossAZ                        // charged on AWS and GCP (inter-zone); free on Azure — inter-AZ charges retired (DEC-014)
	CrossRegion                    // charged everywhere
	InternetEgress                 // charged per GB, tiered pricing
	NATGatewayEgress               // charged per GB + per hour
	VPCPeering                     // charged per GB on AWS
	TransitGateway                 // charged per GB + per hour
	VPCEndpoint                    // cheaper than public endpoint
	CloudServicePublic             // S3/DynamoDB via public endpoint

	// IntraNode is loopback / same-host pod-to-pod traffic. Always $0.
	// Tracked separately so operators can see how much of their traffic
	// is co-located (a sign of good locality scheduling).
	IntraNode

	// ServiceMeshInternal is sidecar-to-app loopback inside a meshed
	// pod (Envoy/Linkerd injected as a sidecar). Always $0 but very
	// large in volume on heavily meshed clusters — surfacing it as its
	// own category prevents it from inflating SameZone aggregates and
	// gives operators a direct measurement of mesh overhead.
	ServiceMeshInternal

	NumTrafficTypes // sentinel — must be last
)

func (t TrafficType) String() string {
	switch t {
	case SameZone:
		return "same_zone"
	case CrossAZ:
		return "cross_az"
	case CrossRegion:
		return "cross_region"
	case InternetEgress:
		return "internet_egress"
	case NATGatewayEgress:
		return "nat_gateway"
	case VPCPeering:
		return "vpc_peering"
	case TransitGateway:
		return "transit_gateway"
	case VPCEndpoint:
		return "vpc_endpoint"
	case CloudServicePublic:
		return "cloud_service_public"
	case IntraNode:
		return "intra_node"
	case ServiceMeshInternal:
		return "service_mesh_internal"
	default:
		return "unknown"
	}
}

// IsFree returns true if this traffic type is free (no per-GB charge).
func (t TrafficType) IsFree() bool {
	switch t {
	case SameZone, IntraNode, ServiceMeshInternal:
		return true
	}
	return false
}

// FlowInfo contains the information needed to classify a flow.
type FlowInfo struct {
	SrcIP           uint32 // BPF IP field: network-order bytes, native-endian decoded (DEC-009)
	DstIP           uint32 // BPF IP field: network-order bytes, native-endian decoded (DEC-009)
	OriginalDstIP   uint32 // pre-DNAT IP (same encoding), 0 if no DNAT
	SrcPort         uint16
	DstPort         uint16
	OriginalDstPort uint16

	// Hints from the agent / enricher. When set, the classifier emits
	// the corresponding fine-grained traffic type instead of folding
	// into SameZone. Both fields default to false; the classifier
	// behaviour is unchanged for callers that don't populate them.
	IntraNode bool // src + dst on same kernel (loopback or same-pod-host)
	IsSidecar bool // sidecar-to-app loopback inside a meshed pod
}

// Result is the classification output for a flow.
type Result struct {
	Type    TrafficType
	SrcZone string // e.g., "us-east-1a"
	DstZone string
}

// Classifier determines the traffic type of network flows.
type Classifier struct {
	resolver *ZoneResolver

	// Prefix tree for O(prefix-length) CIDR → traffic type lookups.
	// Rebuilt from the per-category CIDR sets below on every Set*CIDRs
	// call (replace-on-refresh, DEC-015): the topology refresher calls
	// those setters every few minutes, and append semantics grew the tree
	// unboundedly while keeping deleted peerings classifying forever.
	prefixTree *PrefixTree

	// Per-category topology CIDR sets — the sources the prefix tree is
	// rebuilt from.
	peeringCIDRs  []netip.Prefix
	tgwCIDRs      []netip.Prefix
	endpointCIDRs []netip.Prefix

	// clusterPrefixes are CIDRs that must be treated as cluster-internal
	// regardless of whether they fall in RFC 1918 private space. The K8s
	// informer feeds these from Node.spec.podCIDR + the well-known service
	// CIDR so that EKS Custom Networking (RFC 6598 100.64.0.0/10) and
	// other non-RFC-1918 cluster setups still classify correctly.
	//
	// Stored as a small slice — typically 1-3 entries — so linear scan
	// beats a tree on cache locality. The mu protects swap from
	// SetClusterCIDRs while Classify is reading.
	mu              sync.RWMutex
	clusterPrefixes []netip.Prefix

	natGatewayIPs map[netip.Addr]bool

	// defaultRouteNAT is true when this node's subnet default-routes
	// through a NAT gateway (learned from the cloud provider's route
	// tables, DEC-015). Internet-bound flows from such subnets classify
	// NATGatewayEgress: the destination stays the internet IP, so the
	// dst==NAT-ENI check can never fire for them.
	defaultRouteNAT bool
}

// New creates a Classifier with the given zone resolver.
func New(resolver *ZoneResolver) *Classifier {
	return &Classifier{
		resolver:      resolver,
		prefixTree:    NewPrefixTree(),
		natGatewayIPs: make(map[netip.Addr]bool),
	}
}

// Classify determines the traffic type of a flow.
// Implements the decision tree from the architecture doc.
//
// Decision order:
//  1. ServiceMeshInternal — flow.IsSidecar (mesh sidecar loopback)
//  2. IntraNode — flow.IntraNode OR loopback dst (127/8)
//  3. Cluster-internal CIDRs (operator-supplied or informer-fed)
//  4. RFC 1918 / link-local — NAT IPs, then the peering/TGW/endpoint
//     prefix sets, then zone-based fallback
//  5. External — prefix tree lookup (peering / TGW / VPC endpoints)
//  6. Default: InternetEgress (NATGatewayEgress when the node's subnet
//     default-routes through a NAT gateway, DEC-015)
//
// Cluster-internal classification has priority over RFC 1918 detection
// because some installations use non-RFC-1918 CIDRs for pod IPs (notably
// EKS Custom Networking with 100.64.0.0/10). Without this guard, traffic
// to such pods is incorrectly classified as InternetEgress and the
// flagship per-traffic-type breakdown lies on those clusters.
//
// The RFC 1918 branch consults the peering/TGW/endpoint prefix sets before
// falling back to zone resolution: real VPC peers are almost always RFC 1918,
// and skipping the prefix sets collapsed every peered flow to Unknown — which
// the cost engine prices at $0 (P5: attribute accurately, don't default to
// the flattering answer).
func (c *Classifier) Classify(flow FlowInfo) Result {
	dstAddr := nboToAddr(flow.DstIP)
	result := Result{}

	// Step 1: explicit sidecar hint from the enricher beats everything
	// else. The flow never leaves the kernel; it's $0 either way but we
	// want operators to see how much "traffic" is actually mesh overhead.
	if flow.IsSidecar {
		result.Type = ServiceMeshInternal
		return result
	}

	// Step 2: explicit intra-node hint OR a loopback destination
	// (the kernel never put it on the wire — always free, always
	// distinct from same-zone in our reporting).
	if flow.IntraNode || dstAddr.IsLoopback() {
		result.Type = IntraNode
		return result
	}

	// Step 3: cluster-internal CIDRs (operator-supplied or informer-fed).
	if c.isClusterInternal(dstAddr) {
		return c.classifyInternal(flow, dstAddr, &result)
	}

	// Step 4: RFC 1918 / link-local — NAT and topology prefixes first.
	if isPrivate(dstAddr) {
		return c.classifyPrivate(flow, dstAddr, &result)
	}

	return c.classifyExternal(flow, dstAddr, &result)
}

// isClusterInternal reports whether dstAddr falls within an
// operator-registered cluster CIDR.
func (c *Classifier) isClusterInternal(dstAddr netip.Addr) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, p := range c.clusterPrefixes {
		if p.Contains(dstAddr) {
			return true
		}
	}
	return false
}

// SetClusterCIDRs replaces the cluster-internal CIDR list. Typically
// fed from the K8s informer aggregating Node.spec.podCIDR + a configured
// service CIDR (see pkg/k8s/informer.go).
//
// Idempotent and safe for concurrent invocation alongside Classify.
func (c *Classifier) SetClusterCIDRs(cidrs []netip.Prefix) {
	// Defensive copy — caller may mutate the slice after the call.
	out := make([]netip.Prefix, 0, len(cidrs))
	seen := make(map[netip.Prefix]struct{}, len(cidrs))
	for _, p := range cidrs {
		if !p.IsValid() {
			continue
		}
		// De-duplicate so the informer can call this on every Node update
		// without growing the slice unboundedly.
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	c.mu.Lock()
	c.clusterPrefixes = out
	c.mu.Unlock()
}

// AddClusterCIDR adds a single CIDR to the cluster-internal set. Used
// by event-driven callers that don't have the full set in hand.
// Deduplicates against existing entries.
func (c *Classifier) AddClusterCIDR(cidr netip.Prefix) {
	if !cidr.IsValid() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, existing := range c.clusterPrefixes {
		if existing == cidr {
			return
		}
	}
	c.clusterPrefixes = append(c.clusterPrefixes, cidr)
}

// ClusterCIDRs returns a snapshot of the current cluster-internal CIDR
// list. Useful for /readyz and debug endpoints.
func (c *Classifier) ClusterCIDRs() []netip.Prefix {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]netip.Prefix, len(c.clusterPrefixes))
	copy(out, c.clusterPrefixes)
	return out
}

// classifyPrivate handles non-cluster RFC 1918 / link-local destinations:
// known NAT gateway ENI IPs, then the peering/TGW/endpoint prefix sets, then
// the zone-based fallback. Per P5, the prefix sets are consulted BEFORE zone
// resolution — a peered VPC's addresses never resolve to a local zone, so the
// old order (zones first, prefix tree never) classified real RFC 1918 peers
// as Unknown and priced them at $0.
func (c *Classifier) classifyPrivate(flow FlowInfo, dstAddr netip.Addr, result *Result) Result {
	c.mu.RLock()
	isNAT := c.natGatewayIPs[dstAddr]
	tt, matched := c.prefixTree.Lookup(dstAddr)
	c.mu.RUnlock()

	if isNAT {
		result.Type = NATGatewayEgress
		return *result
	}
	if matched {
		result.Type = tt
		return *result
	}
	return c.classifyInternal(flow, dstAddr, result)
}

func (c *Classifier) classifyInternal(flow FlowInfo, dstAddr netip.Addr, result *Result) Result {
	srcAddr := nboToAddr(flow.SrcIP)

	// Resolve zones for both endpoints.
	result.SrcZone = c.resolver.Resolve(srcAddr)
	result.DstZone = c.resolver.Resolve(dstAddr)

	if result.SrcZone == "" || result.DstZone == "" {
		result.Type = Unknown
		return *result
	}

	if result.SrcZone == result.DstZone {
		result.Type = SameZone
		return *result
	}

	// Different zones — check if same region.
	srcRegion := regionFromZone(result.SrcZone)
	dstRegion := regionFromZone(result.DstZone)

	if srcRegion == dstRegion {
		result.Type = CrossAZ
	} else {
		result.Type = CrossRegion
	}
	return *result
}

func (c *Classifier) classifyExternal(flow FlowInfo, dstAddr netip.Addr, result *Result) Result {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if tt, ok := c.prefixTree.Lookup(dstAddr); ok {
		result.Type = tt
		return *result
	}

	// Per DEC-015: when this node's subnet default-routes through a NAT
	// gateway, internet-bound bytes traverse it and incur NAT processing
	// + egress — the dst stays the internet IP, so only route knowledge
	// can attribute the NAT charge.
	if c.defaultRouteNAT {
		result.Type = NATGatewayEgress
		return *result
	}

	result.Type = InternetEgress
	return *result
}

// rebuildPrefixTreeLocked reconstructs the lookup tree from the per-category
// CIDR sets. Callers must hold c.mu. Replace-on-refresh (DEC-015): the tree
// always reflects exactly the latest topology snapshot, so deleted peerings
// stop classifying and periodic refreshes cannot grow it unboundedly.
func (c *Classifier) rebuildPrefixTreeLocked() {
	tree := NewPrefixTree()
	for _, cidr := range c.peeringCIDRs {
		tree.Add(cidr, VPCPeering)
	}
	for _, cidr := range c.tgwCIDRs {
		tree.Add(cidr, TransitGateway)
	}
	for _, cidr := range c.endpointCIDRs {
		tree.Add(cidr, VPCEndpoint)
	}
	tree.Build()
	c.prefixTree = tree
}

// clonePrefixes copies a caller-owned prefix slice, dropping invalid entries.
func clonePrefixes(cidrs []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, p := range cidrs {
		if p.IsValid() {
			out = append(out, p)
		}
	}
	return out
}

// SetVPCPeeringCIDRs replaces the known VPC peering CIDR ranges.
func (c *Classifier) SetVPCPeeringCIDRs(cidrs []netip.Prefix) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peeringCIDRs = clonePrefixes(cidrs)
	c.rebuildPrefixTreeLocked()
}

// SetTransitGatewayCIDRs replaces the known transit gateway CIDR ranges.
func (c *Classifier) SetTransitGatewayCIDRs(cidrs []netip.Prefix) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tgwCIDRs = clonePrefixes(cidrs)
	c.rebuildPrefixTreeLocked()
}

// SetNATGatewayIPs updates the set of known NAT gateway IPs.
func (c *Classifier) SetNATGatewayIPs(ips []netip.Addr) {
	m := make(map[netip.Addr]bool, len(ips))
	for _, ip := range ips {
		m[ip] = true
	}
	c.mu.Lock()
	c.natGatewayIPs = m
	c.mu.Unlock()
}

// SetVPCEndpointCIDRs replaces the known VPC endpoint prefix lists.
func (c *Classifier) SetVPCEndpointCIDRs(cidrs []netip.Prefix) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.endpointCIDRs = clonePrefixes(cidrs)
	c.rebuildPrefixTreeLocked()
}

// SetDefaultRouteNAT records whether this node's subnet default-routes
// through a NAT gateway (from the cloud provider's route tables, DEC-015).
// When true, internet-bound flows classify NATGatewayEgress.
func (c *Classifier) SetDefaultRouteNAT(viaNAT bool) {
	c.mu.Lock()
	c.defaultRouteNAT = viaNAT
	c.mu.Unlock()
}

// helpers

// nboToAddr converts a uint32 IPv4 field from the BPF data plane into a
// netip.Addr. The kernel stores the address in network byte order and the BPF
// struct is decoded native-endian, so the bytes are recovered with the same
// native endianness — a big-endian decode reverses the octets (the cross-AZ
// misclassification bug, DEC-009). This intentionally mirrors
// pkg/ebpf.AddrFromU32; it is duplicated here only because pkg/classifier is
// cross-platform and must not import the linux-only pkg/ebpf. Keep in sync.
func nboToAddr(v uint32) netip.Addr {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// isPrivate checks if an address is in RFC 1918 / RFC 6598 private ranges.
func isPrivate(addr netip.Addr) bool {
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}

// regionFromZone extracts the region from a zone string.
// AWS: "us-east-1a" → "us-east-1"
// GCP: "us-central1-a" → "us-central1"
// Azure: "eastus-1" → "eastus"
func regionFromZone(zone string) string {
	if zone == "" {
		return ""
	}

	// Azure-style or numeric suffix: try stripping at last '-' and verify
	// the stripped result looks like a region (at least one digit inside,
	// e.g., "eastus-1" → "eastus").
	for i := len(zone) - 1; i >= 0; i-- {
		if zone[i] == '-' {
			candidate := zone[:i]
			if len(candidate) > 0 {
				return candidate
			}
			break
		}
		// AWS-style: zone ends with a letter appended directly to the
		// region (e.g., "us-east-1a"). Detect the letter and verify
		// the preceding character is a digit (the zone index).
		if i == len(zone)-1 && zone[i] >= 'a' && zone[i] <= 'z' {
			if i > 0 && zone[i-1] >= '0' && zone[i-1] <= '9' {
				return zone[:len(zone)-1]
			}
		}
	}

	// If the input is already a bare region name (no zone suffix),
	// return it as-is. This handles "us-east-1", "us-central1", etc.
	return zone
}
