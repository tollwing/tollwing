package classifier

import (
	"encoding/binary"
	"log/slog"
	"net/netip"
	"testing"
)

// ipToNBO builds the uint32 IPv4 value exactly as the BPF data plane delivers
// it to the classifier: the kernel writes the address in network byte order and
// the BPF struct is decoded native-endian, so we load the address bytes
// native-endian here too. This makes the unit tests exercise the real decode
// contract (DEC-009) instead of a self-consistent big-endian shortcut that
// masked the cross-AZ misclassification bug.
func ipToNBO(s string) uint32 {
	b := netip.MustParseAddr(s).As4()
	return binary.NativeEndian.Uint32(b[:])
}

func newTestResolver() *ZoneResolver {
	r := NewZoneResolver(slog.Default())
	return r
}

func TestClassify_SameZone(t *testing.T) {
	r := newTestResolver()
	r.SetIPZone(netip.MustParseAddr("10.0.1.10"), "us-east-1a")
	r.SetIPZone(netip.MustParseAddr("10.0.1.20"), "us-east-1a")

	c := New(r)
	result := c.Classify(FlowInfo{
		SrcIP: ipToNBO("10.0.1.10"),
		DstIP: ipToNBO("10.0.1.20"),
	})

	if result.Type != SameZone {
		t.Fatalf("expected SameZone, got %s", result.Type)
	}
	if result.SrcZone != "us-east-1a" || result.DstZone != "us-east-1a" {
		t.Fatalf("unexpected zones: src=%s dst=%s", result.SrcZone, result.DstZone)
	}
}

func TestClassify_CrossAZ(t *testing.T) {
	r := newTestResolver()
	r.SetIPZone(netip.MustParseAddr("10.0.1.10"), "us-east-1a")
	r.SetIPZone(netip.MustParseAddr("10.0.2.20"), "us-east-1b")

	c := New(r)
	result := c.Classify(FlowInfo{
		SrcIP: ipToNBO("10.0.1.10"),
		DstIP: ipToNBO("10.0.2.20"),
	})

	if result.Type != CrossAZ {
		t.Fatalf("expected CrossAZ, got %s", result.Type)
	}
}

func TestClassify_CrossRegion(t *testing.T) {
	r := newTestResolver()
	r.SetIPZone(netip.MustParseAddr("10.0.1.10"), "us-east-1a")
	r.SetIPZone(netip.MustParseAddr("10.0.2.20"), "eu-west-1a")

	c := New(r)
	result := c.Classify(FlowInfo{
		SrcIP: ipToNBO("10.0.1.10"),
		DstIP: ipToNBO("10.0.2.20"),
	})

	if result.Type != CrossRegion {
		t.Fatalf("expected CrossRegion, got %s", result.Type)
	}
}

func TestClassify_InternetEgress(t *testing.T) {
	r := newTestResolver()
	c := New(r)

	result := c.Classify(FlowInfo{
		SrcIP: ipToNBO("10.0.1.10"),
		DstIP: ipToNBO("8.8.8.8"),
	})

	if result.Type != InternetEgress {
		t.Fatalf("expected InternetEgress, got %s", result.Type)
	}
}

// TestClassify_RealBPFByteOrder is the regression test for the cross-AZ
// misclassification bug surfaced by the L2b real-agent tier (DEC-009). IP
// fields arrive from the BPF data plane as network-order bytes decoded
// native-endian; a prior big-endian decode reversed them, so the in-cluster
// ClusterIP 10.96.14.74 looked like the public address 74.14.96.10 and every
// in-cluster flow on a little-endian host (all x86/arm64) was misclassified as
// internet_egress. ipToNBO now feeds IPs exactly as the kernel delivers them,
// so a reversed-octet regression in nboToAddr would surface here.
func TestClassify_RealBPFByteOrder(t *testing.T) {
	r := newTestResolver()
	r.SetIPZone(netip.MustParseAddr("10.244.2.2"), "us-east-1a")
	r.SetIPZone(netip.MustParseAddr("10.96.14.74"), "us-east-1b")
	c := New(r)

	result := c.Classify(FlowInfo{
		SrcIP: ipToNBO("10.244.2.2"),
		DstIP: ipToNBO("10.96.14.74"),
	})
	if result.Type == InternetEgress {
		t.Fatalf("in-cluster flow misclassified as internet_egress — IP byte order reversed (DEC-009)")
	}
	if result.Type != CrossAZ {
		t.Fatalf("got %s, want cross_az", result.Type)
	}
}

func TestClassify_NATGateway(t *testing.T) {
	r := newTestResolver()
	c := New(r)
	c.SetNATGatewayIPs([]netip.Addr{netip.MustParseAddr("10.0.99.1")})

	result := c.Classify(FlowInfo{
		SrcIP: ipToNBO("10.0.1.10"),
		DstIP: ipToNBO("10.0.99.1"),
	})

	if result.Type != NATGatewayEgress {
		t.Fatalf("expected NATGatewayEgress, got %s", result.Type)
	}
}

func TestClassify_VPCPeering(t *testing.T) {
	r := newTestResolver()
	c := New(r)
	c.SetVPCPeeringCIDRs([]netip.Prefix{netip.MustParsePrefix("52.94.0.0/16")})

	result := c.Classify(FlowInfo{
		SrcIP: ipToNBO("10.0.1.10"),
		DstIP: ipToNBO("52.94.1.50"),
	})

	if result.Type != VPCPeering {
		t.Fatalf("expected VPCPeering, got %s", result.Type)
	}
}

func TestClassify_TransitGateway(t *testing.T) {
	r := newTestResolver()
	c := New(r)
	c.SetTransitGatewayCIDRs([]netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")})

	result := c.Classify(FlowInfo{
		SrcIP: ipToNBO("10.0.1.10"),
		DstIP: ipToNBO("100.64.5.10"),
	})

	if result.Type != TransitGateway {
		t.Fatalf("expected TransitGateway, got %s", result.Type)
	}
}

func TestClassify_VPCEndpoint(t *testing.T) {
	r := newTestResolver()
	c := New(r)
	c.SetVPCEndpointCIDRs([]netip.Prefix{netip.MustParsePrefix("3.5.0.0/16")})

	result := c.Classify(FlowInfo{
		SrcIP: ipToNBO("10.0.1.10"),
		DstIP: ipToNBO("3.5.1.100"),
	})

	if result.Type != VPCEndpoint {
		t.Fatalf("expected VPCEndpoint, got %s", result.Type)
	}
}

func TestClassify_UnknownWhenNoZones(t *testing.T) {
	r := newTestResolver()
	c := New(r)

	result := c.Classify(FlowInfo{
		SrcIP: ipToNBO("10.0.1.10"),
		DstIP: ipToNBO("10.0.2.20"),
	})

	if result.Type != Unknown {
		t.Fatalf("expected Unknown when zones not resolved, got %s", result.Type)
	}
}

// TestClassify_RFC1918PeeringAndTGW is the regression test for the $0 peering
// bug: real VPC peers and TGW attachments are almost always RFC 1918, and the
// old decision order sent every private destination into the zone-based path
// before consulting the peering/TGW prefix sets — peered flows resolved no
// zone, fell to Unknown, and the engine priced them at $0. Per P5, the prefix
// sets must win for private, non-cluster destinations.
func TestClassify_RFC1918PeeringAndTGW(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(c *Classifier)
		dst      string
		expected TrafficType
	}{
		{
			name: "RFC1918 peer CIDR classifies vpc_peering",
			setup: func(c *Classifier) {
				c.SetVPCPeeringCIDRs([]netip.Prefix{netip.MustParsePrefix("10.50.0.0/16")})
			},
			dst:      "10.50.1.10",
			expected: VPCPeering,
		},
		{
			name: "RFC1918 TGW CIDR classifies transit_gateway",
			setup: func(c *Classifier) {
				c.SetTransitGatewayCIDRs([]netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")})
			},
			dst:      "172.16.5.10",
			expected: TransitGateway,
		},
		{
			name: "RFC1918 endpoint CIDR classifies vpc_endpoint",
			setup: func(c *Classifier) {
				c.SetVPCEndpointCIDRs([]netip.Prefix{netip.MustParsePrefix("10.60.0.0/24")})
			},
			dst:      "10.60.0.7",
			expected: VPCEndpoint,
		},
		{
			name: "NAT IP wins over an enclosing peer CIDR",
			setup: func(c *Classifier) {
				c.SetVPCPeeringCIDRs([]netip.Prefix{netip.MustParsePrefix("10.50.0.0/16")})
				c.SetNATGatewayIPs([]netip.Addr{netip.MustParseAddr("10.50.99.1")})
			},
			dst:      "10.50.99.1",
			expected: NATGatewayEgress,
		},
		{
			name: "cluster CIDR wins over an overlapping peer CIDR",
			setup: func(c *Classifier) {
				c.SetVPCPeeringCIDRs([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
				c.SetClusterCIDRs([]netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")})
			},
			dst: "10.0.2.20",
			// Cluster-internal with no zones resolved → Unknown, never
			// vpc_peering: pod traffic must not be billed as peering.
			expected: Unknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(newTestResolver())
			tt.setup(c)

			result := c.Classify(FlowInfo{
				SrcIP: ipToNBO("10.0.1.10"),
				DstIP: ipToNBO(tt.dst),
			})
			if result.Type != tt.expected {
				t.Fatalf("dst %s: expected %s, got %s", tt.dst, tt.expected, result.Type)
			}
		})
	}
}

// TestClassify_ReplaceOnRefresh: the topology refresher re-feeds the CIDR
// sets every few minutes. Each Set* call must REPLACE its category — the old
// append-only tree grew without bound and kept deleted peerings classifying
// forever (DEC-015).
func TestClassify_ReplaceOnRefresh(t *testing.T) {
	c := New(newTestResolver())
	flow := FlowInfo{SrcIP: ipToNBO("10.0.1.10"), DstIP: ipToNBO("10.50.1.10")}

	c.SetVPCPeeringCIDRs([]netip.Prefix{netip.MustParsePrefix("10.50.0.0/16")})
	if got := c.Classify(flow).Type; got != VPCPeering {
		t.Fatalf("before deletion: expected vpc_peering, got %s", got)
	}

	// Peering deleted upstream — next refresh delivers an empty set.
	c.SetVPCPeeringCIDRs(nil)
	if got := c.Classify(flow).Type; got == VPCPeering {
		t.Fatalf("deleted peering still classifies vpc_peering (stale prefix tree)")
	}

	// Other categories must survive a peering-set replacement.
	c.SetTransitGatewayCIDRs([]netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")})
	c.SetVPCPeeringCIDRs([]netip.Prefix{netip.MustParsePrefix("10.70.0.0/16")})
	tgwFlow := FlowInfo{SrcIP: ipToNBO("10.0.1.10"), DstIP: ipToNBO("172.16.5.10")}
	if got := c.Classify(tgwFlow).Type; got != TransitGateway {
		t.Fatalf("TGW set lost after peering refresh: got %s", got)
	}

	// Repeated refreshes with the same set must not grow the tree.
	for i := 0; i < 100; i++ {
		c.SetVPCPeeringCIDRs([]netip.Prefix{netip.MustParsePrefix("10.70.0.0/16")})
	}
	c.mu.RLock()
	size := c.prefixTree.Len()
	c.mu.RUnlock()
	if size != 2 { // 1 peering + 1 TGW
		t.Fatalf("prefix tree grew to %d entries after repeated refreshes, want 2", size)
	}
}

// TestClassify_DefaultRouteNAT: route-based NAT detection (DEC-015). An
// internet-bound flow from a subnet that default-routes through a NAT gateway
// classifies nat_gateway even though the destination is the internet IP —
// dst==NAT-ENI matching can never fire for these flows.
func TestClassify_DefaultRouteNAT(t *testing.T) {
	c := New(newTestResolver())
	internetFlow := FlowInfo{SrcIP: ipToNBO("10.0.1.10"), DstIP: ipToNBO("8.8.8.8")}

	// Without route knowledge: internet egress.
	if got := c.Classify(internetFlow).Type; got != InternetEgress {
		t.Fatalf("expected internet_egress before route detection, got %s", got)
	}

	c.SetDefaultRouteNAT(true)
	if got := c.Classify(internetFlow).Type; got != NATGatewayEgress {
		t.Fatalf("expected nat_gateway for internet-bound flow behind NAT route, got %s", got)
	}

	// Known topology prefixes still win over the NAT-route default —
	// endpoint/peering traffic does not traverse the NAT.
	c.SetVPCEndpointCIDRs([]netip.Prefix{netip.MustParsePrefix("3.5.0.0/16")})
	epFlow := FlowInfo{SrcIP: ipToNBO("10.0.1.10"), DstIP: ipToNBO("3.5.1.100")}
	if got := c.Classify(epFlow).Type; got != VPCEndpoint {
		t.Fatalf("expected vpc_endpoint to win over NAT route, got %s", got)
	}

	// NAT gateway removed (e.g. IGW route restored) — back to egress.
	c.SetDefaultRouteNAT(false)
	if got := c.Classify(internetFlow).Type; got != InternetEgress {
		t.Fatalf("expected internet_egress after NAT route removal, got %s", got)
	}
}

// TestQualifyAzureZone: Azure IMDS and ARM APIs report bare zone ordinals
// ("1"); unqualified, regionFromZone treated "1" vs "2" as different REGIONS
// and cross-AZ flows misclassified as cross_region.
func TestQualifyAzureZone(t *testing.T) {
	tests := []struct {
		region, zone, want string
	}{
		{"eastus", "1", "eastus-1"},
		{"westeurope", "3", "westeurope-3"},
		{"eastus", "eastus-2", "eastus-2"}, // already qualified
		{"eastus", "", ""},                 // non-zonal
		{"", "1", "1"},                     // region unknown — leave as-is
	}
	for _, tt := range tests {
		if got := QualifyAzureZone(tt.region, tt.zone); got != tt.want {
			t.Errorf("QualifyAzureZone(%q, %q) = %q, want %q", tt.region, tt.zone, got, tt.want)
		}
	}

	// The qualified zones must round-trip through regionFromZone so two
	// zones of one region compare as the same region (cross_az, not
	// cross_region).
	if regionFromZone(QualifyAzureZone("eastus", "1")) != regionFromZone(QualifyAzureZone("eastus", "2")) {
		t.Error("two qualified zones of eastus must resolve to the same region")
	}
}

func TestRegionFromZone(t *testing.T) {
	tests := []struct {
		zone, region string
	}{
		{"us-east-1a", "us-east-1"},
		{"us-east-1b", "us-east-1"},
		{"eu-west-1c", "eu-west-1"},
		{"us-central1-a", "us-central1"},
		{"eastus-1", "eastus"},
	}

	for _, tt := range tests {
		got := regionFromZone(tt.zone)
		if got != tt.region {
			t.Errorf("regionFromZone(%q) = %q, want %q", tt.zone, got, tt.region)
		}
	}
}

func TestTrafficType_String(t *testing.T) {
	tests := []struct {
		tt   TrafficType
		want string
	}{
		{Unknown, "unknown"},
		{SameZone, "same_zone"},
		{CrossAZ, "cross_az"},
		{InternetEgress, "internet_egress"},
		{NATGatewayEgress, "nat_gateway"},
	}

	for _, tt := range tests {
		if got := tt.tt.String(); got != tt.want {
			t.Errorf("TrafficType(%d).String() = %q, want %q", tt.tt, got, tt.want)
		}
	}
}

func TestTrafficType_IsFree(t *testing.T) {
	if !SameZone.IsFree() {
		t.Error("SameZone should be free")
	}
	if CrossAZ.IsFree() {
		t.Error("CrossAZ should not be free")
	}
	if InternetEgress.IsFree() {
		t.Error("InternetEgress should not be free")
	}
}
