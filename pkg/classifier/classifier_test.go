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
