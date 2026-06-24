package classifier

import (
	"encoding/binary"
	"log/slog"
	"net/netip"
	"testing"
)

// setupBenchClassifier creates a Classifier with realistic zone data:
// 10 subnets across 3 AZs, NAT gateway IPs, and VPC peering CIDRs.
func setupBenchClassifier() *Classifier {
	r := NewZoneResolver(slog.Default())

	// 10 subnets across 3 AZs (us-east-1a/b/c).
	subnets := []struct {
		prefix string
		zone   string
	}{
		{"10.0.1.0/24", "us-east-1a"},
		{"10.0.2.0/24", "us-east-1a"},
		{"10.0.3.0/24", "us-east-1a"},
		{"10.0.4.0/24", "us-east-1a"},
		{"10.0.10.0/24", "us-east-1b"},
		{"10.0.11.0/24", "us-east-1b"},
		{"10.0.12.0/24", "us-east-1b"},
		{"10.0.20.0/24", "us-east-1c"},
		{"10.0.21.0/24", "us-east-1c"},
		{"10.0.22.0/24", "us-east-1c"},
	}
	for _, s := range subnets {
		r.AddCIDRZone(netip.MustParsePrefix(s.prefix), s.zone)
	}

	// Register individual IPs used in benchmark flows so zone resolution works.
	r.SetIPZone(netip.MustParseAddr("10.0.1.5"), "us-east-1a")
	r.SetIPZone(netip.MustParseAddr("10.0.1.10"), "us-east-1a")
	r.SetIPZone(netip.MustParseAddr("10.0.10.5"), "us-east-1b")

	c := New(r)
	c.SetNATGatewayIPs([]netip.Addr{
		netip.MustParseAddr("10.0.99.1"),
		netip.MustParseAddr("10.0.99.2"),
	})
	c.SetVPCPeeringCIDRs([]netip.Prefix{
		netip.MustParsePrefix("52.94.0.0/16"),
		netip.MustParsePrefix("54.239.0.0/16"),
	})

	return c
}

// nbo builds the uint32 IPv4 value from four octets the way the BPF data plane
// delivers it (network-order bytes, native-endian decoded — DEC-009).
func nbo(a, b, c, d byte) uint32 {
	return binary.NativeEndian.Uint32([]byte{a, b, c, d})
}

func BenchmarkClassify_SameZone(b *testing.B) {
	c := setupBenchClassifier()
	flow := FlowInfo{
		SrcIP: nbo(10, 0, 1, 5),
		DstIP: nbo(10, 0, 1, 10),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Classify(flow)
	}
}

func BenchmarkClassify_CrossAZ(b *testing.B) {
	c := setupBenchClassifier()
	flow := FlowInfo{
		SrcIP: nbo(10, 0, 1, 5),
		DstIP: nbo(10, 0, 10, 5),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Classify(flow)
	}
}

func BenchmarkClassify_InternetEgress(b *testing.B) {
	c := setupBenchClassifier()
	flow := FlowInfo{
		SrcIP: nbo(10, 0, 1, 5),
		DstIP: nbo(8, 8, 8, 8),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Classify(flow)
	}
}

func BenchmarkClassify_NATGateway(b *testing.B) {
	c := setupBenchClassifier()
	flow := FlowInfo{
		SrcIP: nbo(10, 0, 1, 5),
		DstIP: nbo(10, 0, 99, 1),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Classify(flow)
	}
}
