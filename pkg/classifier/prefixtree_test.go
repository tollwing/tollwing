package classifier

import (
	"net/netip"
	"testing"
)

func TestPrefixTree_BasicLookup(t *testing.T) {
	pt := NewPrefixTree()
	pt.Add(netip.MustParsePrefix("52.94.0.0/16"), VPCPeering)
	pt.Add(netip.MustParsePrefix("100.64.0.0/16"), TransitGateway)
	pt.Add(netip.MustParsePrefix("3.5.0.0/16"), VPCEndpoint)
	pt.Build()

	tests := []struct {
		ip   string
		want TrafficType
		ok   bool
	}{
		{"52.94.1.50", VPCPeering, true},
		{"100.64.5.10", TransitGateway, true},
		{"3.5.1.100", VPCEndpoint, true},
		{"8.8.8.8", Unknown, false},
		{"10.0.1.1", Unknown, false},
	}

	for _, tt := range tests {
		got, ok := pt.Lookup(netip.MustParseAddr(tt.ip))
		if ok != tt.ok || got != tt.want {
			t.Errorf("Lookup(%s) = (%s, %v), want (%s, %v)", tt.ip, got, ok, tt.want, tt.ok)
		}
	}
}

func TestPrefixTree_LongestPrefixMatch(t *testing.T) {
	pt := NewPrefixTree()
	pt.Add(netip.MustParsePrefix("10.0.0.0/8"), VPCPeering)      // broad
	pt.Add(netip.MustParsePrefix("10.0.1.0/24"), TransitGateway) // more specific
	pt.Add(netip.MustParsePrefix("10.0.1.128/25"), VPCEndpoint)  // most specific
	pt.Build()

	tests := []struct {
		ip   string
		want TrafficType
	}{
		{"10.0.1.200", VPCEndpoint},   // matches /25 (most specific)
		{"10.0.1.50", TransitGateway}, // matches /24 but not /25
		{"10.0.2.1", VPCPeering},      // only matches /8
	}

	for _, tt := range tests {
		got, ok := pt.Lookup(netip.MustParseAddr(tt.ip))
		if !ok || got != tt.want {
			t.Errorf("Lookup(%s) = (%s, %v), want (%s, true)", tt.ip, got, ok, tt.want)
		}
	}
}

func TestPrefixTree_Empty(t *testing.T) {
	pt := NewPrefixTree()
	pt.Build()

	_, ok := pt.Lookup(netip.MustParseAddr("8.8.8.8"))
	if ok {
		t.Error("expected no match on empty tree")
	}
}

func TestPrefixTree_Reset(t *testing.T) {
	pt := NewPrefixTree()
	pt.Add(netip.MustParsePrefix("10.0.0.0/8"), VPCPeering)
	pt.Build()

	if pt.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", pt.Len())
	}

	pt.Reset()
	if pt.Len() != 0 {
		t.Fatalf("Len() after Reset() = %d, want 0", pt.Len())
	}
}

func BenchmarkPrefixTree_Lookup(b *testing.B) {
	pt := NewPrefixTree()
	// Simulate realistic CIDR config.
	for i := 0; i < 50; i++ {
		pt.Add(netip.MustParsePrefix("52.94.0.0/16"), VPCPeering)
	}
	pt.Build()

	addr := netip.MustParseAddr("52.94.5.10")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pt.Lookup(addr)
	}
}
