package classifier

import (
	"encoding/binary"
	"log/slog"
	"net/netip"
	"testing"
)

// nboFromAddr builds the uint32 IPv4 value the way the BPF data plane delivers
// it (network-order bytes, native-endian decoded) — the faithful inverse of
// pkg/classifier's nboToAddr. See DEC-009.
func nboFromAddr(t *testing.T, s string) uint32 {
	t.Helper()
	b := netip.MustParseAddr(s).As4()
	return binary.NativeEndian.Uint32(b[:])
}

func TestClassify_ClusterInternalBeatsRFC1918Fallback(t *testing.T) {
	// EKS Custom Networking case: pod CIDR is 100.64.0.0/10
	// (RFC 6598 — NOT RFC 1918). Without SetClusterCIDRs, the address
	// would fall through to classifyExternal and be labelled
	// InternetEgress. With it, the flow should classify as same-zone
	// (both ends in the same configured zone).
	resolver := NewZoneResolver(slog.Default())
	c := New(resolver)

	src := netip.MustParseAddr("100.64.0.5")
	dst := netip.MustParseAddr("100.64.0.6")

	resolver.SetIPZone(src, "us-east-1a")
	resolver.SetIPZone(dst, "us-east-1a")

	c.SetClusterCIDRs([]netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")})

	r := c.Classify(FlowInfo{
		SrcIP: nboFromAddr(t, "100.64.0.5"),
		DstIP: nboFromAddr(t, "100.64.0.6"),
	})
	if r.Type != SameZone {
		t.Errorf("got %s, want same_zone (cluster-internal beats RFC1918 fallback)", r.Type)
	}
}

func TestClassify_NoClusterCIDRStillFallsThroughToInternetEgress(t *testing.T) {
	// Sanity check: without SetClusterCIDRs, traffic to 100.64.x.x
	// (which is NOT in RFC 1918) is still classified as external.
	c := New(NewZoneResolver(slog.Default()))
	r := c.Classify(FlowInfo{
		SrcIP: nboFromAddr(t, "10.0.0.1"),
		DstIP: nboFromAddr(t, "100.64.0.5"), // RFC 6598, not 1918
	})
	if r.Type != InternetEgress {
		t.Errorf("got %s, want internet_egress without SetClusterCIDRs", r.Type)
	}
}

func TestClassify_RFC1918StillWorks(t *testing.T) {
	// Sanity check: with no SetClusterCIDRs, RFC 1918 traffic still
	// goes through classifyInternal (it's the path that backs the
	// existing tests).
	resolver := NewZoneResolver(slog.Default())
	c := New(resolver)
	src := netip.MustParseAddr("10.0.1.5")
	dst := netip.MustParseAddr("10.0.2.5")
	resolver.SetIPZone(src, "us-east-1a")
	resolver.SetIPZone(dst, "us-east-1a")

	r := c.Classify(FlowInfo{
		SrcIP: nboFromAddr(t, "10.0.1.5"),
		DstIP: nboFromAddr(t, "10.0.2.5"),
	})
	if r.Type != SameZone {
		t.Errorf("got %s, want same_zone for RFC1918 same-zone flow", r.Type)
	}
}

func TestSetClusterCIDRs_DeduplicatesAndIgnoresInvalid(t *testing.T) {
	c := New(NewZoneResolver(slog.Default()))
	v := netip.MustParsePrefix("10.244.0.0/16")
	c.SetClusterCIDRs([]netip.Prefix{
		v, v, // duplicate
		{}, // invalid (zero prefix)
	})
	got := c.ClusterCIDRs()
	if len(got) != 1 || got[0] != v {
		t.Errorf("ClusterCIDRs = %v, want exactly [%v]", got, v)
	}
}

func TestAddClusterCIDR_IsIdempotent(t *testing.T) {
	c := New(NewZoneResolver(slog.Default()))
	p := netip.MustParsePrefix("10.244.0.0/16")
	c.AddClusterCIDR(p)
	c.AddClusterCIDR(p)
	c.AddClusterCIDR(p)
	if got := c.ClusterCIDRs(); len(got) != 1 {
		t.Errorf("got %d entries, want 1 after 3 idempotent adds", len(got))
	}
	// Add a different prefix; should now have 2.
	c.AddClusterCIDR(netip.MustParsePrefix("10.245.0.0/16"))
	if got := c.ClusterCIDRs(); len(got) != 2 {
		t.Errorf("got %d entries, want 2 after distinct adds", len(got))
	}
}

func TestAddClusterCIDR_RejectsInvalid(t *testing.T) {
	c := New(NewZoneResolver(slog.Default()))
	c.AddClusterCIDR(netip.Prefix{})
	if got := c.ClusterCIDRs(); len(got) != 0 {
		t.Errorf("invalid CIDR should not be stored; got %v", got)
	}
}

func TestClassify_SidecarHintWinsEverything(t *testing.T) {
	c := New(NewZoneResolver(slog.Default()))
	// Sidecar flow to a remote cross-AZ IP should still classify as
	// service_mesh_internal — we want the operator to see mesh overhead
	// as a distinct line item, not folded into cross-AZ.
	r := c.Classify(FlowInfo{
		SrcIP:     nboFromAddr(t, "10.0.1.5"),
		DstIP:     nboFromAddr(t, "10.0.2.5"),
		IsSidecar: true,
	})
	if r.Type != ServiceMeshInternal {
		t.Errorf("got %s, want service_mesh_internal", r.Type)
	}
}

func TestClassify_LoopbackIsIntraNode(t *testing.T) {
	c := New(NewZoneResolver(slog.Default()))
	r := c.Classify(FlowInfo{
		SrcIP: nboFromAddr(t, "127.0.0.1"),
		DstIP: nboFromAddr(t, "127.0.0.1"),
	})
	if r.Type != IntraNode {
		t.Errorf("got %s, want intra_node for loopback flow", r.Type)
	}
}

func TestClassify_ExplicitIntraNodeHint(t *testing.T) {
	c := New(NewZoneResolver(slog.Default()))
	r := c.Classify(FlowInfo{
		SrcIP:     nboFromAddr(t, "10.244.0.5"),
		DstIP:     nboFromAddr(t, "10.244.0.6"),
		IntraNode: true,
	})
	if r.Type != IntraNode {
		t.Errorf("got %s, want intra_node when hint is set", r.Type)
	}
}

func TestNewTrafficTypes_AreFree(t *testing.T) {
	for _, tt := range []TrafficType{IntraNode, ServiceMeshInternal} {
		if !tt.IsFree() {
			t.Errorf("%s should be free (zero cost)", tt)
		}
	}
}

func TestNewTrafficTypes_StringNames(t *testing.T) {
	if IntraNode.String() != "intra_node" {
		t.Errorf("IntraNode.String() = %q", IntraNode.String())
	}
	if ServiceMeshInternal.String() != "service_mesh_internal" {
		t.Errorf("ServiceMeshInternal.String() = %q", ServiceMeshInternal.String())
	}
}

// TestClassify_ConcurrentSetAndClassify is a race-detector smoke test.
// Run with -race; passes if no race is reported.
func TestClassify_ConcurrentSetAndClassify(t *testing.T) {
	c := New(NewZoneResolver(slog.Default()))
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			c.Classify(FlowInfo{
				SrcIP: nboFromAddr(t, "100.64.0.1"),
				DstIP: nboFromAddr(t, "100.64.0.2"),
			})
		}
	}()
	for i := 0; i < 100; i++ {
		c.SetClusterCIDRs([]netip.Prefix{
			netip.MustParsePrefix("100.64.0.0/16"),
			netip.MustParsePrefix("10.244.0.0/16"),
		})
	}
	close(stop)
}
