package enricher

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestIsSidecarPort(t *testing.T) {
	tests := []struct {
		port uint16
		want bool
	}{
		{15001, true}, // Envoy outbound
		{15006, true}, // Envoy inbound
		{15090, true}, // Envoy stats
		{15021, true}, // Envoy health
		{4143, true},  // Linkerd outbound
		{4191, true},  // Linkerd admin
		{8080, false}, // regular port
		{443, false},  // HTTPS
		{0, false},    // zero
	}

	for _, tt := range tests {
		if got := IsSidecarPort(tt.port); got != tt.want {
			t.Errorf("IsSidecarPort(%d) = %v, want %v", tt.port, got, tt.want)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	// bpfIPv4 builds the uint32 as the BPF data plane delivers it: network-order
	// bytes decoded native-endian (DEC-009). The earlier test used the
	// big-endian constant 0x7f000001, which is NOT what reaches IsLoopback at
	// runtime — masking that IsLoopback never matched real loopback flows.
	bpfIPv4 := func(s string) uint32 {
		b := netip.MustParseAddr(s).As4()
		return binary.NativeEndian.Uint32(b[:])
	}

	lo := bpfIPv4("127.0.0.1")
	if !IsLoopback(lo, lo) {
		t.Error("IsLoopback(127.0.0.1, 127.0.0.1) = false, want true")
	}
	if IsLoopback(lo, bpfIPv4("10.0.0.1")) {
		t.Error("IsLoopback(127.0.0.1, 10.0.0.1) = true, want false")
	}
	if IsLoopback(0, 0) { // 0.0.0.0 is not loopback
		t.Error("IsLoopback(0, 0) = true, want false")
	}
}

func TestKnownSidecarProxies(t *testing.T) {
	for _, name := range []string{"envoy", "linkerd-proxy", "linkerd2-proxy", "istio-proxy"} {
		if !KnownSidecarProxies[name] {
			t.Errorf("KnownSidecarProxies[%q] = false, want true", name)
		}
	}

	if KnownSidecarProxies["nginx"] {
		t.Error("KnownSidecarProxies[nginx] = true, want false")
	}
}

func TestKnownSidecarPorts(t *testing.T) {
	if _, ok := KnownSidecarPorts[15001]; !ok {
		t.Error("KnownSidecarPorts[15001] not found")
	}
	if desc := KnownSidecarPorts[15001]; desc != "envoy-outbound" {
		t.Errorf("KnownSidecarPorts[15001] = %q, want envoy-outbound", desc)
	}
}
