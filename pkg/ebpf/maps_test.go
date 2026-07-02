//go:build linux

package ebpf

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"unsafe"
)

func TestFlowKey_Size(t *testing.T) {
	// FlowKey must match the C struct flow_key exactly: 20 bytes.
	// 4+4+2+2+4+1+1+2 = 20
	if got := unsafe.Sizeof(FlowKey{}); got != 20 {
		t.Errorf("FlowKey size = %d, want 20", got)
	}
}

func TestFlowMetrics_Size(t *testing.T) {
	// FlowMetrics must match struct flow_metrics: 48 bytes.
	// 8+8+8+8+8+8 = 48
	if got := unsafe.Sizeof(FlowMetrics{}); got != 48 {
		t.Errorf("FlowMetrics size = %d, want 48", got)
	}
}

func TestFlowKey_Fields(t *testing.T) {
	k := FlowKey{
		SrcIP:     0x0100000A, // 10.0.0.1 NBO
		DstIP:     0x0200000A,
		SrcPort:   8080,
		DstPort:   443,
		PID:       1234,
		Protocol:  6,
		Direction: 0,
	}

	if k.SrcPort != 8080 {
		t.Errorf("SrcPort = %d, want 8080", k.SrcPort)
	}
	if k.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6", k.Protocol)
	}
}

func TestConnInfo_Size(t *testing.T) {
	// ConnInfo must match struct conn_info in maps.h. Layout
	// after IPv6 support was added:
	//   IPv4 fields:                       72 bytes
	//   SrcIP6 + DstIP6 + OriginalDstIP6:  48 bytes (3 × [16]byte)
	//   ----------
	//   Total:                            120 bytes
	// The BPF C struct emits the same 120 bytes — Go and C
	// agree byte-for-byte under natural alignment.
	const want = 120
	got := unsafe.Sizeof(ConnInfo{})
	if got != want {
		t.Errorf("ConnInfo size = %d, want %d", got, want)
	}
}

func TestAgentConfig_Size(t *testing.T) {
	// AgentConfig: 1+1+1+1+4+8 = 16 (udp_socket_tx took one reserved byte,
	// so the kernel-side struct agent_config layout is unchanged)
	if got := unsafe.Sizeof(AgentConfig{}); got != 16 {
		t.Errorf("AgentConfig size = %d, want 16", got)
	}
}

func TestEventType_String(t *testing.T) {
	tests := []struct {
		t    EventType
		want string
	}{
		{EventConnect, "connect"},
		{EventEstablish, "establish"},
		{EventClose, "close"},
		{EventType(99), "unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.t.String(); got != tt.want {
			t.Errorf("EventType(%d).String() = %q, want %q", tt.t, got, tt.want)
		}
	}
}

// bpfIPv4 builds a uint32 IPv4 field exactly as the BPF data plane delivers it:
// the kernel writes the address in network byte order and the struct is decoded
// native-endian (binary.Read / unsafe cast), so we load the address bytes
// native-endian here too. Using this instead of a big-endian constant is what
// makes these tests exercise the real decode path that DEC-009 fixed.
func bpfIPv4(s string) uint32 {
	b := netip.MustParseAddr(s).As4()
	return binary.NativeEndian.Uint32(b[:])
}

func TestFormatIPPort(t *testing.T) {
	result := FormatIPPort(bpfIPv4("10.0.0.1"), 8080)
	if result != "10.0.0.1:8080" {
		t.Errorf("FormatIPPort = %q, want 10.0.0.1:8080", result)
	}
}

// TestAddrFromU32_RealByteOrder is the regression test for the cross-AZ
// misclassification bug (DEC-009). A BPF IP field for the in-cluster ClusterIP
// 10.96.14.74 must decode back to 10.96.14.74, not the byte-reversed public
// address 74.14.96.10 that a big-endian decode produced.
func TestAddrFromU32_RealByteOrder(t *testing.T) {
	if got := AddrFromU32(bpfIPv4("10.96.14.74")).String(); got != "10.96.14.74" {
		t.Fatalf("AddrFromU32 = %q, want 10.96.14.74 (IP byte order reversed — DEC-009)", got)
	}
}

func TestOriginalDst_Addr(t *testing.T) {
	o := OriginalDst{
		IP:   bpfIPv4("10.0.0.1"),
		Port: 443,
	}
	ap := o.Addr()
	if got := ap.Addr().String(); got != "10.0.0.1" {
		t.Errorf("Addr = %q, want 10.0.0.1", got)
	}
	if ap.Port() != 443 {
		t.Errorf("Port = %d, want 443", ap.Port())
	}
}
