//go:build linux

package ebpf

import (
	"testing"
	"unsafe"
)

func TestQuicFlowKeyStructSize(t *testing.T) {
	// QuicFlowKey: src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2) = 12
	got := unsafe.Sizeof(QuicFlowKey{})
	if got != 12 {
		t.Errorf("sizeof(QuicFlowKey) = %d, want 12", got)
	}
}

func TestQuicFlowMetricsStructSize(t *testing.T) {
	// QuicFlowMetrics: tx_bytes(8) + rx_bytes(8) + pkt_count(8) +
	// last_seen_ns(8) + quic_version(4) + is_long_header(1) + pad(3) = 40
	got := unsafe.Sizeof(QuicFlowMetrics{})
	if got != 40 {
		t.Errorf("sizeof(QuicFlowMetrics) = %d, want 40", got)
	}
}

func TestSidecarInfoStructSize(t *testing.T) {
	// SidecarInfo: is_sidecar_internal(1) + pad(3) + app_pid(4) +
	// app_cgroupid(8) = 16
	got := unsafe.Sizeof(SidecarInfo{})
	if got != 16 {
		t.Errorf("sizeof(SidecarInfo) = %d, want 16", got)
	}
}
