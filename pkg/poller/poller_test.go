//go:build linux

package poller

import (
	"testing"

	bpf "github.com/tollwing/tollwing/pkg/ebpf"
)

func TestFlowSnapshot_Fields(t *testing.T) {
	snap := FlowSnapshot{
		SrcIP:     0x0A000001,
		DstIP:     0x0A000002,
		SrcPort:   12345,
		DstPort:   80,
		PID:       42,
		Protocol:  6,
		Direction: 0,
		TxBytes:   1024,
		RxBytes:   2048,
		ConnCount: 3,
	}

	if snap.SrcIP != 0x0A000001 {
		t.Errorf("SrcIP = %d, want %d", snap.SrcIP, 0x0A000001)
	}
	if snap.ConnCount != 3 {
		t.Errorf("ConnCount = %d, want 3", snap.ConnCount)
	}
}

func TestConfig_SetDefaults(t *testing.T) {
	cfg := Config{}
	cfg.setDefaults()

	if cfg.Interval != 5_000_000_000 { // 5s
		t.Errorf("Interval = %v, want 5s", cfg.Interval)
	}
	if cfg.BatchSize != 256 {
		t.Errorf("BatchSize = %d, want 256", cfg.BatchSize)
	}
}

func TestConfig_PreserveExplicit(t *testing.T) {
	cfg := Config{
		Interval:  1_000_000_000,
		BatchSize: 128,
	}
	cfg.setDefaults()

	if cfg.Interval != 1_000_000_000 {
		t.Errorf("Interval = %v, want 1s", cfg.Interval)
	}
	if cfg.BatchSize != 128 {
		t.Errorf("BatchSize = %d, want 128", cfg.BatchSize)
	}
}

func TestSumPerCPU(t *testing.T) {
	key := bpf.FlowKey{
		SrcIP:     0x0A000001,
		DstIP:     0x0A000002,
		SrcPort:   1234,
		DstPort:   80,
		PID:       100,
		Protocol:  6,
		Direction: 0,
	}

	perCPU := []bpf.FlowMetrics{
		{TxBytes: 100, RxBytes: 50, ConnCount: 1},
		{TxBytes: 200, RxBytes: 75, ConnCount: 0},
		{TxBytes: 50, RxBytes: 25, ConnCount: 1},
		{TxBytes: 0, RxBytes: 0, ConnCount: 0},
	}

	snap := sumPerCPU(key, perCPU)

	if snap.SrcIP != key.SrcIP {
		t.Errorf("SrcIP = %d, want %d", snap.SrcIP, key.SrcIP)
	}
	if snap.DstPort != 80 {
		t.Errorf("DstPort = %d, want 80", snap.DstPort)
	}
	if snap.TxBytes != 350 {
		t.Errorf("TxBytes = %d, want 350", snap.TxBytes)
	}
	if snap.RxBytes != 150 {
		t.Errorf("RxBytes = %d, want 150", snap.RxBytes)
	}
	if snap.ConnCount != 2 {
		t.Errorf("ConnCount = %d, want 2", snap.ConnCount)
	}
	if snap.PID != 100 {
		t.Errorf("PID = %d, want 100", snap.PID)
	}
	if snap.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6", snap.Protocol)
	}
}

// TestAppendQuicFlows locks in the authoritative-source contract at the
// poller seam: quic_flows and the socket-level UDP path are made disjoint
// KERNEL-SIDE (tollwing_quic_egress records nothing while
// agent_config.udp_socket_tx is set — see bpf/quic.bpf.c and udpSocketTX in
// pkg/ebpf/loader.go), so the merge must preserve every snapshot from both
// sources, byte-for-byte.
//
// It replaces (and fails against) the deleted dedup heuristic that joined
// the sources on (dst_ip, dst_port): that join missed DNATed QUIC — the
// socket path stores the pre-DNAT connect() destination, the TC hook the
// post-DNAT wire destination — and its destination-only seen-set let one
// pod's connected-socket flow discard every other pod's TC-observed bytes
// to a shared destination.
func TestAppendQuicFlows(t *testing.T) {
	// Socket-path UDP snapshot: created in cgroup/connect4 before the local
	// address is bound, so src_ip/src_port are zero and DstIP is the
	// PRE-DNAT connect() destination (e.g. a ClusterIP).
	socketUDP := FlowSnapshot{
		DstIP: 0x0100000A, DstPort: 443, // pre-DNAT ClusterIP
		PID: 42, Protocol: protoUDP,
		TxBytes: 1000, RxBytes: 500,
	}
	socketTCP := FlowSnapshot{
		SrcIP: 0x0200000A, DstIP: 0x0100000A,
		SrcPort: 33000, DstPort: 443,
		PID: 43, Protocol: 6,
		TxBytes: 4096,
	}
	// TC-observed QUIC to the SAME post-DNAT backend the socketUDP flow was
	// DNATed to. Under the old heuristic this pair double counted (keys
	// differ, no dedup fired); under the new contract it can only coexist
	// with socketUDP when the sources are disjoint (e.g. socketUDP carries
	// only RX bytes because fentry/udp_sendmsg is not attached), so keeping
	// both is correct.
	quicDNAT := FlowSnapshot{
		SrcIP: 0x0300000A, DstIP: 0x0500000A, // post-DNAT backend pod IP
		SrcPort: 51820, DstPort: 443,
		Protocol: protoUDP, TxBytes: 1100, PacketCount: 3,
	}
	// Two pods' TC-observed QUIC to the same CDN destination as socketUDP's
	// pre-DNAT key. The old seen-set dropped BOTH of these (undercount).
	quicPodB := FlowSnapshot{
		SrcIP: 0x0300000A, DstIP: 0x0100000A,
		SrcPort: 51821, DstPort: 443,
		Protocol: protoUDP, TxBytes: 700, PacketCount: 2,
	}
	quicPodC := FlowSnapshot{
		SrcIP: 0x0400000A, DstIP: 0x0100000A,
		SrcPort: 51822, DstPort: 443,
		Protocol: protoUDP, TxBytes: 900, PacketCount: 4,
	}

	tests := []struct {
		name  string
		flows []FlowSnapshot
		quic  []FlowSnapshot
		desc  string // what the case protects
	}{
		{
			// Regression for the destination-keyed undercount: fails on the
			// old code, which discarded quicPodB and quicPodC because
			// socketUDP shares their (dst_ip, dst_port).
			name:  "two pods same destination all kept",
			flows: []FlowSnapshot{socketUDP},
			quic:  []FlowSnapshot{quicPodB, quicPodC},
			desc:  "one pod's socket flow must not discard other pods' TC-observed bytes",
		},
		{
			// The DNAT shape from finding (a): distinct keys, both kept.
			// The double count is prevented kernel-side (quic.bpf.c gate),
			// not here — this case pins that no join on mismatched
			// pre-/post-DNAT keys is attempted.
			name:  "dnated quic kept alongside socket flow",
			flows: []FlowSnapshot{socketUDP, socketTCP},
			quic:  []FlowSnapshot{quicDNAT},
			desc:  "pre-DNAT socket key and post-DNAT TC key are not joinable",
		},
		{
			name:  "no quic flows",
			flows: []FlowSnapshot{socketUDP, socketTCP},
			quic:  nil,
			desc:  "no-op without QUIC data",
		},
		{
			name:  "quic only (-udp off: quic_flows is the sole UDP source)",
			flows: nil,
			quic:  []FlowSnapshot{quicDNAT, quicPodB, quicPodC},
			desc:  "QUIC-only traffic is fully counted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendQuicFlows(tt.flows, tt.quic)

			want := len(tt.flows) + len(tt.quic)
			if len(got) != want {
				t.Fatalf("appendQuicFlows() returned %d snapshots, want %d (%s)",
					len(got), want, tt.desc)
			}

			// Every input snapshot must survive with its bytes intact —
			// each source's bytes are delivered exactly once.
			var wantTx, gotTx uint64
			for _, f := range tt.flows {
				wantTx += f.TxBytes
			}
			for _, f := range tt.quic {
				wantTx += f.TxBytes
			}
			for _, f := range got {
				gotTx += f.TxBytes
			}
			if gotTx != wantTx {
				t.Errorf("total TxBytes = %d, want %d (%s)", gotTx, wantTx, tt.desc)
			}
		})
	}
}
