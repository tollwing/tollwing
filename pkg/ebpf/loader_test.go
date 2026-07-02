//go:build linux

package ebpf

import "testing"

// TestUDPSocketTX pins the authoritative-source decision for UDP TX bytes
// (the -udp on/off matrix). Exactly one source owns UDP TX per agent run:
// the socket path (cgroup/connect4 + fentry/udp_sendmsg) when the bit is 1,
// the TC QUIC hook (quic_flows) when it is 0 — never both, so nothing
// double counts and the poller can merge without dedup (P5). See
// bpf/quic.bpf.c for the full rule and the documented unconnected-UDP
// limitation of the socket path.
func TestUDPSocketTX(t *testing.T) {
	tests := []struct {
		name               string
		trackUDP           bool
		udpSendmsgAttached bool
		want               uint8
		desc               string
	}{
		{
			name:     "udp off",
			trackUDP: false, udpSendmsgAttached: true,
			want: 0,
			desc: "-udp off: no UDP connections entries exist, TC QUIC hook is the sole UDP TX source",
		},
		{
			name:     "udp off and no fentry",
			trackUDP: false, udpSendmsgAttached: false,
			want: 0,
			desc: "-udp off: TC QUIC hook is the sole UDP TX source",
		},
		{
			name:     "udp on with fentry attached",
			trackUDP: true, udpSendmsgAttached: true,
			want: 1,
			desc: "-udp on: socket path owns UDP TX (PID/cgroup attribution); TC records nothing",
		},
		{
			name:     "udp on but fentry attach failed",
			trackUDP: true, udpSendmsgAttached: false,
			want: 0,
			desc: "-udp on without fentry: nothing feeds the socket entries, so TC must stay the TX source or UDP goes fully uncounted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := udpSocketTX(tt.trackUDP, tt.udpSendmsgAttached); got != tt.want {
				t.Errorf("udpSocketTX(%v, %v) = %d, want %d (%s)",
					tt.trackUDP, tt.udpSendmsgAttached, got, tt.want, tt.desc)
			}
		})
	}
}
