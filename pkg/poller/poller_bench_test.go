//go:build linux

package poller

import (
	"runtime"
	"testing"

	bpf "github.com/tollwing/tollwing/pkg/ebpf"
)

// BenchmarkSumPerCPU measures the per-CPU aggregation cost. Called once
// per flow entry on every poll tick, so it's directly on the hot path
// for high-connection-count nodes.
func BenchmarkSumPerCPU(b *testing.B) {
	numCPU := runtime.NumCPU()
	key := bpf.FlowKey{SrcIP: 0x0100007F, DstIP: 0x0200007F, SrcPort: 443, DstPort: 8080, Protocol: 6}
	perCPU := make([]bpf.FlowMetrics, numCPU)
	for i := range perCPU {
		perCPU[i] = bpf.FlowMetrics{
			TxBytes:   1 << 20,
			RxBytes:   1 << 18,
			ConnCount: 5,
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sumPerCPU(key, perCPU)
	}
}

// BenchmarkSumPerCPU_Many simulates a 10k-flow tick on a 32-CPU node.
// Target: the poll handler should be able to process this in < 10 ms so
// it completes well inside the poll interval (default 5 s).
func BenchmarkSumPerCPU_Many(b *testing.B) {
	const flows = 10_000
	numCPU := runtime.NumCPU()
	keys := make([]bpf.FlowKey, flows)
	perCPU := make([][]bpf.FlowMetrics, flows)
	for i := 0; i < flows; i++ {
		keys[i] = bpf.FlowKey{
			SrcIP: 0x0100007F, DstIP: uint32(i),
			SrcPort: 443, DstPort: uint16(1024 + i%60000), Protocol: 6,
		}
		perCPU[i] = make([]bpf.FlowMetrics, numCPU)
		for j := range perCPU[i] {
			perCPU[i][j] = bpf.FlowMetrics{TxBytes: 1 << 16, ConnCount: 1}
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := make([]FlowSnapshot, flows)
		for j := 0; j < flows; j++ {
			out[j] = sumPerCPU(keys[j], perCPU[j])
		}
		_ = out
	}
}
