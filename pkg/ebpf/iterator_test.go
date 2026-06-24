//go:build linux

package ebpf

import (
	"testing"
	"time"
	"unsafe"
)

func TestIterOutputStructSize(t *testing.T) {
	// IterOutput must match struct iter_output in iter.bpf.c.
	// Layout (with Go's natural alignment — matches BPF C's):
	//   FlowKey:        20 bytes of fields + 4 bytes padding to
	//                   align the next uint64 = 24 bytes
	//   6 × uint64:     48 bytes
	//   ----------
	//   Total:          72 bytes
	// The previous formula `Sizeof(FlowKey{}) + 6*8` was wrong —
	// it ignored the 4-byte trailing pad inserted before the
	// first uint64 field. We assert the concrete byte count so
	// future changes to either side surface immediately.
	const want = 72
	got := unsafe.Sizeof(IterOutput{})
	if got != want {
		t.Errorf("sizeof(IterOutput) = %d, want %d", got, want)
	}
}

func TestCostSnapshotActiveSince(t *testing.T) {
	snap := CostSnapshot{
		TxBytes:     5000,
		RxBytes:     3000,
		ActiveSince: 30 * time.Second,
	}

	if snap.ActiveSince != 30*time.Second {
		t.Errorf("ActiveSince = %v, want 30s", snap.ActiveSince)
	}
}

func TestFormatSnapshot(t *testing.T) {
	snap := CostSnapshot{
		FlowKey: FlowKey{
			SrcIP:   0x0100007f, // 127.0.0.1
			DstIP:   0x0200007f,
			SrcPort: 8080,
			DstPort: 443,
		},
		TxBytes:         1000,
		RxBytes:         2000,
		RetransmitBytes: 50,
		CgroupID:        42,
		ActiveSince:     10 * time.Second,
	}

	got := FormatSnapshot(snap)
	if got == "" {
		t.Error("FormatSnapshot returned empty string")
	}
}

func TestSkCostMetaStructSize(t *testing.T) {
	// SkCostMeta mirrors sk_cost_meta: FlowKey aligned-to-24
	// (20 fields + 4 trailing pad before next u64) + 5×u64
	// (40) = 64 bytes.
	const want = 64
	got := unsafe.Sizeof(SkCostMeta{})
	if got != want {
		t.Errorf("sizeof(SkCostMeta) = %d, want %d", got, want)
	}
}
