//go:build linux

package ebpf

import (
	"testing"
	"unsafe"
)

func TestCgroupCostStructSize(t *testing.T) {
	// CgroupCost must match struct cgroup_cost in maps.h:
	// tx_bytes(8) + rx_bytes(8) + retransmit_bytes(8) + conn_count(8) = 32
	got := unsafe.Sizeof(CgroupCost{})
	if got != 32 {
		t.Errorf("sizeof(CgroupCost) = %d, want 32", got)
	}
}

func TestCgroupCostSnapshotFields(t *testing.T) {
	snap := CgroupCostSnapshot{
		CgroupID: 12345,
		Cost: CgroupCost{
			TxBytes:         1000,
			RxBytes:         2000,
			RetransmitBytes: 100,
			ConnCount:       5,
		},
	}

	if snap.CgroupID != 12345 {
		t.Errorf("CgroupID = %d, want 12345", snap.CgroupID)
	}
	if snap.Cost.TxBytes != 1000 {
		t.Errorf("TxBytes = %d, want 1000", snap.Cost.TxBytes)
	}
}

func TestFormatCgroupCost(t *testing.T) {
	c := CgroupCost{TxBytes: 100, RxBytes: 200, RetransmitBytes: 10, ConnCount: 3}
	got := FormatCgroupCost(c)
	want := "tx=100 rx=200 retx=10 conns=3"
	if got != want {
		t.Errorf("FormatCgroupCost() = %q, want %q", got, want)
	}
}
