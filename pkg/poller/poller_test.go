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
