//go:build linux

package agent

import (
	"testing"
	"time"
)

// TestNew_AppliesDefaults verifies the Config+setDefaults() idiom is actually
// wired into the constructor: a zero config must come out with the documented
// defaults, not zeros that downstream packages have to paper over.
func TestNew_AppliesDefaults(t *testing.T) {
	a := New(Config{})

	if a.cfg.CgroupPath != "/sys/fs/cgroup" {
		t.Errorf("CgroupPath = %q, want /sys/fs/cgroup", a.cfg.CgroupPath)
	}
	if a.cfg.SampleRate != 1 {
		t.Errorf("SampleRate = %d, want 1", a.cfg.SampleRate)
	}
	if a.cfg.PollInterval != 5*time.Second {
		t.Errorf("PollInterval = %v, want 5s", a.cfg.PollInterval)
	}
	if a.cfg.MetricsAddr != ":9990" {
		t.Errorf("MetricsAddr = %q, want :9990", a.cfg.MetricsAddr)
	}
}

// TestAgent_ShutdownWithoutComponents ensures shutdown is nil-safe when Run
// never started the poller/publisher/loader (e.g. an early startup error).
func TestAgent_ShutdownWithoutComponents(t *testing.T) {
	a := New(Config{})
	a.shutdown() // must not panic
}

// TestAgent_RunRejectsInvalidConfig verifies Run fails fast on config that
// would silently drop data, before any eBPF or network setup.
func TestAgent_RunRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "wildcard cluster name", cfg: Config{ClusterName: "prod.*"}},
		{name: "negative poll interval", cfg: Config{PollInterval: -time.Second}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := New(tt.cfg)
			if err := a.Run(t.Context()); err == nil {
				t.Fatal("Run() = nil error, want fail-fast config validation error")
			}
		})
	}
}
