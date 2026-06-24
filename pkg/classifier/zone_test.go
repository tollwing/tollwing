package classifier

import (
	"log/slog"
	"net/netip"
	"testing"
)

func TestZoneResolver_LocalIP(t *testing.T) {
	r := NewZoneResolver(slog.Default())
	r.localZone = "us-east-1a"

	addr := netip.MustParseAddr("10.0.1.5")
	r.AddLocalIP(addr)

	zone := r.Resolve(addr)
	if zone != "us-east-1a" {
		t.Fatalf("expected us-east-1a, got %q", zone)
	}
}

func TestZoneResolver_DirectCache(t *testing.T) {
	r := NewZoneResolver(slog.Default())

	addr := netip.MustParseAddr("10.0.2.100")
	r.SetIPZone(addr, "eu-west-1b")

	zone := r.Resolve(addr)
	if zone != "eu-west-1b" {
		t.Fatalf("expected eu-west-1b, got %q", zone)
	}
}

func TestZoneResolver_CIDRLookup(t *testing.T) {
	r := NewZoneResolver(slog.Default())

	r.AddCIDRZone(netip.MustParsePrefix("10.0.0.0/16"), "us-east-1a")
	r.AddCIDRZone(netip.MustParsePrefix("10.1.0.0/16"), "us-east-1b")

	tests := []struct {
		ip   string
		zone string
	}{
		{"10.0.5.10", "us-east-1a"},
		{"10.1.5.10", "us-east-1b"},
		{"10.2.5.10", ""},
	}

	for _, tt := range tests {
		got := r.Resolve(netip.MustParseAddr(tt.ip))
		if got != tt.zone {
			t.Errorf("Resolve(%s) = %q, want %q", tt.ip, got, tt.zone)
		}
	}
}

func TestZoneResolver_SetCIDRZones(t *testing.T) {
	r := NewZoneResolver(slog.Default())

	r.AddCIDRZone(netip.MustParsePrefix("10.0.0.0/16"), "old-zone")

	// Replace all.
	r.SetCIDRZones(map[netip.Prefix]string{
		netip.MustParsePrefix("172.16.0.0/16"): "new-zone",
	})

	// Old should not resolve.
	if got := r.Resolve(netip.MustParseAddr("10.0.1.1")); got != "" {
		t.Errorf("old CIDR should not resolve, got %q", got)
	}

	// New should resolve.
	if got := r.Resolve(netip.MustParseAddr("172.16.1.1")); got != "new-zone" {
		t.Errorf("new CIDR should resolve to new-zone, got %q", got)
	}
}

func TestZoneResolver_LookupPriority(t *testing.T) {
	r := NewZoneResolver(slog.Default())
	r.localZone = "local-zone"

	addr := netip.MustParseAddr("10.0.1.5")

	// All three layers know this IP.
	r.AddLocalIP(addr)
	r.SetIPZone(addr, "cache-zone")
	r.AddCIDRZone(netip.MustParsePrefix("10.0.0.0/16"), "cidr-zone")

	// Local IP should take priority.
	zone := r.Resolve(addr)
	if zone != "local-zone" {
		t.Fatalf("expected local-zone (highest priority), got %q", zone)
	}
}

func TestZoneResolver_UnknownIP(t *testing.T) {
	r := NewZoneResolver(slog.Default())

	zone := r.Resolve(netip.MustParseAddr("192.168.1.1"))
	if zone != "" {
		t.Fatalf("expected empty string for unknown IP, got %q", zone)
	}
}

func TestZoneResolver_LocalZone(t *testing.T) {
	r := NewZoneResolver(slog.Default())
	if r.LocalZone() != "" {
		t.Fatal("expected empty local zone before init")
	}

	r.mu.Lock()
	r.localZone = "us-west-2a"
	r.mu.Unlock()

	if r.LocalZone() != "us-west-2a" {
		t.Fatal("expected us-west-2a")
	}
}
