//go:build linux

package dns

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func BenchmarkTracker_LookupIP(b *testing.B) {
	tracker := &Tracker{
		cfg:           Config{MinTTL: 30 * time.Second, MaxTTL: time.Hour},
		cache:         make(map[netip.Addr]*cacheEntry),
		ring:          make([]netip.Addr, maxCacheEntries),
		serviceMapper: NewServiceMapper(),
	}

	// Populate cache with 1000 entries.
	for i := 0; i < 1000; i++ {
		a := byte(i >> 8)
		bb := byte(i & 0xff)
		addr := netip.AddrFrom4([4]byte{10, 1, a, bb})
		domain := fmt.Sprintf("svc-%d.example.com", i)
		tracker.cacheInsert(addr, domain, time.Hour)
	}

	// Benchmark lookups against a known cached address.
	target := netip.AddrFrom4([4]byte{10, 1, 0, 42})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tracker.LookupIP(target)
	}
}

func BenchmarkTracker_LookupIP_Miss(b *testing.B) {
	tracker := &Tracker{
		cfg:           Config{MinTTL: 30 * time.Second, MaxTTL: time.Hour},
		cache:         make(map[netip.Addr]*cacheEntry),
		ring:          make([]netip.Addr, maxCacheEntries),
		serviceMapper: NewServiceMapper(),
	}

	// Populate cache with 1000 entries.
	for i := 0; i < 1000; i++ {
		a := byte(i >> 8)
		bb := byte(i & 0xff)
		addr := netip.AddrFrom4([4]byte{10, 1, a, bb})
		domain := fmt.Sprintf("svc-%d.example.com", i)
		tracker.cacheInsert(addr, domain, time.Hour)
	}

	// Benchmark lookups against an address not in cache.
	miss := netip.AddrFrom4([4]byte{192, 168, 1, 1})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tracker.LookupIP(miss)
	}
}
