//go:build linux

package dns

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func newTestTracker() *Tracker {
	return &Tracker{
		cfg:             Config{MinTTL: 30 * time.Second, MaxTTL: time.Hour},
		cache:           make(map[netip.Addr]*cacheEntry),
		ring:            make([]netip.Addr, maxCacheEntries),
		ringPos:         0,
		serviceMapper:   NewServiceMapper(),
		queryCounts:     make(map[string]uint64),
		queryCountStart: time.Now(),
	}
}

func TestParseDNSResponse_ARecord(t *testing.T) {
	// Zero-value Builder is invalid — must construct via
	// NewBuilder so internal state machine is initialized.
	buf := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	if err := buf.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := buf.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("example.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	if err := buf.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if err := buf.AResource(dnsmessage.ResourceHeader{
		Name:  dnsmessage.MustNewName("example.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
		TTL:   300,
	}, dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}}); err != nil {
		t.Fatal(err)
	}

	pkt, err := buf.Finish()
	if err != nil {
		t.Fatal(err)
	}

	tracker := newTestTracker()
	tracker.parseDNSResponse(pkt)

	addr := netip.AddrFrom4([4]byte{93, 184, 216, 34})
	domain := tracker.LookupIP(addr)
	if domain != "example.com" {
		t.Errorf("LookupIP() = %q, want example.com", domain)
	}
}

func TestParseDNSResponse_AAAARecord(t *testing.T) {
	buf := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	if err := buf.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := buf.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("ipv6.example.com."),
		Type:  dnsmessage.TypeAAAA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	if err := buf.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if err := buf.AAAAResource(dnsmessage.ResourceHeader{
		Name:  dnsmessage.MustNewName("ipv6.example.com."),
		Type:  dnsmessage.TypeAAAA,
		Class: dnsmessage.ClassINET,
		TTL:   600,
	}, dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}

	pkt, err := buf.Finish()
	if err != nil {
		t.Fatal(err)
	}

	tracker := newTestTracker()
	tracker.parseDNSResponse(pkt)

	addr := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	domain := tracker.LookupIP(addr)
	if domain != "ipv6.example.com" {
		t.Errorf("LookupIP() = %q, want ipv6.example.com", domain)
	}
}

func TestTracker_Lookup_Unified(t *testing.T) {
	tracker := newTestTracker()

	addr := netip.AddrFrom4([4]byte{52, 94, 1, 100})
	tracker.cacheInsert(addr, "dynamodb.us-east-1.amazonaws.com", 300*time.Second)

	di := tracker.Lookup(addr)
	if di.Domain != "dynamodb.us-east-1.amazonaws.com" {
		t.Errorf("Domain = %q, want dynamodb...", di.Domain)
	}
	if di.Service != "DynamoDB" {
		t.Errorf("Service = %q, want DynamoDB", di.Service)
	}
}

func TestTracker_Lookup_Expired(t *testing.T) {
	tracker := newTestTracker()
	tracker.cfg.MinTTL = 10 * time.Millisecond

	addr := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	tracker.cacheInsert(addr, "example.com", 10*time.Millisecond)

	time.Sleep(20 * time.Millisecond)
	di := tracker.Lookup(addr)
	if di.Domain != "" {
		t.Errorf("expected empty domain after expiry, got %q", di.Domain)
	}
}

func TestTracker_RingEviction(t *testing.T) {
	// Use a small cache to test eviction.
	tracker := &Tracker{
		cfg:             Config{MinTTL: time.Hour, MaxTTL: time.Hour},
		cache:           make(map[netip.Addr]*cacheEntry),
		ring:            make([]netip.Addr, 10), // very small ring
		ringPos:         0,
		serviceMapper:   NewServiceMapper(),
		queryCounts:     make(map[string]uint64),
		queryCountStart: time.Now(),
	}

	// Insert 15 entries into a cache that evicts at > 10.
	for i := 0; i < 15; i++ {
		addr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})
		tracker.cacheInsert(addr, "test.com", time.Hour)
	}

	// Cache should not exceed maxCacheEntries (10 in ring).
	// Some early entries should have been evicted.
	if tracker.CacheSize() > 11 {
		t.Errorf("cache size %d, expected <= 11 (ring size + 1 before eviction)", tracker.CacheSize())
	}

	// Latest entries should be present.
	latest := netip.AddrFrom4([4]byte{10, 0, 0, 14})
	if tracker.LookupIP(latest) != "test.com" {
		t.Error("latest entry should still be cached")
	}
}

func TestTracker_CacheSize(t *testing.T) {
	tracker := newTestTracker()
	if tracker.CacheSize() != 0 {
		t.Errorf("expected 0, got %d", tracker.CacheSize())
	}

	tracker.cacheInsert(netip.AddrFrom4([4]byte{1, 2, 3, 4}), "a.com", time.Hour)
	tracker.cacheInsert(netip.AddrFrom4([4]byte{5, 6, 7, 8}), "b.com", time.Hour)

	if tracker.CacheSize() != 2 {
		t.Errorf("expected 2, got %d", tracker.CacheSize())
	}
}

func TestTracker_QueryCounts(t *testing.T) {
	tracker := newTestTracker()
	for i := 0; i < 5; i++ {
		tracker.cacheInsert(netip.AddrFrom4([4]byte{1, 2, 3, byte(i)}), "a.example.com", time.Hour)
	}
	for i := 0; i < 3; i++ {
		tracker.cacheInsert(netip.AddrFrom4([4]byte{4, 5, 6, byte(i)}), "b.example.com", time.Hour)
	}
	counts, window := tracker.QueryCounts()
	if window <= 0 {
		t.Errorf("expected positive window, got %v", window)
	}
	got := map[string]uint64{}
	for _, c := range counts {
		got[c.Domain] = c.Count
	}
	if got["a.example.com"] != 5 {
		t.Errorf("a count = %d, want 5", got["a.example.com"])
	}
	if got["b.example.com"] != 3 {
		t.Errorf("b count = %d, want 3", got["b.example.com"])
	}
}

func TestTracker_ResetQueryCounts(t *testing.T) {
	tracker := newTestTracker()
	tracker.cacheInsert(netip.AddrFrom4([4]byte{1, 2, 3, 4}), "a.com", time.Hour)
	if c, _ := tracker.QueryCounts(); len(c) != 1 {
		t.Fatalf("pre-reset = %d, want 1", len(c))
	}
	tracker.ResetQueryCounts()
	if c, _ := tracker.QueryCounts(); len(c) != 0 {
		t.Errorf("post-reset = %d, want 0", len(c))
	}
}

func TestTracker_CounterEvictionBound(t *testing.T) {
	tracker := newTestTracker()
	// Insert maxQueryCounters + 200 distinct domains; map should stay
	// at or under the cap due to lowest-count eviction.
	total := maxQueryCounters + 200
	for i := 0; i < total; i++ {
		domain := "d-" +
			string(rune('a'+i%26)) +
			string(rune('a'+(i/26)%26)) +
			string(rune('a'+(i/676)%26)) +
			"-" + string(rune('0'+i%10))
		tracker.cacheInsert(
			netip.AddrFrom4([4]byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)}),
			domain,
			time.Hour,
		)
	}
	counts, _ := tracker.QueryCounts()
	if len(counts) > maxQueryCounters {
		t.Errorf("counter map (%d) exceeded cap (%d)", len(counts), maxQueryCounters)
	}
	if len(counts) == 0 {
		t.Error("counter map drained completely — eviction too aggressive")
	}
}
