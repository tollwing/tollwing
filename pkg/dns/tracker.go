//go:build linux

// Package dns consumes DNS events from the eBPF ring buffer and maintains
// an IP-to-domain LRU cache with TTL-based expiry.
package dns

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	maxCacheEntries = 65536
	dnsRawMax       = 512
)

// dnsRawEvent mirrors struct dns_raw_event from dns.bpf.c.
type dnsRawEvent struct {
	Len uint16
	Pad uint16
	// Data follows — variable length, read from RawSample.
}

const dnsRawEventHeaderSize = 4 // len(2) + pad(2)

// cacheEntry is an IP-to-domain mapping with TTL.
type cacheEntry struct {
	domain    string
	service   string // mapped cloud service name
	expiresAt time.Time
}

// Config controls the DNS tracker.
type Config struct {
	// MinTTL is the minimum cache TTL. DNS records with shorter TTLs
	// are cached for at least this long. Default: 30s.
	MinTTL time.Duration

	// MaxTTL caps the maximum cache TTL. Default: 1h.
	MaxTTL time.Duration
}

func (c *Config) setDefaults() {
	if c.MinTTL == 0 {
		c.MinTTL = 30 * time.Second
	}
	if c.MaxTTL == 0 {
		c.MaxTTL = time.Hour
	}
}

// Tracker consumes DNS events from the BPF ring buffer and provides
// IP-to-domain lookups.
type Tracker struct {
	cfg    Config
	log    *slog.Logger
	reader *ringbuf.Reader
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu    sync.RWMutex
	cache map[netip.Addr]*cacheEntry
	// Ring buffer for LRU eviction — fixed-size, wraps around.
	// Avoids the unbounded slice growth of append + reslice.
	ring    []netip.Addr
	ringPos int // next write position

	serviceMapper *ServiceMapper

	// Per-domain query counters. Bounded to maxQueryCounters entries
	// via lowest-count eviction. Counts reset on Reset() so callers
	// can compute rates without unbounded accumulation.
	queryCounts     map[string]uint64
	queryCountStart time.Time
}

// maxQueryCounters caps the number of distinct domains tracked.
// Bounded so a long-lived agent in a chatty cluster can't grow the
// counter map unbounded.
const maxQueryCounters = 4096

// New creates a DNS tracker. dnsEventsMap is the "dns_events" BPF ring buffer.
// Returns nil if the map is nil (graceful degradation).
func New(cfg Config, dnsEventsMap *ebpf.Map, log *slog.Logger) *Tracker {
	if dnsEventsMap == nil {
		return nil
	}
	cfg.setDefaults()
	return &Tracker{
		cfg:             cfg,
		log:             log,
		cache:           make(map[netip.Addr]*cacheEntry, 4096),
		ring:            make([]netip.Addr, maxCacheEntries),
		ringPos:         0,
		serviceMapper:   NewServiceMapper(),
		queryCounts:     make(map[string]uint64, 1024),
		queryCountStart: time.Now(),
	}
}

// Start begins consuming DNS events. Non-blocking.
func (t *Tracker) Start(ctx context.Context, dnsEventsMap *ebpf.Map) error {
	rd, err := ringbuf.NewReader(dnsEventsMap)
	if err != nil {
		return err
	}
	t.reader = rd

	ctx, t.cancel = context.WithCancel(ctx)
	t.wg.Add(1)
	go t.readLoop(ctx)

	t.log.Info("dns tracker started")
	return nil
}

// Stop cancels the read loop and waits for it to exit.
func (t *Tracker) Stop() {
	if t.cancel != nil {
		t.cancel()
	}
	if t.reader != nil {
		t.reader.Close()
	}
	t.wg.Wait()
}

// DNSInfo holds domain and cloud service info from a single lookup.
type DNSInfo struct {
	Domain  string // queried domain name
	Service string // mapped cloud service name, or domain if unmapped
}

// Lookup returns domain + service for an IP in a single lock acquisition.
// Returns zero DNSInfo if unknown or expired.
func (t *Tracker) Lookup(ip netip.Addr) DNSInfo {
	t.mu.RLock()
	entry, ok := t.cache[ip]
	t.mu.RUnlock()

	if !ok || time.Now().After(entry.expiresAt) {
		return DNSInfo{}
	}
	svc := entry.service
	if svc == "" {
		svc = entry.domain
	}
	return DNSInfo{Domain: entry.domain, Service: svc}
}

// LookupIP returns the domain name for an IP, or empty string if unknown.
func (t *Tracker) LookupIP(ip netip.Addr) string {
	return t.Lookup(ip).Domain
}

// LookupService returns the cloud service name for an IP (e.g. "S3", "Azure Blob").
// Falls back to domain name if no service mapping exists.
func (t *Tracker) LookupService(ip netip.Addr) string {
	return t.Lookup(ip).Service
}

// CacheSize returns the current number of entries.
func (t *Tracker) CacheSize() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.cache)
}

func (t *Tracker) readLoop(ctx context.Context) {
	defer t.wg.Done()

	for {
		record, err := t.reader.Read()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			t.log.Error("dns ringbuf read error", "err", err)
			return
		}

		raw := record.RawSample
		if len(raw) < dnsRawEventHeaderSize+12 { // header + min DNS packet
			continue
		}

		pktLen := int(binary.NativeEndian.Uint16(raw[:2]))
		pktData := raw[dnsRawEventHeaderSize:]
		if pktLen > len(pktData) {
			pktLen = len(pktData)
		}
		pktData = pktData[:pktLen]

		t.parseDNSResponse(pktData)
	}
}

func (t *Tracker) parseDNSResponse(pkt []byte) {
	var parser dnsmessage.Parser
	header, err := parser.Start(pkt)
	if err != nil {
		return
	}

	// Only process responses with no errors.
	if !header.Response || header.RCode != dnsmessage.RCodeSuccess {
		return
	}

	// Read the question to get the queried name.
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) == 0 {
		return
	}
	qname := questions[0].Name.String()
	// Remove trailing dot.
	if len(qname) > 0 && qname[len(qname)-1] == '.' {
		qname = qname[:len(qname)-1]
	}

	// Parse all answers for A and AAAA records.
	for {
		ah, err := parser.AnswerHeader()
		if err != nil {
			break
		}

		ttl := time.Duration(ah.TTL) * time.Second

		switch ah.Type {
		case dnsmessage.TypeA:
			r, err := parser.AResource()
			if err != nil {
				return
			}
			addr := netip.AddrFrom4(r.A)
			t.cacheInsert(addr, qname, ttl)

		case dnsmessage.TypeAAAA:
			r, err := parser.AAAAResource()
			if err != nil {
				return
			}
			addr := netip.AddrFrom16(r.AAAA)
			t.cacheInsert(addr, qname, ttl)

		default:
			if err := parser.SkipAnswer(); err != nil {
				return
			}
		}
	}
}

func (t *Tracker) cacheInsert(addr netip.Addr, domain string, ttl time.Duration) {
	if !addr.IsValid() || domain == "" {
		return
	}

	if ttl < t.cfg.MinTTL {
		ttl = t.cfg.MinTTL
	}
	if ttl > t.cfg.MaxTTL {
		ttl = t.cfg.MaxTTL
	}

	service := t.serviceMapper.Lookup(domain)

	t.mu.Lock()
	t.cache[addr] = &cacheEntry{
		domain:    domain,
		service:   service,
		expiresAt: time.Now().Add(ttl),
	}

	// Ring buffer eviction: the ring length IS the cache
	// capacity. When the cache exceeds it, overwrite the
	// oldest slot and delete its corresponding cache entry.
	// (Previously this checked maxCacheEntries — the package
	// constant — which decoupled eviction from the actual
	// ring size and prevented eviction whenever the ring was
	// smaller than the constant.)
	if len(t.cache) > len(t.ring) {
		oldest := t.ring[t.ringPos]
		if oldest.IsValid() {
			delete(t.cache, oldest)
		}
	}
	t.ring[t.ringPos] = addr
	t.ringPos = (t.ringPos + 1) % len(t.ring)

	// Bump the per-domain query counter under the same lock —
	// avoids a second acquisition on the hot path.
	t.queryCounts[domain]++
	if len(t.queryCounts) > maxQueryCounters {
		t.evictLowestCountLocked()
	}
	t.mu.Unlock()
}

// evictLowestCountLocked drops the domain with the fewest observations.
// Called only when the counter map exceeds maxQueryCounters. Must be
// called with t.mu held.
//
// O(N) but only runs on overflow, and N is capped — at 4096 entries
// this is microseconds per eviction.
func (t *Tracker) evictLowestCountLocked() {
	var (
		victimKey   string
		victimCount uint64 = ^uint64(0)
	)
	for k, v := range t.queryCounts {
		if v < victimCount {
			victimKey = k
			victimCount = v
		}
	}
	if victimKey != "" {
		delete(t.queryCounts, victimKey)
	}
}

// QueryCounts returns a snapshot of the per-domain query counters and
// the duration over which they were accumulated. Resetting a snapshot
// is a separate call — callers that want a "rate" should snapshot,
// then call ResetQueryCounts at the start of the next interval.
func (t *Tracker) QueryCounts() (counts []QueryCount, since time.Duration) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]QueryCount, 0, len(t.queryCounts))
	for d, c := range t.queryCounts {
		svc := t.serviceMapper.Lookup(d)
		out = append(out, QueryCount{Domain: d, Service: svc, Count: c})
	}
	return out, time.Since(t.queryCountStart)
}

// ResetQueryCounts clears the per-domain counters and restarts the
// observation window. Safe to call concurrently with cacheInsert.
func (t *Tracker) ResetQueryCounts() {
	t.mu.Lock()
	for k := range t.queryCounts {
		delete(t.queryCounts, k)
	}
	t.queryCountStart = time.Now()
	t.mu.Unlock()
}
