package classifier

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// CloudProvider identifies which cloud the agent is running on.
type CloudProvider string

const (
	ProviderAWS     CloudProvider = "aws"
	ProviderGCP     CloudProvider = "gcp"
	ProviderAzure   CloudProvider = "azure"
	ProviderUnknown CloudProvider = "unknown"
)

// ZoneResolver maps IP addresses to availability zones.
// Uses a layered lookup: local cache → CIDR map → unknown.
type ZoneResolver struct {
	log *slog.Logger

	mu        sync.RWMutex
	localZone string                // this node's zone (from IMDS)
	localIPs  map[netip.Addr]bool   // this node's IPs
	ipToZone  map[netip.Addr]string // direct IP → zone cache
	cidrZones []cidrZoneEntry       // CIDR → zone mappings
	provider  CloudProvider
}

type cidrZoneEntry struct {
	prefix netip.Prefix
	zone   string
}

// ZoneResolverConfig controls resolver behavior.
type ZoneResolverConfig struct {
	// Provider overrides auto-detection. If empty, IMDS is probed.
	Provider CloudProvider
}

// NewZoneResolver creates a resolver. Call Init() to populate from IMDS.
func NewZoneResolver(log *slog.Logger) *ZoneResolver {
	return &ZoneResolver{
		log:      log,
		localIPs: make(map[netip.Addr]bool),
		ipToZone: make(map[netip.Addr]string),
	}
}

// Init detects the cloud provider, queries IMDS for the local zone,
// and sets up initial zone mappings.
func (z *ZoneResolver) Init(ctx context.Context) error {
	provider := detectProvider(ctx)
	z.mu.Lock()
	z.provider = provider
	z.mu.Unlock()

	z.log.Info("detected cloud provider", "provider", provider)

	zone, err := z.queryIMDS(ctx, provider)
	if err != nil {
		z.log.Warn("IMDS zone query failed, zone resolution will be limited", "err", err)
		return nil // non-fatal — we can still classify by IP
	}

	z.mu.Lock()
	z.localZone = zone
	z.mu.Unlock()

	z.log.Info("local availability zone", "zone", zone)
	return nil
}

// Resolve returns the availability zone for an IP address.
// Returns empty string if the zone cannot be determined.
func (z *ZoneResolver) Resolve(addr netip.Addr) string {
	z.mu.RLock()
	defer z.mu.RUnlock()

	// 1. Is this a local node IP?
	if z.localIPs[addr] {
		return z.localZone
	}

	// 2. Direct IP → zone cache (populated by K8s informer, future).
	if zone, ok := z.ipToZone[addr]; ok {
		return zone
	}

	// 3. CIDR → zone map (populated from cloud API).
	for _, entry := range z.cidrZones {
		if entry.prefix.Contains(addr) {
			return entry.zone
		}
	}

	return ""
}

// LocalZone returns this node's availability zone.
func (z *ZoneResolver) LocalZone() string {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.localZone
}

// Provider returns the detected cloud provider.
func (z *ZoneResolver) Provider() CloudProvider {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.provider
}

// AddLocalIP registers an IP as belonging to this node.
func (z *ZoneResolver) AddLocalIP(addr netip.Addr) {
	z.mu.Lock()
	z.localIPs[addr] = true
	z.mu.Unlock()
}

// SetIPZone maps a specific IP to a zone (used by K8s informer).
func (z *ZoneResolver) SetIPZone(addr netip.Addr, zone string) {
	z.mu.Lock()
	z.ipToZone[addr] = zone
	z.mu.Unlock()
}

// AddCIDRZone adds a CIDR → zone mapping (from cloud subnet API).
func (z *ZoneResolver) AddCIDRZone(prefix netip.Prefix, zone string) {
	z.mu.Lock()
	z.cidrZones = append(z.cidrZones, cidrZoneEntry{prefix: prefix, zone: zone})
	z.mu.Unlock()
}

// SetCIDRZones replaces all CIDR → zone mappings.
func (z *ZoneResolver) SetCIDRZones(entries map[netip.Prefix]string) {
	z.mu.Lock()
	z.cidrZones = make([]cidrZoneEntry, 0, len(entries))
	for prefix, zone := range entries {
		z.cidrZones = append(z.cidrZones, cidrZoneEntry{prefix: prefix, zone: zone})
	}
	z.mu.Unlock()
}

// queryIMDS fetches the availability zone from the instance metadata service.
func (z *ZoneResolver) queryIMDS(ctx context.Context, provider CloudProvider) (string, error) {
	switch provider {
	case ProviderAWS:
		return imdsGet(ctx, "http://169.254.169.254/latest/meta-data/placement/availability-zone", map[string]string{})
	case ProviderGCP:
		// GCP returns "projects/<id>/zones/<zone>" — extract the zone part.
		raw, err := imdsGet(ctx, "http://metadata.google.internal/computeMetadata/v1/instance/zone", map[string]string{
			"Metadata-Flavor": "Google",
		})
		if err != nil {
			return "", err
		}
		parts := strings.Split(raw, "/")
		return parts[len(parts)-1], nil
	case ProviderAzure:
		return imdsGet(ctx, "http://169.254.169.254/metadata/instance/compute/zone?api-version=2021-02-01&format=text", map[string]string{
			"Metadata": "true",
		})
	default:
		return "", fmt.Errorf("unknown provider: %s", provider)
	}
}

// detectProvider probes IMDS endpoints to determine the cloud provider.
func detectProvider(ctx context.Context) CloudProvider {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	type probe struct {
		provider CloudProvider
		url      string
		headers  map[string]string
	}

	probes := []probe{
		{ProviderAWS, "http://169.254.169.254/latest/meta-data/", nil},
		{ProviderGCP, "http://metadata.google.internal/", map[string]string{"Metadata-Flavor": "Google"}},
		{ProviderAzure, "http://169.254.169.254/metadata/instance?api-version=2021-02-01", map[string]string{"Metadata": "true"}},
	}

	type result struct {
		provider CloudProvider
		ok       bool
	}

	ch := make(chan result, len(probes))
	for _, p := range probes {
		go func(p probe) {
			req, err := http.NewRequestWithContext(ctx, "GET", p.url, nil)
			if err != nil {
				ch <- result{p.provider, false}
				return
			}
			for k, v := range p.headers {
				req.Header.Set(k, v)
			}
			client := &http.Client{Timeout: 1 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				ch <- result{p.provider, false}
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			ch <- result{p.provider, resp.StatusCode == 200}
		}(p)
	}

	for i := 0; i < len(probes); i++ {
		r := <-ch
		if r.ok {
			return r.provider
		}
	}

	return ProviderUnknown
}

// imdsGet performs a simple HTTP GET to an IMDS endpoint.
func imdsGet(ctx context.Context, url string, headers map[string]string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("IMDS request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("IMDS returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return "", fmt.Errorf("read IMDS response: %w", err)
	}

	return strings.TrimSpace(string(body)), nil
}
