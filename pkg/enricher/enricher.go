//go:build linux

// Package enricher resolves PID → container → pod metadata.
//
// Pipeline: PID → /proc/<pid>/cgroup → container ID
//
//	      /proc/<pid>/cmdline → full command
//	container ID → pod name, namespace, labels (via K8s informer, future)
//
// All lookups are cached with TTL to avoid hammering /proc on every event.
package enricher

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// ProcessInfo holds enriched metadata for a process.
type ProcessInfo struct {
	PID         uint32
	Comm        string // short process name (from /proc/pid/comm or BPF)
	Cmdline     string // full command line
	ContainerID string // container ID extracted from cgroup path, empty if host
	CgroupPath  string // raw cgroup path

	cachedAt time.Time
}

// IsContainer returns true if this process runs inside a container.
func (p *ProcessInfo) IsContainer() bool {
	return p.ContainerID != ""
}

// Config controls the enricher behavior.
type Config struct {
	// CacheTTL controls how long process metadata is cached. Default: 30s.
	CacheTTL time.Duration

	// MaxCacheSize caps the enricher cache to prevent unbounded growth.
	// When exceeded, expired entries are evicted. Default: 16384.
	MaxCacheSize int

	// ProcRoot is the proc filesystem mount point. Default: /proc.
	ProcRoot string
}

func (c *Config) setDefaults() {
	if c.CacheTTL == 0 {
		c.CacheTTL = 30 * time.Second
	}
	if c.MaxCacheSize == 0 {
		c.MaxCacheSize = 16384
	}
	if c.ProcRoot == "" {
		c.ProcRoot = "/proc"
	}
}

// Enricher resolves PID metadata with caching.
type Enricher struct {
	cfg   Config
	log   *slog.Logger
	mu    sync.RWMutex
	cache map[uint32]*ProcessInfo
}

// New creates a new Enricher.
func New(cfg Config, log *slog.Logger) *Enricher {
	cfg.setDefaults()
	return &Enricher{
		cfg:   cfg,
		log:   log,
		cache: make(map[uint32]*ProcessInfo),
	}
}

// Lookup returns enriched metadata for a PID. Results are cached.
// Returns nil if the process no longer exists.
func (e *Enricher) Lookup(pid uint32) *ProcessInfo {
	// Fast path: check cache.
	e.mu.RLock()
	info, ok := e.cache[pid]
	e.mu.RUnlock()

	if ok && time.Since(info.cachedAt) < e.cfg.CacheTTL {
		return info
	}

	// Slow path: read from /proc.
	info = e.resolve(pid)
	if info == nil {
		return nil
	}

	e.mu.Lock()
	e.cache[pid] = info
	// Evict expired entries if cache exceeds max size.
	if len(e.cache) > e.cfg.MaxCacheSize {
		now := time.Now()
		for k, v := range e.cache {
			if now.Sub(v.cachedAt) > e.cfg.CacheTTL {
				delete(e.cache, k)
			}
		}
	}
	e.mu.Unlock()

	return info
}

// Evict removes a PID from the cache (e.g., on connection close).
func (e *Enricher) Evict(pid uint32) {
	e.mu.Lock()
	delete(e.cache, pid)
	e.mu.Unlock()
}

// Len returns the current cache size.
func (e *Enricher) Len() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.cache)
}

func (e *Enricher) resolve(pid uint32) *ProcessInfo {
	info := &ProcessInfo{
		PID:      pid,
		cachedAt: time.Now(),
	}

	base := fmt.Sprintf("%s/%d", e.cfg.ProcRoot, pid)

	// Read comm.
	if data, err := os.ReadFile(base + "/comm"); err == nil {
		info.Comm = strings.TrimSpace(string(data))
	} else {
		// Process gone.
		return nil
	}

	// Read cmdline (null-separated args).
	if data, err := os.ReadFile(base + "/cmdline"); err == nil {
		info.Cmdline = strings.Join(
			strings.Split(strings.TrimRight(string(data), "\x00"), "\x00"),
			" ",
		)
	}

	// Read cgroup to extract container ID.
	info.CgroupPath, info.ContainerID = e.readCgroup(base + "/cgroup")

	return info
}

// readCgroup parses /proc/<pid>/cgroup and extracts the container ID.
// Returns the raw cgroup path and the container ID (empty if not containerized).
//
// Supported formats:
//   - Docker:     /docker/<id>
//   - Kubernetes: /kubepods/burstable/pod<uid>/<id>
//   - containerd: /system.slice/containerd.service/kubepods-...-<id>.scope
//   - cgroup v2:  0::/system.slice/docker-<id>.scope
func (e *Enricher) readCgroup(path string) (cgroupPath, containerID string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// cgroup v2: "0::/path" — prefer this if present.
		// cgroup v1: "N:name:/path"
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		p := parts[2]
		if p == "/" || p == "" {
			continue
		}

		cgroupPath = p

		if id := extractContainerID(p); id != "" {
			containerID = id
			return
		}
	}

	return cgroupPath, ""
}

// extractContainerID tries to extract a 64-char hex container ID from a cgroup path.
func extractContainerID(cgroupPath string) string {
	// Try common patterns:
	// /docker/<id>
	// /kubepods/.../pod<uid>/<id>
	// /system.slice/docker-<id>.scope
	// /system.slice/containerd-<id>.scope
	// /kubepods.slice/...<id>.scope

	// Split on "/" and check each segment.
	segments := strings.Split(cgroupPath, "/")
	for i := len(segments) - 1; i >= 0; i-- {
		seg := segments[i]
		if id := parseIDFromSegment(seg); id != "" {
			return id
		}
	}

	return ""
}

// parseIDFromSegment extracts a 64-char hex ID from a cgroup path segment.
func parseIDFromSegment(seg string) string {
	// Strip known prefixes/suffixes.
	seg = strings.TrimSuffix(seg, ".scope")
	seg = strings.TrimPrefix(seg, "docker-")
	seg = strings.TrimPrefix(seg, "cri-containerd-")
	seg = strings.TrimPrefix(seg, "crio-")
	seg = strings.TrimPrefix(seg, "containerd-")

	// Container IDs are 64-char hex strings (SHA256).
	if len(seg) == 64 && isHex(seg) {
		return seg
	}

	// Some runtimes use shorter IDs (12 chars).
	if len(seg) == 12 && isHex(seg) {
		return seg
	}

	return ""
}

func isHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range []byte(s) {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// EnrichComm updates the process name from BPF-captured comm if we don't
// have it from /proc (process may have exited). This is a best-effort
// fallback using the 16-byte comm from the BPF event.
func (e *Enricher) EnrichComm(pid uint32, bpfComm [16]byte) *ProcessInfo {
	info := e.Lookup(pid)
	if info != nil {
		return info
	}

	// Process is gone — create a minimal entry from BPF data.
	comm := string(bytes.TrimRight(bpfComm[:], "\x00"))
	info = &ProcessInfo{
		PID:      pid,
		Comm:     comm,
		cachedAt: time.Now(),
	}

	e.mu.Lock()
	e.cache[pid] = info
	e.mu.Unlock()

	return info
}
