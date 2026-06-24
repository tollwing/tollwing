//go:build linux

package enricher

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// SidecarDetector identifies sidecar proxy processes and correlates
// external sidecar connections with the true application cgroup.
type SidecarDetector struct {
	log *slog.Logger
	mu  sync.RWMutex
	// pidToComm caches PID → process name lookups.
	pidToComm map[uint32]string
	// sidecarPIDs tracks known sidecar proxy PIDs.
	sidecarPIDs map[uint32]bool
}

// NewSidecarDetector creates a sidecar detector.
func NewSidecarDetector(log *slog.Logger) *SidecarDetector {
	return &SidecarDetector{
		log:         log,
		pidToComm:   make(map[uint32]string),
		sidecarPIDs: make(map[uint32]bool),
	}
}

// IsSidecarProcess checks if a PID belongs to a known sidecar proxy.
// Uses /proc/<pid>/comm for process name detection.
func (sd *SidecarDetector) IsSidecarProcess(pid uint32) bool {
	sd.mu.RLock()
	if known, ok := sd.sidecarPIDs[pid]; ok {
		sd.mu.RUnlock()
		return known
	}
	sd.mu.RUnlock()

	comm := readProcComm(pid)
	isSidecar := KnownSidecarProxies[comm]

	sd.mu.Lock()
	sd.pidToComm[pid] = comm
	sd.sidecarPIDs[pid] = isSidecar
	sd.mu.Unlock()

	return isSidecar
}

// ProcessName returns the cached process name for a PID.
func (sd *SidecarDetector) ProcessName(pid uint32) string {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return sd.pidToComm[pid]
}

// InvalidatePID removes a cached PID entry (e.g., when process exits).
func (sd *SidecarDetector) InvalidatePID(pid uint32) {
	sd.mu.Lock()
	delete(sd.pidToComm, pid)
	delete(sd.sidecarPIDs, pid)
	sd.mu.Unlock()
}

// ShouldAttributeToApp determines if cost for a sidecar connection should
// be attributed to the application (true) or the sidecar (false).
// For external connections originating from a sidecar cgroup, cost should
// go to the application that initiated the original loopback connection.
func (sd *SidecarDetector) ShouldAttributeToApp(pid uint32, srcIP, dstIP uint32) bool {
	if IsLoopback(srcIP, dstIP) {
		return false // internal traffic, skip entirely
	}
	return sd.IsSidecarProcess(pid)
}

func readProcComm(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
