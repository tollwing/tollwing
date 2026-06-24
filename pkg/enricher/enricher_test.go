//go:build linux

package enricher

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExtractContainerID_Docker(t *testing.T) {
	cid := "abc123def4567890abc123def4567890abc123def4567890abc123def4567890" // 64 hex chars
	tests := []struct {
		path string
		want string
	}{
		{"/docker/" + cid, cid},
		{"/system.slice/docker-" + cid + ".scope", cid},
	}

	for _, tt := range tests {
		got := extractContainerID(tt.path)
		if got != tt.want {
			t.Errorf("extractContainerID(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestExtractContainerID_Kubernetes(t *testing.T) {
	cid := "aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd"
	path := "/kubepods/burstable/pod12345/" + cid

	got := extractContainerID(path)
	if got != cid {
		t.Errorf("extractContainerID(k8s path) = %q, want %q", got, cid)
	}
}

func TestExtractContainerID_Containerd(t *testing.T) {
	cid := "aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd"
	path := "/system.slice/containerd.service/kubepods-burstable-pod123.slice/cri-containerd-" + cid + ".scope"

	got := extractContainerID(path)
	if got != cid {
		t.Errorf("extractContainerID(containerd path) = %q, want %q", got, cid)
	}
}

func TestExtractContainerID_HostProcess(t *testing.T) {
	tests := []string{
		"/user.slice/user-1000.slice/session-1.scope",
		"/init.scope",
		"/system.slice/sshd.service",
	}

	for _, path := range tests {
		if got := extractContainerID(path); got != "" {
			t.Errorf("extractContainerID(%q) = %q, want empty", path, got)
		}
	}
}

func TestIsHex(t *testing.T) {
	if !isHex("0123456789abcdef") {
		t.Error("expected hex")
	}
	if !isHex("ABCDEF") {
		t.Error("expected uppercase hex")
	}
	if isHex("xyz") {
		t.Error("xyz is not hex")
	}
	if isHex("") {
		t.Error("empty is not hex")
	}
}

func TestEnricher_LookupSelf(t *testing.T) {
	e := New(Config{}, slog.Default())

	pid := uint32(os.Getpid())
	info := e.Lookup(pid)
	if info == nil {
		t.Fatal("expected to find own process")
	}

	if info.PID != pid {
		t.Errorf("PID = %d, want %d", info.PID, pid)
	}
	if info.Comm == "" {
		t.Error("expected non-empty Comm")
	}
}

func TestEnricher_CacheTTL(t *testing.T) {
	e := New(Config{CacheTTL: 50 * time.Millisecond}, slog.Default())

	pid := uint32(os.Getpid())
	info1 := e.Lookup(pid)
	info2 := e.Lookup(pid)

	// Should be same pointer (cached).
	if info1 != info2 {
		t.Error("expected cached result")
	}

	time.Sleep(60 * time.Millisecond)

	// Should re-resolve after TTL.
	info3 := e.Lookup(pid)
	if info3 == nil {
		t.Fatal("expected non-nil after TTL")
	}
	if info1 == info3 {
		t.Error("expected fresh result after TTL expiry")
	}
}

func TestEnricher_Evict(t *testing.T) {
	e := New(Config{}, slog.Default())

	pid := uint32(os.Getpid())
	e.Lookup(pid)
	if e.Len() != 1 {
		t.Fatalf("cache size = %d, want 1", e.Len())
	}

	e.Evict(pid)
	if e.Len() != 0 {
		t.Fatalf("cache size = %d after evict, want 0", e.Len())
	}
}

func TestEnricher_EnrichComm_Fallback(t *testing.T) {
	e := New(Config{}, slog.Default())

	// Use a non-existent PID.
	var comm [16]byte
	copy(comm[:], "test-proc")

	info := e.EnrichComm(999999999, comm)
	if info == nil {
		t.Fatal("expected non-nil from EnrichComm fallback")
	}
	if info.Comm != "test-proc" {
		t.Errorf("Comm = %q, want test-proc", info.Comm)
	}
}

func TestEnricher_CustomProcRoot(t *testing.T) {
	// Create a fake /proc/<pid> directory.
	tmpDir := t.TempDir()
	pidDir := filepath.Join(tmpDir, "12345")
	os.MkdirAll(pidDir, 0755)

	os.WriteFile(filepath.Join(pidDir, "comm"), []byte("fake-comm\n"), 0644)
	os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte("fake-cmd\x00--flag\x00"), 0644)
	os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte("0::/system.slice/docker-aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd.scope\n"), 0644)

	e := New(Config{ProcRoot: tmpDir}, slog.Default())
	info := e.Lookup(12345)
	if info == nil {
		t.Fatal("expected to find fake process")
	}

	if info.Comm != "fake-comm" {
		t.Errorf("Comm = %q, want fake-comm", info.Comm)
	}
	if info.Cmdline != "fake-cmd --flag" {
		t.Errorf("Cmdline = %q, want 'fake-cmd --flag'", info.Cmdline)
	}
	if info.ContainerID != "aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd" {
		t.Errorf("ContainerID = %q, want 64-char hex", info.ContainerID)
	}
	if !info.IsContainer() {
		t.Error("expected IsContainer() = true")
	}
}
