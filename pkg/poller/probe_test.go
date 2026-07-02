//go:build linux

package poller

import (
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
)

func TestClassifyBatchProbe(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		wantSupported bool
		wantUnexpect  bool
	}{
		{"nil is supported", nil, true, false},
		{"empty map is supported", ebpf.ErrKeyNotExist, true, false},
		{"ErrNotSupported is unavailable", ebpf.ErrNotSupported, false, false},
		{"EINVAL is unavailable", syscall.EINVAL, false, false},
		{"EOPNOTSUPP is unavailable", syscall.EOPNOTSUPP, false, false},
		{"wrapped EINVAL is unavailable", fmt.Errorf("batch lookup: %w", syscall.EINVAL), false, false},
		// The whole point of the hardening: these are NOT "old kernel" and must
		// be surfaced, not silently masked as unsupported.
		{"EPERM is unexpected", syscall.EPERM, false, true},
		{"wrapped EPERM is unexpected", fmt.Errorf("batch lookup: %w", syscall.EPERM), false, true},
		{"arbitrary error is unexpected", errors.New("map type mismatch"), false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			supported, unexpected := classifyBatchProbe(tt.err)
			if supported != tt.wantSupported {
				t.Errorf("supported = %v, want %v", supported, tt.wantSupported)
			}
			if (unexpected != nil) != tt.wantUnexpect {
				t.Errorf("unexpected = %v, want non-nil=%v", unexpected, tt.wantUnexpect)
			}
		})
	}
}
