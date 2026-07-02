package agent

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestConfig_SetDefaults(t *testing.T) {
	tests := []struct {
		name string
		in   Config
		want Config
	}{
		{
			name: "zero config gets documented defaults",
			in:   Config{},
			want: Config{
				CgroupPath:   "/sys/fs/cgroup",
				SampleRate:   1,
				PollInterval: 5 * time.Second,
				MetricsAddr:  ":9990",
			},
		},
		{
			name: "explicit values are preserved",
			in: Config{
				CgroupPath:   "/custom/cgroup",
				SampleRate:   4,
				PollInterval: 30 * time.Second,
				MetricsAddr:  ":9999",
				ClusterName:  "prod",
			},
			want: Config{
				CgroupPath:   "/custom/cgroup",
				SampleRate:   4,
				PollInterval: 30 * time.Second,
				MetricsAddr:  ":9999",
				ClusterName:  "prod",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.in
			got.setDefaults()
			if got.CgroupPath != tt.want.CgroupPath {
				t.Errorf("CgroupPath = %q, want %q", got.CgroupPath, tt.want.CgroupPath)
			}
			if got.SampleRate != tt.want.SampleRate {
				t.Errorf("SampleRate = %d, want %d", got.SampleRate, tt.want.SampleRate)
			}
			if got.PollInterval != tt.want.PollInterval {
				t.Errorf("PollInterval = %v, want %v", got.PollInterval, tt.want.PollInterval)
			}
			if got.MetricsAddr != tt.want.MetricsAddr {
				t.Errorf("MetricsAddr = %q, want %q", got.MetricsAddr, tt.want.MetricsAddr)
			}
			if got.ClusterName != tt.want.ClusterName {
				t.Errorf("ClusterName = %q, want %q", got.ClusterName, tt.want.ClusterName)
			}
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string // substring; "" means valid
	}{
		{name: "zero config is valid (cluster resolved later)", cfg: Config{}},
		{name: "valid cluster and node", cfg: Config{ClusterName: "prod-eu", NodeName: "node-1"}},
		{name: "dotted node name allowed", cfg: Config{NodeName: "ip-10-0-1-5.ec2.internal"}},
		{name: "negative poll interval", cfg: Config{PollInterval: -time.Second}, wantErr: "poll interval"},
		{name: "cluster with wildcard", cfg: Config{ClusterName: "prod*"}, wantErr: "cluster name"},
		{name: "cluster with space", cfg: Config{ClusterName: "prod eu"}, wantErr: "cluster name"},
		{name: "node with empty dot part", cfg: Config{NodeName: "node."}, wantErr: "node name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validate() = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("validate() = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestResolveClusterName is the regression test for the silent-drop finding:
// a default -cluster "" must never reach the publisher — it either derives a
// real identity (kube-system UID, DEC-019) or fails fast at startup.
func TestResolveClusterName(t *testing.T) {
	uidOK := func(context.Context) (string, error) {
		return "3f8a2c1e-9b7d-4e2a-8c1f-0d5e6a7b8c9d", nil
	}
	uidErr := func(context.Context) (string, error) {
		return "", fmt.Errorf("kube-system lookup failed")
	}
	uidInvalid := func(context.Context) (string, error) {
		return "bad token", nil
	}

	tests := []struct {
		name       string
		configured string
		deriveUID  func(context.Context) (string, error)
		want       string
		wantErr    string // substring; "" means success
	}{
		{name: "explicit cluster wins", configured: "prod-eu", deriveUID: uidOK, want: "prod-eu"},
		{name: "empty cluster derives kube-system UID", configured: "", deriveUID: uidOK, want: "3f8a2c1e-9b7d-4e2a-8c1f-0d5e6a7b8c9d"},
		{name: "empty cluster and no informer fails fast", configured: "", deriveUID: nil, wantErr: "-cluster"},
		{name: "derivation failure fails fast", configured: "", deriveUID: uidErr, wantErr: "kube-system"},
		{name: "derived identity is validated too", configured: "", deriveUID: uidInvalid, wantErr: "invalid cluster name"},
		{name: "explicit invalid cluster fails", configured: "prod..eu", deriveUID: uidOK, wantErr: "invalid cluster name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveClusterName(context.Background(), tt.configured, tt.deriveUID, discardLogger())
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("resolveClusterName() error = %v, want nil", err)
				}
				if got != tt.want {
					t.Errorf("resolveClusterName() = %q, want %q", got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("resolveClusterName() = %q with nil error, want error containing %q", got, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestResolveNodeName(t *testing.T) {
	t.Run("explicit node name wins", func(t *testing.T) {
		got, err := resolveNodeName("node-1")
		if err != nil {
			t.Fatalf("resolveNodeName() error = %v", err)
		}
		if got != "node-1" {
			t.Errorf("resolveNodeName() = %q, want node-1", got)
		}
	})

	t.Run("empty falls back to hostname", func(t *testing.T) {
		host, herr := os.Hostname()
		if herr != nil || host == "" {
			t.Skipf("hostname unavailable in this environment: %v", herr)
		}
		got, err := resolveNodeName("")
		if err != nil {
			t.Fatalf("resolveNodeName(\"\") error = %v", err)
		}
		if got != host {
			t.Errorf("resolveNodeName(\"\") = %q, want hostname %q", got, host)
		}
	})

	t.Run("invalid explicit node name fails", func(t *testing.T) {
		if _, err := resolveNodeName("node 1"); err == nil {
			t.Fatal("resolveNodeName(\"node 1\") = nil error, want failure")
		}
	})
}
