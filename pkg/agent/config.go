// Package agent orchestrates the tollwing-agent: it wires the eBPF loader,
// map poller, classifier, cost engine, K8s informer, exporter, and NATS
// publisher into one lifecycle (P1 — the agent is the product).
//
// This file holds Config, its defaults/validation, and the NATS identity
// resolution. It is deliberately cross-platform (no linux build tag) so the
// orchestrator's configuration contract is unit-testable everywhere the
// server/CLI build, while the eBPF data path in agent.go stays linux-only.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	ccnats "github.com/tollwing/tollwing/pkg/nats"
)

// Config holds the top-level agent configuration.
type Config struct {
	// CgroupPath is the cgroup v2 mount point. Default: /sys/fs/cgroup
	CgroupPath string

	// TrackUDP enables UDP connect tracking for DNS cost attribution.
	TrackUDP bool

	// SampleRate controls connection sampling (1 = all, N = 1/N). Default: 1.
	SampleRate uint8

	// PollInterval controls how often the map poller reads connections. Default: 5s.
	PollInterval time.Duration

	// MetricsAddr is the Prometheus /metrics listen address. Default: ":9990".
	MetricsAddr string

	// Kubeconfig path. Empty = in-cluster config. Set to "disable" to skip K8s integration.
	Kubeconfig string

	// LogLevel sets the slog level. Default (zero value): INFO.
	LogLevel slog.Level

	// LogJSON enables structured JSON logging (for production).
	LogJSON bool

	// Provider overrides cloud provider auto-detection ("aws", "gcp", "azure").
	// If empty, detected via IMDS.
	Provider string

	// Region is the cloud region for cost calculation. Default: auto-detected.
	Region string

	// NATSUrl is the NATS server URL for shipping flows to the control plane.
	// Empty disables NATS publishing.
	NATSUrl string

	// ClusterName identifies this cluster in multi-cluster deployments.
	// When NATS publishing is enabled and this is empty, the agent derives
	// it from the kube-system namespace UID (DEC-019) or fails fast.
	ClusterName string

	// NodeName identifies this node. Default: hostname.
	NodeName string
}

// setDefaults fills zero values with the documented defaults.
func (c *Config) setDefaults() {
	if c.CgroupPath == "" {
		c.CgroupPath = "/sys/fs/cgroup"
	}
	if c.SampleRate == 0 {
		c.SampleRate = 1
	}
	if c.PollInterval == 0 {
		c.PollInterval = 5 * time.Second
	}
	if c.MetricsAddr == "" {
		c.MetricsAddr = ":9990"
	}
}

// validate rejects configurations that would start an agent doomed to drop
// data silently. Called at the top of Run so a misconfiguration surfaces as
// one fatal, operator-visible startup error (a crashloop with a clear
// message) instead of a warn-per-poll data loss.
func (c *Config) validate() error {
	if c.PollInterval < 0 {
		return fmt.Errorf("poll interval must be positive, got %v", c.PollInterval)
	}
	if c.ClusterName != "" {
		if err := ccnats.ValidateSubjectToken(c.ClusterName); err != nil {
			return fmt.Errorf("cluster name: %w", err)
		}
	}
	if c.NodeName != "" {
		if err := ccnats.ValidateSubjectToken(c.NodeName); err != nil {
			return fmt.Errorf("node name: %w", err)
		}
	}
	return nil
}

// resolveClusterName returns the cluster identity embedded in the NATS
// publish subject. Order: the explicit -cluster value, else an identity
// derived via deriveUID (the kube-system namespace UID — stable and unique
// for the cluster's lifetime). Per DEC-019 it fails fast when neither is
// available: the previous behavior let an empty cluster build the subject
// "tollwing.flows..node", which NATS rejected on every publish — the agent
// then warn-and-dropped every flow batch forever.
func resolveClusterName(ctx context.Context, configured string, deriveUID func(context.Context) (string, error), log *slog.Logger) (string, error) {
	cluster := configured
	if cluster == "" {
		if deriveUID == nil {
			return "", fmt.Errorf("cluster name is required when NATS publishing is enabled: pass -cluster, or run with the Kubernetes informer enabled so it can be derived from the kube-system namespace UID")
		}
		uid, err := deriveUID(ctx)
		if err != nil {
			return "", fmt.Errorf("derive cluster name from kube-system namespace UID (pass -cluster to set it explicitly): %w", err)
		}
		cluster = uid
		log.Info("cluster name derived from kube-system namespace UID", "cluster", cluster)
	}
	if err := ccnats.ValidateSubjectToken(cluster); err != nil {
		return "", fmt.Errorf("invalid cluster name %q: %w", cluster, err)
	}
	return cluster, nil
}

// resolveNodeName returns the node identity embedded in the NATS publish
// subject: the explicit -node value, else the hostname. Validated as a
// subject token for the same fail-fast reason as resolveClusterName.
func resolveNodeName(configured string) (string, error) {
	node := configured
	if node == "" {
		host, err := os.Hostname()
		if err != nil {
			return "", fmt.Errorf("resolve node name from hostname (pass -node to set it explicitly): %w", err)
		}
		node = host
	}
	if err := ccnats.ValidateSubjectToken(node); err != nil {
		return "", fmt.Errorf("invalid node name %q: %w", node, err)
	}
	return node, nil
}
