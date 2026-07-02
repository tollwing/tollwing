//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/tollwing/tollwing/pkg/agent"
)

func main() {
	var (
		cgroupPath   = flag.String("cgroup", "/sys/fs/cgroup", "cgroup v2 mount path")
		trackUDP     = flag.Bool("udp", false, "track UDP via connected sockets (DNS + per-pod QUIC attribution); makes the socket path the sole UDP TX source — unconnected-UDP egress is then uncounted (see pkg/ebpf/bpf/quic.bpf.c)")
		sampleRate   = flag.Uint("sample-rate", 1, "connection sampling rate (1=all, N=1/N)")
		pollInterval = flag.Duration("poll-interval", 5*time.Second, "map poll interval")
		metricsAddr  = flag.String("metrics", ":9990", "Prometheus /metrics listen address")
		kubeconfig   = flag.String("kubeconfig", "", "path to kubeconfig (empty=in-cluster, 'disable'=skip k8s)")
		debugFlag    = flag.Bool("debug", false, "enable debug logging")
		jsonLog      = flag.Bool("json", false, "output structured JSON logs")
		memLimit     = flag.Int64("mem-limit", 128, "soft memory limit in MB (GOMEMLIMIT)")
		gogc         = flag.Int("gogc", 50, "GC target percentage (GOGC, lower = less memory, more CPU)")
		provider     = flag.String("provider", "", "cloud provider override (aws, gcp, azure; auto-detected if empty)")
		region       = flag.String("region", "", "cloud region override (auto-detected if empty)")
		natsURL      = flag.String("nats", "", "NATS URL for shipping flows to control plane (empty=disabled)")
		clusterName  = flag.String("cluster", "", "cluster name for multi-cluster identification")
		nodeName     = flag.String("node", "", "node name override (default: hostname)")
	)
	flag.Parse()

	// Set GOMEMLIMIT for predictable memory usage under pressure.
	// Only set if not already overridden via environment variable.
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(*memLimit * 1024 * 1024)
	}
	// Set GOGC for reduced heap overhead. Default Go is 100; 50 trades
	// ~5% CPU for ~30% less memory on steady-state workloads.
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(*gogc)
	}

	level := slog.LevelInfo
	if *debugFlag {
		level = slog.LevelDebug
	}

	a := agent.New(agent.Config{
		CgroupPath:   *cgroupPath,
		TrackUDP:     *trackUDP,
		SampleRate:   uint8(*sampleRate),
		PollInterval: *pollInterval,
		MetricsAddr:  *metricsAddr,
		Kubeconfig:   *kubeconfig,
		LogLevel:     level,
		LogJSON:      *jsonLog,
		Provider:     *provider,
		Region:       *region,
		NATSUrl:      *natsURL,
		ClusterName:  *clusterName,
		NodeName:     *nodeName,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := a.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
