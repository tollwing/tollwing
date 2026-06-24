//go:build linux

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"net/netip"

	"github.com/tollwing/tollwing/pkg/classifier"
	"github.com/tollwing/tollwing/pkg/cloud"
	awscloud "github.com/tollwing/tollwing/pkg/cloud/aws"
	"github.com/tollwing/tollwing/pkg/cost"
	"github.com/tollwing/tollwing/pkg/dns"
	bpf "github.com/tollwing/tollwing/pkg/ebpf"
	"github.com/tollwing/tollwing/pkg/enricher"
	"github.com/tollwing/tollwing/pkg/exporter"
	"github.com/tollwing/tollwing/pkg/intent"
	"github.com/tollwing/tollwing/pkg/k8s"
	ccnats "github.com/tollwing/tollwing/pkg/nats"
	"github.com/tollwing/tollwing/pkg/poller"
)

// Config holds the top-level agent configuration.
type Config struct {
	// CgroupPath is the cgroup v2 mount point. Default: /sys/fs/cgroup
	CgroupPath string

	// TrackUDP enables UDP connect tracking for DNS cost attribution.
	TrackUDP bool

	// SampleRate controls connection sampling (1 = all, N = 1/N).
	SampleRate uint8

	// PollInterval controls how often the map poller reads connections. Default: 5s.
	PollInterval time.Duration

	// MetricsAddr is the Prometheus /metrics listen address. Default: ":9990".
	MetricsAddr string

	// Kubeconfig path. Empty = in-cluster config. Set to "disable" to skip K8s integration.
	Kubeconfig string

	// LogLevel sets the slog level. Default: INFO.
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
	ClusterName string

	// NodeName identifies this node. Default: hostname.
	NodeName string
}

// Agent is the top-level tollwing-agent orchestrator.
type Agent struct {
	cfg             Config
	log             *slog.Logger
	loader          *bpf.Loader
	enricher        *enricher.Enricher
	sidecarDetector *enricher.SidecarDetector
	classifier      *classifier.Classifier
	resolver        *classifier.ZoneResolver
	poller          *poller.Poller
	exporter        *exporter.Exporter
	informer        *k8s.Informer
	dnsTracker      *dns.Tracker
	costEngine      *cost.Engine
	rateStore       *cost.RateCardStore
	natsPublisher   *ccnats.Publisher
	topoRefresher   *cloud.TopologyRefresher

	// intentCache correlates post-DNAT poll snapshots back to the pre-DNAT
	// ClusterIP (service intent), populated from sock_ops establish events.
	intentCache *intent.Cache

	// Cached provider/region resolved once at startup — avoids re-resolving per flow.
	resolvedProvider string
	resolvedRegion   string

	// Pre-allocated poll buffers — reused across ticks to avoid GC pressure.
	pollClassified []exporter.ClassifiedFlow
	pollTypeCounts [classifier.NumTrafficTypes]int
}

// New creates a new Agent with the given configuration.
func New(cfg Config) *Agent {
	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.LogJSON {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	log := slog.New(handler)

	resolver := classifier.NewZoneResolver(log)

	return &Agent{
		cfg:             cfg,
		log:             log,
		enricher:        enricher.New(enricher.Config{}, log),
		sidecarDetector: enricher.NewSidecarDetector(log),
		resolver:        resolver,
		classifier:      classifier.New(resolver),
		intentCache:     intent.New(0),
	}
}

// Run starts the agent and blocks until the context is cancelled or a
// termination signal is received. Returns nil on clean shutdown.
func (a *Agent) Run(ctx context.Context) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Log kernel feature probe results.
	a.logFeatures()

	// Initialize zone resolver (IMDS probe, local zone detection).
	if err := a.resolver.Init(ctx); err != nil {
		a.log.Warn("zone resolver init failed", "err", err)
	}

	// Initialize cost engine with appropriate provider rate card.
	a.initCostEngine()

	// Start Kubernetes informer if available.
	if a.cfg.Kubeconfig != "disable" && k8s.IsAvailable() {
		inf, err := k8s.NewInformer(k8s.Config{
			Kubeconfig: a.cfg.Kubeconfig,
		}, a.log)
		if err != nil {
			a.log.Warn("k8s informer init failed, continuing without k8s metadata", "err", err)
		} else {
			inf.OnZoneUpdate = a.resolver.SetIPZone
			// Wire pod CIDR discovery into the classifier so non-RFC-1918
			// cluster CIDRs (e.g. EKS Custom Networking with 100.64/10) are
			// recognised as cluster-internal traffic. Without this, pod-to-pod
			// flows in such clusters get mis-classified as InternetEgress.
			inf.OnPodCIDR = a.classifier.AddClusterCIDR
			inf.Start(ctx)
			a.informer = inf
			a.log.Info("k8s informer started")
		}
	}

	// Start the cloud topology refresher in the BACKGROUND. It must never block
	// agent startup: when the cloud API/IMDS is unreachable (kind, on-prem, or a
	// forced -provider on a non-cloud host) the SDK client creation can hang, and
	// a synchronous call here would stall Run() before the exporter/poller start —
	// crashlooping the agent under its liveness probe. Classification works from
	// K8s node-label zones without it (P3 — degrade gracefully).
	go a.initTopologyRefresher(ctx)

	// Create and start the BPF loader.
	a.loader = bpf.NewLoader(bpf.LoaderConfig{
		CgroupPath:    a.cfg.CgroupPath,
		Enabled:       true,
		TrackUDP:      a.cfg.TrackUDP,
		SampleRate:    a.cfg.SampleRate,
		AggregationNs: 5_000_000_000,
		OnConnect:     a.handleConnect,
		OnEstablish:   a.handleEstablish,
		OnClose:       a.handleClose,
	}, a.log)

	if err := a.loader.Start(ctx); err != nil {
		return fmt.Errorf("start ebpf loader: %w", err)
	}
	defer a.loader.Close()

	// Get DNS tracker from loader (nil if kernel too old).
	a.dnsTracker = a.loader.DNSTracker()
	if a.dnsTracker != nil {
		a.log.Info("dns tracking active", "cache_size", a.dnsTracker.CacheSize())
	}

	// Start the map poller.
	maps := a.loader.Maps()
	flowAggMap := maps["flow_aggregates"]
	if flowAggMap != nil {
		a.poller = poller.New(poller.Config{
			Interval: a.cfg.PollInterval,
		}, flowAggMap, a.handlePoll, a.log)

		// Wire QUIC flows map if available.
		if quicMap := maps["quic_flows"]; quicMap != nil {
			a.poller.SetQuicMap(quicMap)
			a.log.Info("QUIC flow polling enabled")
		}

		a.poller.Start(ctx)
		defer a.poller.Stop()
	}

	// Start Prometheus exporter.
	a.exporter = exporter.New(exporter.Config{
		ListenAddr: a.cfg.MetricsAddr,
	}, a.log)
	a.exporter.SetHealthStats(func() exporter.HealthStats {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		h := exporter.HealthStats{
			EnricherCacheSize: a.enricher.Len(),
			GoroutineCount:    runtime.NumGoroutine(),
			HeapAllocBytes:    ms.HeapAlloc,
			HeapSysBytes:      ms.HeapSys,
		}
		if a.dnsTracker != nil {
			h.DNSCacheSize = a.dnsTracker.CacheSize()
		}
		return h
	})
	if err := a.exporter.Start(ctx); err != nil {
		return fmt.Errorf("start exporter: %w", err)
	}

	// Start NATS publisher if configured.
	if a.cfg.NATSUrl != "" {
		nodeName := a.cfg.NodeName
		if nodeName == "" {
			nodeName, _ = os.Hostname()
		}
		pub, err := ccnats.NewPublisher(ccnats.PublisherConfig{
			URL:     a.cfg.NATSUrl,
			Cluster: a.cfg.ClusterName,
			Node:    nodeName,
		}, a.log)
		if err != nil {
			a.log.Warn("nats publisher init failed, flows will not be shipped", "err", err)
		} else {
			a.natsPublisher = pub
			defer a.natsPublisher.Close()
			a.log.Info("nats publisher started", "url", a.cfg.NATSUrl, "cluster", a.cfg.ClusterName)
		}
	}

	a.log.Info("tollwing-agent running, press Ctrl+C to stop")
	<-ctx.Done()
	a.log.Info("shutting down")

	return nil
}

// initCostEngine sets up the cost calculation engine with the appropriate
// cloud provider rate card. Provider is auto-detected via IMDS or overridden
// via config.
func (a *Agent) initCostEngine() {
	a.rateStore = cost.NewRateCardStore()

	// Determine provider: config override → IMDS auto-detect.
	provider := string(a.resolver.Provider())
	if a.cfg.Provider != "" {
		provider = a.cfg.Provider
	}

	// Determine region: config override → zone resolver.
	region := a.cfg.Region
	if region == "" {
		zone := a.resolver.LocalZone()
		if zone != "" {
			// Extract region from zone (e.g., "us-east-1a" → "us-east-1").
			region = regionFromZone(zone)
		}
		if region == "" {
			region = "us-east-1" // sensible default
		}
	}

	// Load default rate card for the provider.
	switch provider {
	case "gcp":
		a.rateStore.Set(cost.DefaultGCPRateCard(region))
	case "azure":
		a.rateStore.Set(cost.DefaultAzureRateCard(region))
	default:
		provider = "aws"
		a.rateStore.Set(cost.DefaultAWSRateCard(region))
	}

	a.costEngine = cost.NewEngine(a.rateStore)
	a.log.Info("cost engine initialized", "provider", provider, "region", region)

	// Cache resolved provider/region for use in calculateFlowCost.
	a.resolvedProvider = provider
	a.resolvedRegion = region
}

// initTopologyRefresher starts the cloud topology refresher that periodically
// syncs subnet→zone mappings, NAT gateway IPs, VPC peering CIDRs, and service
// CIDRs from the cloud provider API into the classifier and zone resolver.
func (a *Agent) initTopologyRefresher(ctx context.Context) {
	provider := string(a.resolver.Provider())
	if a.cfg.Provider != "" {
		provider = a.cfg.Provider
	}

	region := a.cfg.Region
	if region == "" {
		zone := a.resolver.LocalZone()
		if zone != "" {
			region = regionFromZone(zone)
		}
		if region == "" {
			region = "us-east-1"
		}
	}

	var cloudProvider cloud.Provider
	switch provider {
	case "aws":
		awsProvider := awscloud.New(awscloud.Config{
			Region: region,
			Zone:   a.resolver.LocalZone(),
		}, a.log)
		// Wire the real EC2 SDK client for live subnet/NAT/peering/TGW discovery.
		// Bound it with a deadline: NewSDKClient loads AWS config / probes IMDS,
		// which hangs when the cloud API is unreachable — fail fast and degrade.
		sdkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		ec2Client, err := awscloud.NewSDKClient(sdkCtx, region, a.log)
		cancel()
		if err != nil {
			a.log.Warn("failed to create EC2 SDK client, topology refresh will be limited", "err", err)
		} else {
			awsProvider.SetEC2Client(ec2Client)
		}
		cloudProvider = awsProvider
	default:
		// Non-AWS providers (gcp, azure) are supplied by the Enterprise build
		// (-tags enterprise) via newCloudProvider. The open-source build is
		// AWS-only and does not ship the gcp/azure provider packages (Path-1
		// open-core split), so this resolves to "unavailable" there.
		p, ok := newCloudProvider(provider, region, a.resolver.LocalZone(), a.log)
		if !ok {
			a.log.Info("topology refresher not available for provider", "provider", provider)
			return
		}
		cloudProvider = p
	}

	a.topoRefresher = cloud.NewTopologyRefresher(cloudProvider, a.classifier, a.resolver, a.log)
	a.topoRefresher.Start(ctx)
	a.log.Info("cloud topology refresher started", "provider", provider, "interval", "5m")

	// Start live pricing refresher (fetches real rates every 6 hours).
	refresher := cost.NewRateCardRefresher(a.rateStore, cloudProvider, region, a.log)
	refresher.Start(ctx)
	a.log.Info("rate card refresher started", "interval", "6h")
}

// regionFromZone extracts the region from a zone string.
// AWS: "us-east-1a" → "us-east-1"; GCP: "us-central1-a" → "us-central1".
func regionFromZone(zone string) string {
	if zone == "" {
		return ""
	}
	last := zone[len(zone)-1]
	if last >= 'a' && last <= 'z' {
		candidate := zone[:len(zone)-1]
		if len(candidate) > 0 && candidate[len(candidate)-1] != '-' {
			return candidate
		}
		return candidate[:len(candidate)-1]
	}
	for i := len(zone) - 1; i >= 0; i-- {
		if zone[i] == '-' {
			return zone[:i]
		}
	}
	return zone
}

// calculateFlowCost computes the estimated USD cost for a single flow.
// Uses cached provider/region resolved once at startup.
func (a *Agent) calculateFlowCost(trafficType int, txBytes, rxBytes uint64) float64 {
	if a.costEngine == nil {
		return 0
	}

	record := cost.FlowRecord{
		TrafficType: classifier.TrafficType(trafficType),
		TxBytes:     txBytes,
		RxBytes:     rxBytes,
	}
	results := a.costEngine.Calculate(a.resolvedProvider, a.resolvedRegion, []cost.FlowRecord{record})
	if len(results) > 0 {
		return results[0].CostUSD
	}
	return 0
}

// handleConnect enriches and logs pre-DNAT destination capture.
func (a *Agent) handleConnect(evt bpf.ConnectEvent) {
	info := a.enricher.EnrichComm(evt.PID, evt.Comm)

	attrs := []any{
		"pid", evt.PID,
		"comm", info.Comm,
		"original_dst", evt.DstAddr().String(),
		"proto", protoName(evt.Protocol),
		"cookie", evt.Cookie,
	}

	if info.ContainerID != "" {
		attrs = append(attrs, "container", shortID(info.ContainerID))
	}

	a.log.Debug("connect (pre-DNAT)", attrs...)
}

// handleEstablish logs the completed two-phase capture with classification.
func (a *Agent) handleEstablish(evt bpf.EstablishEvent) {
	info := a.enricher.EnrichComm(evt.PID, evt.Comm)

	// Classify the flow.
	result := a.classifier.Classify(classifier.FlowInfo{
		SrcIP:           evt.SrcIP,
		DstIP:           evt.DstIP,
		OriginalDstIP:   evt.OriginalDstIP,
		SrcPort:         evt.SrcPort,
		DstPort:         evt.DstPort,
		OriginalDstPort: evt.OriginalDstPort,
	})

	// Record the pre-DNAT (ClusterIP) destination so the poll path — which
	// only sees the post-DNAT 5-tuple — can recover the dialed service. Keyed
	// by the same fields as the flow_aggregates key so the establish event and
	// the poll snapshot for one connection join. Removed again on close.
	if evt.WasDNATed() {
		a.intentCache.Put(intent.Key{
			SrcIP: evt.SrcIP, DstIP: evt.DstIP,
			SrcPort: evt.SrcPort, DstPort: evt.DstPort,
			PID: evt.PID, Protocol: evt.Protocol, Direction: evt.Direction,
		}, intent.Dst{IP: evt.OriginalDstIP, Port: evt.OriginalDstPort})
	}

	dir := "outgoing"
	if !evt.IsOutgoing() {
		dir = "incoming"
	}

	attrs := []any{
		"dir", dir,
		"pid", evt.PID,
		"comm", info.Comm,
		"src", evt.SrcAddr().String(),
		"dst", evt.ActualDstAddr().String(),
		"traffic", result.Type.String(),
		"cookie", evt.Cookie,
	}

	if result.SrcZone != "" {
		attrs = append(attrs, "src_zone", result.SrcZone)
	}
	if result.DstZone != "" {
		attrs = append(attrs, "dst_zone", result.DstZone)
	}
	if a.dnsTracker != nil {
		dstIP := ipFromUint32(evt.DstIP)
		di := a.dnsTracker.Lookup(dstIP)
		if di.Domain != "" {
			attrs = append(attrs, "domain", di.Domain)
		}
		if di.Service != "" {
			attrs = append(attrs, "cloud_service", di.Service)
		}
	}
	if evt.WasDNATed() {
		attrs = append(attrs, "original_dst", evt.OriginalDstAddr().String())
	}
	if info.ContainerID != "" {
		attrs = append(attrs, "container", shortID(info.ContainerID))
		if a.informer != nil {
			if pod := a.informer.LookupContainerID(info.ContainerID); pod != nil {
				attrs = append(attrs, "pod", pod.Namespace+"/"+pod.Name)
			}
		}
	}

	a.log.Info("established", attrs...)

	if a.exporter != nil {
		a.exporter.RecordEstablish()
	}
}

// handleClose logs connection teardown with final byte counters and classification.
func (a *Agent) handleClose(evt bpf.CloseEvent) {
	result := a.classifier.Classify(classifier.FlowInfo{
		SrcIP:           evt.SrcIP,
		DstIP:           evt.DstIP,
		OriginalDstIP:   evt.OriginalDstIP,
		SrcPort:         evt.SrcPort,
		DstPort:         evt.DstPort,
		OriginalDstPort: evt.OriginalDstPort,
	})

	attrs := []any{
		"dst", evt.ActualDstAddr().String(),
		"traffic", result.Type.String(),
		"pid", evt.PID,
		"cookie", evt.Cookie,
		"tx_bytes", evt.TxBytes,
		"rx_bytes", evt.RxBytes,
		"duration_ms", evt.DurationNs / 1_000_000,
	}

	if a.dnsTracker != nil {
		dstIP := ipFromUint32(evt.DstIP)
		di := a.dnsTracker.Lookup(dstIP)
		if di.Domain != "" {
			attrs = append(attrs, "domain", di.Domain)
		}
		if di.Service != "" {
			attrs = append(attrs, "cloud_service", di.Service)
		}
	}
	if evt.OriginalDstIP != 0 {
		attrs = append(attrs, "original_dst", evt.OriginalDstAddr().String())
	}

	a.log.Info("closed", attrs...)

	if a.exporter != nil {
		a.exporter.RecordClose()
	}
	a.enricher.Evict(evt.PID)
	a.intentCache.Delete(intent.Key{
		SrcIP: evt.SrcIP, DstIP: evt.DstIP,
		SrcPort: evt.SrcPort, DstPort: evt.DstPort,
		PID: evt.PID, Protocol: evt.Protocol, Direction: evt.Direction,
	})
}

// handlePoll processes a batch of active flow snapshots from the map poller.
// Classifies each flow once and shares the result with both logging and the exporter.
// Reuses pre-allocated buffers to avoid per-tick GC pressure.
func (a *Agent) handlePoll(flows []poller.FlowSnapshot) {
	// Reset reusable buffers.
	a.pollClassified = a.pollClassified[:0]
	for i := range a.pollTypeCounts {
		a.pollTypeCounts[i] = 0
	}

	var totalTx, totalRx uint64
	debugEnabled := a.log.Enabled(context.Background(), slog.LevelDebug)

	for _, f := range flows {
		// Sidecar dedup: detect loopback/sidecar-internal connections.
		isSidecar := enricher.IsLoopback(f.SrcIP, f.DstIP) ||
			enricher.IsSidecarPort(f.SrcPort) ||
			enricher.IsSidecarPort(f.DstPort) ||
			a.sidecarDetector.IsSidecarProcess(f.PID)

		result := a.classifier.Classify(classifier.FlowInfo{
			SrcIP:   f.SrcIP,
			DstIP:   f.DstIP,
			SrcPort: f.SrcPort,
			DstPort: f.DstPort,
		})

		idx := int(result.Type)
		if idx >= 0 && idx < len(a.pollTypeCounts) && !isSidecar {
			a.pollTypeCounts[idx]++
		}
		totalTx += f.TxBytes
		totalRx += f.RxBytes

		// Resolve pod metadata for per-pod metrics.
		var ns, podName string
		var srcMeta *k8s.PodMeta
		info := a.enricher.Lookup(f.PID)
		if info != nil && info.ContainerID != "" && a.informer != nil {
			if pod := a.informer.LookupContainerID(info.ContainerID); pod != nil {
				ns = pod.Namespace
				podName = pod.Name
				srcMeta = pod
			}
		}

		// Calculate cost for non-sidecar flows.
		var flowCost float64
		if !isSidecar {
			flowCost = a.calculateFlowCost(idx, f.TxBytes, f.RxBytes)
		}

		// DNS cascade attribution: if the destination IP was resolved
		// from a recent DNS query, tag the flow with the domain so the
		// control plane can roll cost up by domain. Lookup is cheap
		// (LRU cache hit) and skipped entirely when the tracker isn't
		// configured.
		var resolvedDomain, cloudService string
		if a.dnsTracker != nil {
			dstAddr := ipFromUint32(f.DstIP)
			if dstAddr.IsValid() {
				resolvedDomain = a.dnsTracker.LookupIP(dstAddr)
				cloudService = a.dnsTracker.LookupService(dstAddr)
			}
		}

		// Service-dependency graph enrichment: resolve the source service,
		// both zones, and the destination's service identity. The destination
		// prefers the pre-DNAT ClusterIP intent (recovered from the
		// establish-event correlation in intentCache) over the post-DNAT
		// backend pod. All lookups are O(1) map hits and nil-safe; any field
		// may stay empty when K8s metadata is unavailable.
		srcZone, dstZone := result.SrcZone, result.DstZone
		var srcService, dstNamespace, dstPod, dstService string
		if a.informer != nil && !isSidecar {
			if srcMeta != nil && srcMeta.PodIP != "" {
				if svcs := a.informer.LookupService(srcMeta.PodIP); len(svcs) > 0 {
					srcService = svcs[0].ServiceName
				}
			}
			if d, ok := a.intentCache.Get(intent.Key{
				SrcIP: f.SrcIP, DstIP: f.DstIP,
				SrcPort: f.SrcPort, DstPort: f.DstPort,
				PID: f.PID, Protocol: f.Protocol, Direction: f.Direction,
			}); ok && d.IP != 0 {
				// Per DEC-010: recover the dialed service IDENTITY from the
				// pre-DNAT ClusterIP, but deliberately NOT a backend zone to
				// re-derive result.Type. The dialer side only sees the zoneless
				// ClusterIP; the backend-node agent already classifies this
				// interaction cross_az and its (Tx+Rx) covers both directions,
				// so reclassifying the dialer leg here would double-count (P4).
				// Canonical dialer-attributed, deduped cross-AZ across the two
				// endpoint views is cross-node work — a control-plane job (P1).
				if ref, ok := a.informer.LookupClusterIP(ipFromUint32(d.IP).String()); ok {
					dstNamespace, dstService = ref.Namespace, ref.Name
				}
			}
			if dstMeta := a.informer.LookupPodIP(ipFromUint32(f.DstIP).String()); dstMeta != nil {
				dstPod = dstMeta.Name
				if dstNamespace == "" {
					dstNamespace = dstMeta.Namespace
				}
				if dstService == "" {
					if svcs := a.informer.LookupService(dstMeta.PodIP); len(svcs) > 0 {
						dstService = svcs[0].ServiceName
						if dstNamespace == "" {
							dstNamespace = svcs[0].ServiceNamespace
						}
					}
				}
				if dstZone == "" && dstMeta.NodeName != "" {
					dstZone = a.informer.NodeZone(dstMeta.NodeName)
				}
			}
		}

		a.pollClassified = append(a.pollClassified, exporter.ClassifiedFlow{
			TrafficType:     idx,
			TxBytes:         f.TxBytes,
			RxBytes:         f.RxBytes,
			RetransmitBytes: f.RetransmitBytes,
			RetransmitCount: f.RetransmitCount,
			CostUSD:         flowCost,
			Namespace:       ns,
			Pod:             podName,
			IsSidecar:       isSidecar,
			SrcZone:         srcZone,
			SrcService:      srcService,
			DstNamespace:    dstNamespace,
			DstPod:          dstPod,
			DstService:      dstService,
			DstZone:         dstZone,
			ResolvedDomain:  resolvedDomain,
			CloudService:    cloudService,
		})

		// Debug logging.
		if debugEnabled {
			comm := ""
			container := ""
			if info != nil {
				comm = info.Comm
				if info.ContainerID != "" {
					container = shortID(info.ContainerID)
				}
			}

			attrs := []any{
				"pid", f.PID,
				"comm", comm,
				"dst", bpf.FormatIPPort(f.DstIP, f.DstPort),
				"traffic", result.Type.String(),
				"tx", f.TxBytes,
				"rx", f.RxBytes,
				"conns", f.ConnCount,
			}
			if isSidecar {
				attrs = append(attrs, "sidecar", true)
			}
			if a.dnsTracker != nil {
				dstIP := ipFromUint32(f.DstIP)
				di := a.dnsTracker.Lookup(dstIP)
				if di.Domain != "" {
					attrs = append(attrs, "domain", di.Domain)
				}
				if di.Service != "" {
					attrs = append(attrs, "cloud_service", di.Service)
				}
			}
			if ns != "" {
				attrs = append(attrs, "pod", ns+"/"+podName)
			} else if container != "" {
				attrs = append(attrs, "container", container)
			}
			a.log.Debug("flow", attrs...)
		}
	}

	// Update exporter with pre-classified data (single classification pass).
	if a.exporter != nil {
		a.exporter.UpdateFromPoll(a.pollClassified)
		a.exporter.RecordPoll()
	}

	// Ship flow data to NATS for the control plane.
	if a.natsPublisher != nil && len(a.pollClassified) > 0 {
		costResults := make([]cost.CostResult, 0, len(a.pollClassified))
		for _, cf := range a.pollClassified {
			if cf.IsSidecar {
				continue
			}
			costResults = append(costResults, cost.CostResult{
				FlowRecord: cost.FlowRecord{
					TrafficType:    classifier.TrafficType(cf.TrafficType),
					TxBytes:        cf.TxBytes,
					RxBytes:        cf.RxBytes,
					SrcNamespace:   cf.Namespace,
					SrcPod:         cf.Pod,
					SrcZone:        cf.SrcZone,
					SrcService:     cf.SrcService,
					DstNamespace:   cf.DstNamespace,
					DstPod:         cf.DstPod,
					DstService:     cf.DstService,
					DstZone:        cf.DstZone,
					ResolvedDomain: cf.ResolvedDomain,
					CloudService:   cf.CloudService,
				},
				CostUSD: cf.CostUSD,
			})
		}
		if len(costResults) > 0 {
			if err := a.natsPublisher.Publish(costResults); err != nil {
				a.log.Warn("nats publish failed", "err", err, "flows", len(costResults))
			}
		}
	}

	// Summary log.
	attrs := []any{
		"active_connections", len(flows),
		"total_tx", totalTx,
		"total_rx", totalRx,
		"cache_size", a.enricher.Len(),
	}
	for i, count := range a.pollTypeCounts {
		if count > 0 {
			attrs = append(attrs, classifier.TrafficType(i).String(), count)
		}
	}
	a.log.Info("poll", attrs...)
}

// logFeatures logs the kernel eBPF feature probe results at startup.
func (a *Agent) logFeatures() {
	required, optional := bpf.ProbeAll()

	for _, r := range required {
		lvl := slog.LevelInfo
		status := "supported"
		if !r.Supported {
			lvl = slog.LevelError
			status = "missing"
		}
		a.log.Log(context.Background(), lvl, "feature probe",
			"feature", r.Name,
			"status", status,
		)
	}
	for _, r := range optional {
		status := "supported"
		if !r.Supported {
			status = "unavailable"
		}
		a.log.Info("feature probe (optional)",
			"feature", r.Name,
			"status", status,
		)
	}
}

func protoName(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("proto(%d)", proto)
	}
}

func shortID(id string) string {
	if len(id) >= 12 {
		return id[:12]
	}
	return id
}

// ipFromUint32 converts a uint32 IPv4 field from a BPF map/event into a
// netip.Addr. Delegates to the single canonical BPF-field decoder so the
// agent's DNS/pod-IP/ClusterIP lookups share the exact byte-order contract used
// by classification and logging (network-order bytes, native-endian decoded —
// DEC-009). The previous hand-rolled little-endian decode happened to be
// correct on little-endian hosts but drifted from pkg/classifier's big-endian
// decode; reconciling the two is what DEC-009 fixes.
func ipFromUint32(ip uint32) netip.Addr {
	return bpf.AddrFromU32(ip)
}
