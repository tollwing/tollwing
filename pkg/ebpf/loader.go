//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"unsafe"

	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/tollwing/tollwing/pkg/dns"
)

// MapSizeConfig controls BPF map sizes for memory footprint tuning.
// All values are in number of entries (or bytes for ring buffers).
// Zero means use the compiled-in default (see setDefaults).
type MapSizeConfig struct {
	Connections    uint32 // connections LRU_HASH (default: 65536)
	FlowAggregates uint32 // flow_aggregates PERCPU_HASH (default: 16384)
	NatMappings    uint32 // nat_mappings LRU_HASH (default: 16384)
	QuicFlows      uint32 // quic_flows PERCPU_HASH (default: 8192)
	EventsRingBuf  uint32 // events ring buffer in bytes (default: 1MB)
	DNSRingBuf     uint32 // dns_events ring buffer in bytes (default: 256KB)
}

func (c *MapSizeConfig) setDefaults() {
	if c.Connections == 0 {
		c.Connections = 65536 // 64K — sufficient for most nodes
	}
	if c.FlowAggregates == 0 {
		c.FlowAggregates = 16384 // 16K unique flows per CPU
	}
	if c.NatMappings == 0 {
		c.NatMappings = 16384
	}
	if c.QuicFlows == 0 {
		c.QuicFlows = 8192
	}
	if c.EventsRingBuf == 0 {
		c.EventsRingBuf = 1 << 20 // 1MB
	}
	if c.DNSRingBuf == 0 {
		c.DNSRingBuf = 1 << 18 // 256KB
	}
}

// LoaderConfig controls the BPF loader behavior.
type LoaderConfig struct {
	// CgroupPath is the cgroup v2 mount point for program attachment.
	// Default: /sys/fs/cgroup
	CgroupPath string

	// Enabled activates traffic capture on load. Can be toggled at runtime.
	Enabled bool

	// TrackUDP enables UDP connect tracking (for DNS cost attribution).
	TrackUDP bool

	// SampleRate controls connection sampling. 1 = every connection,
	// N = 1/N sampling for high-throughput nodes.
	SampleRate uint8

	// AggregationInterval is the flow flush interval in nanoseconds.
	// Default: 5_000_000_000 (5s).
	AggregationNs uint64

	// InterfaceName is the network interface for QUIC TC attachment.
	// Default: auto-detect default route interface.
	InterfaceName string

	// MapSizes controls BPF map sizes. Zero values use compiled defaults.
	MapSizes MapSizeConfig

	// Event handlers — called from a dedicated goroutine, must not block.
	OnConnect   func(ConnectEvent)
	OnEstablish func(EstablishEvent)
	OnClose     func(CloseEvent)
}

func (c *LoaderConfig) setDefaults() {
	if c.CgroupPath == "" {
		c.CgroupPath = "/sys/fs/cgroup"
	}
	if c.SampleRate == 0 {
		c.SampleRate = 1
	}
	if c.AggregationNs == 0 {
		c.AggregationNs = 5_000_000_000
	}
}

// Loader manages the lifecycle of all tollwing BPF programs.
// Load → Attach → run event loop → Close.
type Loader struct {
	cfg        LoaderConfig
	log        *slog.Logger
	collection *ebpf.Collection
	links      []link.Link
	reader     *ringbuf.Reader
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	dnsTracker *dns.Tracker
}

// NewLoader creates a Loader with the given config. Call Start to load and
// attach programs.
func NewLoader(cfg LoaderConfig, log *slog.Logger) *Loader {
	cfg.setDefaults()
	return &Loader{
		cfg: cfg,
		log: log,
	}
}

// Start loads BPF programs, attaches them, pushes config, and starts the
// ring buffer reader goroutine.
func (l *Loader) Start(ctx context.Context) error {
	// Probe kernel features before attempting to load.
	if err := CheckRequired(); err != nil {
		return err
	}

	l.log.Info("loading BPF programs")

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfProgram))
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}

	// Apply map size defaults and overrides for memory footprint tuning.
	l.cfg.MapSizes.setDefaults()
	l.applyMapSizeOverrides(spec)

	// Remove optional programs from the spec that are known to be unsupported
	// on this kernel. This prevents verifier failures from blocking the
	// entire collection load.
	l.pruneOptionalPrograms(spec)

	// Try loading the collection. If it still fails due to a verifier error
	// on an optional program, iteratively remove the failing program and retry.
	coll, err := l.loadCollectionWithFallback(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}
	l.collection = coll

	// Free kernel BTF cache — it's large and no longer needed after load.
	btf.FlushKernelSpec()
	runtime.GC()

	// ---- Attach cgroup/connect4 + connect6 ----
	if err := l.attachCgroupProg(coll, "tollwing_connect4", ebpf.AttachCGroupInet4Connect); err != nil {
		l.Close()
		return err
	}
	if err := l.attachCgroupProg(coll, "tollwing_connect6", ebpf.AttachCGroupInet6Connect); err != nil {
		l.log.Warn("cgroup/connect6 unavailable, IPv6 pre-DNAT tracking disabled", "err", err)
	}

	// ---- Attach sock_ops ----
	if err := l.attachCgroupProg(coll, "tollwing_sockops", ebpf.AttachCGroupSockOps); err != nil {
		l.Close()
		return err
	}

	// ---- Attach byte counting hooks ----
	// Prefer fentry (reliable bpf_get_socket_cookie with struct sock *).
	// Fall back to kprobe if fentry is unavailable.
	if err := l.attachByteCountingHooks(coll); err != nil {
		l.Close()
		return err
	}

	// ---- Attach conntrack NAT resolution (tiered degradation) ----
	// Tier 1: netfilter prog with CT kfuncs (kernel 6.4+)
	// Tier 2: fentry/nf_conntrack_confirm (kernel 5.11+)
	// Tier 3: two-phase only (cgroup/connect4 + sock_ops)
	if HaveNetfilterProg() {
		if err := l.attachNetfilter(coll, "tollwing_conntrack_kfunc"); err != nil {
			l.log.Warn("netfilter/conntrack_kfunc unavailable, trying fentry", "err", err)
			l.attachFentryConntrack(coll)
		} else {
			l.log.Info("netfilter/conntrack kfunc attached (tier 1 NAT resolution)")
		}
	} else if HaveFentry() {
		l.attachFentryConntrack(coll)
	} else {
		l.log.Info("conntrack hooks unavailable, using two-phase correlation only")
	}

	// ---- Attach optional fentry retransmit hooks (kernel 5.11+) ----
	if HaveFentry() {
		if err := l.attachFentry(coll, "tollwing_tcp_retransmit", "tcp_retransmit_skb"); err != nil {
			l.log.Warn("fentry/tcp_retransmit_skb unavailable", "err", err)
		} else {
			l.log.Info("fentry/tcp_retransmit_skb attached (retransmit tracking)")
		}
		if err := l.attachFentry(coll, "tollwing_tcp_loss_probe", "tcp_send_loss_probe"); err != nil {
			l.log.Warn("fentry/tcp_send_loss_probe unavailable", "err", err)
		} else {
			l.log.Info("fentry/tcp_send_loss_probe attached (TLP tracking)")
		}
	}

	// ---- Attach optional DNS tracking (kernel 5.17+ for bpf_loop) ----
	if HaveFentry() {
		if err := l.attachFentry(coll, "tollwing_dns_recvmsg", "udp_recvmsg"); err != nil {
			l.log.Warn("fentry/udp_recvmsg unavailable, DNS tracking disabled", "err", err)
		} else {
			l.log.Info("fentry/udp_recvmsg attached (DNS tracking)")
			// Create DNS tracker from the dns_events ring buffer map.
			if dnsEventsMap := coll.Maps["dns_events"]; dnsEventsMap != nil {
				tracker := dns.New(dns.Config{}, dnsEventsMap, l.log)
				if tracker != nil {
					l.dnsTracker = tracker
				}
			}
		}
	}

	// ---- Attach optional UDP byte counting (fentry) ----
	if HaveFentry() {
		if err := l.attachFentry(coll, "tollwing_udp_sendmsg", "udp_sendmsg"); err != nil {
			l.log.Warn("fentry/udp_sendmsg unavailable, UDP TX byte counting disabled", "err", err)
		} else {
			l.log.Info("fentry/udp_sendmsg attached (UDP TX byte counting)")
		}
		// fexit uses the same AttachTracing API — the SEC("fexit/...") type is in the BPF object.
		if err := l.attachFentry(coll, "tollwing_udp_recvmsg_exit", "udp_recvmsg"); err != nil {
			l.log.Warn("fexit/udp_recvmsg unavailable, UDP RX byte counting disabled", "err", err)
		} else {
			l.log.Info("fexit/udp_recvmsg attached (UDP RX byte counting)")
		}
	}

	// ---- Attach optional QUIC TC program (kernel 6.6+ for TCX) ----
	if prog := coll.Programs["tollwing_quic_egress"]; prog != nil {
		ifIndex, ifErr := l.resolveInterface()
		if ifErr != nil {
			l.log.Warn("QUIC tracking disabled, could not resolve interface", "err", ifErr)
		} else if HaveTCX() {
			if err := l.attachTCX(coll, "tollwing_quic_egress", ifIndex); err != nil {
				l.log.Warn("QUIC TCX attachment failed", "err", err, "ifindex", ifIndex)
			} else {
				l.log.Info("QUIC TC program attached via TCX", "ifindex", ifIndex)
			}
		} else {
			l.log.Warn("QUIC tracking requires kernel 6.6+ (TCX), skipping")
		}
	}

	// ---- Push config to BPF maps ----
	if err := l.pushConfig(); err != nil {
		l.Close()
		return fmt.Errorf("push config: %w", err)
	}

	// ---- Start ring buffer reader ----
	eventsMap := coll.Maps["events"]
	if eventsMap == nil {
		l.Close()
		return fmt.Errorf("BPF map 'events' not found in collection")
	}

	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		l.Close()
		return fmt.Errorf("open ringbuf reader: %w", err)
	}
	l.reader = rd

	childCtx, cancel := context.WithCancel(ctx)
	l.cancel = cancel
	l.wg.Add(1)
	go l.readEvents(childCtx)

	// Start DNS tracker ring buffer reader.
	if l.dnsTracker != nil {
		dnsMap := coll.Maps["dns_events"]
		if err := l.dnsTracker.Start(childCtx, dnsMap); err != nil {
			l.log.Warn("dns tracker start failed", "err", err)
			l.dnsTracker = nil
		}
	}

	l.log.Info("tollwing eBPF agent active",
		"track_udp", l.cfg.TrackUDP,
		"sample_rate", l.cfg.SampleRate,
	)

	return nil
}

// SetEnabled toggles the BPF-side enabled flag without reloading programs.
func (l *Loader) SetEnabled(enabled bool) error {
	if l.collection == nil {
		return fmt.Errorf("collection not loaded")
	}
	cfgMap := l.collection.Maps["agent_config"]
	if cfgMap == nil {
		return fmt.Errorf("BPF map 'agent_config' not found")
	}

	var val uint8
	if enabled {
		val = 1
	}

	// Read current config, update enabled flag, write back.
	var cfg AgentConfig
	key := uint32(0)
	if err := cfgMap.Lookup(&key, &cfg); err != nil {
		return fmt.Errorf("read agent_config: %w", err)
	}
	cfg.Enabled = val
	if err := cfgMap.Update(&key, &cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update agent_config: %w", err)
	}
	return nil
}

// DNSTracker returns the DNS tracker, or nil if DNS tracking is unavailable.
func (l *Loader) DNSTracker() *dns.Tracker {
	return l.dnsTracker
}

// Close detaches all BPF programs and releases resources.
// Safe to call multiple times.
func (l *Loader) Close() error {
	l.log.Info("stopping eBPF loader")

	if l.cancel != nil {
		l.cancel()
	}
	if l.dnsTracker != nil {
		l.dnsTracker.Stop()
	}
	if l.reader != nil {
		l.reader.Close()
	}
	l.wg.Wait()

	for _, lnk := range l.links {
		lnk.Close()
	}
	l.links = nil

	if l.collection != nil {
		l.collection.Close()
		l.collection = nil
	}

	l.log.Info("eBPF loader stopped")
	return nil
}

// Maps returns the underlying BPF collection's maps for direct access
// (e.g., map polling by the aggregator). Returns nil if not loaded.
func (l *Loader) Maps() map[string]*ebpf.Map {
	if l.collection == nil {
		return nil
	}
	return l.collection.Maps
}

// optionalPrograms lists BPF programs that should not prevent the agent from
// starting if they fail to load. They are pruned before collection creation
// when feature probes indicate the kernel lacks support.
var optionalPrograms = map[string]struct{}{
	"tollwing_connect6":                 {},
	"tollwing_conntrack_confirm":        {},
	"tollwing_conntrack_confirm_kprobe": {},
	"tollwing_conntrack_kfunc":          {},
	"tollwing_tcp_retransmit":           {},
	"tollwing_tcp_loss_probe":           {},
	"tollwing_dns_recvmsg":              {},
	"tollwing_udp_recvmsg_exit":         {},
	"tollwing_udp_sendmsg":              {},
	"tollwing_quic_egress":              {},
	"tollwing_tcp_sendmsg_fentry":       {},
	"tollwing_tcp_cleanup_rbuf_fentry":  {},
	"tollwing_tcp_sendmsg":              {},
	"tollwing_tcp_cleanup_rbuf":         {},
}

// pruneOptionalPrograms removes optional BPF programs from the spec when
// feature probes indicate they cannot be loaded on this kernel.
func (l *Loader) pruneOptionalPrograms(spec *ebpf.CollectionSpec) {
	// Conntrack kfunc requires netfilter prog type (kernel 6.4+)
	if !HaveNetfilterProg() {
		l.removeProgram(spec, "tollwing_conntrack_kfunc")
	}

	// fentry-based programs require tracing support
	if !HaveFentry() {
		for _, name := range []string{
			"tollwing_conntrack_confirm",
			"tollwing_tcp_retransmit",
			"tollwing_tcp_loss_probe",
			"tollwing_dns_recvmsg",
			"tollwing_udp_recvmsg_exit",
			"tollwing_udp_sendmsg",
			"tollwing_tcp_sendmsg_fentry",
			"tollwing_tcp_cleanup_rbuf_fentry",
		} {
			l.removeProgram(spec, name)
		}
		// Keep kprobe conntrack variant when fentry unavailable.
	} else {
		// When fentry IS available, prune kprobe byte counting since
		// bpf_get_socket_cookie may not work in kprobe context.
		l.removeProgram(spec, "tollwing_tcp_sendmsg")
		l.removeProgram(spec, "tollwing_tcp_cleanup_rbuf")
		// Keep both conntrack variants — loader will try fentry first,
		// fall back to kprobe. The fallback handles the case where fentry
		// is generally supported but nf_conntrack_confirm specifically
		// isn't traceable (module-local symbol).
	}

	// QUIC TC requires TCX (kernel 6.6+)
	if !HaveTCX() {
		l.removeProgram(spec, "tollwing_quic_egress")
	}
}

// applyMapSizeOverrides adjusts BPF map max_entries from config.
// This allows tuning memory footprint without recompiling BPF objects.
func (l *Loader) applyMapSizeOverrides(spec *ebpf.CollectionSpec) {
	overrides := map[string]uint32{
		"connections":     l.cfg.MapSizes.Connections,
		"flow_aggregates": l.cfg.MapSizes.FlowAggregates,
		"nat_mappings":    l.cfg.MapSizes.NatMappings,
		"quic_flows":      l.cfg.MapSizes.QuicFlows,
		"events":          l.cfg.MapSizes.EventsRingBuf,
		"dns_events":      l.cfg.MapSizes.DNSRingBuf,
	}

	for name, size := range overrides {
		if size == 0 {
			continue
		}
		if m, ok := spec.Maps[name]; ok {
			old := m.MaxEntries
			m.MaxEntries = size
			l.log.Info("overriding BPF map size", "map", name, "old", old, "new", size)
		}
	}
}

func (l *Loader) removeProgram(spec *ebpf.CollectionSpec, name string) {
	if _, ok := spec.Programs[name]; ok {
		delete(spec.Programs, name)
		l.log.Info("pruned optional BPF program (unsupported kernel)", "program", name)
	}
}

// loadCollectionWithFallback tries to create a BPF collection from the spec.
// If loading fails due to a verifier error on an optional program, it removes
// the failing program and retries. Required programs always cause a hard failure.
func (l *Loader) loadCollectionWithFallback(spec *ebpf.CollectionSpec) (*ebpf.Collection, error) {
	for attempts := 0; attempts < 5; attempts++ {
		coll, err := ebpf.NewCollection(spec)
		if err == nil {
			return coll, nil
		}

		// Check if the error mentions an optional program we can remove.
		removed := false
		for name := range optionalPrograms {
			if _, exists := spec.Programs[name]; !exists {
				continue
			}
			// The cilium/ebpf error format includes "program <name>:" prefix.
			if containsProgName(err.Error(), name) {
				l.log.Warn("optional BPF program failed to load, removing",
					"program", name, "err", err)
				delete(spec.Programs, name)
				removed = true
				break
			}
		}
		if !removed {
			return nil, err
		}
	}
	// Final attempt after all removals.
	return ebpf.NewCollection(spec)
}

// containsProgName checks if an error message references a specific BPF program.
func containsProgName(errMsg, progName string) bool {
	// cilium/ebpf errors look like: "program tollwing_dns_recvmsg: load program: ..."
	return len(errMsg) > 0 && len(progName) > 0 &&
		bytes.Contains([]byte(errMsg), []byte("program "+progName))
}

// attachByteCountingHooks attaches tcp_sendmsg and tcp_cleanup_rbuf hooks.
// Prefers fentry (kernel 5.5+, reliable socket cookie) over kprobe.
func (l *Loader) attachByteCountingHooks(coll *ebpf.Collection) error {
	// Try fentry first — bpf_get_socket_cookie is reliably available.
	if HaveFentry() {
		sendmsgOk := true
		cleanupOk := true

		if prog := coll.Programs["tollwing_tcp_sendmsg_fentry"]; prog != nil {
			if err := l.attachFentry(coll, "tollwing_tcp_sendmsg_fentry", "tcp_sendmsg"); err != nil {
				l.log.Warn("fentry/tcp_sendmsg unavailable, will try kprobe", "err", err)
				sendmsgOk = false
			}
		} else {
			sendmsgOk = false
		}

		if prog := coll.Programs["tollwing_tcp_cleanup_rbuf_fentry"]; prog != nil {
			if err := l.attachFentry(coll, "tollwing_tcp_cleanup_rbuf_fentry", "tcp_cleanup_rbuf"); err != nil {
				l.log.Warn("fentry/tcp_cleanup_rbuf unavailable, will try kprobe", "err", err)
				cleanupOk = false
			}
		} else {
			cleanupOk = false
		}

		if sendmsgOk && cleanupOk {
			l.log.Info("byte counting via fentry (preferred)")
			return nil
		}
	}

	// Fall back to kprobe.
	l.log.Info("falling back to kprobe byte counting")
	if err := l.attachKprobe(coll, "tollwing_tcp_sendmsg", "tcp_sendmsg"); err != nil {
		return err
	}
	if err := l.attachKprobe(coll, "tollwing_tcp_cleanup_rbuf", "tcp_cleanup_rbuf"); err != nil {
		return err
	}
	return nil
}

// attachCgroupProg finds a program by name and attaches it to the cgroup.
func (l *Loader) attachCgroupProg(coll *ebpf.Collection, name string, at ebpf.AttachType) error {
	prog := coll.Programs[name]
	if prog == nil {
		return fmt.Errorf("BPF program %q not found in collection", name)
	}

	l.log.Info("attaching BPF program", "name", name, "cgroup", l.cfg.CgroupPath)

	lnk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    l.cfg.CgroupPath,
		Attach:  at,
		Program: prog,
	})
	if err != nil {
		return fmt.Errorf("attach %s: %w", name, err)
	}
	l.links = append(l.links, lnk)
	return nil
}

// attachKprobe finds a program by name and attaches it as a kprobe to a kernel function.
func (l *Loader) attachKprobe(coll *ebpf.Collection, progName, symbol string) error {
	prog := coll.Programs[progName]
	if prog == nil {
		return fmt.Errorf("BPF program %q not found in collection", progName)
	}

	l.log.Info("attaching kprobe", "program", progName, "symbol", symbol)

	lnk, err := link.Kprobe(symbol, prog, nil)
	if err != nil {
		return fmt.Errorf("attach kprobe %s to %s: %w", progName, symbol, err)
	}
	l.links = append(l.links, lnk)
	return nil
}

// attachFentryConntrack tries to attach conntrack hooks.
// Tries fentry first, then kprobe fallback for module-local symbols.
func (l *Loader) attachFentryConntrack(coll *ebpf.Collection) {
	// Try fentry/nf_conntrack_confirm first.
	if err := l.attachFentry(coll, "tollwing_conntrack_confirm", "nf_conntrack_confirm"); err == nil {
		l.log.Info("fentry/nf_conntrack_confirm attached (tier 2 NAT resolution)")
		return
	} else {
		l.log.Debug("fentry/nf_conntrack_confirm unavailable, trying kprobe fallback", "err", err)
	}

	// Fallback: kprobe on __nf_conntrack_confirm (module-local symbol).
	if err := l.attachKprobe(coll, "tollwing_conntrack_confirm_kprobe", "__nf_conntrack_confirm"); err == nil {
		l.log.Info("kprobe/__nf_conntrack_confirm attached (tier 2 NAT resolution)")
		return
	} else {
		l.log.Warn("conntrack hooks unavailable, using two-phase fallback only", "err", err)
	}
}

// attachNetfilter attaches a netfilter BPF program (kernel 6.4+).
func (l *Loader) attachNetfilter(coll *ebpf.Collection, progName string) error {
	prog := coll.Programs[progName]
	if prog == nil {
		return fmt.Errorf("BPF program %q not found in collection", progName)
	}

	l.log.Info("attaching netfilter program", "name", progName)

	lnk, err := link.AttachNetfilter(link.NetfilterOptions{
		Program:        prog,
		ProtocolFamily: 2, // AF_INET
		HookNumber:     3, // NF_INET_LOCAL_OUT
		Priority:       1,
	})
	if err != nil {
		return fmt.Errorf("attach netfilter %s: %w", progName, err)
	}
	l.links = append(l.links, lnk)
	return nil
}

// attachTCX attaches a TC program using TCX (kernel 6.6+) for deterministic ordering.
// Falls back to legacy tc filter if TCX is unavailable.
func (l *Loader) attachTCX(coll *ebpf.Collection, progName string, ifIndex int) error {
	prog := coll.Programs[progName]
	if prog == nil {
		return fmt.Errorf("BPF program %q not found in collection", progName)
	}

	l.log.Info("attaching TC program via TCX", "name", progName, "ifindex", ifIndex)

	lnk, err := link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Attach:    ebpf.AttachTCXEgress,
		Interface: ifIndex,
	})
	if err != nil {
		return fmt.Errorf("attach TCX %s: %w", progName, err)
	}
	l.links = append(l.links, lnk)
	return nil
}

// attachFentry attaches a BPF program as an fentry tracing hook to a kernel function.
// Returns an error if the program or kernel function is unavailable (non-fatal).
func (l *Loader) attachFentry(coll *ebpf.Collection, progName, symbol string) error {
	prog := coll.Programs[progName]
	if prog == nil {
		return fmt.Errorf("BPF program %q not found in collection", progName)
	}

	l.log.Info("attaching fentry", "program", progName, "symbol", symbol)

	lnk, err := link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
	if err != nil {
		return fmt.Errorf("attach fentry %s to %s: %w", progName, symbol, err)
	}
	l.links = append(l.links, lnk)
	return nil
}

// resolveInterface determines the network interface index for TC program attachment.
func (l *Loader) resolveInterface() (int, error) {
	name := l.cfg.InterfaceName
	if name == "" {
		// Auto-detect: use the first non-loopback interface that is up.
		ifaces, err := net.Interfaces()
		if err != nil {
			return 0, fmt.Errorf("list interfaces: %w", err)
		}
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			name = iface.Name
			break
		}
		if name == "" {
			return 0, fmt.Errorf("no suitable network interface found")
		}
		l.log.Info("auto-detected network interface for QUIC", "iface", name)
	}

	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("interface %q: %w", name, err)
	}
	return iface.Index, nil
}

// pushConfig writes the agent configuration to the BPF agent_config map.
func (l *Loader) pushConfig() error {
	cfgMap := l.collection.Maps["agent_config"]
	if cfgMap == nil {
		return fmt.Errorf("BPF map 'agent_config' not found")
	}

	var enabled, trackUDP uint8
	if l.cfg.Enabled {
		enabled = 1
	}
	if l.cfg.TrackUDP {
		trackUDP = 1
	}

	cfg := AgentConfig{
		Enabled:       enabled,
		TrackUDP:      trackUDP,
		SampleRate:    l.cfg.SampleRate,
		AggregationNs: l.cfg.AggregationNs,
	}

	key := uint32(0)
	if err := cfgMap.Update(&key, &cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("write agent_config: %w", err)
	}
	return nil
}

// readEvents consumes the ring buffer and dispatches events by type.
// Uses unsafe pointer casting instead of reflection-based binary.Read
// to eliminate allocations on the hot path.
func (l *Loader) readEvents(ctx context.Context) {
	defer l.wg.Done()

	for {
		record, err := l.reader.Read()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			l.log.Error("ringbuf read error", "err", err)
			return
		}

		raw := record.RawSample
		if len(raw) < 1 {
			continue
		}

		evtType := EventType(raw[0])

		switch evtType {
		case EventConnect:
			if len(raw) < int(unsafe.Sizeof(ConnectEvent{})) {
				l.log.Warn("truncated connect event", "len", len(raw))
				continue
			}
			evt := *(*ConnectEvent)(unsafe.Pointer(&raw[0]))
			if l.cfg.OnConnect != nil {
				l.cfg.OnConnect(evt)
			}

		case EventEstablish:
			if len(raw) < int(unsafe.Sizeof(EstablishEvent{})) {
				l.log.Warn("truncated establish event", "len", len(raw))
				continue
			}
			evt := *(*EstablishEvent)(unsafe.Pointer(&raw[0]))
			if l.cfg.OnEstablish != nil {
				l.cfg.OnEstablish(evt)
			}

		case EventClose:
			if len(raw) < int(unsafe.Sizeof(CloseEvent{})) {
				l.log.Warn("truncated close event", "len", len(raw))
				continue
			}
			evt := *(*CloseEvent)(unsafe.Pointer(&raw[0]))
			if l.cfg.OnClose != nil {
				l.cfg.OnClose(evt)
			}

		default:
			l.log.Warn("unknown event type", "type", evtType)
		}
	}
}
