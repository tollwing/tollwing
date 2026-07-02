# Tollwing: eBPF-Based Cloud Network Cost Optimization Platform

## Complete Architecture Document

---

> **Editions.** This document describes the full Tollwing system. The free, Apache-2.0 **open-source edition is the agent**: it attributes per-pod network cost across the 9 AWS billing paths and exposes `tollwing_*` Prometheus metrics that your Grafana reads directly, with no control-plane server. The **control plane** described below (the API server, ClickHouse storage, the alert/anomaly engine, recommendations, what-if, auto-remediation, multi-cluster aggregation, GCP/Azure, SSO/RBAC) is **Tollwing Enterprise** (self-hosted, license-gated, early access) and is not part of the open-source tree. The authoritative statement of that boundary is [`OPEN-CORE.md`](OPEN-CORE.md); §13 below summarizes it.
>
> **Document status.** This document describes the system as built, except where a passage is explicitly marked **(roadmap)** — those parts do not exist yet. If you find an unmarked passage describing code that is not in the tree, that is a documentation bug: fix it or mark it (per the living-documents discipline in [`CLAUDE.md`](CLAUDE.md)).

---

## 1. HIGH-LEVEL ARCHITECTURE

```
+-----------------------------------------------------------------------------------+
|                              CONTROL PLANE                                         |
|  +------------------+  +------------------+  +------------------+                  |
|  |   API Server     |  |  Cost Engine     |  |  Alert Engine    |                  |
|  |   (Go, REST/JSON)|  |  (Go)            |  |  (Go)            |                  |
|  +--------+---------+  +--------+---------+  +--------+---------+                  |
|           |                     |                     |                             |
|  +--------+---------------------+---------------------+---------+                  |
|  |                    Aggregation Bus (NATS JetStream)          |                  |
|  +--------+---------------------+---------------------+---------+                  |
|           |                     |                     |                             |
|  +--------+---------+  +--------+---------+  +--------+---------+                  |
|  |  Storage Layer   |  |  Cloud Billing   |  |  Metadata Cache  |                  |
|  |  (ClickHouse +   |  |  Reconciler      |  |  (K8s informers  |                  |
|  |   Prometheus)    |  |  (AWS/GCP/Azure) |  |   + IMDS cache)  |                  |
|  +------------------+  +------------------+  +------------------+                  |
+-----------------------------------------------------------------------------------+

+-----------------------------------------------------------------------------------+
|                         DATA PLANE (per node, DaemonSet)                           |
|                                                                                    |
|  +------------------------------------------------------------------+             |
|  |                    Userspace Agent (Go)                           |             |
|  |  +-------------+ +-------------+ +--------------+ +------------+ |             |
|  |  | Event Reader| | Enricher    | | Aggregator   | | Exporter   | |             |
|  |  | (ring buf)  | | (pid->pod,  | | (per-conn    | | (NATS /    | |             |
|  |  |             | |  cgroup,    | |  -> per-svc  | |  Prometheus| |             |
|  |  |             | |  zone, svc) | |  rollup)     | |  remote wr)| |             |
|  |  +------+------+ +------+------+ +------+-------+ +------+-----+ |             |
|  +---------|---------------|---------------|---------------|----------+             |
|            |               |               |               |                       |
|  +---------+---------------+---------------+---------------+---------+             |
|  |                    eBPF Programs (C, CO-RE)                       |             |
|  |                                                                   |             |
|  |  +------------------+  +------------------+  +------------------+ |             |
|  |  | sock_ops         |  | cgroup/connect   |  | kprobe:          | |             |
|  |  | (connection      |  | (service mesh    |  | tcp_sendmsg /    | |             |
|  |  |  lifecycle)      |  |  pre-NAT capture)|  | tcp_cleanup_rbuf | |             |
|  |  +------------------+  +------------------+  | (byte counters)  | |             |
|  |  +------------------+  +------------------+  +------------------+ |             |
|  |  | cgroup/          |  | fentry:          |                      |             |
|  |  | sock_release     |  | tcp_retransmit   |                      |             |
|  |  | (close + UDP     |  | _skb (retransmit |                      |             |
|  |  |  table cleanup)  |  |  accounting)     |                      |             |
|  |  +------------------+  +------------------+                      |             |
|  +------------------------------------------------------------------+             |
|                                                                                    |
|  Kernel                                                                            |
+-----------------------------------------------------------------------------------+
```

---

## 2. eBPF DATA PLANE

### 2.1 Hook Selection and Rationale

The design uses a layered hook strategy. Not every kernel supports every hook, so the agent must probe capabilities (exactly as our reference eBPF agent does with `HaveSockOps()`) and degrade gracefully.

**Primary Hooks (required, kernel 5.8+):**

| Hook | Type | Purpose | Why This Hook |
|------|------|---------|---------------|
| `sock_ops` | `BPF_PROG_TYPE_SOCK_OPS` | Connection lifecycle events (established, close) | Fires on `ACTIVE_ESTABLISHED_CB`, `PASSIVE_ESTABLISHED_CB`, `STATE_CB`. Gives 4-tuple + socket cookie. Close accounting fires on `TCP_CLOSE` only — half-closed states (`FIN_WAIT`, `CLOSE_WAIT`, …) still carry legal bytes and keep counting (P5). |
| `cgroup/connect4` / `cgroup/connect6` | `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` | Capture pre-NAT destination for ClusterIP resolution | **This is the critical hook Kubecost misses.** Fires BEFORE kube-proxy DNAT, so you see the original ClusterIP:port, not the pod IP. |
| `fentry/tcp_sendmsg` (kprobe fallback) | fentry, kprobe on <5.11 | Byte counting per socket | Captures exact bytes sent per `sock`. Combined with socket cookie, gives per-connection egress bytes. fentry is preferred (reliable `bpf_get_socket_cookie` with `struct sock *`); the loader probes and falls back to the kprobe. |
| `fentry/tcp_cleanup_rbuf` (kprobe fallback) | fentry, kprobe on <5.11 | Byte counting for received data | Captures bytes received. Combined with sendmsg, gives full bidirectional byte accounting. |

**Secondary Hooks (optional — probed at load, degrade gracefully):**

| Hook | Type | Purpose | Kernel Req |
|------|------|---------|------------|
| `cgroup/sock_release` | cgroup | Final byte tally on socket close; deletes UDP entries from the `connections` map (which otherwise have no close event and would only leave via LRU eviction) | 5.8+ |
| `fentry/tcp_retransmit_skb`, `fentry/tcp_send_loss_probe` | fentry | Retransmit accounting (`tollwing_retransmit_*` metrics — wasted, re-billed bytes) | 5.11+ |
| `fentry/udp_sendmsg` | fentry | UDP TX byte counting (enabled with `-udp`) | 5.11+ |
| `fentry`/`fexit` on `udp_recvmsg` (`dns.bpf.c`) | fentry/fexit | DNS answer capture for destination enrichment | 5.11+ |
| TC egress QUIC classifier (`quic.bpf.c`) | TCX link (6.6+) or legacy tc filter | QUIC/HTTP3 flow detection on the wire; the poller deduplicates against socket-level UDP accounting so nothing double-counts | 5.10+ |

> The `fentry/nf_conntrack_confirm` NAT-resolution hook that earlier revisions listed here was removed per [DEC-016](decisions/DEC-016-remove-dormant-cgroup-storage-iterator-and-conntrack-machinery.md): it wrote per-packet into a map nothing read. Pre-DNAT intent comes from the two-phase capture (§2.2); NAT *gateway* detection is a cloud-API concern, not a kernel one (§4.3, [DEC-015](decisions/DEC-015-route-based-nat-detection-and-hourly-charges.md)).

**NOT using XDP:** XDP fires too early (before socket association), so you cannot attribute traffic to processes. XDP is useful for packet-level inspection but not for cost attribution. The overhead of copying full packets is also unacceptable.

**NOT using tc/cls_bpf for attribution:** Same problem as XDP — no process context. The one TC program we ship (the optional QUIC egress classifier above) does protocol *detection* only; attribution still happens at the socket layer, and socket-level accounting wins when both see the same flow.

### 2.2 The ClusterIP Problem (and the Solution)

Kubecost's cross-AZ classification is broken because it only sees post-DNAT IPs. When Pod A in zone us-east-1a talks to ClusterIP service `10.96.0.15:80`, kube-proxy DNATs this to a backend pod, say `10.244.3.7:8080` in us-east-1b. Kubecost sees the pod IP and may not correctly attribute the cost to the service or may miss the original intent.

**The solution is a two-phase capture:**

```
Phase 1: cgroup/connect4 fires BEFORE DNAT
  - Record: socket_cookie -> (original_dst = 10.96.0.15:80, service = "payment-svc")
  - Store in BPF map: cookie_to_original_dst

Phase 2: sock_ops ACTIVE_ESTABLISHED fires AFTER DNAT
  - Record: socket_cookie -> (actual_dst = 10.244.3.7:8080)
  - Look up cookie_to_original_dst to get original ClusterIP
  - Now you have both: the service-level intent AND the actual backend pod + its zone

This gives you:
  - Accurate service-level cost attribution (not just pod-level)
  - Correct cross-AZ detection (because you know the backend pod's zone)
  - Connection-level granularity tied to the originating process
```

For service meshes (Istio/Linkerd), the same approach works because `cgroup/connect4` fires before the sidecar proxy's iptables rules redirect traffic; sidecar-internal loopback legs are classified `service_mesh_internal` so mesh overhead is visible without inflating same-zone aggregates. Reading an eBPF mesh's (Cilium's) own service maps for identity is **(roadmap)** — today those clusters rely on the same pre-DNAT capture.

### 2.3 BPF Map Architecture

The authoritative definitions live in `pkg/ebpf/bpf/maps.h`; this is the map inventory (abridged — IPv6 fields and retransmit counters elided here, present in the source):

```c
// ====== CONNECTION TRACKING ======

// Primary connection table. Keyed by socket cookie (u64).
// Updated on establish, read on byte count, deleted on TCP_CLOSE
// (TCP) or cgroup/sock_release (UDP).
struct conn_info {
    u32 src_ip;
    u32 dst_ip;
    u32 original_dst_ip;    // pre-DNAT (ClusterIP), 0 if no DNAT
    u16 src_port;
    u16 dst_port;
    u16 original_dst_port;  // pre-DNAT port
    u8  family;             // AF_INET=2, AF_INET6=10
    u8  protocol;           // TCP=6, UDP=17
    u32 pid;                // tgid from bpf_get_current_pid_tgid()
    u64 cgroupid;           // from bpf_get_current_cgroup_id()
    u64 start_ns;           // bpf_ktime_get_ns()
    u64 tx_bytes;
    u64 rx_bytes;
    /* … retransmit counters, direction/state, IPv6 addresses … */
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 524288);  // 512K connections
    __type(key, u64);             // socket cookie
    __type(value, struct conn_info);
} connections SEC(".maps");

// ====== PRE-DNAT RESOLUTION ======

// Populated by cgroup/connect4/6, read by sock_ops.
// Short-lived: entries removed after sock_ops correlates them.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);              // socket cookie
    __type(value, struct original_dst); // ip/port + pid, cgroup, comm
} cookie_to_original_dst SEC(".maps");

// ====== AGGREGATION (in-kernel rollup) ======

// Per-flow byte counters, drained atomically by the poller each tick
// (batch LookupAndDelete where the kernel supports it).
// This reduces event volume by 100-1000x versus per-call events.
struct flow_key {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 pid;
    u8  protocol;
    u8  direction;
    u16 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 131072);  // 128K unique flows per CPU;
                                  // keys include the ephemeral src_port,
                                  // so this is sized for churn
    __type(key, struct flow_key);
    __type(value, struct flow_metrics); // tx/rx bytes, conn count,
                                        // retransmits, last_updated_ns
} flow_aggregates SEC(".maps");

// ====== DROP ACCOUNTING (P4: losses are counted, never silent) ======

// Incremented on every ringbuf-reserve failure and map-full insert;
// mirrored into tollwing_ringbuf_drops_total /
// tollwing_map_update_drops_total by the exporter.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    /* one slot per drop category */
} drop_counters SEC(".maps");

// ====== CONFIGURATION ======

struct agent_config {
    u8  enabled;
    u8  track_udp;         // also hook UDP (for DNS/QUIC cost attribution)
    u8  sample_rate;       // 1 = every conn, N = 1/N sampling
    u8  reserved[5];
    u64 aggregation_ns;    // flush interval (default: 5s)
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct agent_config);
} agent_config SEC(".maps");

// ====== EVENTS (connection lifecycle, not byte counting) ======

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);  // 4MB ring buffer
} events SEC(".maps");
```

Also present: `quic_flows` (PERCPU_HASH fed by the TC QUIC classifier; deduplicated against socket-level UDP in the poller), `sidecar_storage` (mesh-sidecar detection), and the `dns_events` ring buffer in `dns.bpf.c`. Three maps earlier revisions documented — `nat_mappings`, `cgroup_cost_storage`, and the sk-storage iterator source — were removed per [DEC-016](decisions/DEC-016-remove-dormant-cgroup-storage-iterator-and-conntrack-machinery.md) (dormant machinery with per-packet cost and no consumer).

### 2.4 Performance Budget: Staying Under 1% CPU

**Strategy 1: In-kernel aggregation.** The `flow_aggregates` PERCPU_HASH map accumulates bytes in-kernel. Instead of emitting a perf event per `tcp_sendmsg` call (which on a busy node could be millions/sec), we just increment counters. Userspace reads and resets these maps on a 5-second interval.

**Strategy 2: Ring buffer, not perf events.** Use `BPF_MAP_TYPE_RINGBUF` (kernel 5.8+) instead of perf event arrays. Ring buffers have lower overhead: no per-CPU allocation, no wakeup per event. Reserve + commit pattern avoids copies.

**Strategy 3: Sampling for extreme throughput.** The `sample_rate` config field allows 1/N sampling on connection establishment for nodes handling millions of short-lived connections. Byte counters still accumulate accurately for sampled connections.

**Strategy 4: Tail calls for complex logic.** Split the sock_ops program into a dispatcher + tail-called handlers. This keeps each program small (staying within the BPF verifier's instruction limit) and avoids branching overhead.

**Strategy 5: LRU maps with appropriate sizing.** LRU eviction means we never block on a full map. Size connections at 512K entries (about 40MB of kernel memory), which covers even the busiest nodes.

**Strategy 6: count what gets dropped.** Ring-buffer reserve failures and map-full inserts increment the `drop_counters` map, exported as `tollwing_ringbuf_drops_total` / `tollwing_map_update_drops_total`. Per P4, data loss under pressure is measured and visible, never silent.

**Overhead budget (an expectation, not yet a published measurement):** Based on comparable tools (Cilium Hubble, Pixie — Pixie publishes <5%, typically <2%, for full protocol tracing, which is far heavier than flow accounting), the combined overhead of sock_ops + the byte-count fentry/kprobes + in-kernel aggregation should be 0.1–0.5% of one core on a node handling 100K active connections. We do not publish this as a measured number; a reproducible benchmark (`make bench`-style, with instance type, kernel, and flow rate stated) is **(roadmap)**, and public claims are qualified until it lands.

---

## 3. USERSPACE AGENT

### 3.1 Language Choice

**Go for the entire userspace agent.** Rationale:

- You already have deep Go + cilium/ebpf experience from our reference eBPF agent. The `cilium/ebpf` library is the best Go eBPF loader.
- The userspace agent is I/O-bound (reading maps, enriching metadata, exporting). Go's goroutine model is ideal.
- Rust would gain nothing here; the hot path is in-kernel C. Userspace just reads aggregated data every 5 seconds.
- Single binary deployment, CGO_ENABLED=0, same as our reference eBPF agent's build model.

**C for all eBPF programs.** CO-RE with vmlinux headers, same pattern as our reference eBPF agent.

### 3.2 Agent Architecture

```
+-------------------------------------------------------------------+
|                     tollwing-agent (Go binary)                   |
|                                                                   |
|  +-----------+     +-----------+     +-----------+                |
|  |  BPF      |     |  Map      |     |  Event    |                |
|  |  Loader   |---->|  Poller   |---->|  Enricher |                |
|  |           |     |  (5s tick)|     |           |                |
|  +-----------+     +-----------+     +-----+-----+                |
|                                            |                      |
|                    +----------+      +-----+-----+                |
|                    | Metadata |<---->| Traffic    |                |
|                    | Cache    |      | Classifier |                |
|                    +----------+      +-----+-----+                |
|                                            |                      |
|                    +-----------+     +-----+-----+                |
|                    | Local     |<----| Aggregator |                |
|                    | Prometheus|     | (per-svc   |                |
|                    | Exporter  |     |  rollup)   |                |
|                    +-----------+     +-----+-----+                |
|                                            |                      |
|                                      +-----+-----+                |
|                                      | NATS       |                |
|                                      | Export     |                |
|                                      +-----------+                |
+-------------------------------------------------------------------+
```

### 3.3 Component Breakdown

**BPF Loader** (pattern from our reference eBPF agent's `Manager`):
- Loads CO-RE objects via `cilium/ebpf.LoadCollectionSpecFromReader`
- Probes kernel features (`features.go`: `HaveSockOps`, `HaveCgroupConnect4`, `HaveRingBuf`, `HaveFentry`, `HaveTCX`, …) — every probe tests the actual capability it claims (DEC-016 fixed a TCX probe that reported "supported" on every kernel since 4.1)
- Graceful degradation: fentry byte counters fall back to kprobes; TCX falls back to a legacy tc filter; optional programs (retransmit, DNS, UDP, QUIC, sock_release) degrade to warn-and-continue
- Pushes config to BPF maps (`pushConfig()`)

**Map Poller:**
- Runs on a configurable tick (default 5s)
- Drains `flow_aggregates` (PERCPU_HASH) with batch `LookupAndDelete` where the kernel supports it (5.14+), atomic per-key `LookupAndDelete` otherwise — the drain is delta-safe: bytes counted between read and delete are never lost, and the sole pre-5.6 lossy fallback warns once
- Reads connection lifecycle events from the ring buffer
- Deduplicates TC-observed QUIC flows against socket-level UDP accounting (the socket-level entry wins)
- Reads `drop_counters` each tick and feeds the exporter's drop metrics

**Metadata Cache** (the enrichment layer):
- **Process metadata:** `/proc/<pid>/cgroup` to get container ID, `/proc/<pid>/comm` and `/proc/<pid>/cmdline` for process name. Cached by PID with TTL.
- **Container/Pod metadata:** Kubernetes informer (client-go SharedInformerFactory) watching Pods. Maps container ID to pod name, namespace, labels, node, zone. Non-Kubernetes enrichment (Docker API / containerd CRI) is **(roadmap)** — on bare VMs today the agent enriches from `/proc` and IMDS only.
- **Zone resolution:** On startup, query IMDS (AWS: `http://169.254.169.254/latest/meta-data/placement/availability-zone`, GCP: metadata server, Azure: IMDS — Azure zone ordinals are region-qualified, e.g. `eastus-1`, so bare `"1"`s from different regions never compare equal). Cache the local node's zone. For remote IPs, resolve via the Kubernetes Node object's `topology.kubernetes.io/zone` label.
- **Service resolution:** Watch Kubernetes Services and EndpointSlices. Build a reverse map: pod IP:port -> service name, with per-slice bookkeeping (each slice's contributions are tracked individually, so a single-slice update on a >100-endpoint service never wipes its sibling slices, and slice/service deletions drain exactly their own entries). Combined with the pre-DNAT capture from `cgroup/connect4`, gives full service attribution.
- **Cluster identity:** resolved once at startup — explicit `-cluster` flag, else derived from the kube-system namespace UID (stable, unique per cluster). An invalid or unresolvable identity **fails the agent fast** at startup rather than silently dropping every NATS publish ([DEC-019](decisions/DEC-019-cluster-identity-fail-fast-nats-subject.md)).

**Traffic Classifier** (see Section 4 in detail).

**Aggregator:**
- Rolls up flow-level data into service-level, namespace-level, and cluster-level summaries
- Produces three tiers: raw flows (short retention), service aggregates (medium retention), cost summaries (long retention)

**Exporters:**
- Local Prometheus `/metrics` endpoint (`:9990/metrics`, the `tollwing_*` series) — the complete free-tier output; your Prometheus scrapes it
- NATS JetStream publish (for Enterprise control-plane consumption)
- On shutdown, the poller's final flush publishes **before** the NATS connection drains and eBPF detaches last — a rolling restart loses no poll interval
- Prometheus remote write and OTLP export are **(roadmap)**

### 3.4 Process-Level Attribution

The `pid` captured by `bpf_get_current_pid_tgid()` in the sock_ops/kprobe hooks gives the kernel thread group ID. The enrichment pipeline maps this to:

```
PID -> /proc/<pid>/cgroup -> container ID
     -> container ID -> (pod, namespace, labels) via K8s informer
     -> /proc/<pid>/comm -> process name (e.g., "envoy", "nginx", "java")
     -> /proc/<pid>/cmdline -> full command line
```

For non-containerized workloads (VMs), the PID directly gives the process. Serverless attribution (Lambda/Cloud Functions extensions) is **(roadmap)** — nothing ships for it today.

---

## 4. TRAFFIC CLASSIFICATION ENGINE

This is the core differentiator. The classifier determines the traffic type for every flow **deterministically**: every branch is decided by observed facts (hints from the enricher, operator/cloud-fed prefix sets, zone data). Anything it cannot prove is classified `Unknown` — never guessed (P5, [DEC-010](decisions/DEC-010-clusterip-dialer-side-cross-az-attribution.md)). The full type set is defined by `classifier.TrafficType` (the canonical owner of the wire strings, P6): the 9 billed paths plus `intra_node`, `service_mesh_internal`, and `unknown`.

### 4.1 Classification Decision Tree

The implemented order (`pkg/classifier/traffic.go`, `Classify`):

```
For each flow (dst_ip, original_dst_ip, hints, zones):

1. Sidecar hint from the enricher?          -> SERVICE_MESH_INTERNAL ($0, tracked)
2. Intra-node hint or loopback dst?         -> INTRA_NODE ($0, tracked)
3. dst in a cluster-internal CIDR
   (operator-supplied or informer-fed)?
   +-- src_zone and dst_zone both known?
   |   +-- equal            -> SAME_ZONE (free on all clouds)
   |   +-- same region      -> CROSS_AZ  (charged on AWS/GCP; free on Azure)
   |   +-- different region -> CROSS_REGION
   +-- a zone is unknown    -> UNKNOWN (never assume same-zone;
                                the dialer-side ClusterIP leg lands
                                here by design, DEC-003/DEC-010)
4. dst is RFC 1918 / link-local (not cluster-internal)?
   -- topology prefixes are consulted BEFORE zone fallback,
      because real VPC peers are almost always RFC 1918:
   +-- dst is a known NAT gateway ENI IP    -> NAT_GATEWAY
   +-- dst in a VPC-peering prefix          -> VPC_PEERING
   +-- dst in a Transit-Gateway prefix      -> TRANSIT_GATEWAY
   +-- dst in a VPC-endpoint prefix         -> VPC_ENDPOINT
   +-- else: zone comparison as in (3), UNKNOWN if unprovable
5. Public destination:
   +-- dst in a peering / TGW / endpoint prefix  -> as above
   +-- the node's subnet default-routes via a
       NAT gateway (route-table fact, §4.3)      -> NAT_GATEWAY
   +-- else                                      -> INTERNET_EGRESS
```

`cloud_service_public` is not inferred from IP prefixes — it is a DNS/enrichment outcome (a flow to a provider service's public endpoint identified by name). Published provider IP ranges (`ip-ranges.json` and friends) are deliberately **not** fed into the endpoint prefix set: a public range says nothing about whether *this* VPC has an endpoint for it, and doing so once priced public-EC2 traffic at $0.01/GB "vpc_endpoint" instead of ~$0.09/GB egress ([DEC-015](decisions/DEC-015-route-based-nat-detection-and-hourly-charges.md)).

### 4.2 Zone Resolution Strategy

```
+---------------------------------------------------------------+
|                   Zone Resolution Pipeline                     |
|                                                                |
|  IP Address                                                    |
|      |                                                         |
|      v                                                         |
|  [Local Node Cache]  -- Is this the local node's IP? -->       |
|      |                   Return local zone immediately         |
|      v                                                         |
|  [K8s Node Map]  -- Is this a known node/pod IP? -->           |
|      |              Return zone from node's topology label     |
|      v                                                         |
|  [CIDR-to-Zone Map]  -- Does IP fall in a known subnet? -->    |
|      |                   Return zone from subnet mapping       |
|      |                   (populated from the cloud subnet API, |
|      |                    replace-on-refresh every 5 minutes)  |
|      v                                                         |
|  [Unknown]  -- classify UNKNOWN; never assume a zone (P5).     |
|               Per-IP cloud-API fallback lookups are (roadmap). |
+---------------------------------------------------------------+
```

The CIDR-to-zone map is the key innovation. On startup, the agent queries:
- **AWS:** `ec2:DescribeSubnets` to get subnet CIDR -> AZ mapping
- **GCP:** `compute.subnetworks.list` — GCP subnets are **regional**, so they contribute **no** CIDR-to-zone entries: mapping a regional CIDR to any single zone would make real cross-zone traffic (charged $0.01/GiB since GCP introduced inter-zone pricing) read as free `same_zone`. Zone facts on GCP come from per-IP sources (node labels via the informer); without them the classification is an honest `Unknown` ([DEC-015](decisions/DEC-015-route-based-nat-detection-and-hourly-charges.md))
- **Azure:** `network/virtualNetworks` API for subnet -> zone mapping, with bare zone ordinals region-qualified (`QualifyAzureZone("eastus","1")` = `eastus-1`) so cross-AZ never misreads as cross-region

Each agent refreshes this map itself every 5 minutes (`cloud.TopologyRefresher`); sharing one leader-fetched copy across agents via the control plane is **(roadmap)**. Every `Set*CIDRs` feed is replace-on-refresh: the classifier's prefix tree always equals the latest topology snapshot, so deleted peerings stop classifying within one refresh and the tree stays bounded (P2).

### 4.3 NAT Gateway Detection

NAT gateways are invisible at the socket layer — an internet-bound flow's destination is the internet IP, never the NAT ENI, so IP matching alone can never attribute NAT data-processing spend. Per [DEC-015](decisions/DEC-015-route-based-nat-detection-and-hourly-charges.md), detection is **route-based**:

1. On AWS, the provider resolves the node's subnet (config override or IMDS MAC lookup) and inspects `ec2:DescribeRouteTables` — the subnet's associated table, or the VPC main table when unassociated — for a `0.0.0.0/0` route targeting a NAT gateway (`aws.Provider.NodeRoutesViaNAT`).
2. `cloud.TopologyRefresher` feeds the result to `classifier.SetDefaultRouteNAT`: internet-bound flows from NAT-routed subnets classify `nat_gateway`.
3. `ec2:DescribeNatGateways` still supplies NAT ENI IPs; flows addressed *to* the ENI itself match directly.
4. Pricing: a NAT-classified flow costs NAT per-GB processing **plus** the internet-DTO leg on its Tx bytes. The gateway's fixed *hourly* charge is deliberately **not** spread across flows (that would require inventing a utilization share, violating P4/P5); it surfaces in billing reconciliation's explicit unaccounted bucket (§5.3).

Known limits (recorded in DEC-015): route-based detection is **AWS-only** today — GCP/Azure NAT-routed internet flows still classify `internet_egress`, under-reporting their NAT processing component; and detection is subnet-granular (the default route stands in for per-prefix routes).

### 4.4 VPC Peering and Transit Gateway Detection

On startup and every refresh, query:
- **AWS:** `ec2:DescribeVpcPeeringConnections`, `ec2:DescribeTransitGatewayAttachments`
- Map peering CIDRs and TGW attachment CIDRs into the classifier's lookup table (replace-on-refresh, §4.2)
- Any flow destined to a peering CIDR is classified as VPC_PEERING; a TGW attachment CIDR is TRANSIT_GATEWAY — these prefixes are consulted *before* zone fallback for RFC 1918 destinations, since real VPC peers are almost always RFC 1918
- VPC-endpoint prefixes come from explicit operator configuration; deriving them automatically from deployed endpoints (`ec2:DescribeVpcEndpoints`) is **(roadmap)** — published provider ranges are never used as a stand-in (§4.1)

---

## 5. COST CALCULATION ENGINE

### 5.1 Rate Card Model

The rate card — not the engine — is the authority on billing semantics ([DEC-014](decisions/DEC-014-metered-directions-and-marginal-default-pricing.md)). The `TrafficType` enumeration is owned by `pkg/classifier` (§4, P6); the card lives in `pkg/cost`:

```go
// RateCard holds per-GB pricing AND billing semantics for a provider + region.
type RateCard struct {
    Provider   string            // "aws", "gcp", "azure"
    Region     string            // "us-east-1"
    Rates      map[classifier.TrafficType]TieredRate
    NATGateway NATGatewayRate    // per-hour + per-GB
    TransitGW  TransitGWRate     // per-attachment-hour + per-GB

    // Directions states which side(s) of a flow are billable, per
    // traffic type, from the observing node's perspective: AWS
    // cross-AZ meters Tx+Rx ($0.01/GB each direction); internet
    // egress, cross-region, and TGW meter Tx only; GCP meters the
    // sender; Azure cross-AZ meters nothing (charges retired 2024).
    // The engine bills only MeteredBytes(tt, tx, rx).
    Directions map[classifier.TrafficType]MeteredDirection

    LastUpdated time.Time // dates the rates (P4) — for the built-in
                          // defaults this is the verification date
                          // (2026-07-02), never time.Now()
    Source      string    // e.g. "aws-price-list-api", or the dated
                          // defaults label
    Fallback    bool      // true when defaults substitute for live
                          // pricing — a stale default must look stale,
                          // never silently pass as fresh (P4)
}

// TieredRate supports volume-based pricing (e.g., AWS internet egress).
type TieredRate struct {
    Tiers []Tier  // sorted by threshold ascending
}

type Tier struct {
    UpToGB  float64  // cumulative GB threshold (math.Inf for last tier)
    PerGB   float64  // price per GB in this tier
}
```

**Pricing modes** (`cost.EngineConfig`, DEC-014): the default is `PricingModeMarginal` — every metered GB prices at the marginal post-free-tier list rate (`TieredRate.MarginalRate()`), with **no cumulative state**. That is the only honest default for a distributed fleet: N per-node engines each tracking "the account's" free tier would grant it N times and reset it on every restart. `PricingModeSingleMeter` (explicit opt-in via `cost.NewEngineWithConfig`) applies the full tier table cumulatively and is valid only where exactly one engine meters all the account's traffic — the Enterprise server's aggregation path. Even then the true tier position belongs to CUR reconciliation (§5.3), which sees non-Kubernetes spend too.

### 5.2 Rate Card Sources

| Provider | Live source (`pkg/cloud/*/pricing.go`) | Fallback |
|----------|-----------|-----------------|
| AWS | AWS Price List API (`GetProducts`), `Source: "aws-price-list-api"` | Dated defaults, `Fallback: true` |
| GCP | Cloud Billing Catalog API | Dated defaults, `Fallback: true` |
| Azure | Retail Prices API (`https://prices.azure.com/api/retail/prices`) | Dated defaults, `Fallback: true` |

The agent's 6-hour rate-card refresher wires the live AWS pricing client (the OSS build is AWS-scoped, §13); on failure it warns loudly and falls back to the built-in defaults, which carry their list-price verification date (2026-07-02, sources in DEC-014) — a rate without a date is untraceable (P4). A provider that cannot fetch live pricing returns its default card marked `Fallback: true` instead of silently substituting it.

**Committed/discounted pricing:** list rates are what the agent can honestly compute from bytes alone. Your *actual discounted* rates (Savings Plans, CUDs, private pricing) enter through CUR reconciliation (§5.3, Enterprise), which compares metered traffic against the real bill. Querying commitment APIs to pre-apply effective rates per flow is **(roadmap)**.

### 5.3 Billing Reconciliation

```
+-------------------------------------------------------------------+
|                  Billing Reconciliation Pipeline                   |
|                                                                    |
|  eBPF-measured traffic          Cloud billing data                 |
|  (per connection, per hour)     (per service, per day)             |
|         |                              |                           |
|         v                              v                           |
|  [Aggregate to hourly          [Parse CUR/billing export           |
|   per-service buckets]          into hourly buckets]               |
|         |                              |                           |
|         +----------+-------------------+                           |
|                    |                                               |
|                    v                                               |
|           [Reconciliation Engine]                                  |
|           - Compare eBPF total vs billing total per traffic type   |
|           - Compute drift percentage                               |
|           - If drift > 5%: alert + investigate                     |
|           - Apply correction factor to future estimates            |
|           - Attribute unmatched billing to "unmeasured" bucket     |
|             (managed services, control plane traffic, etc.)        |
|                                                                    |
|           Output:                                                  |
|           - Reconciled cost per service/namespace/process          |
|           - Accuracy score (e.g., "94% of billing accounted for") |
|           - Drift report for unaccounted costs                     |
+-------------------------------------------------------------------+
```

Fixed hourly charges (NAT gateway hours, TGW attachment hours) are **not** attributed per flow — a per-flow dollar must be that flow's bytes × a dated rate (P4), and spreading a fixed charge requires inventing a utilization share (P5). They land in the reconciliation's explicit **unaccounted** bucket, where the drift report names them ([DEC-015](decisions/DEC-015-route-based-nat-detection-and-hourly-charges.md)).

AWS billing integration:
- **Cost and Usage Report (CUR):** S3-delivered Parquet files, contains per-resource-hour costs. Parse `lineItem/UsageType` for `DataTransfer-*` line items.
- **Cost Explorer API:** For on-demand queries. Rate-limited; cache aggressively.

GCP:
- **BigQuery Billing Export:** Standard export dataset. Query `service.description = "Compute Engine"` and `sku.description LIKE "%Egress%"`.

Azure:
- **Cost Management API:** `/query` endpoint for custom date ranges.

### 5.4 Handling Managed Services

For traffic to/from managed services (RDS, ElastiCache, S3, etc.):
- The agent running on the node sees outbound connections to managed service IPs and attributes the cost to the pod/process that initiated the connection
- Identifying a destination as a *named* cloud service (`cloud_service_public`) is a DNS/enrichment outcome, not an IP-prefix inference
- Published provider ranges (`ip-ranges.json`, GCP ranges, Azure Service Tags) are deliberately **not** used to classify — matching against them once priced public-EC2/internet traffic as cheap `vpc_endpoint` traffic ([DEC-015](decisions/DEC-015-route-based-nat-detection-and-hourly-charges.md)); without endpoint knowledge the honest classification for a public address is the default egress path

Serverless (Lambda-extension agent, per-invocation traffic costs) is **(roadmap)**.

---

## 6. STORAGE AND QUERY LAYER

### 6.1 Storage Architecture

```
+-------------------------------------------------------------------+
|                      Storage Tiers                                 |
|                                                                    |
|  Tier 1: Hot (0-24h)                                              |
|  +----------------------------+                                    |
|  | Prometheus (local per-node)|  Per-flow metrics, 15s resolution |
|  | Used for: real-time alerts |  Retention: 24h, WAL-only        |
|  +----------------------------+                                    |
|                                                                    |
|  Tier 2: Warm (1-30 days)                                         |
|  +----------------------------+                                    |
|  | ClickHouse (clustered)     |  Per-service aggregates, 1m res  |
|  | Used for: dashboards,      |  Retention: 30 days              |
|  |   cost reports, queries    |  Partitioned by day              |
|  +----------------------------+                                    |
|                                                                    |
|  Tier 3: Cold (30d-1yr)                                           |
|  +----------------------------+                                    |
|  | ClickHouse (S3-backed)     |  Per-namespace daily summaries   |
|  | Used for: trend analysis,  |  Retention: 1 year               |
|  |   billing reconciliation   |  Tiered storage to S3/GCS        |
|  +----------------------------+                                    |
+-------------------------------------------------------------------+
```

### 6.2 ClickHouse Schema (Core Tables)

```sql
-- Raw flow records (Tier 2, MergeTree, 30-day retention)
CREATE TABLE flows (
    timestamp       DateTime64(3),
    cluster         LowCardinality(String),
    node            LowCardinality(String),
    src_namespace   LowCardinality(String),
    src_pod         String,
    src_process     String,
    src_zone        LowCardinality(String),
    dst_namespace   LowCardinality(String),
    dst_pod         String,
    dst_service     String,
    dst_zone        LowCardinality(String),
    traffic_type    Enum8('unknown'=0, 'same_zone'=1, 'cross_az'=2,
                          'cross_region'=3, 'internet_egress'=4,
                          'nat_gateway'=5, 'vpc_peering'=6,
                          'transit_gateway'=7, 'vpc_endpoint'=8,
                          'cloud_service_public'=9),
    tx_bytes        UInt64,
    rx_bytes        UInt64,
    connections     UInt32,
    retransmit_bytes UInt64 DEFAULT 0,
    retransmit_count UInt32 DEFAULT 0,
    cost_usd        Float64
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (cluster, src_namespace, dst_service, timestamp)
TTL toDateTime(timestamp) + INTERVAL 30 DAY;

-- Service cost summary (materialized view, automatic rollup)
CREATE MATERIALIZED VIEW IF NOT EXISTS service_costs_hourly
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMMDD(hour)
ORDER BY (cluster, src_namespace, src_pod, dst_service, traffic_type, hour)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    cluster, src_namespace, src_pod, dst_service, traffic_type,
    sum(tx_bytes) AS tx_bytes,
    sum(rx_bytes) AS rx_bytes,
    sum(connections) AS connections,
    sum(cost_usd) AS cost_usd
FROM flows
GROUP BY hour, cluster, src_namespace, src_pod, dst_service, traffic_type;
```

### 6.3 Why ClickHouse Over Pure Prometheus

- Prometheus is excellent for real-time alerting but poor for ad-hoc cost queries with high cardinality (process x service x zone x traffic_type)
- ClickHouse handles billions of rows with sub-second query latency
- Columnar compression means storage costs are 10-50x lower than Prometheus for the same data
- SQL interface makes it accessible for BI tools and custom reports
- ClickHouse's SummingMergeTree provides automatic rollup, reducing storage as data ages

Prometheus is still used at the node level for real-time metrics and alerting via standard PromQL.

---

## 7. CONTROL PLANE / API

### 7.1 Components

```
+-------------------------------------------------------------------+
|                     Control Plane Services                        |
|                                                                    |
|  +-------------------+  +-------------------+                      |
|  | API Server        |  | Cost Engine       |                      |
|  | - REST/JSON       |  | - Rate card mgmt  |                      |
|  |   (/api/v1/*)     |  | - Billing recon   |                      |
|  | - serves the UI   |  | - Cost allocation |                      |
|  +-------------------+  +-------------------+                      |
|                                                                    |
|  +-------------------+  +-------------------+                      |
|  | Alert Engine      |  | Recommendation    |                      |
|  | - Real-time eval  |  |   Engine          |                      |
|  | - Anomaly detect  |  | - Topology hints  |                      |
|  | - Notification    |  | - Co-location     |                      |
|  +-------------------+  +-------------------+                      |
|                                                                    |
|  +-------------------+  +-------------------+                      |
|  | Cluster Manager   |  | Cloud Connector   |                      |
|  | - Multi-cluster   |  | - AWS/GCP/Azure   |                      |
|  |   registration    |  |   API abstraction |                      |
|  | - Config distrib  |  | - Rate card sync  |                      |
|  +-------------------+  +-------------------+                      |
+-------------------------------------------------------------------+
```

### 7.2 API Design

The API is **REST/JSON under `/api/v1/*`** (`pkg/api`). There is no gRPC or GraphQL layer — a dead gRPC contract (`proto/`) that earlier revisions described was removed per [DEC-017](decisions/DEC-017-remove-dead-proto-and-honest-cost-export.md) (no generated code, no importers).

Every route is declared in one table (`pkg/api/routes.go`) that carries, per route: the RBAC action required for reads and writes, a *mutating* marker, and the license feature flag that gates it (DEC-020). `buildMux` walks the table to register handlers; the RBAC and license tests walk the same table, so a route cannot be added without declaring its enforcement. The surface, by area:

```
Cost & flows:      /api/v1/costs*, /api/v1/flows*, top-talkers, trends
Reconciliation:    /api/v1/reconcile            (finops role; "reconciliation" feature)
What-if / CI gate: /api/v1/whatif, /api/v1/cicd/* ("whatif" feature) — fed from live
                   costed flow batches; answers 503 until data has been ingested,
                   never a fake $0 delta
Alerts/anomalies:  /api/v1/alerts*, /api/v1/anomalies ("anomaly" feature)
Recommendations:   /api/v1/recommendations* et al. ("recommendations" feature)
Remediation:       /api/v1/remediations*, /api/v1/autoremediate/*
                   ("remediation" feature; the autoremediation policy write is
                   admin-only — the P8 approval gate)
Multi-cluster:     /api/v1/clusters* ("multicluster" feature; community cap = 1
                   cluster, enforced at registration)
Audit:             /api/v1/audit* ("audit-log" feature; entries are recorded
                   regardless of license)
```

### 7.3 Inter-Component Communication

**NATS JetStream** for agent-to-control-plane communication:

- Subjects: `tollwing.flows.{cluster}.{node}` -- flow aggregates
- Subjects: `tollwing.events.{cluster}.{node}` -- lifecycle events
- Subjects: `tollwing.config.{cluster}` -- config distribution
- JetStream provides at-least-once delivery, replay, and consumer groups
- Agents publish; control plane services consume
- Subject tokens are validated at publisher construction and the agent resolves its cluster/node identity before the first publish ([DEC-019](decisions/DEC-019-cluster-identity-fail-fast-nats-subject.md)) — an empty `-cluster` used to build `tollwing.flows..{node}` and silently drop every batch
- The subscriber `Term`s poison messages, `Nak`s transient failures with exponential backoff, and caps redelivery (`MaxDeliver=5`) — dropped data is logged, never hot-looped (DEC-020)

Why NATS over Kafka: Lower operational complexity, single binary, built-in clustering, sufficient throughput (millions of messages/sec), and NATS is already popular in the cloud-native ecosystem.

---

## 8. ALERTING AND RECOMMENDATIONS

### 8.1 Real-Time Alerting

```
Alert Types:
  1. Cost Anomaly
     - Baseline: rolling 7-day average cost per service per traffic type
     - Alert when: current hour > 3x baseline (configurable)
     - Example: "payment-svc cross-AZ traffic is 5x normal: $12.40/hr vs $2.50/hr avg"

  2. New Traffic Pattern
     - Alert when: a service starts communicating with a new external endpoint
     - Alert when: a new cross-AZ traffic path appears
     - Example: "frontend-svc is now sending 500MB/hr to eu-west-1 (new pattern)"

  3. Cost Budget
     - Per-namespace or per-team monthly budget
     - Alert at 50%, 80%, 100% thresholds
     - Projected overage based on current burn rate

  4. NAT Gateway Surprise
     - Alert when: traffic through NAT gateway exceeds threshold
     - Many teams accidentally route internal traffic through NAT gateways
     - Example: "85% of api-svc egress goes through NAT gateway ($340/day)"

  5. Suboptimal Topology
     - Alert when: >30% of a service's traffic is cross-AZ
     - Suggests enabling topology-aware routing
     - Example: "redis-cache: 67% cross-AZ traffic, enable TopologyAwareHints to save $890/mo"
```

### 8.2 Recommendation Engine

```
Recommendation Categories:

1. Topology Constraints (TopologySpreadConstraints, pod anti-affinity)
   - Detect: service A always talks to service B, but they're in different zones
   - Recommend: co-locate via pod affinity or topology spread constraints
   - Estimated savings: calculate from current cross-AZ bytes * rate

2. Endpoint Slices / Topology Aware Hints
   - Detect: Kubernetes service with backends in multiple zones, clients mostly in one zone
   - Recommend: enable topology-aware hints (service.kubernetes.io/topology-mode: Auto)
   - Estimated savings: cross-AZ bytes that would become same-zone * delta rate

3. VPC Endpoint vs Public Endpoint
   - Detect: traffic to S3/DynamoDB going through NAT gateway or internet
   - Recommend: create VPC Gateway/Interface endpoint
   - Estimated savings: NAT gateway processing charges eliminated

4. NAT Gateway Optimization
   - Detect: internal-to-internal traffic routing through NAT gateway
   - Recommend: fix routing tables or use VPC peering
   - Estimated savings: NAT per-GB charges eliminated

5. Service Mesh Optimization
   - Detect: Envoy sidecar-to-sidecar traffic patterns causing extra hops
   - Recommend: use locality-aware load balancing in Istio
   - Estimated savings: reduced cross-AZ proxy hops

6. Data Transfer Optimization
   - Detect: large data transfers between regions
   - Recommend: consider data replication, caching, or CDN
   - Estimated savings: cross-region rate delta
```

### 8.3 Notification Channels

- **Prometheus Alertmanager:** Native integration, leverages existing routing rules
- **Slack/Teams:** Webhook-based, rich formatting with cost breakdowns
- **PagerDuty/OpsGenie:** For critical cost anomalies
- **Email:** Daily/weekly cost digest reports
- **Custom Webhook:** For integration with internal systems

---

## 9. DASHBOARD / UI

### 9.1 Technology Choice

**React + TypeScript frontend (`ui/`, Vite + Recharts), served by the API server** (Enterprise). This is a standard choice that enables rich interactive visualizations over the REST API. Real-time WebSocket updates and embeddable Grafana panels are **(roadmap)**; the free tier's dashboard story is the 23-panel Grafana dashboard over your own Prometheus (§13.1).

### 9.2 Key Views

```
1. Overview Dashboard
   +--------------------------------------------------+
   |  Total Network Cost: $4,230/day  (+12% vs last)  |
   |                                                    |
   |  [Donut: Cost by Traffic Type]                     |
   |  Cross-AZ: 45%  Internet: 30%  NAT-GW: 15%       |
   |  Cross-Region: 8%  Other: 2%                      |
   |                                                    |
   |  [Bar: Top 10 Services by Cost]                    |
   |  [Line: Cost Trend (7d)]                           |
   |  [Map: Inter-Zone Traffic Flow]                    |
   +--------------------------------------------------+

2. Service Deep Dive
   +--------------------------------------------------+
   |  Service: payment-svc (namespace: production)     |
   |  Monthly Cost: $1,240  Processes: java, envoy     |
   |                                                    |
   |  [Sankey: Traffic flow diagram]                    |
   |  payment-svc -> redis-cache (cross-AZ, $340/mo)   |
   |  payment-svc -> order-svc (same-zone, $0)         |
   |  payment-svc -> stripe.com (internet, $120/mo)    |
   |                                                    |
   |  [Table: Per-connection breakdown]                 |
   |  [Recommendations: 2 active]                       |
   +--------------------------------------------------+

3. Billing Reconciliation
   +--------------------------------------------------+
   |  Month: March 2026                                |
   |  eBPF Measured: $42,300  Cloud Bill: $44,100      |
   |  Accuracy: 95.9%  Unaccounted: $1,800             |
   |                                                    |
   |  [Stacked Area: Daily measured vs billed]          |
   |  [Table: Unaccounted cost breakdown]               |
   +--------------------------------------------------+

4. Process-Level View
   +--------------------------------------------------+
   |  Node: ip-10-0-1-42  Zone: us-east-1a            |
   |                                                    |
   |  [Tree: Process -> Container -> Pod hierarchy]     |
   |  PID 1234 (java) -> container-abc -> payment-pod  |
   |    TX: 2.3 GB/hr  RX: 1.1 GB/hr  Cost: $0.12/hr |
   |  PID 1235 (envoy) -> sidecar-xyz -> payment-pod   |
   |    TX: 2.3 GB/hr  RX: 2.3 GB/hr  Cost: $0.12/hr |
   +--------------------------------------------------+
```

---

## 10. DEPLOYMENT MODEL

### 10.1 Architecture

```
Kubernetes Deployment:

1. DaemonSet: tollwing-agent
   - Runs on every node (or selected nodes via nodeSelector)
   - Privileged: needs CAP_BPF, CAP_SYS_ADMIN (for cgroup attachment)
   - Mounts: /sys/fs/cgroup, /proc (read-only), /sys/kernel/btf
   - Resources: 50m CPU request, 200m limit; 128Mi memory request, 512Mi limit
   - Tolerates all taints (master, GPU, etc.)

2. Deployment: tollwing-server (control plane)
   - 2-3 replicas behind a Service
   - Needs: cloud provider credentials (IAM role / workload identity)
   - Resources: 500m CPU, 1Gi memory

3. StatefulSet: ClickHouse
   - 3 replicas with PVCs
   - OR: use managed ClickHouse (ClickHouse Cloud, Altinity)

4. Deployment: NATS
   - 3-node cluster
   - JetStream enabled with PVCs

5. Optional: Grafana Deployment (if not using existing)
```

### 10.2 Helm Chart Structure

Three charts under `deploy/helm/`, split along the open-core boundary (§13):

```
deploy/helm/
  tollwing-agent/        # the free agent DaemonSet (published):
                         #   daemonset, serviceaccount, clusterrole(+binding),
                         #   configmap, optional cost-export sidecar
  tollwing-server/       # the Enterprise control plane:
                         #   server deployment/service, storage wiring
  tollwing-scheduler/    # Enterprise scheduler integration
```

### 10.3 Operator Pattern (Phase 2)

A Kubernetes operator managing `CostPolicy` and `AlertRule` CRDs:

```yaml
apiVersion: tollwing.io/v1alpha1
kind: CostPolicy
metadata:
  name: production-budget
  namespace: production
spec:
  budget:
    monthly: 5000  # USD
  alerts:
    - threshold: 80
      channel: slack-finops
    - threshold: 100
      channel: pagerduty-oncall
  topologyHints:
    autoEnable: true  # automatically enable topology-aware hints when savings > $100/mo
```

### 10.4 Non-Kubernetes Deployment

For VMs and bare metal:
- **Systemd unit:** `tollwing-agent.service` + `agent.yaml` config (`deploy/systemd/`)
- Metadata enrichment falls back to: IMDS for cloud metadata, `/proc` for process info, no pod/service context
- .deb/.rpm packaging (GoReleaser) and control-plane registration via bootstrap token are **(roadmap)**

Serverless (Lambda/Cloud Functions extension agents, VPC Flow Logs fallback) is **(roadmap)** — nothing ships for it today.

---

## 11. MULTI-CLOUD SUPPORT

### 11.1 Cloud Abstraction Layer

```go
// Provider abstracts cloud-specific operations (pkg/cloud/provider.go).
type Provider interface {
    // Identity
    Name() string  // "aws", "gcp", "azure"
    Region() string
    Zone() string
    AccountID(ctx context.Context) (string, error)

    // Network Topology
    GetSubnetZoneMapping(ctx context.Context) (map[netip.Prefix]string, error)
    GetNATGateways(ctx context.Context) ([]NATGateway, error)
    GetVPCPeerings(ctx context.Context) ([]VPCPeering, error)
    GetTransitGateways(ctx context.Context) ([]TransitGateway, error)
    GetServiceCIDRs(ctx context.Context) (map[string][]netip.Prefix, error)

    // Pricing
    GetRateCard(ctx context.Context, region string) (*cost.RateCard, error)

    // Billing
    GetBillingData(ctx context.Context, start, end time.Time) (*cost.BillingData, error)
}
```

Route-based NAT detection (§4.3) is an *optional* interface (`natRouteDetector`, implemented by AWS today), so providers gain no new required method (P11).

### 11.2 Provider-Specific Differences

Rates below are the defaults verified against provider pricing pages on **2026-07-02** ([DEC-014](decisions/DEC-014-metered-directions-and-marginal-default-pricing.md) has the full table with sources); which *direction* of a flow is billable differs per provider and is carried on the rate card (`Directions`):

| Feature | AWS | GCP | Azure |
|---------|-----|-----|-------|
| Cross-AZ pricing | $0.01/GB **each direction** | $0.01/GiB, billed to the sender | **Free** (inter-AZ charges retired 2024) |
| Internet egress | 100 GB/mo free, then tiered $0.09→$0.05/GB | Tiered $0.12→$0.08/GiB (Premium) | 100 GB/mo free, then tiered $0.087→$0.05/GB |
| NAT Gateway | $0.045/hr + $0.045/GB | Cloud NAT: per-VM-hr + $0.045/GiB | NAT Gateway: $0.045/hr + $0.045/GB |
| VPC Peering | $0.01/GB each direction cross-AZ (free same-AZ, but the peer's AZ is unobservable — priced conservatively at the cross-AZ rate) | Standard inter-zone rates | VNet peering: $0.01/GB in **and** out |
| Zone metadata | IMDS v2 | Metadata server | IMDS (region-qualified ordinals, §4.2) |
| Billing source | CUR (S3 Parquet) | BigQuery export | Cost Management API |
| Metered direction (default table) | cross-AZ/peering/endpoint/NAT: Tx+Rx; egress/cross-region/TGW: Tx | Sender-side (Tx); PSC/NAT per-GB: Tx+Rx | Cross-AZ: none; egress/inter-region: Tx; peering/Private Link: Tx+Rx |

The classifier's decision tree has provider-specific *pricing*, not provider-specific branches: on Azure a cross-AZ classification prices at $0, and on GCP the sender side pays — the classification itself stays honest everywhere (a GCP flow without per-IP zone data is `Unknown`, §4.2).

---

## 12. SECURITY CONSIDERATIONS

### 12.1 Sensitive Data

| Data | Sensitivity | Handling |
|------|-------------|----------|
| Connection 4-tuples | Medium | IP addresses reveal topology. Encrypt at rest, restrict API access. |
| Process names/cmdlines | Medium | May reveal service architecture. Redact in multi-tenant mode. |
| Cloud billing data | High | Contains account-level cost data. Strict RBAC. |
| Cloud API credentials | Critical | Use workload identity / IAM roles, never static keys. |
| BPF programs | Low | Open source, no secrets. |

### 12.2 RBAC Model

```
Roles (pkg/auth/rbac.go; optionally namespace-scoped):
  viewer:    Read cost data, dashboards, recommendations
  approver:  Above + remediation approve/reject/apply (write_deploy)
  finops:    Above + billing reconciliation (read_billing — billing data is
             classified High in §12.1 and is not a viewer read)
  admin:     Every action, including manage_policy — the only role that can
             write the autonomous-remediation policy (the P8 approval gate,
             DEC-020)

Kubernetes RBAC:
  Agent ServiceAccount:
    - get/list/watch: pods, services, endpoints, endpointslices, nodes
    - get: namespaces (for labels)
    - NO write permissions to any workload resources

  Server ServiceAccount:
    - get/list/watch: all of agent's permissions
    - create/update: CostPolicy and AlertRule CRDs
    - get: secrets (for cloud credentials, namespaced)
```

API-surface hardening (DEC-020): handlers return generic 500s with details in `slog` (no driver/SQL internals on the wire, P12); one trusted-proxy-aware client-IP derivation (`-trust-xff`, `-trusted-proxies`, rightmost-entry semantics) feeds both the rate limiter and the audit log; the tamper-evident audit ring is signed (`-audit-signing-key`, else an ephemeral per-process key) and verified from its eviction watermark, so a wrapped ring does not raise a false SOC2 incident.

### 12.3 Agent Security Hardening

- Run as non-root where possible (CAP_BPF + CAP_SYS_ADMIN only, drop everything else)
- Seccomp profile restricting system calls
- Read-only root filesystem
- No network egress except to control plane (NetworkPolicy)
- BPF programs are embedded in the binary (not loaded from disk at runtime), same pattern as our reference eBPF agent's `bpf/bin/` precompiled objects

### 12.4 Data Retention

- Flow-level data: 30 days (configurable)
- Service aggregates: 1 year
- Billing reconciliation: 2 years (for compliance)
- All storage encrypted at rest (ClickHouse + cloud storage encryption)

---

## 13. OPEN SOURCE VS. COMMERCIAL SPLIT

**The authoritative statement of this boundary is [`OPEN-CORE.md`](OPEN-CORE.md)** (adopted per [DEC-013](decisions/DEC-013-open-core-repo-split-allow-list-boundary.md)); if this section and that document ever disagree, `OPEN-CORE.md` governs. Summary:

### 13.1 Open Source (Apache 2.0)

Everything in the public repository ([github.com/tollwing/tollwing](https://github.com/tollwing/tollwing)) is Apache-2.0 and runs standalone — no license key, no phone-home, no control-plane server required:

- The eBPF agent (`tollwing-agent`), in full: the 9-way per-pod classifier, the eBPF data plane (with the BPF sources and vendored build inputs to compile them yourself), pre-DNAT intent capture and service-graph attribution, and list-price cost math (measured bytes × dated rate card, P4)
- Output you already own: `tollwing_*` Prometheus metrics on `:9990/metrics`, the 23-panel Grafana dashboard, and the FOCUS-aligned JSON cost-export sidecar (`opencost-plugin/`)
- `tollwing-terraform` — the standalone Terraform network-cost estimator
- The pure-Go proof suite (`test/sim/`, `make demo`) and the agent Helm chart
- The governance system: `CONSTITUTION.md`, the public decision log, `docs/governance/`, `tools/governance`

Scope of the free tier: **single cluster, AWS**, with retention set by your own Prometheus. It is the complete live per-pod view — not a trial or a teaser build. Per OPEN-CORE.md, **accuracy and honesty fixes are always free** (P4/P5), and nothing that has shipped free ever moves behind the license (the no-rug-pull commitment).

### 13.2 Commercial (Tollwing Enterprise — offline signed license)

The self-hosted control plane built on the same agent, licensed with an offline signed license (no phone-home, air-gappable; DEC-012). Its source lives in the private monorepo and is not published:

- **The control-plane server (`tollwing-server`):** long-term history (ClickHouse), the REST API, the CLI (`tollwing-cli`), the Cost Savings Report
- **Multi-cluster aggregation:** fleet-wide views across clusters
- **CUR reconciliation:** your *actual discounted* rates, drift and accuracy scoring
- **Acting on the data:** alerts, anomaly detection, recommendations, what-if analysis, approval-gated auto-remediation (P8)
- **GCP and Azure** provider support
- **Organizational features:** SSO/RBAC, multi-tenancy, HA, the operator, integrations (Slack, MCP, CI/CD, admission webhook)

These are enforced as license *features* at the API route table (`"multicluster"`, `"reconciliation"`, `"whatif"`, `"anomaly"`, `"remediation"`, `"recommendations"`, `"audit-log"` — §7.2, DEC-020).

### 13.3 Commercial Model

- Open core: free agent, paid self-hosted control plane
- **Not a hosted service:** there is no SaaS offering; agents never ship data to a Tollwing-operated backend. The free tier does not depend on the company existing
- On-premise Enterprise license (offline Ed25519-signed, DEC-012); unlicensed or expired deployments degrade to community features and caps
- The dividing line tracks P1: the agent measures; state, history, cross-cluster correlation, and actions live in the control plane — and the control plane is the commercial product

---

## 14. PROJECT STRUCTURE

Binaries are thin `cmd/<name>/main.go` wrappers; the work lives in flat `pkg/<concern>` packages. Abridged to the load-bearing paths:

```
tollwing/
├── cmd/
│   ├── tollwing-agent/       # DaemonSet agent binary (Linux + eBPF)
│   ├── tollwing-terraform/   # standalone Terraform network-cost estimator
│   ├── tollwing-server/      # control plane (Enterprise)
│   ├── tollwing-cli/         # CLI (Enterprise)
│   └── tollwing-{license,mcp,slack,admission}/   # Enterprise tooling/integrations
├── pkg/
│   ├── ebpf/                 # BPF loading, feature probes, map access
│   │   └── bpf/              # tollwing.bpf.c, quic.bpf.c, dns.bpf.c,
│   │                         # maps.h, Makefile (CO-RE, clang)
│   ├── poller/               # map drains (batch LookupAndDelete), QUIC dedup
│   ├── exporter/             # Prometheus /metrics endpoint
│   ├── agent/                # agent orchestration: config, lifecycle, shutdown order
│   ├── intent/               # two-phase pre-DNAT correlation (DEC-003)
│   ├── classifier/           # TrafficType (canonical enum) + decision tree (§4)
│   ├── cost/                 # rate cards, engine, pricing modes, reconcile
│   ├── cloud/                # Provider interface + aws/ gcp/ azure/
│   ├── k8s/                  # informers: pods, services, EndpointSlices, cluster UID
│   ├── dns/                  # DNS answer cache for destination enrichment
│   ├── nats/                 # JetStream publisher/subscriber
│   ├── api/                  # REST/JSON control-plane API (Enterprise; route table §7.2)
│   ├── auth/                 # OIDC + RBAC (Enterprise)
│   ├── storage/clickhouse/   # warm/cold store (Enterprise, DEC-004)
│   └── …                     # further Enterprise control-plane packages
│                             # (alert, anomaly, recommend, whatif, license, …)
│                             # live only in the private monorepo (§13)
├── opencost-plugin/          # FOCUS-aligned JSON cost-export sidecar (DEC-017)
├── test/sim/                 # pure-Go proof suite + demo (DEC-008)
├── tools/governance/         # index / scan / audit (stdlib-only)
├── decisions/                # ADRs + generated index
├── docs/governance/          # conventions, compatibility, audit playbook
├── deploy/                   # helm/ (tollwing-agent, …), systemd/, kubernetes/, …
├── ui/                       # React dashboard (Enterprise, served by the server)
├── vmlinux/                  # generated kernel BTF headers (vendored)
├── include/                  # BPF helper headers (vendored)
├── Makefile
├── go.mod
└── go.sum
```

There is no `proto/` directory: the API is REST/JSON, and the dead gRPC contract that used to live there was removed per [DEC-017](decisions/DEC-017-remove-dead-proto-and-honest-cost-export.md).

---

## 16. KEY TECHNICAL RISKS AND MITIGATIONS

| Risk | Impact | Mitigation |
|------|--------|------------|
| Kernel version fragmentation | Hooks unavailable on older kernels | Feature probing (our reference eBPF agent pattern) + graceful degradation. Minimum kernel: 5.8. |
| High connection rate overwhelming maps | Lost connections, inaccurate counts | LRU maps auto-evict. Sampling mode for extreme cases. PERCPU maps avoid lock contention. |
| ClusterIP resolution race condition | cgroup/connect4 fires but sock_ops doesn't (connection fails) | LRU map with TTL in cookie_to_original_dst. Stale entries auto-evict. |
| ClickHouse operational complexity | Storage becomes the bottleneck | Offer managed ClickHouse integration. Provide embedded single-node mode for small clusters. |
| Cloud API rate limits | Stale zone/pricing data | Aggressive caching (5-minute refresh). Fan out across agents (one leader per cluster queries cloud API). |
| Service mesh complicating attribution | Double counting (app -> sidecar -> remote sidecar -> app) | Detect Envoy/Linkerd PIDs, attribute traffic to the application process, not the proxy. Mark proxy-to-proxy flows. |
| BPF verifier complexity limits | Programs rejected on older kernels | Tail calls to split logic. Keep individual programs small. Test against kernel 5.8, 5.15, 6.1 LTS. |

---

## 17. INTEGRATION POINTS

| System | Integration Method | Direction |
|--------|-------------------|-----------|
| Prometheus | Scrape endpoint (`:9990/metrics`, free tier) | Export |
| Grafana | 23-panel dashboard over your Prometheus (free); ClickHouse datasource for the Enterprise store | Query |
| External cost tooling | FOCUS-aligned JSON cost-export sidecar (`opencost-plugin/`, [DEC-017](decisions/DEC-017-remove-dead-proto-and-honest-cost-export.md)) — **not** an OpenCost plugin | Export |
| OpenCost | Differential harness (`test/sim/differential`) deploys real OpenCost to *compare against* — it demonstrates the attribution gap, it does not feed OpenCost | Testing |
| Datadog / Splunk | Async event exporters (`pkg/integrations`, Enterprise) | Export |
| Slack | Bot + webhooks (`cmd/tollwing-slack`, Enterprise) | Alerts |
| PagerDuty / OpsGenie / Alertmanager | Alert notifiers (`pkg/alert/notify.go`, Enterprise) | Alerts |
| MCP | `cmd/tollwing-mcp` (Enterprise) | Query |
| CI/CD | Cost gate (`/api/v1/cicd/evaluate`, Enterprise) — 503 until real flow data has been ingested, never a $0 verdict from empty matrices | Gate |
| Admission webhook | `cmd/tollwing-admission` (Enterprise) | Gate |
| Terraform | `tollwing-terraform` estimates a plan's network cost from the same rate cards (free) | Estimate |
| Kubecost data import, OTLP metric export | **(roadmap)** | Import/Export |

---

This architecture addresses the gaps identified in the market research: process-level attribution (via PID capture in BPF hooks), accurate cross-AZ classification (via the cgroup/connect4 pre-DNAT technique), eBPF + billing reconciliation (via CUR/BigQuery integration, Enterprise), connection-level cost attribution (via socket cookie keyed maps), and real-time alerting (via streaming anomaly detection, Enterprise). Non-Kubernetes support beyond the systemd unit is roadmap (§10.4).

The critical technical innovation is the two-phase capture using `cgroup/connect4` (pre-DNAT) + `sock_ops` (post-DNAT) to solve the ClusterIP problem that Kubecost cannot solve. This, combined with in-kernel aggregation via PERCPU_HASH maps, keeps overhead under 1% while providing connection-level granularity.

