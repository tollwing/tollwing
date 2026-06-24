# Tollwing: eBPF-Based Cloud Network Cost Optimization Platform

## Complete Architecture Document

---

> **Editions.** This document describes the full Tollwing system. The free, Apache-2.0 **open-source edition is the agent**: it attributes per-pod network cost across the 9 AWS billing paths and exposes `tollwing_*` Prometheus metrics that your Grafana reads directly, with no control-plane server. The **control plane** described below (the API server, ClickHouse storage, the alert/anomaly engine, recommendations, what-if, auto-remediation, multi-cluster aggregation, GCP/Azure, SSO/RBAC) is **Tollwing Enterprise** (self-hosted, license-gated, early access) and is not part of the open-source tree.

---

## 1. HIGH-LEVEL ARCHITECTURE

```
+-----------------------------------------------------------------------------------+
|                              CONTROL PLANE                                         |
|  +------------------+  +------------------+  +------------------+                  |
|  |   API Server     |  |  Cost Engine     |  |  Alert Engine    |                  |
|  |   (Go, gRPC+HTTP)|  |  (Go)            |  |  (Go)            |                  |
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
|  |  | tracepoint:      |  | fentry:          |                      |             |
|  |  | sock/inet_sock   |  | nf_conntrack     |                      |             |
|  |  | _set_state       |  | _confirm         |                      |             |
|  |  | (state changes)  |  | (NAT resolution) |                      |             |
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
| `sock_ops` | `BPF_PROG_TYPE_SOCK_OPS` | Connection lifecycle events (established, close) | You already use this in our reference eBPF agent. Fires on `ACTIVE_ESTABLISHED_CB`, `PASSIVE_ESTABLISHED_CB`, `STATE_CB`. Gives 4-tuple + socket cookie. |
| `cgroup/connect4` / `cgroup/connect6` | `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` | Capture pre-NAT destination for ClusterIP resolution | **This is the critical hook Kubecost misses.** Fires BEFORE kube-proxy DNAT, so you see the original ClusterIP:port, not the pod IP. |
| `kprobe/tcp_sendmsg` | kprobe | Byte counting per socket | Captures exact bytes sent per `sock`. Combined with socket cookie, gives per-connection egress bytes. |
| `kprobe/tcp_cleanup_rbuf` | kprobe | Byte counting for received data | Captures bytes received. Combined with sendmsg, gives full bidirectional byte accounting. |

**Secondary Hooks (optional, for enhanced accuracy):**

| Hook | Type | Purpose | Kernel Req |
|------|------|---------|------------|
| `fentry/nf_conntrack_confirm` | fentry/fexit | Capture conntrack NAT mapping (pre-DNAT -> post-DNAT) | 5.11+ |
| `tracepoint/sock/inet_sock_set_state` | tracepoint | TCP state transitions (SYN_SENT, ESTABLISHED, CLOSE_WAIT, etc.) | 4.16+ |
| `cgroup/sock_release` | cgroup | Detect socket close for final byte tallying | 5.8+ |
| `fentry/ip_route_output_flow` | fentry | Capture routing decisions (which interface, next hop) for egress classification | 5.11+ |

**NOT using XDP:** XDP fires too early (before socket association), so you cannot attribute traffic to processes. XDP is useful for packet-level inspection but not for cost attribution. The overhead of copying full packets is also unacceptable.

**NOT using tc/cls_bpf:** Same problem as XDP for attribution. Useful only if you need to inspect packet headers for protocol classification, which is better done at the socket level.

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

For service meshes (Istio/Linkerd), the same approach works because `cgroup/connect4` fires before the sidecar proxy's iptables rules redirect traffic. If the mesh uses eBPF (Cilium), we detect this and read Cilium's own maps for service identity.

### 2.3 BPF Map Architecture

```c
// ====== CONNECTION TRACKING ======

// Primary connection table. Keyed by socket cookie (u64).
// Updated on establish, read on byte count, deleted on close.
struct conn_info {
    u32 src_ip;
    u32 dst_ip;
    u32 original_dst_ip;    // pre-DNAT (ClusterIP), 0 if no DNAT
    u16 src_port;
    u16 dst_port;
    u16 original_dst_port;  // pre-DNAT port
    u32 pid;                // tgid from bpf_get_current_pid_tgid()
    u32 cgroupid;           // from bpf_get_current_cgroup_id()
    u64 start_ns;           // bpf_ktime_get_ns()
    u64 tx_bytes;           // atomically updated by tcp_sendmsg hook
    u64 rx_bytes;           // atomically updated by tcp_cleanup_rbuf hook
    u8  protocol;           // TCP=6, UDP=17
    u8  state;              // current TCP state
    u8  direction;          // 0=outgoing, 1=incoming
    u8  reserved;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 524288);  // 512K connections
    __type(key, u64);             // socket cookie
    __type(value, struct conn_info);
} connections SEC(".maps");

// ====== PRE-DNAT RESOLUTION ======

// Populated by cgroup/connect4, read by sock_ops.
// Short-lived: entries removed after sock_ops reads them.
struct original_dst {
    u32 ip;
    u16 port;
    u16 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);              // socket cookie
    __type(value, struct original_dst);
} cookie_to_original_dst SEC(".maps");

// ====== AGGREGATION (in-kernel rollup) ======

// Per-flow byte counters, flushed to userspace periodically.
// Key is a 5-tuple hash. Value accumulates bytes.
// This reduces perf event volume by 100-1000x.
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

struct flow_metrics {
    u64 tx_bytes;
    u64 rx_bytes;
    u64 conn_count;
    u64 last_updated_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 131072);  // 128K unique flows per CPU
    __type(key, struct flow_key);
    __type(value, struct flow_metrics);
} flow_aggregates SEC(".maps");

// ====== CONFIGURATION ======

struct agent_config {
    u8  enabled;
    u8  track_udp;         // also hook UDP (for DNS cost attribution)
    u8  sample_rate;       // 1 = every conn, N = 1/N sampling for high throughput
    u8  reserved[5];
    u64 aggregation_ns;    // flush interval (default: 5s = 5_000_000_000)
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct agent_config);
} agent_config SEC(".maps");

// ====== EVENTS (for connection lifecycle, not byte counting) ======

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);  // 4MB ring buffer
} events SEC(".maps");
```

### 2.4 Performance Budget: Staying Under 1% CPU

**Strategy 1: In-kernel aggregation.** The `flow_aggregates` PERCPU_HASH map accumulates bytes in-kernel. Instead of emitting a perf event per `tcp_sendmsg` call (which on a busy node could be millions/sec), we just increment counters. Userspace reads and resets these maps on a 5-second interval.

**Strategy 2: Ring buffer, not perf events.** Use `BPF_MAP_TYPE_RINGBUF` (kernel 5.8+) instead of perf event arrays. Ring buffers have lower overhead: no per-CPU allocation, no wakeup per event. Reserve + commit pattern avoids copies.

**Strategy 3: Sampling for extreme throughput.** The `sample_rate` config field allows 1/N sampling on connection establishment for nodes handling millions of short-lived connections. Byte counters still accumulate accurately for sampled connections.

**Strategy 4: Tail calls for complex logic.** Split the sock_ops program into a dispatcher + tail-called handlers. This keeps each program small (staying within the BPF verifier's instruction limit) and avoids branching overhead.

**Strategy 5: LRU maps with appropriate sizing.** LRU eviction means we never block on a full map. Size connections at 512K entries (about 40MB of kernel memory), which covers even the busiest nodes.

**Measured overhead expectation:** Based on comparable tools (Cilium Hubble, Pixie), the combined overhead of sock_ops + kprobe/tcp_sendmsg + kprobe/tcp_cleanup_rbuf + in-kernel aggregation should be 0.1-0.5% CPU on a node handling 100K active connections.

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
|                                      | NATS /     |                |
|                                      | gRPC Export|                |
|                                      +-----------+                |
+-------------------------------------------------------------------+
```

### 3.3 Component Breakdown

**BPF Loader** (pattern from our reference eBPF agent's `Manager`):
- Loads CO-RE objects via `cilium/ebpf.LoadCollectionSpecFromReader`
- Probes kernel features (extending our reference eBPF agent's `features.go` pattern)
- Graceful degradation: if `fentry/nf_conntrack_confirm` is unavailable, fall back to `cgroup/connect4`-only mode
- Pushes config to BPF maps (same pattern as our reference eBPF agent's `pushConfig()`)

**Map Poller:**
- Runs on a configurable tick (default 5s)
- Iterates `flow_aggregates` PERCPU_HASH, sums per-CPU values, resets entries
- Reads `connections` map for new/closed connections via ring buffer
- Batch iteration with `MapBatchLookupAndDelete` for efficiency

**Metadata Cache** (the enrichment layer):
- **Process metadata:** `/proc/<pid>/cgroup` to get container ID, `/proc/<pid>/comm` and `/proc/<pid>/cmdline` for process name. Cached by PID with TTL.
- **Container/Pod metadata:** Kubernetes informer (client-go SharedInformerFactory) watching Pods. Maps container ID to pod name, namespace, labels, node, zone. For non-K8s: Docker API or containerd CRI.
- **Zone resolution:** On startup, query IMDS (AWS: `http://169.254.169.254/latest/meta-data/placement/availability-zone`, GCP: metadata server, Azure: IMDS). Cache the local node's zone. For remote IPs, resolve via the Kubernetes Node object's `topology.kubernetes.io/zone` label.
- **Service resolution:** Watch Kubernetes Services and Endpoints/EndpointSlices. Build a reverse map: pod IP:port -> service name. Combined with the pre-DNAT capture from `cgroup/connect4`, gives full service attribution.

**Traffic Classifier** (see Section 4 in detail).

**Aggregator:**
- Rolls up flow-level data into service-level, namespace-level, and cluster-level summaries
- Produces three tiers: raw flows (short retention), service aggregates (medium retention), cost summaries (long retention)

**Exporters:**
- Prometheus remote write (for Grafana integration)
- NATS JetStream publish (for control plane consumption)
- Local Prometheus `/metrics` endpoint for scraping
- Optional OTLP export

### 3.4 Process-Level Attribution

The `pid` captured by `bpf_get_current_pid_tgid()` in the sock_ops/kprobe hooks gives the kernel thread group ID. The enrichment pipeline maps this to:

```
PID -> /proc/<pid>/cgroup -> container ID
     -> container ID -> (pod, namespace, labels) via K8s informer
     -> /proc/<pid>/comm -> process name (e.g., "envoy", "nginx", "java")
     -> /proc/<pid>/cmdline -> full command line
```

For non-containerized workloads (VMs), the PID directly gives the process. For serverless (Lambda, Cloud Functions), the agent runs as a sidecar extension and captures the function invocation context.

---

## 4. TRAFFIC CLASSIFICATION ENGINE

This is the core differentiator. The classifier must determine the traffic type for every flow with zero guesswork.

### 4.1 Classification Decision Tree

```
For each flow (src_ip, dst_ip, original_dst_ip, src_zone, dst_zone):

1. Is dst_ip a private IP (RFC 1918 / RFC 4193)?
   |
   +-- YES: Internal traffic
   |   |
   |   +-- Is src_zone == dst_zone?
   |   |   +-- YES: SAME_ZONE (free on all clouds)
   |   |   +-- NO:  Is same region?
   |   |       +-- YES: CROSS_AZ (charged on AWS/Azure, free on GCP intra-region)
   |   |       +-- NO:  CROSS_REGION (charged everywhere)
   |   |
   |   +-- Is dst_ip a known NAT gateway internal IP?
   |       +-- YES: Reclassify based on NAT gateway's actual destination
   |
   +-- NO: External traffic
       |
       +-- Is dst_ip in a known VPC peering CIDR?
       |   +-- YES: VPC_PEERING (charged per GB on AWS)
       |
       +-- Is dst_ip in a known Transit Gateway CIDR?
       |   +-- YES: TRANSIT_GATEWAY (charged per GB + per hour)
       |
       +-- Does the route go through a NAT Gateway?
       |   +-- YES: NAT_GATEWAY_EGRESS (charged per GB + per hour)
       |   +-- NO:  INTERNET_EGRESS (charged per GB, tiered pricing)
       |
       +-- Is dst_ip a cloud service endpoint (S3, DynamoDB, etc.)?
           +-- YES: Is it a VPC endpoint or public endpoint?
               +-- VPC_ENDPOINT: cheaper
               +-- PUBLIC_ENDPOINT: charged as internet egress
```

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
|      |                   (populated from cloud API on startup) |
|      v                                                         |
|  [Cloud API Fallback]  -- Query cloud API for subnet/zone     |
|      |                    Cache result. Rate-limited.          |
|      v                                                         |
|  [Unknown]  -- Mark as UNKNOWN, alert, request manual config   |
+---------------------------------------------------------------+
```

The CIDR-to-zone map is the key innovation. On startup, the agent queries:
- **AWS:** `ec2:DescribeSubnets` to get subnet CIDR -> AZ mapping
- **GCP:** `compute.subnetworks.list` for subnet -> region mapping (GCP does not charge cross-AZ within a region, so region granularity suffices)
- **Azure:** `network/virtualNetworks` API for subnet -> zone mapping

This map is refreshed every 5 minutes and shared across agents via the control plane.

### 4.3 NAT Gateway Detection

NAT gateways are invisible at the socket layer. The agent detects NAT gateway traffic by:

1. Reading the routing table (`ip route get <dst>`) to check if a route goes through a known NAT gateway IP
2. On AWS: Querying `ec2:DescribeNatGateways` to get NAT gateway ENI IPs
3. Correlating: if a flow's next hop matches a NAT gateway ENI, classify as NAT_GATEWAY_EGRESS
4. The optional `fentry/ip_route_output_flow` hook gives real-time routing decisions without shelling out

### 4.4 VPC Peering and Transit Gateway Detection

On startup, query:
- **AWS:** `ec2:DescribeVpcPeeringConnections`, `ec2:DescribeTransitGatewayAttachments`
- Map peering CIDRs and TGW attachment CIDRs into the classifier's lookup table
- Any flow destined to a peering CIDR is classified as VPC_PEERING
- Any flow routed through a TGW attachment is TRANSIT_GATEWAY

---

## 5. COST CALCULATION ENGINE

### 5.1 Rate Card Model

```go
// TrafficType enumeration
type TrafficType int
const (
    SameZone TrafficType = iota
    CrossAZ
    CrossRegion
    InternetEgress
    NATGateway
    VPCPeering
    TransitGateway
    VPCEndpoint
    CloudServicePublic
)

// RateCard holds per-GB pricing for a cloud provider + region
type RateCard struct {
    Provider    string            // "aws", "gcp", "azure"
    Region      string            // "us-east-1"
    Rates       map[TrafficType]TieredRate
    NATGateway  NATGatewayRate    // per-hour + per-GB
    TransitGW   TransitGWRate     // per-attachment-hour + per-GB
    LastUpdated time.Time
}

// TieredRate supports volume-based pricing (e.g., AWS internet egress)
type TieredRate struct {
    Tiers []Tier  // sorted by threshold ascending
}

type Tier struct {
    UpToGB  float64  // cumulative GB threshold (math.Inf for last tier)
    PerGB   float64  // price per GB in this tier
}
```

### 5.2 Rate Card Sources

| Provider | Data Source | Update Frequency |
|----------|-----------|-----------------|
| AWS | AWS Price List API (`/offers/v1.0/aws/AmazonEC2/current/`) + Savings Plans API | Daily |
| GCP | Cloud Billing Catalog API (`services.skus.list`) | Daily |
| Azure | Retail Prices API (`https://prices.azure.com/api/retail/prices`) | Daily |

**Committed/Reserved Pricing:** The cost engine queries:
- AWS: Savings Plans utilization via Cost Explorer API
- GCP: Committed Use Discounts via Billing API
- Azure: Reserved Instance utilization via Consumption API

And applies the effective rate (not list rate) to traffic calculations.

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

AWS billing integration:
- **Cost and Usage Report (CUR):** S3-delivered Parquet files, contains per-resource-hour costs. Parse `lineItem/UsageType` for `DataTransfer-*` line items.
- **Cost Explorer API:** For on-demand queries. Rate-limited; cache aggressively.

GCP:
- **BigQuery Billing Export:** Standard export dataset. Query `service.description = "Compute Engine"` and `sku.description LIKE "%Egress%"`.

Azure:
- **Cost Management API:** `/query` endpoint for custom date ranges.

### 5.4 Handling Managed Services

For traffic to/from managed services (RDS, ElastiCache, S3, etc.):
- The agent running on the node sees outbound connections to managed service IPs
- Classify by matching destination IP against known cloud service CIDR ranges (published by each cloud)
- AWS publishes `ip-ranges.json`; GCP publishes IP ranges; Azure publishes Service Tags
- Attribute the cost to the pod/process that initiated the connection

For serverless (Lambda):
- Deploy the agent as a Lambda extension (lightweight sidecar)
- Uses the same eBPF hooks but scoped to the function's cgroup
- Reports per-invocation traffic costs

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
    traffic_type    Enum8('same_zone'=0, 'cross_az'=1, 'cross_region'=2,
                          'internet_egress'=3, 'nat_gateway'=4,
                          'vpc_peering'=5, 'transit_gateway'=6),
    tx_bytes        UInt64,
    rx_bytes        UInt64,
    connections     UInt32,
    cost_usd        Float64
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (cluster, src_namespace, dst_service, timestamp)
TTL timestamp + INTERVAL 30 DAY;

-- Service cost summary (materialized view, automatic rollup)
CREATE MATERIALIZED VIEW service_costs_hourly
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (cluster, src_namespace, src_pod, dst_service, traffic_type, hour)
AS SELECT
    toStartOfHour(timestamp) as hour,
    cluster, src_namespace, src_pod, dst_service, traffic_type,
    sum(tx_bytes) as tx_bytes,
    sum(rx_bytes) as rx_bytes,
    sum(connections) as connections,
    sum(cost_usd) as cost_usd,
    timestamp
FROM flows
GROUP BY hour, cluster, src_namespace, src_pod, dst_service, traffic_type, timestamp;
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
|  | - gRPC (internal) |  | - Rate card mgmt  |                      |
|  | - REST (external) |  | - Billing recon   |                      |
|  | - GraphQL (UI)    |  | - Cost allocation |                      |
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

```
gRPC Services:
  FlowService:
    - QueryFlows(timerange, filters) -> FlowStream
    - GetTopTalkers(timerange, groupBy) -> TopTalkers

  CostService:
    - GetCostBreakdown(timerange, groupBy, filters) -> CostBreakdown
    - GetCostTrend(timerange, granularity) -> TimeSeries
    - GetReconciliationReport(month) -> ReconciliationReport

  AlertService:
    - ListAlerts(filters) -> AlertList
    - CreateAlertRule(rule) -> AlertRule
    - AcknowledgeAlert(id) -> Ack

  RecommendationService:
    - GetRecommendations(scope) -> RecommendationList
    - GetSavingsEstimate(recommendation_id) -> SavingsEstimate

  ClusterService:
    - RegisterCluster(cluster) -> ClusterRegistration
    - ListClusters() -> ClusterList
    - GetClusterHealth(id) -> HealthStatus

  ConfigService:
    - GetAgentConfig(cluster, node) -> AgentConfig
    - UpdateAgentConfig(cluster, config) -> Ack

REST/GraphQL: Thin layer over gRPC for dashboard consumption.
```

### 7.3 Inter-Component Communication

**NATS JetStream** for agent-to-control-plane communication:

- Subjects: `tollwing.flows.{cluster}.{node}` -- flow aggregates
- Subjects: `tollwing.events.{cluster}.{node}` -- lifecycle events
- Subjects: `tollwing.config.{cluster}` -- config distribution
- JetStream provides at-least-once delivery, replay, and consumer groups
- Agents publish; control plane services consume

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

**React + TypeScript frontend, served by the API server.** This is a standard choice that enables:
- Rich interactive visualizations (D3.js or Recharts for Sankey diagrams)
- Real-time updates via WebSocket subscription
- Embeddable panels for Grafana (via iframe or Grafana plugin)

Alternatively, ship a full Grafana plugin for teams that prefer Grafana-native. The ClickHouse datasource plugin already exists.

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

```
tollwing/
  Chart.yaml
  values.yaml
  templates/
    agent/
      daemonset.yaml
      serviceaccount.yaml
      clusterrole.yaml        # RBAC for node, pod, service, endpoint watching
      clusterrolebinding.yaml
      configmap.yaml           # agent config
    server/
      deployment.yaml
      service.yaml
      ingress.yaml
      configmap.yaml
      secret.yaml              # cloud credentials
    storage/
      clickhouse-statefulset.yaml  (optional, can use external)
      nats-statefulset.yaml        (optional, can use external)
    crds/
      costpolicy-crd.yaml     # CRD for cost policies / budgets
      alertrule-crd.yaml      # CRD for alert rules
    operator/                  # Optional: Kubernetes operator
      controller-deployment.yaml
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
- **Systemd unit:** `tollwing-agent.service`
- **Package:** .deb and .rpm packages via GoReleaser (same pattern as our reference eBPF agent's `.github/workflows/release.yaml`)
- **Config:** YAML file at `/etc/tollwing/agent.yaml`
- Metadata enrichment falls back to: IMDS for cloud metadata, `/proc` for process info, no pod/service context
- Registration with control plane via agent bootstrap token

For serverless:
- **AWS Lambda:** Lambda Layer containing the agent binary, invoked as extension
- **GCP Cloud Functions:** Similar layer/sidecar approach
- Limited eBPF support in serverless; fall back to VPC Flow Logs ingestion

---

## 11. MULTI-CLOUD SUPPORT

### 11.1 Cloud Abstraction Layer

```go
// CloudProvider abstracts cloud-specific operations
type CloudProvider interface {
    // Identity
    GetRegion() string
    GetZone() string
    GetAccountID() string

    // Network Topology
    GetSubnetZoneMapping() (map[string]string, error)  // CIDR -> zone
    GetNATGateways() ([]NATGateway, error)
    GetVPCPeerings() ([]VPCPeering, error)
    GetTransitGateways() ([]TransitGateway, error)
    GetServiceCIDRs() (map[string][]string, error)  // service name -> CIDRs

    // Pricing
    GetRateCard(region string) (*RateCard, error)
    GetCommittedUsePricing() (*CommittedPricing, error)

    // Billing
    GetBillingData(start, end time.Time) (*BillingData, error)
}
```

### 11.2 Provider-Specific Differences

| Feature | AWS | GCP | Azure |
|---------|-----|-----|-------|
| Cross-AZ pricing | $0.01/GB each way | Free (intra-region) | $0.01/GB each way |
| Internet egress | Tiered: $0.09-$0.05/GB | Tiered: $0.085-$0.05/GB | Tiered: $0.087-$0.05/GB |
| NAT Gateway | $0.045/hr + $0.045/GB | Cloud NAT: $0.045/GB | NAT Gateway: $0.045/hr + per GB |
| VPC Peering | Free same-region, $0.01/GB cross-region | Free same-region | Free same-region, per-GB cross |
| Zone metadata | IMDS v2 | Metadata server | IMDS |
| Billing source | CUR (S3 Parquet) | BigQuery export | Cost Management API |
| Service CIDRs | `ip-ranges.json` | Published ranges | Service Tags |

The classifier's decision tree has provider-specific branches. On GCP, cross-AZ within a region is free, so the classifier only cares about cross-region. On AWS/Azure, cross-AZ is significant cost.

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
Roles:
  viewer:      Read dashboards, view costs
  team-lead:   Above + view own namespace costs, set budgets
  finops:      Above + view all namespaces, billing reconciliation
  admin:       Above + manage agent config, alert rules, cloud credentials
  super-admin: Above + multi-cluster management

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

### 13.1 Open Source (Apache 2.0)

Core functionality that establishes the project and builds community:

- eBPF agent with all hooks (sock_ops, cgroup/connect, kprobes)
- Connection tracking with process-level attribution
- Traffic classification (same-zone, cross-AZ, cross-region, internet)
- ClusterIP / pre-DNAT resolution
- Prometheus metrics export
- Local node dashboard
- Single-cluster mode
- CLI tool for ad-hoc queries
- AWS support (most popular cloud)
- Helm chart for single-cluster deployment
- Basic alerting (threshold-based)

### 13.2 Commercial (License: BSL or proprietary)

Advanced features requiring significant ongoing investment:

- **Multi-cluster management:** Central control plane, fleet-wide views
- **Billing reconciliation:** Cloud billing API integration, drift analysis
- **Advanced recommendations:** Automated topology optimization, what-if analysis
- **Anomaly detection:** ML-based anomaly detection (not just threshold)
- **Multi-cloud:** GCP and Azure provider support
- **SSO/SAML:** Enterprise authentication
- **Role-based dashboards:** Custom views per team/namespace
- **SLA reporting:** Uptime, accuracy guarantees
- **Dedicated support:** Engineering support channel
- **Long-term storage:** Managed ClickHouse, S3-tiered cold storage
- **Compliance:** SOC2, audit logging

### 13.3 Monetization Strategy

- Open core model: free agent, paid control plane
- Cloud-hosted SaaS option (agents ship data to managed backend)
- On-premise enterprise license
- Pricing: per-node/month for the agent fleet

---

## 14. PROJECT STRUCTURE

```
tollwing/
├── cmd/
│   ├── agent/              # DaemonSet agent binary
│   │   └── main.go
│   ├── server/             # Control plane server binary
│   │   └── main.go
│   └── cli/                # CLI tool (tollwingctl)
│       └── main.go
├── pkg/
│   ├── ebpf/               # eBPF program management (mirrors our reference eBPF agent/pkg/ebpf)
│   │   ├── bpf/
│   │   │   ├── sockops.bpf.c
│   │   │   ├── connect.bpf.c    # cgroup/connect4 for pre-DNAT
│   │   │   ├── tcpcount.bpf.c   # kprobe tcp_sendmsg/cleanup_rbuf
│   │   │   ├── conntrack.bpf.c  # fentry nf_conntrack (optional)
│   │   │   ├── maps.h
│   │   │   ├── common.h
│   │   │   └── Makefile
│   │   ├── loader.go
│   │   ├── features.go
│   │   ├── poller.go        # map batch reader
│   │   └── types.go
│   ├── enricher/            # Metadata enrichment
│   │   ├── process.go       # PID -> process info from /proc
│   │   ├── container.go     # container ID -> container runtime
│   │   ├── kubernetes.go    # K8s informer-based enrichment
│   │   ├── zone.go          # IP -> zone resolution
│   │   └── service.go       # endpoint -> service mapping
│   ├── classifier/          # Traffic classification
│   │   ├── classifier.go    # Main classification engine
│   │   ├── cidr.go          # CIDR-based lookup tables
│   │   ├── nat.go           # NAT gateway detection
│   │   └── types.go
│   ├── cost/                # Cost calculation
│   │   ├── engine.go
│   │   ├── ratecard.go
│   │   ├── tiered.go
│   │   └── reconcile.go
│   ├── cloud/               # Cloud provider abstraction
│   │   ├── provider.go      # Interface
│   │   ├── aws/
│   │   ├── gcp/
│   │   └── azure/
│   ├── storage/             # Storage layer
│   │   ├── clickhouse/
│   │   └── prometheus/
│   ├── alert/               # Alert engine
│   │   ├── engine.go
│   │   ├── anomaly.go
│   │   └── notify/
│   ├── recommend/           # Recommendation engine
│   │   ├── topology.go
│   │   ├── endpoint.go
│   │   └── natgw.go
│   ├── api/                 # gRPC + REST API
│   │   ├── grpc/
│   │   ├── rest/
│   │   └── graphql/
│   └── agent/               # Agent orchestration
│       ├── agent.go         # Main agent lifecycle (like our reference eBPF agent's engine.Engine)
│       └── config.go
├── proto/                   # Protobuf definitions
│   ├── flow.proto
│   ├── cost.proto
│   └── alert.proto
├── deploy/
│   ├── helm/
│   │   └── tollwing/
│   ├── systemd/
│   └── lambda/
├── ui/                      # React dashboard
├── vmlinux/                 # vmlinux headers (same as our reference eBPF agent)
├── include/                 # BPF helper headers (same as our reference eBPF agent)
├── Makefile
├── go.mod
└── go.sum
```

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
| Prometheus | Remote write + scrape endpoint | Export |
| Grafana | ClickHouse datasource + optional plugin | Query |
| Datadog | DogStatsD metrics + custom check | Export |
| Slack | Webhook | Alerts |
| PagerDuty | Events API v2 | Alerts |
| OpsGenie | API | Alerts |
| Terraform | Provider for CostPolicy CRDs | Config |
| Kubecost | Import existing Kubecost data for migration | Import |
| OpenCost | Compatible Prometheus metrics | Export |
| OTLP/OpenTelemetry | OTLP exporter for traces/metrics | Export |

---

This architecture addresses all six gaps identified in the market research: process-level attribution (via PID capture in BPF hooks), accurate cross-AZ classification (via the cgroup/connect4 pre-DNAT technique), eBPF + billing reconciliation (via CUR/BigQuery integration), connection-level cost attribution (via socket cookie keyed maps), real-time alerting (via streaming anomaly detection), and non-Kubernetes support (via systemd/Lambda deployment paths).

The critical technical innovation is the two-phase capture using `cgroup/connect4` (pre-DNAT) + `sock_ops` (post-DNAT) to solve the ClusterIP problem that Kubecost cannot solve. This, combined with in-kernel aggregation via PERCPU_HASH maps, keeps overhead under 1% while providing connection-level granularity.

