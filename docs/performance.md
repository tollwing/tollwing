# Tollwing performance: design budget, methodology, and measurements

**The one-line version:** the agent overhead figure quoted in public —
**0.1–0.5% of one core per node** — is a **design budget**, not a benchmark
result. This document states exactly what has been measured, on what rig,
and what has not been measured yet. *(Last revised 2026-07-02.)*

The honesty rule the cost engine lives by (P4: every dollar traceable)
applies to performance claims too: every number here is either a
measurement with its rig stated, or a budget labeled as a budget.

## 1. The headline number, honestly

The **0.1–0.5%-of-one-core** figure on tollwing.com and in
[`README.md`](../README.md) is the agent's **overhead budget**
([`ARCHITECTURE.md`](../ARCHITECTURE.md) §2.4): an expectation derived from
the mechanism (socket-level eBPF hooks + in-kernel PERCPU aggregation, so
there is no per-packet userspace handoff) and from published numbers for
comparable-but-heavier tools (Pixie publishes <5%, typically <2%, for full
protocol tracing, which is far heavier than flow accounting).

**The agent's CPU under sustained production load has not been measured
yet, and no number in this document is that number.** We will publish a
measured figure only alongside a reproducible benchmark — `make bench`-style,
with instance type, kernel version, and flow rate stated. That benchmark is
on the roadmap; until it lands, every public claim stays in budget voice.

One figure below invites misreading, so its exact label goes up front:
**"0.56% of one core" is the Enterprise control-plane server, idle, sampled
over 40 seconds** on the rig in §3. It is not the agent, and it is not a
load number. The same server under a 16,860 req/s synthetic flood used
~30% of one core.

## 2. What is and isn't measured

| Question | Status |
|---|---|
| Agent memory footprint & stability (9-day idle soak + 2 h load) | **Measured** (§4) |
| Agent CPU under sustained load | **Not measured** — design budget only (§1) |
| Enterprise server footprint / throughput / latency / chaos | **Measured** (§5–§7) — the server is not part of the free install |
| Hot-path microbenchmarks | **Measured** (§8) |
| Agent-side throughput at 10k+ flows/sec | **Not measured** (needs a flood generator) |
| 24 h+ soak *under load* | **Not measured** (the 9-day soak was idle) |
| Real NATS JetStream + ClickHouse stack end-to-end | **Not measured** (kind rig is memory-constrained; needs a 5+ node staging cluster) |

## 3. The rig (methodology)

Every measurement below is a real measurement — nothing simulated. The rig,
however, is a laptop-hosted kind cluster, not a production cloud node:

- 3-node **kind** cluster on Apple M1 Max (10 CPU / 32 GB host; 4 CPU /
  8 GB per node), Linux kernel 6.6.
- **Agent:** live DaemonSet on all 3 nodes, running continuously for 9 days
  idle, then 2 hours of realistic microservice traffic (RPC + DNS +
  external egress; 1,193 concurrently active connections; 443,815
  connections handled).
- **Server (Enterprise control plane):** k6 0.49.0 as an in-cluster Job,
  three scenarios in parallel (§6), rate limit raised to 50k/s so the
  limiter wouldn't cap the test.
- Memory read from `/proc/<pid>/status` (`VmRSS`/`RssAnon`/`RssFile`) and
  cgroup `memory.current`; CPU from cgroup usage deltas over the stated
  windows.

Treat these numbers as evidence of resource *behavior* — footprint,
stability, leak-freedom — not as a prediction of overhead on your nodes.
The point of an open agent is that you can measure it on your own nodes.

## 4. Agent: measured memory footprint & stability

**9-day idle baseline (no traffic):**

| Metric | Value |
|--------|-------|
| `VmRSS` | 45.9 MB |
| `RssAnon` (actual heap) | 16.3 MB |
| `RssFile` (text + ro data) | 29.7 MB |
| `VmSwap` | 0 |
| Threads | 12 |
| Open FDs | 51 |

**Under load** (1,193 active connections, 443,815 connections handled,
RPC + DNS + external egress traffic):

| Metric | Value |
|--------|-------|
| `VmRSS` | 34.4 MB (the OS reclaimed 11 MB of file-backed pages) |
| `RssAnon` | 18.1 MB |
| Threads | 12 (stable) |
| Open FDs | 51 (stable) |

**Key observations:**

- After 9 days of continuous idle runtime, the agent's anonymous heap grew
  exactly **0 MB**. No leaks.
- `RssAnon` grew by 2 MB across 443k connections — per-connection userspace
  overhead is effectively zero because aggregation happens in-kernel in the
  `flow_aggregates` PERCPU_HASH map.
- File-backed pages (text + read-only data) shrank under memory pressure,
  exactly as designed.
- Zero swap, zero OOMs across all 3 nodes for 9+ days.

**What this section does not show:** agent CPU. The rig's traffic level is
far below the 100K-active-connection node the §1 budget is stated against,
so a CPU% from this rig would flatter us; we won't quote one until the
reproducible benchmark exists.

## 5. Enterprise control-plane server footprint

Everything in §5–§7 measures `tollwing-server`, the **Enterprise control
plane**. It does not run in the free, agent-only install and it is not the
agent — no number here says anything about per-node agent overhead.

Binary: 35 MB statically linked Go. Container image: **37.5 MB**
(distroless base + binary). No shell, no package manager, runs as UID 65532.

**Idle** (process up, no requests):

| Metric | Value |
|--------|-------|
| cgroup `memory.current` | 5.9 MB |
| `VmRSS` | 26 MB |
| `RssAnon` (heap) | 5.0 MB |
| Threads | 8 |
| CPU (40 s sample, **idle server** — the figure labeled in §1) | 0.56% of one core |

**Under sustained load** (16,860 req/s across 3 endpoints, 40 s):

| Metric | Value |
|--------|-------|
| cgroup `memory.current` peak | 14.8 MB |
| `VmRSS` | 32 MB |
| `RssAnon` (heap) | 10.2 MB |
| Threads | 14 |
| CPU | ~30% of one core |
| CPU throttled periods | 0 / 409 |

**3-minute leak test (under load):**

| Time | cgroup memory | Goroutines |
|------|---------------|------------|
| 0 s  | 7.3 MB | 10 |
| 30 s | 8.0 MB | 10 |
| 60 s | 8.2 MB | 10 |
| 90 s | 8.6 MB | 10 |
| 120 s | 8.6 MB | 10 |
| 150 s | 8.6 MB | 10 |
| 180 s | 8.6 MB | 10 |

Memory grew ~1.3 MB during load then held flat. Goroutine count stayed at
exactly 10. No leaks.

## 6. HTTP throughput (Enterprise server)

Tool: k6 0.49.0, run as an in-cluster Job. Three scenarios in parallel:
`/healthz` (10 VUs), `/readyz` + `/api/v1/license` (20 VUs),
`/api/v1/whatif` POST (30 VUs). Total 60 VUs, 40-second run.

| Metric | Value |
|--------|-------|
| Throughput | **16,860 req/s** sustained |
| Iterations completed | 571,248 |
| Total requests | 674,494 |
| Failures | **0.00 %** (0 failed out of 674k) |
| Data transferred | 152 MB received, 146 MB sent |
| Latency p50 (overall) | 781 µs |
| Latency p90 | 4.09 ms |
| Latency p95 | 8.80 ms |
| Latency p99 | ~15 ms |
| Latency max | 87.83 ms |

**Per-scenario p95:**

| Scenario | p95 | Threshold |
|----------|-----|-----------|
| `/healthz` | 5.10 ms | < 50 ms ✓ |
| `/readyz` + `/api/v1/license` | 10.64 ms | < 100 ms ✓ |
| `/api/v1/whatif` POST | 10.03 ms | < 200 ms ✓ |

All three SLO thresholds passed.

### In-process load (no network stack)

For comparison, the same `/healthz` endpoint tested **in-process**
(no container networking, `httptest.NewServer`):

| Concurrency | Throughput | p95 | p99 |
|-------------|-----------|-----|-----|
| 8 | 48k req/s | 289 µs | 622 µs |
| 64 | **88k req/s** | 1.6 ms | 2.7 ms |
| 256 | 79k req/s | 6.6 ms | 12 ms |

The in-cluster numbers are ~20% of the in-process numbers because of
kube-proxy + CNI overhead. Both are far above what any cost-observability
workload will generate.

## 7. Chaos scenarios (Enterprise server)

### In-process (7 scenarios, race detector on)

| Scenario | Result |
|----------|--------|
| Slow ClickHouse (hung Ping) | ✓ `/readyz` times out at 2 s, returns 503, does not hang |
| 500 concurrent remediation approvals | ✓ Exactly 1 succeeds, 499 clean errors, no panic |
| Corrupted state file (4 variants) | ✓ Returns clean error, no panic |
| Concurrent register + save (500 ms) | ✓ 14 saves, 37 reads, **0 partial-write parse errors** — atomic rename works |
| License expiry mid-flight | ✓ `/readyz` flips 200→503, `/healthz` stays 200 |
| 1 MiB body DoS | ✓ Rejected at middleware (400/413), not buffered |
| Spot tracker concurrent writes | ✓ Race detector clean, 3,200 events preserved |

### Live on kind

**Pod kill during load (60-second continuous requests, pod killed at t=5 s):**

| Metric | Value |
|--------|-------|
| Total requests | 600 |
| Succeeded (HTTP 200) | 585 (**97.5 %**) |
| Failed (connection refused) | 15 (**2.5 %**) |
| Recovery time | ~1.5 s |

The 15 failures occurred during the Service-endpoints-update window after
the pod was killed. Once the new pod was Ready, requests resumed at full
throughput.

## 8. Microbenchmarks (hot paths)

All measured on Apple M1 Max, Go 1.25, `-benchtime=2s`. Microbenchmarks
characterize per-operation cost of the hot paths; they are not a
whole-agent overhead measurement.

**Attribution path (ships in this repository):**

| Operation | ns/op | B/op | allocs/op | Notes |
|-----------|-------|------|-----------|-------|
| `classifier.Classify` (SameZone) | 49 | 0 | **0** | zero-alloc hot path |
| `classifier.Classify` (InternetEgress) | 19 | 0 | **0** | |
| `prefixtree.Lookup` | 4.6 | 0 | **0** | CIDR lookup |
| `dns.Tracker.LookupIP` (hit) | (fast) | 0 | 0 | |
| `cost.Engine.Calculate` (1000 flows) | 65,727 | 233,632 | 128 | 66 ns/flow |

**Enterprise control plane (private tree; features listed in
[`OPEN-CORE.md`](../OPEN-CORE.md)):**

| Operation | ns/op | B/op | allocs/op | Notes |
|-----------|-------|------|-----------|-------|
| Cost forecast (90-day series) | 3,167 | 7,376 | 13 | Holt-Winters + STL |
| Cost forecast (365-day series) | 8,201 | 18,896 | 13 | |
| Anomaly detection | 160 | 8 | 1 | |
| API auth middleware (hit) | 104 | 208 | 4 | |
| API auth middleware (miss) | 586 | 1,425 | 14 | JSON error encoding |
| Remediation proposal | 2,403 | 599 | 18 | |
| Remediation proposal (parallel) | 2,669 | 557 | 18 | no lock contention |

**Concurrent ID uniqueness test:** 10,000 proposals from 64 goroutines →
**0 collisions**.

## 9. Found here, since fixed: the kind pod-CIDR classification gap

An earlier revision of this report recorded a live finding: on the kind
rig, in-cluster pod↔pod traffic was classified `internet_egress` instead of
`same_zone`/`cross_az`, because the classifier's prefix tree didn't know
the kind cluster's pod CIDR (10.244.0.0/16). That was a config gap, not a
hot-path issue, and it has since been fixed: the classifier now learns
cluster-internal CIDRs from the Kubernetes informer (`Node.spec.podCIDR`,
plus the service CIDR) via `SetClusterCIDRs`, so non-RFC-1918 cluster
setups classify correctly too (`pkg/classifier/traffic.go`,
`pkg/k8s/informer.go`). The finding stays in this report because an honest
perf report doesn't silently delete its own findings.

## 10. Before we publish a measured overhead number

In order, the gaps between this document and a quotable agent-overhead
measurement:

1. A reproducible `make bench`-style benchmark: stated instance type,
   kernel, and generated flow rate, runnable by anyone.
2. Agent CPU% under that load on real cloud nodes (not a laptop kind
   cluster), at flow rates up to the 100K-active-connection design point.
3. A 24 h+ soak *under load* (the current 9-day soak was idle).

Until those exist, the public claim is the budget in §1 — and if the
measured number ever lands outside 0.1–0.5% of one core, the public copy
changes, not the benchmark.
