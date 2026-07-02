# The cross-AZ differential — Tollwing vs OpenCost / Kubecost

> The headline claim, stated and proven fairly. This is the "we're right where
> post-DNAT-only tools are wrong" comparison from the charter — now backed by a
> **full three-tool head-to-head measured live on one L2b cluster** (Tollwing,
> OpenCost, and Kubecost's own network-costs daemon; see §"The live head-to-head").
> Companion to `simulation-suite-design.md` (monorepo) and DEC-008,
> DEC-003 (pre-DNAT capture), DEC-010 (which leg carries the charge).

## The claim

Tollwing attributes cross-AZ network cost to **the Kubernetes Service the client
dialed** (recovered from the pre-DNAT ClusterIP, DEC-003) — correctly, with
**zero configuration**. OpenCost and Kubecost, which classify from post-DNAT
data and node→zone IP mapping, either report **nothing** out of the box or
attribute only to the **source pod**, never the dialed Service.

## The shared scenario (identical for all three tools)

The L2b workload (`test/sim/substrate/l2b-workload.yaml`): a `client` pod pinned
to **zone-a** dials the `echo` **Service** (ClusterIP), whose only backend pod is
pinned to **zone-b**. Every byte is a genuine cross-AZ interaction. Same topology,
same bytes, same per-GiB rate for every tool — so any difference is *attribution*,
not pricing.

## Tollwing — measured live (the proof, not a claim)

`make sim-l2b`, real eBPF agent on a real kind cluster (Lima BTF VM):

```
backend-node agent (worker2 / zone-b):  tollwing_tx_bytes_total{traffic_type="cross_az"} = 24,823,504
dialer-node agent  (worker  / zone-a):  cross_az = 0   (the ClusterIP leg is Unknown — DEC-010)
```

- **Correct cross_az classification** from the backend pod's real zone, captured
  by the agent's `cgroup/connect4` + `sock_ops` + byte-counting hooks.
- **Attributed to the dialed Service** (`src_service=client`, `dst_service=echo`)
  via the recovered pre-DNAT ClusterIP, not the backend pod IP.
- **Counted exactly once** — the dialer leg is deliberately left `Unknown` so the
  same bidirectional interaction isn't double-billed (DEC-010).
- **Zero configuration** — zones come from `topology.kubernetes.io/zone` node
  labels via the informer; no per-subnet CIDR setup.

## OpenCost — out of the box: `$0` cross-AZ

OpenCost computes network cost from a metric
(`kubecost_pod_network_egress_bytes_total{internet,same_zone,same_region}`)
emitted by a **separate per-node `network-costs` DaemonSet** that reads the Linux
conntrack table. **The OpenCost community Helm chart does not ship that DaemonSet**
(its templates are a Deployment + UI + RBAC only) — so out of the box OpenCost's
`networkCrossZoneCost` allocation field is **empty / `$0`** for this workload that
our agent measures at ~24 MB. ([opencost/opencost] cost model; [opencost-helm-chart]
templates.)

Even *with* the daemon bolted on, OpenCost's `NetworkUsageData` keys on
`namespace + pod + clusterID` and buckets cost into `internet / cross-zone /
cross-region` — **there is no destination-Service field**. It attributes the
cross-AZ cost to the **source pod**, never to the dialed `echo` Service.

## Kubecost — source-pod attribution, wrong-by-default

Kubecost is the same cost engine plus the `network-costs` daemon (image
`kubecost/network-costs`). Its daemon decides cross-zone by mapping a **remote IP
→ node → `topology.kubernetes.io/zone`**. A **ClusterIP is virtual** (no node, no
zone), and the shipped default config classifies the entire `10.0.0.0/8` private
range as `in-zone` — so genuine cross-AZ pod traffic is **silently labeled
`same_zone` (free)** until an operator hand-enumerates every per-AZ subnet CIDR
(reproduced as recently as Kubecost v2.5.3 — [kubecost#3819]). Once tuned, it
counts the cross-zone bytes at **source-pod** granularity; its only "service"
concept is external cloud-provider CIDRs (S3, RDS…), **never the in-cluster
Service the client dialed**.

## The honest verdict (fairness guardrails observed)

| | cross-AZ $ for this flow (measured live) | attributed to | config needed | correct by default? |
|---|---|---|---|---|
| **Tollwing** | **$0.000819** on ~80 MB (eBPF, exact) | **the dialed `echo` Service** | none | ✅ |
| **Kubecost** | **$0** — Service/ClusterIP traffic stays `same_zone=free` *even after* per-AZ CIDR tuning (only raw pod-IP traffic classifies cross-zone) | the **source pod** (`service=""`) — never `echo` | region label **+** per-AZ CIDR lists | 🔴 cross-AZ free by default ([kubecost#3819]); ClusterIP traffic mislabeled even when tuned |
| **OpenCost** | **$0.000000** (all 24 pods) | nothing | must bolt on Kubecost's daemon | 🔴 no network daemon in the chart |

Being fair (per the research's guardrails): with manual CIDR config Kubecost's
cross-AZ **dollar** can be made right **for raw pod-IP traffic** — but the live test
showed it stays **$0 / `same_zone=free` for ClusterIP (Service) traffic even after
that tuning**, because the daemon classifies on the post-DNAT tuple (see §"The live
head-to-head"). So the durable edge is sharper than a config gap: **granularity (per
dialed Service), correctness-by-default, zero-config, and a pre-DNAT/service-intent
gap that CIDR tuning cannot close for Service traffic** — plus the *structural* fact
that neither tool has a field to name the destination Service (`service=""`,
confirmed live). Do **not** claim they "read the pre-DNAT tuple in code" — their
daemon is closed-source; assert the **observable** behavior (measured above) and the
**missing service field**, both of which are now established live.

## The live head-to-head — measured (2026-05-30)

All three tools were deployed on the **same L2b cluster** (the real eBPF agent in
the Lima BTF VM) against the **same** client→`echo`-Service workload and queried
live. Echo's ClusterIP was `10.96.14.74`, its backend pod on `worker2`/`us-east-1b`;
the clients on `worker`/`us-east-1a`. Every byte is genuine cross-AZ. No longer a
deferred follow-up — these are the literal numbers.

### Tollwing — correct, zero-config

```
tollwing_tx_bytes_total{traffic_type="cross_az"}  (backend-node agent, worker2)
   = 79,606,000 bytes  →  tollwing_cost_usd_total{cross_az} = $0.000819
   (cumulative over the session: ~1.77 GB cross_az, all on the backend agent)
```

Classified **cross_az** from the backend pod's real zone, **attributed to the
dialed `echo` Service** via the recovered pre-DNAT ClusterIP (DEC-003), counted
once on the backend agent (DEC-010). Zones came from `topology.kubernetes.io/zone`;
the **region was derived from the zone name** (`us-east-1a`→`us-east-1`) — no region
label required.

### OpenCost — `$0.000000`, confirmed live

OpenCost (community Helm chart + Prometheus) came up healthy: it scraped Prometheus
and returned **24 real pod allocations with non-zero CPU/RAM cost**. Yet the network
field was empty for every one:

```
GET /allocation/compute?window=30m&aggregate=pod
   → networkCrossZoneCost = $0.000000 for ALL 24 pods (every client, echo, system pod)
   → SUM cross-zone across the cluster = $0.000000
kubectl get daemonset -A  → only tollwing-agent, kindnet, kube-proxy
                          → OpenCost ships NO network-costs DaemonSet
```

For the flow Tollwing measured at ~80 MB / $0.000819, **OpenCost reports $0** — not
because it's wrong about the bytes, but because the metric that would carry them
(`kubecost_pod_network_egress_bytes_total`) is never produced.

### Kubecost network-costs daemon — wrong-by-default, source-pod-only

We deployed Kubecost's **own** `kubecost-network-costs` DaemonSet (image `v0.17.6`,
rendered from the cost-analyzer chart **2.5.3**) on the same cluster. Four findings,
in the order we hit them:

1. **It emits *nothing* without a region label.** Out of the box the daemon logged
   `Could not locate region for local node: …worker2` and `Failed to classify
   TransportData` on a loop — **zero data series** — because our nodes carried
   `topology.kubernetes.io/zone` but not `…/region`. Only after we hand-added
   `topology.kubernetes.io/region=us-east-1` did it produce any data. (Tollwing
   needed no such label — it derives the region from the zone name.)

2. **By default it bills genuine cross-AZ as `same_zone` (free).** With the shipped
   `in-zone: [10.0.0.0/8, …]` config, the cross-AZ client→`echo` traffic returns:
   ```
   kubecost_pod_network_egress_bytes_total{pod_name="client-…",namespace="l2b",
       internet="false", same_region="true", same_zone="true", service=""}  8,742,897
   ```
   `same_zone="true"` on traffic that physically crosses `us-east-1a`→`us-east-1b`,
   i.e. silently **free**. This is kubecost/kubecost#3819, reproduced live.

3. **Even after hand-tuning per-AZ CIDRs, Service (ClusterIP) traffic stays
   mislabeled** — the pre-DNAT gap, demonstrated. We applied the operator's fix:
   moved zone-b's pod CIDR (`10.244.1.0/24`) out of `in-zone` into `in-region`. The
   result split cleanly by **destination tuple**:
   - a probe hitting echo's **pod IP** (`10.244.1.2`) directly →
     `same_zone="false"` ✓ (cross-zone, 2.96 MB) — tuning works for raw pod IPs;
   - the real clients dialing echo's **ClusterIP** (`10.96.14.74`) → **still
     `same_zone="true"`** (free), because the daemon classifies on the post-DNAT /
     ClusterIP tuple, which no per-AZ *pod*-subnet rule can match.

   This is the structural fact DEC-003 is built on: a Service's ClusterIP is virtual
   and zone-less; without recovering the **pre-DNAT** intent you cannot classify
   Service traffic by zone at all. Tollwing recovers it; Kubecost's daemon cannot —
   so for the dominant real-world case (pods dialing Services) the cross-AZ cost is
   **free-by-default even after the documented CIDR tuning**.

4. **No destination-Service field, ever.** Every series above carries `service=""`
   and is keyed by the **source** `pod_name`. The metric structurally cannot name the
   `echo` Service the client dialed.

### Resilience (L3 extensions, measured live)

Same agent, same cluster:

- **k6 wire-load** (`grafana/k6`, 80 VUs / 60 s, zone-a → echo Service): **222,141
  requests at 3,700 req/s, 0.00% failed**, 190 MB received. The backend agent
  captured **+230 MiB** of cross_az and held **heap ≤10 MiB, goroutines flat at 46,
  zero restarts** — the P2 budget under real load.
- **Zone-failure chaos** (cordon `worker2` + delete the `echo` backend → genuine
  zone-b outage → uncordon to recover): the agent stayed `Running` throughout —
  **goroutines 46→46, heap 9→7 MiB, no new restart** — and capture resumed cleanly
  on recovery (a fresh probe measured **+22 MiB** cross_az in 25 s). Chaos Mesh's
  operator-driven injection remains a heavier documented extension; this cordon/kill
  cycle exercises the same agent-resilience assertion without the operator overhead.

### Reproducing this — `make sim-differential`

This whole head-to-head is a **repeatable, version-pinned tier** of the proof suite
(`test/sim/differential/run.sh`, DEC-008). On the L2b cluster (`make sim-l2b` first):

```sh
make sim-differential   # deploys all three, captures the numbers, prints the table, asserts the differential
```

It is idempotent (`helm upgrade --install` / `kubectl apply`) and **self-checking**:
the three assertions above are encoded, so if a future competitor release *fixes* a
behavior we claim (e.g. Kubecost stops billing cross-AZ as `same_zone`, or OpenCost
ships a daemon) the run **fails loudly** — the tripwire that keeps this comparison
honest and current. To refresh against newer releases, bump the pins at the top of
the script (currently **OpenCost chart `2.5.22`**, **Prometheus `29.9.0`**,
**Kubecost `2.5.3` / daemon `v0.17.6`**) and re-run.

Under the hood it installs Prometheus + OpenCost (internal Prometheus) and reads
`GET /allocation/compute` → `$0`; renders Kubecost's own `kubecost-network-costs`
DaemonSet + config from chart `2.5.3`, adds the `topology.kubernetes.io/region`
label the daemon requires, restarts it to load the shipped default config, and reads
its `:3001/metrics`. The k6 wire-load and the cordon/kill zone-failure are the
`test/sim/l3` resilience extensions.

**Teardown** — reclaim the competitors' memory (leaves Tollwing's L2b agent up):
`kubectl delete ns opencost prometheus-system kubecost`. To stop everything and free
the VM's CPU/RAM: `limactl stop tollwing-ebpf`.

## Sources

- OpenCost cost model + the `network-costs` scrape target: `opencost/opencost`
  (`pkg/costmodel/networkcosts.go`, `modules/.../scrape/network.go`).
- OpenCost Helm chart ships no network DaemonSet: `opencost/opencost-helm-chart` `charts/opencost/templates/`.
- Kubecost network daemon + default `in-zone 10.0.0.0/8` + node-zone affinity: `kubecost/kubecost` `kubecost/values.yaml` (`networkCosts:`).
- Cross-AZ-as-free default, reproduced v2.5.3: kubecost/kubecost#3819 (+ #2464 ClusterIP/DNAT root cause, #820).

[opencost/opencost]: https://github.com/opencost/opencost
[opencost-helm-chart]: https://github.com/opencost/opencost-helm-chart
[kubecost#3819]: https://github.com/kubecost/kubecost/issues/3819
