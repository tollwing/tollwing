# Tollwing

[![CI](https://github.com/tollwing/tollwing/actions/workflows/ci.yml/badge.svg)](https://github.com/tollwing/tollwing/actions/workflows/ci.yml)
[![Website](https://img.shields.io/badge/website-tollwing.com-0a7ea4)](https://tollwing.com)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/tollwing/tollwing?sort=semver)](https://github.com/tollwing/tollwing/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/tollwing/tollwing)](go.mod)

**Per-pod Kubernetes network cost, by AWS billing path.**

An eBPF agent meters every byte of pod TCP traffic in-kernel (UDP and QUIC are one flag away: `-udp`), attributes it to the pod that sent or received it, and prices it across **9 AWS billing paths** (same-zone, cross-AZ, cross-region, internet egress, NAT gateway, VPC peering, transit gateway, VPC endpoint, cloud-service public endpoint): live, per-pod, per-namespace. Of the metered bytes, the few whose billing path can't be proven are booked as **Unknown — never guessed**; bytes it doesn't meter are absent, never estimated. Every dollar you see is metered bytes × a dated rate: traceable, auditable, and honest about its own blind spots. No app changes. Designed to a 0.1–0.5%-of-one-core overhead budget ([`ARCHITECTURE.md`](ARCHITECTURE.md) §2.4); we'll publish measured numbers only alongside a reproducible benchmark.

> Most tools tell you your data-transfer bill is high. Tollwing tells you **which pod, talking to which service, over which of 9 AWS billing paths, in dollars**. As of July 2026 nothing else we know of ships all three at once: Datadog spreads bill-line spend to workloads proportionally (no per-pod, 4 CUR transfer types), Kubecost meters per pod but into 3 heuristic buckets and loses ClusterIP intent ([kubecost#2464](https://github.com/kubecost/kubecost/issues/2464), closed unfixed), and AWS's Container Network Observability shows bytes, not dollars. Know a tool that does all three? [Open an issue](https://github.com/tollwing/tollwing/issues) — we'll correct this line.

![make demo: the cross-AZ differentiator scenario and all 9 billing paths, priced through the production cost engine](docs/images/demo.gif)

*`make demo`, real output: the cross-AZ intent that post-DNAT tools mis-attribute, priced correctly to the dialed service — then every billing path through the same engine. ([recording source](docs/images/demo.cast))*

## See it in 60 seconds: no cloud account, no cluster

```sh
make demo
```

Prices a real cross-AZ + NAT-gateway scenario through the pure-Go cost oracle (`test/sim/`): no AWS creds, no kind, no kernel, runs in milliseconds. The headline scenario (`test/sim/scenarios/cross-az-differentiator.yaml`): `cart` in `us-east-1a` dials the `checkout` ClusterIP whose backends live in `us-east-1b`. 1 GiB of cross-AZ traffic, correctly attributed to `checkout` at **$0.01**, which post-DNAT-only tools mis-attribute to the source pod or miss entirely.

## What you'll see: live, per-pod, in your Grafana

The agent classifies every metered byte and exposes it as `tollwing_*` Prometheus metrics; the included 23-panel dashboard renders the breakdown. A namespace's network cost by billing path looks like:

```
cross_az            $5.67   (46%)
internet_egress     $4.32   (35%)
nat_gateway         $1.23   (10%)
```

No control-plane server is needed for this single-cluster view: the agent exposes the metrics, your Prometheus scrapes them, Grafana shows them.

## One-command scan: where's my data-transfer money going?

Once the agent is scraped by Prometheus, `tollwing-scan` prints the headline in one shot: spend by AWS billing path over a window, projected to a month, the **addressable** slice (cross-AZ + NAT, the paths with a known low-effort fix), and the top cost-driving pods.

```sh
go run ./cmd/tollwing-scan --prometheus http://prometheus:9090   # scan a live fleet
make scan-demo                                                    # synthetic, no cluster
```

```
  NETWORK DATA-TRANSFER COST
     projected/mo    $2,050.50
     addressable/mo  $1,504.50   (73%, has a known low-effort fix)

  BY AWS BILLING PATH  (projected monthly)
     cross_az                    $942.00      46%   ◀ addressable
     nat_gateway                 $562.50      27%   ◀ addressable
     internet_egress             $363.00      18%
```

Free and Apache-2.0, reads only the agent's metrics (`--json` for machine output). Long-term history, multi-cluster rollups, and the Cost Savings Report are **Tollwing Enterprise** — see [Open-core: free vs Tollwing Enterprise](#open-core-free-vs-tollwing-enterprise) for the full split.

## How it compares

| | per-pod | by AWS billing path | eBPF | dollars |
|---|:---:|:---:|:---:|:---:|
| **Tollwing** | ✓ | ✓ (9-way, per flow) | ✓ | ✓ |
| Datadog CCM + CNM | workload-level¹ | 4 CUR transfer types | ✓ | ✓ |
| Kubecost / OpenCost | ✓ (conntrack)² | 3 buckets (heuristic) | ✗ | ✓ |
| AWS Container Network Observability (EKS) | ✓ | partial | ✓ | ✗ (bytes, not dollars) |

Comparison as of 2026-07-02, from each vendor's published docs; if we got a row wrong, [open an issue](https://github.com/tollwing/tollwing/issues) and we'll fix it.

¹ Datadog allocates CUR data-transfer spend down to the *workload* level by spreading node bill lines proportionally by traffic volume (requires Cloud Network Monitoring on every host; its docs state individual pods are not tracked). Tollwing meters each flow bottom-up, pre-DNAT, and prices it per path — different question, different answer.
² Kubecost's conntrack daemonset is per-pod but classifies post-DNAT into 3 buckets; ClusterIP/RFC1918 traffic defaults to in-zone ([kubecost#2464](https://github.com/kubecost/kubecost/issues/2464)).

## Install

```sh
helm install tollwing-agent ./deploy/helm/tollwing-agent \
  --namespace tollwing --create-namespace \
  --set agent.provider=aws --set agent.region=us-east-1
```

The agent auto-detects provider + region via IMDS, and exposes `tollwing_*` Prometheus metrics on `:9990/metrics`. Point your Prometheus at it and import the 23-panel Grafana dashboard (`test/local/grafana-dashboard.json`). That is the complete live, single-cluster view, with no extra backend to run.

The control-plane server (long-term history, multi-cluster aggregation, REST API, CLI, alerts, and the premium analytics) is **Tollwing Enterprise**. See [Open-core: free vs Tollwing Enterprise](#open-core-free-vs-tollwing-enterprise).

## How it works: the part post-DNAT tools structurally miss

Tollwing captures each connection's destination **before kube-proxy DNAT** (via `cgroup/connect4`), recovering the original ClusterIP *intent* instead of only the rewritten backend IP. The backend-node agent then observes the real pod endpoint and prices cross-AZ movement exactly once; the dialer-side ClusterIP leg stays `Unknown` rather than guessing a zone (DEC-003 / DEC-010). "Classified deterministically" means we refuse to guess, not that we pretend to know everything: anything Tollwing can't prove lands in an explicit `Unknown` bucket. In-kernel PERCPU aggregation keeps the per-packet work in the kernel; the overhead budget is 0.1–0.5% of one core ([`ARCHITECTURE.md`](ARCHITECTURE.md) §2.4). Full detail in [`ARCHITECTURE.md`](ARCHITECTURE.md).

Outputs: `tollwing_*` Prometheus metrics, the 23-panel Grafana dashboard, and a standalone **FOCUS-aligned JSON cost-export** sidecar (`opencost-plugin/`) for external cost tooling.

## Open-core: free vs Tollwing Enterprise

The agent that attributes the cost is free and Apache-2.0, and runs standalone: it exposes Prometheus metrics your Grafana reads directly, with no control-plane server. **Tollwing Enterprise** (early access) adds the self-hosted, license-gated control plane on top of the same agent, via an offline signed license (no phone-home). It is not a hosted service:

| Free (the agent, Apache-2.0) | Tollwing Enterprise (early access, the control plane) |
|---|---|
| 9-way per-pod classifier + eBPF agent | Control-plane server: long-term history, REST API, CLI, Cost Savings Report |
| Pre-DNAT cross-AZ + service-graph attribution | Multi-cluster aggregation · CUR reconciliation → your *actual discounted* rates |
| Prometheus + 23-panel Grafana + FOCUS-aligned JSON cost export | Alerts · anomaly detection · recommendations · what-if · auto-remediation |
| Single cluster, AWS, your Prometheus retention | GCP/Azure · SSO/RBAC (early access) · multi-tenant |

The free agent runs unlicensed, with no extra infrastructure and no phone-home. The precise boundary, the no-rug-pull commitment, and where new features land: [`OPEN-CORE.md`](OPEN-CORE.md).

## Engineering governance

Tollwing keeps a small, mechanically-enforced set of principles and an append-only decision log: [`CONSTITUTION.md`](CONSTITUTION.md) (twelve binding principles, P1–P12), [`decisions/`](decisions/) (ADRs), and [`docs/governance/`](docs/governance/). CI blocks constitutional regressions via `go run ./tools/governance scan`. Project governance — maintainer model, decision rights, how the public repo is generated: [`GOVERNANCE.md`](GOVERNANCE.md). New contributors: [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Development

```sh
go build ./cmd/tollwing-terraform                    # cross-platform, CGO_ENABLED=0
make -f pkg/ebpf/bpf/Makefile bpf-all                # compile BPF (needs clang)
go build ./cmd/tollwing-agent                         # agent: Linux + eBPF
go test ./pkg/...
make demo                                             # pure-Go cost scenarios
```


See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full design, and `tollwing-agent -h` / `tollwing-terraform -h` for the complete flag reference.

## License

Apache-2.0 (core). See [`LICENSE`](LICENSE). Vendored eBPF build inputs (libbpf headers, generated kernel BTF) retain their own licenses: see [`THIRD_PARTY-LICENSES.md`](THIRD_PARTY-LICENSES.md).
