# Tollwing

[![CI](https://github.com/tollwing/tollwing/actions/workflows/ci.yml/badge.svg)](https://github.com/tollwing/tollwing/actions/workflows/ci.yml)
[![Website](https://img.shields.io/badge/website-tollwing.com-0a7ea4)](https://tollwing.com)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/tollwing/tollwing?sort=semver)](https://github.com/tollwing/tollwing/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/tollwing/tollwing)](go.mod)

**Per-pod Kubernetes network cost, by AWS billing path.**

An eBPF agent attributes every byte of network traffic to the exact pod paying for it, classifies it across **9 AWS billing paths** (same-zone, cross-AZ, cross-region, internet egress, NAT gateway, VPC peering, transit gateway, VPC endpoint, cloud-service public endpoint), and turns it into dollars: live, per-pod, per-namespace. No app changes. ~0.1–0.5% CPU.

> Most tools tell you your data-transfer bill is high. Tollwing tells you **which pod, talking to which pod, over which billing path** is paying it, the slice nobody else has at pod resolution.

## See it in 60 seconds: no cloud account, no cluster

```sh
make demo
```

Prices a real cross-AZ + NAT-gateway scenario through the pure-Go cost oracle (`test/sim/`): no AWS creds, no kind, no kernel, runs in milliseconds. The headline scenario (`test/sim/scenarios/cross-az-differentiator.yaml`): `cart` in `us-east-1a` dials the `checkout` ClusterIP whose backends live in `us-east-1b`. 1 GiB of cross-AZ traffic, correctly attributed to `checkout` at **$0.01**, which post-DNAT-only tools mis-attribute to the source pod or miss entirely.

## What you'll see: live, per-pod, in your Grafana

The agent classifies every byte and exposes it as `tollwing_*` Prometheus metrics; the included 23-panel dashboard renders the breakdown. A namespace's network cost by billing path looks like:

```
cross_az            $5.67   (46%)
internet_egress     $4.32   (35%)
nat_gateway         $1.23   (10%)
```

No control-plane server is needed for this single-cluster view: the agent exposes the metrics, your Prometheus scrapes them, Grafana shows them.

## How it compares

| | per-pod | by AWS billing path | eBPF | dollars |
|---|:---:|:---:|:---:|:---:|
| **Tollwing** | ✓ | ✓ (9-way) | ✓ | ✓ |
| Datadog CCM | cluster-level | 4 buckets | ✓ | ✓ |
| Kubecost / OpenCost | partial | 3 buckets (heuristic) | ✗ | ✓ |
| AWS Network Flow Monitor | ✓ | partial | ✓ | ✗ |

## Install

```sh
helm install tollwing-agent ./deploy/helm/tollwing-agent \
  --namespace tollwing --create-namespace \
  --set agent.provider=aws --set agent.region=us-east-1
```

The agent auto-detects provider + region via IMDS, and exposes `tollwing_*` Prometheus metrics on `:9990/metrics`. Point your Prometheus at it and import the 23-panel Grafana dashboard (`test/local/grafana-dashboard.json`). That is the complete live, single-cluster view, with no extra backend to run.

The control-plane server (long-term history, multi-cluster aggregation, REST API, CLI, alerts, and the premium analytics) is **Tollwing Enterprise**. See [Open-core](#open-core).

## How it works: the part nobody else does

Tollwing captures each connection's destination **before kube-proxy DNAT** (via `cgroup/connect4`), recovering the original ClusterIP *intent* instead of only the rewritten backend IP. The backend-node agent then observes the real pod endpoint and prices cross-AZ movement exactly once; the dialer-side ClusterIP leg stays `Unknown` rather than guessing a zone (DEC-003 / DEC-010). In-kernel PERCPU aggregation keeps overhead at ~0.1–0.5% CPU. Full detail in [`ARCHITECTURE.md`](ARCHITECTURE.md).

Outputs: Prometheus/OTel metrics, Grafana dashboards, and an **OpenCost-compatible** plugin.

## Open-core

The agent that attributes the cost is free and Apache-2.0, and runs standalone: it exposes Prometheus metrics your Grafana reads directly, with no control-plane server. **Tollwing Enterprise** (early access) adds the self-hosted, license-gated control plane on top of the same agent, via an offline signed license (no phone-home). It is not a hosted service:

| Free (the agent, Apache-2.0) | Tollwing Enterprise (early access, the control plane) |
|---|---|
| 9-way per-pod classifier + eBPF agent | Control-plane server: long-term history, REST API, CLI, Cost Savings Report |
| Pre-DNAT cross-AZ + service-graph attribution | Multi-cluster aggregation · CUR reconciliation → your *actual discounted* rates |
| Prometheus + 23-panel Grafana + OpenCost plugin | Alerts · anomaly detection · recommendations · what-if · auto-remediation |
| Single cluster, AWS, your Prometheus retention | GCP/Azure · SSO/RBAC (early access) · multi-tenant |

The free agent runs unlicensed, with no extra infrastructure and no phone-home.

## Engineering governance

Tollwing keeps a small, mechanically-enforced set of principles and an append-only decision log: [`CONSTITUTION.md`](CONSTITUTION.md) (twelve binding principles, P1–P12), [`decisions/`](decisions/) (ADRs), and [`docs/governance/`](docs/governance/). CI blocks constitutional regressions via `go run ./tools/governance scan`. New contributors: [`CONTRIBUTING.md`](CONTRIBUTING.md).

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
