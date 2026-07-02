# Tollwing Open Core

**Status:** ACTIVE — adopted 2026-07-02 per [DEC-013](decisions/DEC-013-open-core-repo-split-allow-list-boundary.md)
**Authority:** This document is the source of truth for what is open source and what is commercial. Where an older document describes a different split, this one governs. Changes follow the rules at the bottom of this file.

Tollwing is open core: the per-node agent that measures and prices your traffic is free and Apache-2.0; the control plane that stores, aggregates, and acts on that data is a commercial product. This document states the boundary precisely, commits to keeping it stable, and is honest about how it moves.

---

## What is free (Apache-2.0)

Everything in the public repository ([github.com/tollwing/tollwing](https://github.com/tollwing/tollwing)) is Apache-2.0 and runs standalone — no license key, no account, no phone-home, no control-plane server required:

- **The eBPF agent (`tollwing-agent`)** — the per-node DaemonSet, in full:
  - The **9-way per-pod classifier**: same-zone, cross-AZ, cross-region, internet egress, NAT gateway, VPC peering, transit gateway, VPC endpoint, cloud-service public endpoint.
  - The **eBPF data plane**: socket-level hooks (`sock_ops`, `cgroup/connect4`, kprobes) with in-kernel aggregation, including the BPF sources and the vendored build inputs (`include/`, `vmlinux/`) to compile them yourself.
  - **Pre-DNAT intent capture** and service-graph attribution — the two-phase ClusterIP recovery that is the product's differentiator (DEC-003, DEC-010).
  - **List-price cost math**: measured bytes × dated AWS rate card, per pod, per namespace (P4).
- **Output you already own**: `tollwing_*` Prometheus metrics on `:9990/metrics`, the 23-panel Grafana dashboard, and the FOCUS-aligned JSON cost-export sidecar (`opencost-plugin/`, see DEC-017).
- **`tollwing-terraform`** — the standalone Terraform network-cost estimator.
- **The pure-Go proof suite** (`test/sim/`, `make demo`) — priced scenarios with no cluster, kernel, or cloud account.
- **Deployment**: the agent Helm chart (`deploy/helm/tollwing-agent`).
- **Governance**: `CONSTITUTION.md`, the public decision log (`decisions/`), `docs/governance/`, and the stdlib-Go governance tooling (`tools/governance`).

Scope of the free tier: **single cluster, AWS**, with retention set by your own Prometheus. That is the complete live per-pod view described in the [README](README.md) — it is not a trial or a teaser build.

## What is Enterprise

**Tollwing Enterprise** is the self-hosted control plane built on the same agent. It is licensed with an offline signed license (no phone-home, air-gappable) and is not a hosted service. Its source lives in the private monorepo and is not published:

- **The control-plane server (`tollwing-server`)** — long-term history (ClickHouse), the REST API, the CLI (`tollwing-cli`), and the Cost Savings Report.
- **Multi-cluster aggregation** — fleet-wide views across clusters.
- **CUR reconciliation** — pricing against your *actual discounted* rates from the AWS Cost and Usage Report, with drift and accuracy scoring.
- **Acting on the data**: alerts, anomaly detection, recommendations (rightsizing, topology, spot/commitment), what-if analysis, and approval-gated auto-remediation (P8).
- **GCP and Azure** provider support.
- **Organizational features**: SSO/RBAC, multi-tenancy, HA, the Kubernetes operator, and integrations (Slack, MCP, CI/CD, admission webhook).

The dividing line is the one the constitution already draws (P1): the agent measures; state, history, cross-cluster correlation, and actions live in the control plane — and the control plane is the commercial product.

## The commitment (no rug-pull)

1. **What shipped free stays free.** No feature that has shipped in the free agent will move to Enterprise. We will not remove, degrade, or license-gate a published capability in order to sell it back.
2. **The public tree stays Apache-2.0.** We will not relicense it (to BSL, SSPL, or anything else). The Apache-2.0 grant on everything already published is irrevocable regardless — this commitment covers the future of the repository, not just its past.
3. **The free agent contains no license code.** No license checks, no node or cluster caps, no expiry, no phone-home — there is nothing in it to unlock. (You can verify this: `pkg/license` does not exist in the public tree, and the agent's dependency closure never included it.)
4. **The free tier does not depend on us existing.** The single-cluster view needs no Tollwing-operated service. If the company disappeared tomorrow, the agent you run today keeps working unchanged.

What this commitment does **not** promise: that every new feature lands free, that the free tier grows without bound, or a maintenance SLA. It promises direction — the boundary only ever moves *toward* free, never away from it.

## Where new features land

The rule, which tracks P1:

- A capability lands in the **free agent** when it is needed to measure, classify, or price traffic correctly on a single AWS cluster and expose it through the agent's existing outputs (metrics, dashboard, cost-export sidecar). **Accuracy and honesty fixes are always free** (P4, P5): a correction to the numbers the free agent reports is never held back as a paid feature.
- A capability lands in **Enterprise** when it needs cross-cluster or historical state, cloud-bill access (CUR), a running server, acts on your infrastructure, or is an organizational concern (SSO, RBAC, tenancy).

The honest caveat: this rule is a heuristic, not a formula, and the call for a genuinely ambiguous feature is made by the maintainer as a business judgment — Tollwing is a company as well as a project, and the free/paid placement of *new* work is not a community vote (see [GOVERNANCE.md](GOVERNANCE.md)). Ambiguous placements are discussed in the open where possible (a GitHub issue), and any decision that moves the boundary itself is recorded as an ADR. What we bind ourselves to is that ambiguity never resolves *backwards*: however a new feature lands, nothing already free goes behind the license (commitment 1).

## How the boundary is enforced

The boundary is defined twice, deliberately:

1. **This document** — the human-readable contract.
2. **Mechanically** — the public tree is generated from the private monorepo by an allow-list publish script: the exact Go dependency closure of the public binaries plus an explicit asset list, with a private-package deny pattern (`PRIVATE_RE`) asserted against the closure before anything is copied. The public repo then self-defends: its own CI (`oss-guard`) fails if a private package, binary, or Enterprise build marker ever appears in the tree, however it got there.

If the script and this document ever disagree, this document wins and the script has a bug. See [GOVERNANCE.md](GOVERNANCE.md) for what the generated-repo model means for contributors, and [CONTRIBUTING.md](CONTRIBUTING.md) for how a public PR lands.

## Changes to this document

Per P11, this document is a public contract and evolves like one:

- Moving a shipped free feature to Enterprise is **prohibited** by the commitment above; no process exists to do it, on purpose.
- Moving a feature from Enterprise to free is always allowed and is recorded here.
- Any other change to the boundary or the placement rule requires an ADR in [`decisions/`](decisions/) and a change to this file in the same commit.
