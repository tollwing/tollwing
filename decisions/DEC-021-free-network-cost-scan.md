# DEC-021 — Ship a free one-shot network-cost scan (`tollwing-scan`)

**Status:** ACCEPTED
**Date:** 2026-07-02
**Author(s):** Baris Erdem (with Claude Fable 5)

---

## Context

The agent exports rich per-pod, per-billing-path cost as `tollwing_*` Prometheus
metrics, but the *first* thing a prospective user wants is not a Grafana board to
build — it is a single answer: "how much am I wasting on data transfer, and
where?" The GPU sibling already ships exactly this shape (a free one-shot
efficiency scan) as its demand instrument; the network flagship had no
equivalent. The launch plan's own kill/So-what signal ("> $5k/mo cross-AZ found
per scan") also presupposes a scan that can be run and counted — and none
existed. So the flagship was missing both its lowest-friction on-ramp and its
demand-validation instrument.

## Decision

We ship **`cmd/tollwing-scan`**, a free, Apache-2.0, cross-platform
(`CGO_ENABLED=0`) CLI that reads the agent's exported metrics from Prometheus
and prints a network data-transfer waste report: spend by AWS billing path over
a window, projected to a month, the *addressable* slice (cross-AZ + NAT, which
have known low-effort fixes) with a concrete action, and the top cost-driving
pods. Logic lives in the public `pkg/scan` package (`Analyze`, `PromSource`);
the CLI adds `--demo` (synthetic, no cluster), `--prometheus URL` (live fleet),
and `--input file.json` (offline), with `--window`, `--json`, and `--top`.
`make scan-demo` runs it. It is added to the OSS publish roots so it ships in the
public tree.

Per P4, every figure traces to the agent's `metered bytes × dated rate`; the
scan only sums, ranks, and projects, and the one introduced estimate — the
linear monthly projection of the window — is always labelled as such.

## Alternatives considered

### Alternative A — Leave it to Grafana + the shipped dashboard
The 23-panel dashboard already renders the breakdown.
**Why not:** it requires Prometheus + Grafana wiring and dashboard literacy
before the user sees a single dollar. The scan answers the headline question in
one command against a Prometheus URL, and runs `--demo` with no infra at all —
the on-ramp the dashboard can't be.

### Alternative B — Put the scan in the Enterprise control plane
The server already computes richer cost views.
**Why not:** that inverts the funnel. The scan's job is adoption and demand
signal; gating it behind a license defeats the purpose, and it needs nothing the
control plane provides — only the free agent's metrics. Per OPEN-CORE.md, a
capability that measures/classifies/prices on a single cluster from the agent's
own outputs lands free. Deeper per-connection/per-service savings reports remain
Enterprise; the scan says so in its own footer.

### Alternative C — Compute "waste" as a hard savings guarantee
Multiply cross-AZ bytes by the rate delta and promise that number.
**Why not:** it would overclaim (P5). Realised savings depend on topology
changes we can't see from metrics alone. "Addressable" is framed as "has a known
low-effort fix," not a guaranteed saving, and the action is a pointer, not a
promise.

## Consequences

### Positive
- A one-command on-ramp and the flagship's missing demand instrument, using code
  and metrics that already exist.
- Reusable `pkg/scan` (Prometheus source + report) that other surfaces can call.

### Negative
- A new public CLI is a public contract (P11): its flags, JSON shape, and the
  metric names it queries now evolve under the compatibility policy.
- The monthly projection is a linear extrapolation; a bursty window mis-projects.
  Mitigated by labelling it and defaulting to a 24h window.

### Neutral
- The scan is read-only against Prometheus; it holds no state and needs no cloud
  credentials.

## Constitutional principles touched

- **P1 (the agent is the product):** advances — a SKU-shaped surface on top of
  the one agent's existing output, no new agent capability.
- **P4 (every dollar traceable):** advances — figures are the agent's
  `bytes × dated rate`; the projection is the only estimate and is labelled.
- **P5 (never guess):** advances — "addressable" is honestly scoped; no
  guaranteed-savings claim.
- **P11 (public contracts):** requires care — the CLI/JSON/queried-metric names
  are now versioned surfaces; changes follow `docs/governance/compatibility.md`.

## Re-evaluation triggers

- The queried metric names (`tollwing_cost_usd_total`,
  `tollwing_pod_cost_usd_total`) change — the scan's PromQL must move with them.
- Demand signal: if scans consistently surface material cross-AZ/NAT spend, a
  shareable HTML report and a scheduled/recurring mode become worth building.
- If projection error becomes a support burden, add a p50/p95 or a
  same-window-last-period comparison instead of a flat linear factor.

## Related decisions

- [DEC-013](DEC-013-open-core-repo-split-allow-list-boundary.md) — the open-core
  boundary that places this free.
- [DEC-014](DEC-014-metered-directions-and-marginal-default-pricing.md),
  [DEC-015](DEC-015-route-based-nat-detection-and-hourly-charges.md) — the
  corrected pricing whose output the scan sums (a scan is only as honest as the
  numbers underneath it).

## References

- `cmd/tollwing-scan/main.go`, `pkg/scan/{scan,prometheus,report}.go`,
  `pkg/scan/scan_test.go`.
- `pkg/exporter/prometheus.go` — the `tollwing_cost_usd_total{traffic_type}` and
  `tollwing_pod_cost_usd_total{namespace,pod}` series the scan queries.

## Notes

A shareable single-file HTML report (the analogue of the GPU scan's shareable
artifact) is a deliberate follow-up, gated on demand rather than built up front.
