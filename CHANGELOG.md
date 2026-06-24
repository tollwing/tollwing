# Changelog

All notable changes to Tollwing are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/). Public contracts and their compatibility
guarantees are defined in [`docs/governance/compatibility.md`](docs/governance/compatibility.md)
(constitution **P11**).

> Tollwing is pre-1.0 (`0.x`): during `0.x`, a minor release may make a breaking change,
> but it is always recorded here with a deprecation note where feasible. Changes before the
> governance system was introduced live in the git history.

## [Unreleased]

### Added
- **Engineering-governance system:** `CONSTITUTION.md` (twelve principles, P1–P12);
  `decisions/` (append-only ADRs with an auto-generated index); `docs/governance/`
  (audit playbook, conventions, compatibility policy, data-handling policy, quarterly
  review template); a GitHub issue (feature-proposal process); `tools/governance`
  (stdlib-only Go: `index` / `scan` / `audit`); a CI `governance` job plus `govulncheck`
  and a weekly governance-drift cron; a warn-only pre-commit hook; `CLAUDE.md` / `AGENTS.md`
  agent operating protocol; `CONTRIBUTING.md`; `SECURITY.md`; and a PR template.
- **GPU cross-AZ data-movement attribution (`GET /api/v1/cost/gpu/cross-az`, Enterprise):**
  slices the existing cross-AZ/region network cost down to GPU workloads and categorizes it
  by *why* the data moved — `cloud_storage`, `inter_pod_sync`, `other_external` — with a
  per-category and top-GPU-pod dollar breakdown. Attribution credits each flow to its GPU
  side exactly once and refuses to attribute movement involving no known GPU pod. 503 until
  storage is wired. No new agent capability (P1/P2), no schema change (P7), purely additive
  endpoint (P11).

### Changed
- _(none)_

### Deprecated
- _(none)_

### Removed
- _(none)_

### Fixed
- **Cost counters under-reported to $0 for many-small-flow workloads:** the agent accumulated
  network cost as integer micro-USD floored *per flow* (`uint64(CostUSD * 1e6)`), so any flow
  costing less than `$0.000001` truncated to `0`. A tight client loop opens a distinct
  short-lived connection per request, so each flow was sub-micro-dollar and vanished —
  `tollwing_cost_usd_total{traffic_type=…}` and `tollwing_pod_cost_usd_total` stayed at
  `0.000000` despite real byte volume (L2b: ~376 MB `cross_az` reporting `$0.000000`, vs the
  expected ~`$0.0039` at `$0.01/GB`). Cost is now accumulated in full-precision float dollars
  and rounded to the emitted `%.6f` exactly once, at scrape time, for both counters. The
  emitted metric contract (names, type, labels, format) is unchanged. Found via the L2b
  real-agent tier. See [DEC-011](decisions/DEC-011-float-cost-accumulation-round-at-emit.md).
  No public-contract change.
- **IP byte-order misclassification:** all private/in-cluster traffic was classified as
  `internet_egress` instead of `cross_az`/`same_zone`/`intra_node` on every little-endian
  host (all x86 and arm64). The agent decoded BPF-delivered IP fields inconsistently —
  network-order bytes are loaded native-endian, but the classifier and log formatters
  decoded them big-endian, reversing the octets (e.g. a ClusterIP `10.96.14.74` looked like
  the public address `74.14.96.10`). All IP decoders now share one canonical native-endian
  contract (`pkg/ebpf.AddrFromU32`); byte counts were always correct, so only classification
  labels (and the cost attached to them) change. Found by the L2b real-agent simulation tier.
  See [DEC-009](decisions/DEC-009-canonical-bpf-ip-byte-order.md). No public-contract change.
