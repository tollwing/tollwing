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

_(nothing yet)_

## [0.2.0] - 2026-07-02

Most entries in this release come out of a full-repo audit and its remediation:
they are **bug fixes**, and several of them **change the dollars the product
displays** — per P4 that is stated plainly below, with the old and new numbers
where they are known.

### Added

- **Engineering-governance system:** `CONSTITUTION.md` (twelve principles, P1–P12);
  `decisions/` (append-only ADRs with an auto-generated index); `docs/governance/`
  (audit playbook, conventions, compatibility policy, data-handling policy, quarterly
  review template); a GitHub issue (feature-proposal process); `tools/governance`
  (stdlib-only Go: `index` / `scan` / `audit`); a CI `governance` job plus `govulncheck`
  and a weekly governance-drift cron; a warn-only pre-commit hook; `CLAUDE.md` / `AGENTS.md`
  agent operating protocol; `CONTRIBUTING.md`; `SECURITY.md`; and a PR template.
- **Project and open-core governance (2026-07-02):** [`OPEN-CORE.md`](OPEN-CORE.md) — the
  authoritative free/Enterprise boundary, the no-rug-pull commitment, and the placement
  rule for new features — and [`GOVERNANCE.md`](GOVERNANCE.md) (maintainer model, decision
  rights, generated-public-repo disclosure). `CONTRIBUTING.md` now requires DCO sign-off
  and documents how a public PR lands; Code of Conduct enforcement moved to
  conduct@tollwing.com; `SECURITY.md` prefers GitHub private vulnerability reporting.
  See [DEC-013](decisions/DEC-013-open-core-repo-split-allow-list-boundary.md).

### Changed

- **Displayed dollars changed — pricing is now direction-true, dated, and stateless by
  default (2026-07-02):** the cost engine previously billed `Tx+Rx` bytes for *every*
  traffic type, billing ingress at egress rates on flows all three providers charge
  one-way. Rate cards now carry a per-provider, per-traffic-type metered-direction
  table (`cost.RateCard.Directions` / `MeteredBytes`), and every default rate was
  re-verified against the provider pricing pages on 2026-07-02 and dated
  (`LastUpdated` is the verification date, with a `Source` label). Rates that were
  simply wrong were corrected: GCP cross-AZ $0 → $0.01/GiB, Azure cross-AZ
  $0.01 → **$0** (Microsoft retired inter-AZ charges in 2024), AWS internet-egress
  free tier 1 GB → 100 GB/month, the $0.085 tier boundary 40 TB → 50 TB, plus
  corrected GCP/Azure egress, peering, and endpoint rates. Cumulative free-tier
  tracking per engine was a fiction (every node granted itself the account-wide free
  tier, reset on restart): the default is now stateless **marginal** pricing at the
  post-free-tier list rate; single-meter cumulative tiering is an explicit opt-in
  (`cost.NewEngineWithConfig`) for the one place a single engine meters everything.
  Visible effect in `make demo`: cross_region $0.02 → $0.01, nat_gateway
  $0.09 → $0.27, internet_egress $0.36 → $0.45, transit_gateway $0.02 → $0.01 per
  scenario; the cross-AZ headline is unchanged at $0.01. Providers now mark default
  cards `Fallback: true` instead of silently substituting them for live pricing.
  See [DEC-014](decisions/DEC-014-metered-directions-and-marginal-default-pricing.md).
- **`opencost-plugin/` re-scoped to what it is (2026-07-02):** a standalone,
  FOCUS-aligned JSON cost-export sidecar — **not** an OpenCost plugin (the real
  OpenCost contract is a hashicorp/go-plugin gRPC subprocess this component never
  implemented). Window handling is now honest per P4: agent-scrape mode refuses
  `window=` (its counters are cumulative-since-agent-start and are now labeled so),
  server mode parses `7d`-style windows correctly and returns 400 for unparseable
  ones instead of silently substituting 24h, and `/costs` validates and URL-encodes
  RFC3339 bounds. Callers relying on the lenient mislabeled 200s now get 400s.
  `/config` version 1.0.0 → 1.1.0.
  See [DEC-017](decisions/DEC-017-remove-dead-proto-and-honest-cost-export.md).

### Removed

- **`proto/` (dead gRPC contract, 2026-07-02):** `flow.proto`/`cost.proto` had no
  generated code, no protoc/buf step, and no importers; every transport they described
  actually runs as REST/JSON or NATS, and the proto enum duplicated
  `classifier.TrafficType` outside its canonical owner (P6). Removing a never-shipped
  spec breaks no consumer (P11).
  See [DEC-017](decisions/DEC-017-remove-dead-proto-and-honest-cost-export.md).
- **Dormant eBPF machinery (2026-07-02):** the CGRP_STORAGE cgroup-cost accumulator
  (compiled out of *every* build by an `#ifdef` on a vmlinux enum, while userspace
  blamed the kernel), the consumer-less sk-storage iterator, and both conntrack NAT
  programs plus the `nat_mappings` map (two writers with incompatible key schemes,
  zero readers — per-packet kernel cost producing nothing). `HaveTCX` now probes TCX
  itself instead of reporting "supported" on every kernel since 4.1. API notes:
  `exporter.RecordRingbufDrop` (zero callers) was replaced by `SetKernelDropStats`;
  `MapSizeConfig.NatMappings` was removed; the Prometheus metric contract is
  unchanged. See
  [DEC-016](decisions/DEC-016-remove-dormant-cgroup-storage-iterator-and-conntrack-machinery.md).

### Fixed

- **NAT gateway and private-peering attribution (2026-07-02):** NAT egress was only
  detected when a flow's destination equaled the NAT ENI IP — which internet-bound
  flows never do — so the dominant NAT cost driver always misclassified as
  `internet_egress` and NAT data-processing dollars were never attributed. The AWS
  provider now reads the node's route table (`DescribeRouteTables`) and
  internet-bound flows from NAT-routed subnets classify `nat_gateway`, priced as NAT
  processing **plus** the internet-DTO leg on Tx; fixed hourly gateway charges stay
  out of per-flow cost and surface in reconciliation's explicit unaccounted bucket.
  Also fixed in the same pass: RFC 1918 destinations now check NAT IPs and the
  peering/TGW/endpoint prefixes *before* zone fallback (peered-VPC traffic no longer
  collapses to Unknown/$0); `ip-ranges.json` no longer feeds the VPC-endpoint set
  (public-EC2 traffic prices as egress again, ~$0.09/GB instead of $0.01);
  classifier prefix sets are replace-on-refresh (deleted peerings stop classifying);
  GCP regional subnets no longer fabricate a same-zone mapping (cross-zone traffic
  without per-IP zone data is now an honest Unknown/$0 instead of a false
  same_zone/$0); Azure zone ordinals are region-qualified. Route-based NAT detection
  is AWS-only for now — GCP/Azure NAT-routed internet flows still classify
  `internet_egress`, under-reporting the NAT processing component.
  See [DEC-015](decisions/DEC-015-route-based-nat-detection-and-hourly-charges.md).
- **eBPF counting honesty (2026-07-02):** with `-udp` enabled, the TC QUIC hook and
  the socket-level UDP path double-counted the same packets (now deduplicated,
  socket-level entry wins); map drains used lossy read-then-delete (now atomic
  `LookupAndDelete`), and the batch read path had *never actually engaged* due to a
  wrong per-CPU buffer shape (fixed, verified live on kernel 6.8); half-closed TCP
  connections stopped counting legal bytes (close accounting deferred to
  `TCP_CLOSE`); UDP entries leaked in the connections map until LRU pressure evicted
  live TCP entries (cleaned via a new `cgroup/sock_release` program);
  `tollwing_ringbuf_drops_total` had no writers and read 0 forever — a kernel
  `drop_counters` map now counts every ringbuf-reserve failure and map-full insert,
  exported with the new `tollwing_map_update_drops_total`; the DNS fentry no longer
  dereferences the empty-queue sentinel, and a 512-byte DNS payload no longer copies
  0 bytes; the `flow_aggregates` default rose 16,384 → 131,072 entries to match the
  compiled object and `ARCHITECTURE.md` §2.3 (documented kernel-memory math).
  See [DEC-016](decisions/DEC-016-remove-dormant-cgroup-storage-iterator-and-conntrack-machinery.md) (Notes).
- **Agent silently shipped nothing without `-cluster` (2026-07-02):** an empty
  `-cluster` built the NATS subject `tollwing.flows..node`, which NATS rejects per
  publish — every flow batch from every node was dropped forever behind a repeating
  warning. The publisher now rejects invalid subject tokens at construction, and the
  agent resolves identity at startup: explicit `-cluster` wins, else the cluster name
  derives from the kube-system namespace UID, else the agent **fails fast** with an
  actionable error (deployments that previously "ran" while shipping nothing now
  refuse to start). Also fixed: the shutdown ordering lost one poll interval of data
  per rolling restart (the poller's final flush now publishes before the NATS drain,
  with eBPF detach last); EndpointSlice bookkeeping wiped sibling slices of
  >100-endpoint services on single-slice updates and leaked deleted services (now
  per-slice tracked, tombstone-aware); and the 6-hour rate-card refresher now
  actually wires the live AWS pricing client instead of re-fetching hardcoded
  defaults (loud warn + dated-default fallback on failure).
  See [DEC-019](decisions/DEC-019-cluster-identity-fail-fast-nats-subject.md).
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


## [0.1.0] - 2026-06-24

Initial public release: the open-core eBPF agent (9-way per-pod billing-path
classifier, pre-DNAT ClusterIP intent capture, Prometheus metrics, 23-panel
Grafana dashboard, Helm chart, `tollwing-terraform`, and the pure-Go proof
suite), published from the monorepo under Apache-2.0.

[Unreleased]: https://github.com/tollwing/tollwing/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/tollwing/tollwing/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tollwing/tollwing/releases/tag/v0.1.0
