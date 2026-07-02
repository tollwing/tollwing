# DEC-014 — Meter billable directions per traffic type; price distributed engines at the marginal list rate

**Status:** ACCEPTED
**Date:** 2026-07-02
**Author(s):** Baris Erdem (with Claude, money-path remediation)
**Reviewer(s):** —

---

## Context

A deep audit of the money path found the displayed dollars wrong on every
cloud provider — a direct P4 violation ("every displayed dollar traceable to
bytes × dated-rate"). Three of the defects are settled by this decision:

1. **Blanket Tx+Rx metering** (`pkg/cost/engine.go`): the engine charged
   `TxBytes + RxBytes` at the per-GB rate for *all* traffic types. That is
   correct for AWS cross-AZ (billed $0.01/GB in each direction) but wrong for
   internet egress and cross-region transfer, where all three providers bill
   the egress side only — ingress was silently billed at egress rates.
2. **Wrong/stale rate constants** (`pkg/cost/ratecard.go`), locked in by the
   very tests meant to guard them: GCP cross-AZ priced $0 (reality:
   $0.01/GiB inter-zone), Azure cross-AZ priced $0.01 (Azure retired
   inter-AZ charges), the AWS internet-egress free tier at 1 GB (it has been
   100 GB/month, account-aggregated, since December 2021), and the $0.085
   band ending at 40 TB instead of 50 TB ("next 40 TB" after the 10 TB
   band).
3. **Per-process tier fiction** (`pkg/cost/engine.go`): cumulative tier
   state lived in an in-memory map inside each `Engine`. Every agent node
   and the server run their own engine, so a 500-node fleet granted itself
   the account-wide free tier 500 times, and any restart reset the mid-month
   tier position.

## Decision

We will make the rate card, not the engine, the authority on billing
semantics, and make the default pricing honest for a distributed fleet:

- **Metered-direction table.** `cost.RateCard` gains a
  `Directions map[classifier.TrafficType]MeteredDirection` table
  (`MeterTxRx`, `MeterTx`, `MeterRx`, `MeterNone`), built per provider by
  `cost.DefaultMeteredDirections`. The engine bills only
  `card.MeteredBytes(tt, tx, rx)`. Directions are defined from the observing
  node's perspective: AWS cross-AZ meters both directions (this node pays
  $0.01/GB out for Tx *and* $0.01/GB in for Rx; the peer node's agent meters
  the same wire bytes from its side, so the fleet sum reproduces the bill
  without double counting), while internet egress, cross-region, and TGW
  data processing meter Tx only.
- **Verified, dated rates.** The default cards carry list prices verified
  against the provider pricing pages on **2026-07-02** (sources below), with
  `LastUpdated` pinned to that verification date (not `time.Now()`) and a
  `Source` label — per P4, a rate without a date is untraceable, and a stale
  default must look stale.
- **Marginal pricing is the default** (`PricingModeMarginal`, the zero value
  of `cost.EngineConfig`): every metered GB prices at the marginal
  post-free-tier list rate (`TieredRate.MarginalRate()` — the first paid
  tier). No cumulative state exists in this mode.
- **Single-meter pricing is explicit opt-in** (`PricingModeSingleMeter`, via
  `cost.NewEngineWithConfig`): the full tier table with cumulative tracking,
  valid only where exactly one engine meters the whole account's traffic —
  the Enterprise server's aggregation path. The meter remains per-process
  and resets on restart; that limitation is accepted here and is a
  re-evaluation trigger below.

### Verified rates (as of 2026-07-02)

| Provider | Traffic type | Rate | Metered |
|---|---|---|---|
| AWS us-east-1 | cross-AZ | $0.01/GB **each direction** | Tx+Rx |
| AWS us-east-1 | cross-region | $0.02/GB | Tx |
| AWS us-east-1 | internet egress | 100 GB/mo free; ≤10 TB $0.09; next 40 TB (≤50 TB) $0.085; next 100 TB (≤150 TB) $0.07; >150 TB $0.05 | Tx |
| AWS us-east-1 | VPC peering (intra-region) | $0.01/GB each direction | Tx+Rx |
| AWS us-east-1 | PrivateLink endpoint | $0.01/GB processed | Tx+Rx |
| AWS us-east-1 | NAT gateway | $0.045/hr + $0.045/GB processed | Tx+Rx (per-GB) |
| AWS us-east-1 | Transit Gateway | $0.05/attachment-hr + $0.02/GB sent into TGW | Tx |
| GCP us-central1 | inter-zone (cross-AZ) | $0.01/GiB, billed to the sender | Tx |
| GCP us-central1 | inter-region (NA) | $0.02/GiB | Tx |
| GCP us-central1 | internet egress (Premium, NA) | ≤1 TiB $0.12; 1–10 TiB $0.11; >10 TiB $0.08 | Tx |
| GCP us-central1 | VPC peering | standard inter-zone rates ($0.01/GiB) | Tx |
| GCP us-central1 | PSC endpoint | $0.01/GiB consumer data processing | Tx+Rx |
| GCP us-central1 | Cloud NAT | $0.0014/VM-hr (cap $0.044/hr) + $0.045/GiB | Tx+Rx (per-GB) |
| Azure eastus | cross-AZ | **$0 — inter-AZ charges retired (2024)** | — |
| Azure eastus | inter-region (NA) | $0.02/GB | Tx |
| Azure eastus | internet egress (Zone 1) | 100 GB/mo free; ≤10 TB $0.087; ≤50 TB $0.083; ≤150 TB $0.07; >150 TB $0.05 | Tx |
| Azure eastus | VNet peering (intra-region) | $0.01/GB inbound AND outbound | Tx+Rx |
| Azure eastus | Private Link | $0.01/hr + $0.01/GB in + out | Tx+Rx (per-GB) |
| Azure eastus | NAT Gateway | $0.045/hr + $0.045/GB processed | Tx+Rx (per-GB) |

Caveats recorded with the rates: AWS same-AZ peering is free but the peer's
AZ is unobservable from flow data, so peering prices at the cross-AZ rate
(conservative, documented). GCP's 1 GiB/mo "Always Free" egress and Azure's
"free egress when leaving Azure" are account-level programs, not rate tiers,
and are deliberately not modelled (P5: never guess account state).

## Alternatives considered

### Alternative A — Keep blanket Tx+Rx metering (status quo)

**Why not:** It bills ingress at egress rates. An Rx-heavy internet flow
(e.g. pulling data in) displayed real dollars for bytes AWS/GCP/Azure charge
$0 for — a P4 violation on the product's one job.

### Alternative B — Hardcode directions in the engine's switch statement

**Why not:** Directions differ per provider (AWS cross-AZ bills both
directions; GCP bills the sender only; Azure bills neither). A single switch
cannot express that without provider conditionals scattered through the
engine; the table lives with the rest of the provider's billing semantics on
the rate card, where live pricing clients can inherit it.

### Alternative C — Keep per-engine cumulative tiering as the default

**Why not:** This is the audited bug: N engines grant the free tier N times
and restarts reset the meter — systematic under-reporting that no one
configured and no one can see (P5 anti-example: the flattering answer).

### Alternative D — Distributed tier coordination (share the meter across agents)

**Why not:** Cross-node state in the agent violates P1/P2 (one lean agent,
no cross-node logic), and even a coordinated meter cannot see non-Tollwing
egress (S3, Lambda, other clusters) that consumes the same account-wide
allowance. The marginal rate is the honest, defensible default; the true
tier position belongs to the single-meter server path and to billing
reconciliation.

### Alternative E — Model the free tier as "first N GB per node"

**Why not:** Pure fiction — the allowance is per account, not per node.

## Consequences

### Positive

- Displayed dollars match provider billing semantics per direction; every
  rate carries a verification date and source (P4).
- The default mode is stateless: restart-safe, fleet-safe, deterministic.
- Wrong-rate regressions now fail two independent gates: engine unit tests
  assert hand-derived provider-sheet dollars, and the test/sim oracle prices
  from its own transcribed sheet (DEC-008).

### Negative

- Marginal pricing over-reports egress for accounts genuinely inside the
  free tier or above the 10 TB band (list-rate ceiling). Reconciliation
  against the real bill (P4's accuracy score) is the corrective, not
  per-node guessing.
- Rates changed: cross-region and TGW scenario dollars halved (Tx-only),
  NAT flows now include the DTO leg (DEC-015), GCP cross-AZ is no longer
  free, Azure cross-AZ is now free. Dashboards trained on the old numbers
  will move.

### Neutral

- `NewEngine` keeps its signature (defaults to marginal); the server opts
  into single-meter with one line:
  `cost.NewEngineWithConfig(store, cost.EngineConfig{Mode: cost.PricingModeSingleMeter})`.

## Constitutional principles touched

- **P1 (the agent is the product):** advances — no new agent state or
  cross-node logic; the honest default is stateless.
- **P2 (lean agent):** advances — marginal mode removes the unbounded
  cumulative map from the default path.
- **P4 (honest, traceable cost):** advances — dated, sourced rates;
  direction-true metering; no invisible free-tier grants.
- **P5 (accurate attribution over convenient approximation):** advances —
  the engine no longer guesses the account's tier position or bills
  unbillable directions.
- **P6 (canonical representations):** neutral — the direction table is keyed
  by `classifier.TrafficType`; tier keys derive from `TrafficType.String()`.
- **P11 (compatible contracts):** neutral — `RateCard` gains fields
  (additive); `NewEngine` unchanged; `NewEngineWithConfig` is new.

## Re-evaluation triggers

- Any provider changes a listed rate, tier boundary, or direction semantics
  (verify at least quarterly against the sources below; the CUR/billing
  reconciliation drift alert is the runtime tripwire).
- The Enterprise server persists tier state across restarts (removes the
  single-meter restart caveat) — revisit whether single-meter should become
  the server default.
- Live pricing APIs begin exposing billing directions — the hardcoded
  direction tables could then be fetched instead of transcribed.

## Related decisions

[DEC-008] (the sim suite that cross-checks these rates), [DEC-011] (float
accumulation of the resulting dollars), [DEC-015] (NAT route detection and
hourly charges; the DTO leg on NAT flows).

## References

- `pkg/cost/ratecard.go` (rates, directions, `MarginalRate`),
  `pkg/cost/engine.go` (`EngineConfig`, `PricingMode`, `MeteredBytes` use),
  `pkg/cost/engine_test.go`, `pkg/cost/pipeline_test.go`,
  `test/sim/oracle.go` (independent sheet).
- AWS: https://aws.amazon.com/ec2/pricing/on-demand/ (Data Transfer),
  https://aws.amazon.com/vpc/pricing/,
  https://aws.amazon.com/transit-gateway/pricing/,
  https://aws.amazon.com/privatelink/pricing/,
  https://docs.aws.amazon.com/vpc/latest/userguide/nat-gateway-pricing.html,
  https://aws.amazon.com/blogs/networking-and-content-delivery/exploring-data-transfer-costs-for-aws-network-load-balancers/
  (the "$0.01/GB in each direction" cross-AZ statement).
- GCP: https://cloud.google.com/vpc/network-pricing,
  https://cloud.google.com/network-tiers/pricing,
  https://cloud.google.com/nat/pricing, https://cloud.google.com/vpc/pricing.
- Azure: https://azure.microsoft.com/en-us/pricing/details/bandwidth/,
  https://azure.microsoft.com/en-us/pricing/details/virtual-network/,
  https://azure.microsoft.com/en-us/pricing/details/azure-nat-gateway/,
  https://azure.microsoft.com/en-us/pricing/details/private-link/,
  https://azure.microsoft.com/en-in/updates?id=update-on-interavailability-zone-data-transfer-pricing
  (inter-AZ charge retirement).

## Notes

The AWS free tier (100 GB/mo) is aggregated across ALL services and regions
on the account — even a true single meter over Tollwing flows can only see
the Kubernetes share of it. Single-meter mode is therefore also an
approximation, just a far better one; reconciliation remains the source of
billing truth.
