# DEC-015 — Detect NAT egress from route tables; price the DTO leg; keep hourly charges out of per-flow cost

**Status:** ACCEPTED
**Date:** 2026-07-02
**Author(s):** Baris Erdem (with Claude, money-path remediation)
**Reviewer(s):** —

---

## Context

The money-path audit found NAT gateway attribution structurally broken, plus
three adjacent topology-feed defects that poisoned classification:

1. **NAT detection never matched.** `pkg/classifier` classified a flow as
   NAT egress only when `dst == NAT ENI IP`. An internet-bound flow's
   destination is the internet IP — it never equals the NAT ENI — so the
   dominant NAT cost driver (pod → internet through NAT) always classified
   `internet_egress` and the $0.045/GB NAT data-processing charge was never
   attributed.
2. **NAT/TGW hourly rates were charged nowhere.** `NATGatewayRate.PerHourUSD`
   and `TransitGWRate.PerAttachmentHourUSD` existed but no code path priced
   them.
3. **ip-ranges.json poisoned the endpoint set.**
   `cloud.TopologyRefresher.refreshServiceCIDRs` flattened ALL published
   service ranges — including the giant AMAZON/EC2 blocks — into
   `SetVPCEndpointCIDRs`, so public-EC2/internet traffic billed $0.01/GB
   "vpc_endpoint" instead of ~$0.09/GB egress.
4. **The classifier prefix tree was append-only** under the 5-minute
   refresher: unbounded growth, and deleted peerings kept classifying
   forever.

## Decision

We will attribute NAT costs from **route knowledge**, price the **full
byte-metered** cost of a NAT flow, and keep **fixed hourly charges out of
per-flow dollars**:

- **Route-based NAT detection.** The AWS provider gains
  `NodeRoutesViaNAT(ctx)`: it resolves the node's subnet (config override or
  IMDS `network/interfaces/macs/<mac>/subnet-id`) and inspects
  `DescribeRouteTables` — the subnet's associated table, or the VPC main
  table when unassociated — for a `0.0.0.0/0` route targeting a NAT gateway.
  `cloud.TopologyRefresher` feeds the result to
  `classifier.SetDefaultRouteNAT`; unmatched internet-bound flows from such
  subnets classify `nat_gateway`. The capability is an optional interface
  (`natRouteDetector`) so GCP/Azure providers are unaffected until they can
  implement it. The dst==NAT-ENI check remains (it still catches flows
  addressed to the ENI itself).
- **NAT flows price processing + the DTO leg.** A NAT-classified flow costs
  `NATGateway.PerGBUSD × metered(Tx+Rx)` **plus** the internet-egress rate on
  the Tx bytes (marginal or single-meter per DEC-014, feeding the same
  egress meter). Route-detected NAT flows are by construction
  internet-bound: after the NAT, the bytes still exit the cloud and incur
  data-transfer-out. Charging only the $0.045 processing (as before) hid
  ~$0.09/GB of real spend.
- **Hourly charges are NOT per-flow.** Per P4, a displayed per-flow dollar
  must be that flow's bytes × a dated rate. A gateway-hour is a fixed charge
  that exists whether or not any flow runs; splitting it across flows
  requires inventing a utilization share (P5: never guess). The hourly
  fields stay on the rate card as reference data, and the spend surfaces
  where it is honest: billing reconciliation's explicit "unaccounted"
  bucket (`pkg/cost/reconcile.go` — proven by
  `test/sim/reconcile_test.go::TestReconcile_NATHoursUnaccounted`).
- **Topology feed hygiene** (same refresher, same money path):
  - Published service ranges are no longer fed to `SetVPCEndpointCIDRs`. A
    public range says nothing about whether THIS VPC has an endpoint for it;
    endpoint CIDRs must come from actually-deployed endpoints (a future
    `DescribeVpcEndpoints` feed) or explicit operator configuration.
  - The classifier's `Set{VPCPeering,TransitGateway,VPCEndpoint}CIDRs` are
    now **replace-on-refresh**: each call replaces its category and the
    prefix tree is rebuilt from the per-category sets, so the tree always
    equals the latest topology snapshot.
  - The RFC 1918 branch of `Classify` consults NAT IPs and the
    peering/TGW/endpoint prefix sets **before** zone-based fallback — real
    VPC peers are almost always RFC 1918, and the old order collapsed them
    to Unknown/$0 (fixed alongside, tested in
    `TestClassify_RFC1918PeeringAndTGW`; rate side in DEC-014).
  - GCP's regional subnets produce **no** CIDR→zone mapping (a regional CIDR
    spans all zones — mapping it to the local zone made cross-zone traffic
    read same_zone/$0), and Azure's bare zone ordinals are region-qualified
    (`QualifyAzureZone("eastus","1") = "eastus-1"`) so cross-AZ no longer
    misclassifies as cross-region.

## Alternatives considered

### Alternative A — Keep IP-based NAT detection only (status quo)

**Why not:** It cannot ever match the internet-bound flows that generate NAT
data-processing spend; the product's headline NAT number was structurally $0
for the common architecture (private subnets behind NAT).

### Alternative B — Amortize hourly charges across flows (per-GB uplift)

**Why not:** The uplift depends on utilization (an idle gateway's $32/month
against 1 GB would price $32/GB; a busy one pennies) — an invented,
unstable rate that violates P4's "bytes × dated-rate" and P5's "never
guess". Reconciliation already surfaces the fixed spend honestly.

### Alternative C — Emit synthetic hourly line-item flows from the engine

**Why not:** The engine's contract is flow costing; a synthetic flow with no
bytes breaks P4's traceability invariant (cost with bytes=0) and would
double-count once the server reconciles against the bill. If per-resource
hourly reporting is wanted, it belongs in the control plane's reconcile
path, which already has the bill.

### Alternative D — Classify NAT-routed internet flows as internet_egress and add a NAT surcharge there

**Why not:** It erases the operator-facing distinction the product sells —
"which pods route through the NAT (and could use a VPC endpoint instead)".
`nat_gateway` as the traffic type with the DTO leg priced in keeps both the
attribution and the dollars right.

### Alternative E — Keep feeding ip-ranges.json as CloudServicePublic instead of VPCEndpoint

**Why not:** Still a guess: without knowing an endpoint (or the service
semantics) the honest classification for a public address is the default
egress path. `cloud_service_public` remains a DNS/FOCUS-enrichment outcome,
not an IP-prefix inference (per the existing sim design).

## Consequences

### Positive

- NAT spend is attributable for the architecture that actually generates it;
  the NAT dollar now includes the real DTO component.
- Deleted peerings stop classifying within one refresh; the prefix tree is
  bounded by the live topology size.
- Public-EC2 traffic prices as egress again (~$0.09/GB, not $0.01).

### Negative

- Route-based detection is AWS-only for now; GCP/Azure NAT attribution still
  relies on NAT IP matching (their flows misclassify as internet_egress —
  under-reported by the NAT processing component until implemented).
- Subnet-level route detection is coarse: a subnet with per-prefix routes
  (some via NAT, some via IGW) is represented by its default route only.
- Losing the ip-ranges feed means no automatic vpc_endpoint classification
  until a DescribeVpcEndpoints feed exists; operators can still set endpoint
  CIDRs explicitly.

### Neutral

- `GetServiceCIDRs` remains on the `cloud.Provider` interface (P11); the
  refresher simply no longer routes it into classification.

## Constitutional principles touched

- **P1 (the agent is the product):** neutral — one more cloud API read per
  refresh cycle; no new agent subsystem.
- **P2 (lean agent):** advances — the prefix tree is now bounded.
- **P4 (honest, traceable cost):** advances — NAT dollars are bytes × dated
  rates (processing + DTO); hourly spend stays in the explicit unaccounted
  bucket instead of being silently dropped or invented per-flow.
- **P5 (accurate attribution):** advances — route truth replaces an
  impossible IP match; stale peerings and regional-subnet zone guesses no
  longer misattribute.
- **P11 (compatible contracts):** neutral — `natRouteDetector` is an
  optional interface; `Provider` gains no required methods.
- **P12 (data minimization):** neutral — route tables describe
  infrastructure, not workload payloads.

## Re-evaluation triggers

- GCP/Azure providers gain route/NAT-config APIs in our SDK surface —
  implement `natRouteDetector` for them and revisit the "AWS-only" negative.
- AWS `DescribeVpcEndpoints` feed lands — re-enable automatic vpc_endpoint
  classification from deployed endpoints and revisit Alternative E.
- Reconciliation shows persistent NAT drift >5% — the subnet-level
  granularity may need per-route-prefix detection.
- AWS Regional/Provisioned NAT gateway pricing models (per-Gbps-hour, free
  data processing) become common — the per-GB NAT model needs a variant.

## Related decisions

[DEC-014] (metered directions + marginal default; the DTO leg prices under
its rules), [DEC-008] (nat-gateway-route and vpc-peering-rfc1918 scenarios
prove this end-to-end), [DEC-010] (dialer-side Unknown stays Unknown).

## References

- `pkg/cloud/aws/aws.go` (`NodeRoutesViaNAT`, `nodeSubnetID`),
  `pkg/cloud/aws/ec2_client.go` (`DescribeRouteTables`),
  `pkg/cloud/topology.go` (`refreshNATRoute`, service-CIDR removal note),
  `pkg/classifier/traffic.go` (`SetDefaultRouteNAT`, `classifyPrivate`,
  `rebuildPrefixTreeLocked`), `pkg/cloud/gcp/gcp.go`
  (`GetSubnetZoneMapping`), `pkg/classifier/zone.go` (`QualifyAzureZone`),
  `pkg/cost/engine.go` (NAT pricing), `test/sim/scenarios/nat-gateway-route.yaml`,
  `test/sim/scenarios/vpc-peering-rfc1918.yaml`.
- AWS NAT pricing (processing + DTO stack):
  https://docs.aws.amazon.com/vpc/latest/userguide/nat-gateway-pricing.html,
  https://aws.amazon.com/vpc/pricing/.
- Route-table semantics: EC2 `DescribeRouteTables` (main-table fallback for
  unassociated subnets).

## Notes

The reconciler already maps `NatGateway-Hours` CUR line items into the
unaccounted bucket and raises a drift alert — that behaviour is the other
half of this decision and was kept intact deliberately.
