# DEC-010 — Leave the ClusterIP dialer-side leg Unknown; cross-AZ dedup/attribution is a control-plane job

**Status:** ACCEPTED
**Date:** 2026-05-30
**Author(s):** Baris Erdem (with Claude Opus 4.8, supervising founder)

---

## Context

Fixing the IP byte-order bug ([DEC-009](DEC-009-canonical-bpf-ip-byte-order.md)) and re-running the L2b real-agent tier surfaced a follow-up question. For a flow where a client pod dials a Kubernetes Service ClusterIP whose backend lives in another zone, the two endpoint agents classify it differently:

- **Client-node agent** (the dialer): at the socket layer it sees the **pre-DNAT ClusterIP** as the destination ([DEC-003](DEC-003-two-phase-pre-dnat-capture.md)). A ClusterIP has no zone in the `ZoneResolver` (the K8s informer feeds pod-IP→zone and node→zone, never ClusterIP→backend-zone), so `classifier.classifyInternal` resolves the src zone but gets `""` for the dst and returns **`Unknown`** (correctly refusing to guess — P5).
- **Backend-node agent** (the responder): it sees client-pod-IP → echo-pod-IP — both real pod IPs with resolvable zones — and classifies **`cross_az`**.

Verified live on L2b (client `10.244.2.2`/us-east-1a → echo ClusterIP `10.96.14.74`, backend pod `10.244.1.2`/us-east-1b): the client-node agent reports the bytes under `traffic_type="unknown"`; the backend-node agent reports them under `cross_az`.

The question: **should the dialer-side leg also be attributed `cross_az`** (e.g. by resolving ClusterIP → EndpointSlice → backend pod → node zone and re-deriving the type in `handlePoll`)?

The decisive facts, from reading the cost and graph code:

1. **Cost is `(TxBytes + RxBytes) × rate`** (`pkg/cost/engine.go:101-102`). A single flow's cost already includes **both** the request and response bytes.
2. The backend-node agent's `cross_az` flow therefore has `(Tx+Rx)` = response + request = the **full bidirectional volume** of the interaction. It captures the entire cross-AZ cost **once**.
3. The dialer-side flow's `(Tx+Rx)` is the **same** bidirectional volume (client's tx = request, rx = response). Classifying it `cross_az` too would bill the same interaction's cross-AZ volume **a second time**.
4. The service graph keys cross-AZ off the `traffic_type` string (`pkg/servicegraph/graph.go:101-104` `crossZoneCharged`) and the ClickHouse rollup sums `tx_bytes + rx_bytes` and `cost_usd` per edge (`pkg/servicegraph/source.go:55-57`). So a second `cross_az` edge for the same interaction doubles both the bytes and the dollars in every downstream view.

## Decision

**Leave the dialer-side leg classified `Unknown`. Do not resolve the backend zone in the agent to re-classify ClusterIP dialer flows as `cross_az`.**

The cross-AZ dollar total is already captured exactly once by the backend-node agent (fact 2). The agent does what it can see locally and honestly marks `Unknown` what it cannot (P5). Any *canonical, dialer-attributed, deduplicated* cross-AZ view — putting the charge on the `client→echo` edge while not double-counting the `echo→client` view — requires correlating the two endpoint agents' observations of one connection, which is **cross-node correlation and therefore a control-plane (`tollwing-server`/`pkg/servicegraph`) responsibility, not an agent one** (P1). It is recorded here as future work, not implemented now.

An inline guard-rail in `pkg/agent/agent.go` `handlePoll` (where the pre-DNAT ClusterIP is recovered to a service *identity* but deliberately not to a *zone*) cites this ADR so a future contributor does not "fix" the `Unknown` into a double-count.

## Alternatives considered

### Alternative A — Resolve the backend zone in the agent and classify the dialer leg `cross_az`

Resolve ClusterIP → EndpointSlice → backend pod → node zone in `handlePoll` and re-derive the traffic type from src-zone + backend-zone.
**Why not:** it **double-counts** (facts 1–4): the dialer flow's `(Tx+Rx)` is the same bidirectional volume the backend-node agent already counts as `cross_az`, so the cross-AZ bytes and dollars would be billed twice across the fleet — a direct hit on **P4** ("an attribution that double-counts or invents dollars" is an explicit anti-example). It also pushes EndpointSlice-watching and cross-node reasoning into the per-node agent, eroding **P1/P2** (the agent should stay lean; correlation belongs in the control plane).

### Alternative B — Keep the dialer leg Unknown; reconcile in the control plane (chosen)

Accept the agent-side `Unknown` (the cost is captured once on the backend side) and document the limitation; treat canonical dialer-attribution + dedup as a control-plane feature.
**Why chosen:** it preserves correct cost totals (no double-count, **P4**), keeps the agent honest and lean (**P5/P1**), and puts the genuinely cross-node problem where it can actually be solved (the control plane already holds both endpoints' flows and the service identities).

### Alternative C — Suppress the responder (`echo→client`) leg and move cross-AZ onto the dialer leg, in the agent

Classify the dialer leg `cross_az` *and* suppress the backend-node `cross_az` flow so the total stays single-counted and lands on the `client→echo` edge.
**Why not:** the suppression requires knowing that the backend's incoming flow is the *response* to a dialed connection observed on a *different node* — the agent cannot know this locally. It is the same cross-node correlation as Alternative B's proper fix, so it belongs in the control plane, not split across two blind agents.

## Consequences

### Positive

- Cross-AZ **dollar total is correct** — captured once via the backend-node agent's `(Tx+Rx)` flow; no double-count (P4).
- The agent stays lean and honest: it never guesses a zone for a ClusterIP (P5) and takes on no EndpointSlice state or cross-node logic (P1/P2).

### Negative

- In the **direct, per-edge** view the cross-AZ charge sits on the responder edge (`echo→client`, attributed to the responder) rather than the dialer edge (`client→echo`), which is the [DEC-003] ideal ("attribute to the service the client dialed"). The graph's **transitive** responsibility model (`pkg/servicegraph/attribution.go`) partially compensates — because the dialer drives the responder's inbound traffic, `AttributeFrom(client)` surfaces the cost as the client's *induced* cross-zone cost — but the direct breakdown and the agent's own Prometheus `cross_az` byte metric still land on the responder side.
- For a workload where one endpoint is **not** a Kubernetes Service (e.g. the L2b `client` Deployment), the dialer flow lacks a `dst_service`/`src_service` and is filtered out of the graph entirely (`pkg/servicegraph/source.go:60-61`); only the backend's `cross_az` flow carries the interaction, reinforcing that reconciliation must be a control-plane concern.

### Neutral

- No code behavior change ships with this ADR (only a guard-rail comment + this record). The proper fix is deferred to a future control-plane reconciliation feature.
- Surfaced a **separate, unrelated** bug while investigating: the agent's `tollwing_cost_usd_total` reads `$0` for `cross_az` despite hundreds of MB, because `pkg/exporter/prometheus.go:267-268` floors each flow's cost with `uint64(f.CostUSD * 1_000_000)` and the tight-loop workload's many short-lived per-connection flows are each sub-microdollar → truncated to 0. Tracked separately (not part of this decision) — **fixed in [DEC-011](DEC-011-float-cost-accumulation-round-at-emit.md)**.

## Constitutional principles touched

- **P4 (honest, traceable cost):** advances — the decisive reason; classifying the dialer leg `cross_az` under the `(Tx+Rx)` cost model would double-count the cross-AZ bill.
- **P5 (accurate attribution over convenient approximation):** advances — `Unknown` for an unresolvable ClusterIP zone is the honest answer; we do not fabricate a `cross_az` (or `same_zone`) the dialer side cannot prove.
- **P1 (the agent is the product):** advances — the cross-node correlation needed to attribute cross-AZ to the dialer and dedup the two views is a control-plane job; the agent stays lean.
- **P2 (near-zero node overhead):** advances/neutral — avoids adding EndpointSlice-watching and per-flow re-resolution to the DaemonSet.

## Re-evaluation triggers

- The cost model changes from `(Tx+Rx)` to a **per-direction** charge (each agent counts only its node's egress) — then each endpoint counts a distinct half and the dialer leg *should* carry its direction's cross-AZ cost; revisit.
- `pkg/servicegraph` gains **bidirectional reconciliation** (collapse the two endpoint views of one connection into a single dialer-attributed edge) — then the dialer-attribution gap is closed in the right place and this ADR's "future work" is done.
- A dataplane (eBPF service mesh / Cilium) preserves the **ClusterIP and the backend zone to the dialer socket**, making the dialer-side zone resolvable without cross-node correlation — revisit whether the agent can attribute the dialer leg without double-counting.

## Related decisions

- [DEC-011](DEC-011-float-cost-accumulation-round-at-emit.md) — the fix for the cost-truncation bug this ADR surfaced and deferred (see Notes and Consequences→Neutral).
- [DEC-009](DEC-009-canonical-bpf-ip-byte-order.md) — the byte-order fix that unmasked this; the L2b run that surfaced it.
- [DEC-003](DEC-003-two-phase-pre-dnat-capture.md) — recovers the pre-DNAT ClusterIP (the dialed-service intent) this decision relies on for the dst *identity*; the dst *zone* is the part the dialer side still can't resolve.
- [DEC-008](DEC-008-local-proof-simulation-suite.md) — the suite. Note the sim-vs-real divergence: the L2a injector classifies the **backend pod IP** (which has a zone) and gets `cross_az`, while the real L2b agent classifies the **ClusterIP** and gets `Unknown`. A future L2 scenario should assert the real-agent behavior so the suite reflects it.

## References

- `pkg/cost/engine.go:101-102` — cost = `(TxBytes + RxBytes) × rate`.
- `pkg/servicegraph/graph.go:101-104` (`crossZoneCharged`), `pkg/servicegraph/source.go:55-61` (rollup sums tx+rx and cost; requires src_service + a dst identity), `pkg/servicegraph/attribution.go` (transitive responsibility).
- `pkg/agent/agent.go` `handlePoll` — recovers the ClusterIP→service identity via `intentCache` + `informer.LookupClusterIP`, deliberately not the backend zone (guard-rail comment cites this ADR).
- `pkg/cost/ratecard.go:81` — AWS `CrossAZ` = `$0.01/GB` (so the cost is real, just single-counted on the backend side today).

## Notes

The separate cost-truncation bug (`pkg/exporter/prometheus.go:267-268`, per-flow `uint64(CostUSD × 1e6)` flooring sub-microdollar flows to 0) is tracked outside this ADR; it under-reports cost generally and is independent of the cross-AZ attribution decision recorded here. **Fixed in [DEC-011](DEC-011-float-cost-accumulation-round-at-emit.md).**
