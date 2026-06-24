# DEC-011 — Accumulate network cost in full-precision float dollars; round once at emit (fix sub-micro-dollar flow truncation)

**Status:** ACCEPTED
**Date:** 2026-05-30
**Author(s):** Baris Erdem (with Claude Opus 4.8, supervising founder)

---

## Context

The agent's Prometheus cost counters — `tollwing_cost_usd_total{traffic_type=…}` and `tollwing_pod_cost_usd_total{namespace,pod}` — under-reported to **$0** for any workload made of many small, short-lived flows, even when the byte counters showed real volume.

Root cause: `pkg/exporter/prometheus.go` `UpdateFromPoll` accumulated cost as **integer micro-USD, floored per flow**:

```go
microUSD := uint64(f.CostUSD * 1_000_000)            // per-type
e.state.podCost[pk] += uint64(f.CostUSD * 1_000_000) // per-pod
```

Any single flow whose cost is below `$0.000001` floors to `0` and is lost. A tight client loop (e.g. `wget` in a loop) opens a distinct short-lived connection per request, so the in-kernel `flow_aggregates` map holds many distinct 5-tuples each with tiny byte counts; each flow's cost (`bytes/GiB × per-GB rate`) is sub-micro-dollar, truncates to `0`, and the counter never moves.

This bug was surfaced — but deliberately **not** fixed — while recording [DEC-010](DEC-010-clusterip-dialer-side-cross-az-attribution.md) (see its Consequences→Neutral and Notes, which track the `prometheus.go` floor), and confirmed live on the L2b real-agent tier ([DEC-008](DEC-008-local-proof-simulation-suite.md)): the backend-node agent reported `tollwing_tx_bytes_total{traffic_type="cross_az"}` ≈ 376 MB but `tollwing_cost_usd_total{traffic_type="cross_az"}` = `0.000000`, even though the AWS rate card prices CrossAZ at `$0.01/GB` (`pkg/cost/ratecard.go:81`). `0.387 GiB × $0.01 ≈ $0.0039`, which should display as `0.003900`.

A cost counter that reads `$0` while bytes flow is a direct **P4** violation: the displayed dollar figure is no longer derivable from `bytes × dated-rate`. It is independent of the byte-order bug ([DEC-009](DEC-009-canonical-bpf-ip-byte-order.md)) and of the cross-AZ dialer-attribution decision ([DEC-010](DEC-010-clusterip-dialer-side-cross-az-attribution.md)).

The original integer representation was a deliberate code choice — its comment read *"Stored as uint64 micro-USD to avoid floating-point atomics."* That choice (avoid float atomics) is exactly what introduced the per-flow floor, so fixing the bug means revisiting it.

## Decision

**Accumulate cost in full-precision float dollars across the poll(s) and round to the emitted `%.6f` exactly once, at scrape time, for both the per-traffic-type and the per-pod counters.**

Concretely, in `pkg/exporter/prometheus.go`:

- **Per-pod cost** becomes `map[podKey]float64` (USD). It is already accumulated and read under `podMu`, so it needs no atomics: `e.state.podCost[pk] += f.CostUSD`.
- **Per-type cost** stays a `[numTrafficTypes]atomic.Uint64` so the `/metrics` scrape keeps reading it **lock-free** (as the byte counters do), but the `uint64` now holds the **float64 bits** of the accumulated dollars. A small `addCostUSD(c *atomic.Uint64, delta float64)` helper does a `Load → Float64frombits → +delta → Float64bits → CompareAndSwap` loop. The poll loop (`pkg/agent.handlePoll` → `UpdateFromPoll`) is the only writer, so the CAS is effectively uncontended; the atomic exists solely for the concurrent scrape read.
- **Emit** decodes once and formats unchanged: `math.Float64frombits(load)` → `%.6f`.

The **emitted Prometheus contract is unchanged** — same metric names, `counter` type, `traffic_type` / `namespace` / `pod` labels, and `%.6f` USD formatting. Only the internal accumulation representation and the lost-precision behavior change. The counters remain monotonic. This is a bug fix, not a contract change (P11): a counter that was stuck at `0` now advances correctly; no client breaks.

## Alternatives considered

### Alternative A — Status quo: integer micro-USD, floored per flow

Keep `uint64(f.CostUSD * 1_000_000)` per flow.
**Why not:** it *is* the bug. It under-reports any sub-micro-dollar flow to `$0`, and a many-small-flow workload to `$0` in aggregate — an untraceable dollar figure (**P4**).

### Alternative B — Sum floats per poll, floor to micro-USD once per poll (keep the uint64 store)

Accumulate a local `float64` per type within `UpdateFromPoll`, then `Add(uint64(sum * 1e6))` once per poll.
**Why not:** it only *narrows* the bug. It still discards up to `<$0.000001` per type **per poll**; over a 5 s poll interval that is a systematic, silent under-count that compounds for the lifetime of the process (and worse across per-pod cardinality). A counter that leaks value every poll is still P4-dishonest, just less visibly.

### Alternative C — Round (not floor) per flow to the nearest micro-USD

`uint64(f.CostUSD*1e6 + 0.5)` per flow.
**Why not:** any flow below `$0.0000005` still rounds to `0`, and rounding the rest *up* introduces a positive bias that does not conserve dollars. It trades a guaranteed under-count for a noisy, biased count — still not `bytes × rate` (**P4**).

### Alternative D — Switch the integer scale to nano-USD (or pico-USD)

Accumulate `uint64` nano-USD (`f.CostUSD * 1e9`), keep integer atomics, divide by `1e9` at emit.
**Why not:** it pushes the truncation threshold down rather than removing it (a sub-nano-dollar flow still floors to `0`), and it adds a second fixed-point scale that must be kept in sync with the `%.6f` emit. It is the closest "keep integer atomics" option and is recorded for that reason, but float-dollars-accumulated-once is simpler and exact to float precision across the dollar ranges a per-node counter will ever hold.

### Alternative E — Protect cost with a dedicated mutex instead of atomic float bits

Drop the atomic; guard `costByType` with a lock on both write and scrape.
**Why not:** it gives up the **lock-free scrape** that every other per-type counter (`txByType`, `rxByType`, …) enjoys, adding lock contention to the hot `/metrics` path for no benefit. The float-bits CAS is the minimal change that preserves the existing concurrency model.

## Consequences

### Positive

- Cost counters are **honest for many-small-flow workloads** — the L2b `cross_az` case now reports `~0.003900` instead of `0.000000`, and every dollar again traces to `bytes × dated-rate` (**P4**).
- Per-type and per-pod cost share the **same accumulate-precise / round-once contract**, so they cannot drift from each other.
- The emitted metric contract is untouched, so dashboards, alerts, and the N-1 fleet keep working (**P11**).

### Negative

- Reintroduces **floating-point atomics** (a CAS loop) that the original code explicitly avoided. Mitigated: a single writer makes the CAS effectively uncontended, and the operation is two atomic ops + a float add + two (free) bit-casts per costed flow — negligible against the per-flow classification/enrichment already on that path (**P2**).
- `float64` accumulation carries bounded rounding error (~`2⁻⁵²` relative). For realistic per-counter magnitudes this is many orders of magnitude below the emitted `%.6f` resolution; it would only matter if a single counter accumulated past ~`$10⁹` with sub-cent additions, which a per-node agent counter will not.

### Neutral

- **No public-contract change**: internal representation only. No version bump, no deprecation. Recorded in `CHANGELOG.md` under *Fixed* (P4 / P11).
- The per-type `atomic.Uint64` field is **reused** (it now holds float64 bits rather than micro-USD); no struct-size or layout change.

## Constitutional principles touched

- **P4 (honest, traceable cost):** advances — the decisive reason. A cost counter reading `$0` while bytes flow is an untraceable figure; accumulating precise dollars and rounding once restores `bytes × rate`.
- **P2 (near-zero node overhead):** neutral — reverses the "avoid float atomics" micro-optimization, but the added cost (an uncontended CAS per costed flow) is negligible and bounded; no new state or allocation.
- **P11 (public contracts evolve compatibly):** advances/neutral — the emitted metric (name, type, labels, `%.6f`) is preserved; a stuck-at-zero counter advancing correctly is a bug fix, not a break, so no version bump is required.
- **P1 (the agent is the product):** neutral — the fix stays inside the existing exporter; it adds no cross-node logic or unbounded state to the agent.
- **P6 (one canonical representation):** neutral — the regression test derives its `traffic_type` label from `classifier.CrossAZ.String()`, never a hardcoded literal.

## Re-evaluation triggers

- A requirement for **exact decimal accounting** (e.g. billing-grade reconciliation that must conserve cents exactly) — then move to an integer minor-unit (nano-/pico-USD) or a decimal type and revisit the float choice.
- The emitted precision changes from **`%.6f`** — re-derive the rounding boundary and the regression test's expected values.
- A single per-node cost counter is observed approaching **float64 integer-exactness limits** (~`$9×10⁹` of accumulated micro-precision) — revisit the representation.
- The exporter gains **multiple concurrent writers** to `costByType` — the CAS already handles it, but re-confirm the "single writer ⇒ uncontended" assumption that justifies the P2 cost.

## Related decisions

- [DEC-010](DEC-010-clusterip-dialer-side-cross-az-attribution.md) — surfaced and explicitly deferred this bug (its Consequences→Neutral and Notes); this ADR is that deferred fix.
- [DEC-009](DEC-009-canonical-bpf-ip-byte-order.md) — the byte-order fix whose corrected L2b run made the `cross_az` bytes (and thus the `$0` cost) visible.
- [DEC-008](DEC-008-local-proof-simulation-suite.md) — the L2b real-agent tier that exercises the many-short-lived-flows workload which triggers the truncation.

## References

- `pkg/exporter/prometheus.go` — `UpdateFromPoll` (per-type + per-pod accumulation), `addCostUSD` (atomic float64 add via CAS), `handleMetrics` (emit). Regression test `TestExporter_CostMetrics_SubMicroDollarFlows` in `pkg/exporter/exporter_test.go`.
- `pkg/cost/ratecard.go:81` — AWS `CrossAZ` = `$0.01/GB` (so `0.387 GiB ≈ $0.0039`).
- `pkg/agent/agent.go` `handlePoll` → `UpdateFromPoll` — the single writer that justifies the uncontended-CAS assumption.
- [DEC-010](DEC-010-clusterip-dialer-side-cross-az-attribution.md) — where this bug was first written down as "tracked separately" (its Consequences→Neutral and Notes).

## Notes

The fix preserves monotonicity (cost only ever increases) and the `%.6f` emit, so a Prometheus `rate()` / `increase()` over the counter is unaffected — except that it now reflects real cost instead of staying flat at zero. The previous integer representation was self-consistent and fast; it was simply lossy at the sub-micro-dollar scale that this product's smallest unit of value (a single short-lived flow) routinely occupies.
