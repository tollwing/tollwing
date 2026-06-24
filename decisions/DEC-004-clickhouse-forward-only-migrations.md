# DEC-004 — ClickHouse for warm/cold storage with forward-only, additive, idempotent migrations

**Status:** ACCEPTED
**Date:** 2026-05-30
**Author(s):** Baris Erdem (with Claude Opus 4.8, supervising founder)

---

## Context

Tollwing produces high-cardinality cost data (process × service × zone × traffic-type × time) and must answer ad-hoc cost queries over long retention windows, plus power billing reconciliation against the cloud bill. Prometheus is excellent for real-time alerting but poor for high-cardinality ad-hoc cost queries. The historical store *is* the product's memory, so how its schema evolves is a correctness concern, not just an ops detail. (Retroactive: `ARCHITECTURE.md` §6; implemented in `pkg/storage/clickhouse`.)

## Decision

Use **ClickHouse** for the warm (per-service, ~30d) and cold (daily summaries, ~1y) tiers, with `MergeTree` / `SummingMergeTree` / `ReplacingMergeTree` engines and materialized-view rollups. Govern its schema with three rules:

1. **Forward-only, additive migrations.** Every change appends a `Migration{Version, Description, SQL}`; never reorder or rewrite an applied migration; evolve additively (`ADD COLUMN IF NOT EXISTS`). **No down-migrations.**
2. **Idempotent.** Migrations use `IF [NOT] EXISTS` and record applied versions in a `schema_migrations` table (`ReplacingMergeTree`, read with `FINAL`), because ClickHouse has no reliable multi-statement transactions — apply-then-record can fail between steps, so re-running must be safe.
3. **Registered `database/sql` driver.** A blank import in `pkg/storage/clickhouse/driver.go` registers the `clickhouse` driver so `sql.Open("clickhouse", dsn)` works uniformly for the server, the service-graph snapshotter, and integration tests.

## Alternatives considered

### Alternative A — Prometheus / TSDB only

**Why not:** High-cardinality cost queries (the core use case) explode a TSDB; no ergonomic ad-hoc SQL for reports and reconciliation. Prometheus is retained for real-time node metrics, not historical cost.

### Alternative B — Postgres / TimescaleDB

**Why not:** Worse columnar compression and scan performance at the billions-of-rows scale; ClickHouse's `SummingMergeTree` gives automatic rollup that shrinks storage as data ages.

### Alternative C — Reversible (up/down) migrations

**Why not:** A down-migration on the historical cost record is a foot-gun that can destroy the data customers rely on for trends — and ClickHouse can't run the apply+record atomically anyway. Forward-only + idempotent is the only safe contract here. A genuinely needed destructive change must come with its own ADR exception and a data-migration plan.

## Consequences

### Positive

- Sub-second high-cardinality queries; cheap columnar storage; additive evolution that never loses history (**P4**, **P7**).
- One driver registration serves every consumer; the failure mode (`unknown driver "clickhouse"`) is documented inline to prevent regressions.

### Negative

- ClickHouse is operationally non-trivial; mitigated by supporting managed/embedded single-node deployments.
- "No down-migrations" means a mistaken additive migration can only be fixed by another forward migration.

### Neutral

- The `flows.traffic_type` ClickHouse enum mirrors `classifier.TrafficType` — that single-source-of-truth requirement is **P6**, enforced by the scanner.

## Constitutional principles touched

- **P7 (forward-only, additive storage):** advances — the canonical implementation; the migration list's own comment is the rule.
- **P4 (honest, traceable cost):** advances — preserved history is what reconciliation and accuracy scoring are computed against.
- **P6 (one canonical representation):** advances — the ClickHouse traffic-type enum derives from `TrafficType.String()`.

## Re-evaluation triggers

- A migration genuinely requires a destructive/rewriting change (→ ADR exception + data-migration plan).
- ClickHouse gains reliable multi-statement transactions (the idempotency workaround could relax).
- A second storage backend is needed (would generalize the migration mechanism).

## Related decisions

Constrained by [DEC-001]. Related to the (backlogged) service-graph snapshotter decision, which depends on the registered driver.

## References

- `ARCHITECTURE.md` §6 (Storage and Query Layer).
- `pkg/storage/clickhouse/migrations.go:18-20` ("Never reorder, never rewrite history — always append"), `:124-128` (idempotency rationale).
- `pkg/storage/clickhouse/driver.go` (driver registration + documented failure mode).

## Notes

If a destructive migration is ever truly required, it is an explicit constitutional exception under **P7** — write the ADR, scope it, and include the data-migration plan before touching released migrations.
