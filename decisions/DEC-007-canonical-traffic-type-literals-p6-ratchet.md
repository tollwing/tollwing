# DEC-007 — Eliminate hardcoded traffic-type literals and ratchet the P6 scan to blocking

**Status:** ACCEPTED
**Date:** 2026-05-30
**Author(s):** Baris Erdem (with Claude Opus 4.8, supervising founder)

---

## Context

`go run ./tools/governance scan` reported 33 **P6** warnings: double-quoted traffic-type wire-strings (`"cross_az"`, `"nat_gateway"`, `"vpc_peering"`, …) appearing outside the canonical enum file `pkg/classifier/traffic.go`. P6 ("one canonical representation; no drift across boundaries") requires that these strings have a single source of truth — `classifier.TrafficType` with its `String()` method — and that every other boundary derive from it.

These 33 were recorded as known, warn-only debt in [`docs/governance/audit-playbook.md`](../docs/governance/audit-playbook.md) §7, with an explicit ratchet: *once the literals are cleaned up to derive from `TrafficType.String()`, promote the P6 check to blocking.* Warn-only findings get ignored; the playbook states the number "should go down, never up." This ADR records the cleanup and pulls the ratchet.

On inspection the 33 occurrences split into three kinds:

1. **Genuine TrafficType references (18).** A value that really is a traffic type, written as a literal instead of via the enum — `alert.Alert.TrafficType` assignments, the `api` round-trip `trafficTypeFromString` (the inverse of `String()`), the `cost` reconciler's `mapUsageType` (whose keys must line up with measured-side keys that come from `String()`), and two `servicegraph` doc-comment examples.
2. **Coincidental tokens (15).** Strings that merely *spell the same* as a wire string but belong to a different domain: the `pkg/terraform` resource-category vocabulary (`networkResourceTypes` values + the `change.Type` switch + `strings.Contains` resource-type matches) and `recommend.Category`'s JSON value `"vpc_endpoint"`. These are **not** `classifier.TrafficType` values.

## Decision

We will:

1. **Replace genuine literals with the enum.** In `pkg/alert/engine.go`, `pkg/api/reconcile.go`, and `pkg/cost/reconcile.go`, derive the wire string from `classifier.TrafficType.String()` (and write the `api` inverse switch as `case classifier.X.String():`). Reword the two `pkg/servicegraph/graph.go` doc-comment examples so they no longer embed the quoted literal.
2. **Annotate the coincidental tokens, in place.** Leave the Terraform category tokens and the `recommend.Category` value as literals — they are independent public contracts — and mark each with `// not a classifier.TrafficType (DEC-007)`. The inline `DEC-007` citation is exactly the scanner's exception mechanism (`reDECcite`), so these become INFO, not warnings, and read as intentional.
3. **Ratchet P6 to blocking.** Set `blocking: true` on the P6 finding in `tools/governance/scan.go` (the `trafficTypeLiterals` loop in `scanGoFile`). With the warnings at zero, `go run ./tools/governance scan -gate` (the CI `governance` job) now fails on any *new* hardcoded traffic-type literal.

## Alternatives considered

### Alternative A — Leave P6 warn-only

**Why not:** Warn-only debt is debt that never gets paid — it scrolls past in CI and the count drifts up. The audit playbook explicitly designed this as a ratchet; the whole point is to convert a cleaned-up warning into an enforced floor.

### Alternative B — Add a canonical `classifier.ParseTrafficType` and centralize the inverse map

**Why not:** Only one caller (`api.trafficTypeFromString`) is a pure inverse of `String()`. `cost.mapUsageType` maps AWS CUR usage-type *substrings* (not wire strings) and includes a category with no enum (`internet_ingress`), so it could not use a shared parser. Writing each case as `case classifier.X.String():` already gives a single source of truth without adding exported API to the canonical file. (Re-evaluate if a third independent string→TrafficType mapper appears.)

### Alternative C — Refactor the Terraform categories into named constants

**Why not:** It would collapse the per-line citations to a handful of `const` definitions, but it is a broader structural change to a working table. The categories are a Terraform-domain vocabulary; a scoped, documented exception (leave + annotate) is the lighter and equally-correct resolution. Constants remain on the table if the table grows.

### Alternative D — Couple `recommend.Category` / Terraform tokens to `classifier...String()`

**Why not:** Semantically wrong. `recommend.Category`'s `"vpc_endpoint"` and Terraform's `"nat_gateway"` are independent contracts (a recommendation-category JSON value; a Terraform resource category) that happen to share spelling with a traffic type. Coupling them to the classifier would mean a future classifier rename silently changes an API category or a Terraform match — the exact cross-boundary drift P6 exists to prevent, inverted.

## Consequences

### Positive

- Zero P6 warnings; the canonical `TrafficType.String()` is the only definition of these strings in Go code.
- New drift is caught at CI (`scan -gate`) instead of accruing as warnings.
- The reconciler's billed-side and measured-side keys are now provably the same source, so a per-type breakdown cannot silently misalign.

### Negative

- The `api` inverse switch evaluates `String()` per case label (negligible — reconciliation is not a hot path).
- Fifteen coincidental lines now carry an explanatory `// not a classifier.TrafficType (DEC-007)` comment.

### Neutral

- SQL-embedded, single-quoted wire strings (e.g. `traffic_type = 'cross_az'` in ClickHouse queries) are the **storage side** of the same SSOT and are intentionally **not** in scope: the scanner targets double-quoted Go literals by design (see the P6 false-positive note in audit-playbook §3, and [DEC-004]). They remain unchanged.

## Constitutional principles touched

- **P6 (one canonical representation):** advances — removes the parallel Go literals and converts the check from advisory to enforced.
- **P10 (multi-cloud is one abstraction):** neutral — the Terraform per-provider category tables are untouched; only annotated.

## Re-evaluation triggers

- A third independent string→`TrafficType` inverse mapper appears → add `classifier.ParseTrafficType` and centralize (Alternative B).
- The Terraform category table grows enough that per-line citations become noisy → adopt named constants (Alternative C).
- A new `TrafficType` is added → it propagates through `String()` automatically; no literal edits are needed, which is the property this ADR protects.

## Related decisions

Refines [DEC-001] (the governance constitution + tooling) and discharges the P6 known-debt item in `docs/governance/audit-playbook.md` §7. [DEC-004] (ClickHouse forward-only migrations) defines the storage-side `Enum8` that is the other half of this SSOT.

## References

- `pkg/classifier/traffic.go` — canonical `TrafficType` + `String()`.
- `tools/governance/scan.go` — the P6 check (now `blocking: true`).
- Fixed: `pkg/alert/engine.go`, `pkg/api/reconcile.go`, `pkg/cost/reconcile.go`, `pkg/servicegraph/graph.go`.
- Scoped exceptions: `pkg/terraform/parser.go`, `pkg/terraform/estimator.go`, `pkg/recommend/recommend.go`.
- `docs/governance/audit-playbook.md` §7 (the ratchet) and §3 (the P6 false-positive note).

## Notes

The scanner's exception mechanism is an inline `DEC-NNN` citation, not a free-text marker — `// not a classifier.TrafficType` alone would still warn. The chosen comment carries both: it documents intent for a reader and contains `DEC-007` for the scanner.
