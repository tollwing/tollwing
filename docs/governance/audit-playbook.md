# Tollwing Audit Playbook

**Status:** v1.0.0 — adopted 2026-05-30 per [DEC-001](../../decisions/DEC-001-adopt-constitution-and-governance.md)

How to audit Tollwing's code against [`CONSTITUTION.md`](../../CONSTITUTION.md). An audit is a reproducible process — runnable by a human or an AI agent — for finding violations the mechanical scanner can't see. The scanner is a floor; this playbook is how you reach the rest.

---

## 0. Audit philosophy

The audit's job is to report what is wrong, fully and honestly. It is **not** the audit's job to minimize disruption, to pre-bias toward fixing-in-place, to soften a severity so a subsystem looks healthier, or to defer a hard call.

- **Engineering excellence is the standard.** "It mostly works" is not compliance.
- **Severity is not impact.** A HIGH violation in rarely-run code is still a HIGH.
- **The cost of a rewrite is not an audit concern.** If the right answer is "rewrite this", say so. The auditor *recommends*; the maintainer *decides* and owns the trade-off.
- **An audit that never recommends the drastic path is biased.** If Path 5 (rewrite/kill) is never on the table, the audit is systematically protecting the status quo.

This applies to AI-agent auditors especially: do not invent findings to look thorough, and do not suppress real ones to look reassuring.

---

## 1. Audit modes

| Mode | Cadence | Scope | Mechanism |
|---|---|---|---|
| **A — Continuous** | every PR / commit | changed files | `go run ./tools/governance scan` (the regex floor) + PR-template review |
| **B — Subsystem deep audit** | ad-hoc | one package vs all twelve principles | `go run ./tools/governance audit -subsystem <name>` → prompt → agent/human |
| **C — Principle sweep** | quarterly (rotate principles) | one principle, whole codebase | `go run ./tools/governance audit -principle <Pn>` |
| **D — Pre-release** | before a tagged release | everything material | run B across the changed subsystems + C on the highest-risk principle; produce a GO / NO-GO |

Mode A is mechanical and lives in CI (the `governance` job) and the pre-commit hook. Modes B–D are judgment-driven: the `audit` subcommand **generates a prompt**, it never calls an LLM — you paste the prompt into Claude Code / an agent (or work it yourself), and the agent produces the report.

---

## 2. Running an audit

```sh
# Deep-audit one subsystem against all twelve principles:
go run ./tools/governance audit -subsystem servicegraph

# Sweep one principle across the whole codebase:
go run ./tools/governance audit -principle P4

# See what's auditable:
go run ./tools/governance audit -list
```

The generated prompt names the required reading, the scope, the per-principle "look for" hints, the remediation paths, and the output path. Reports land in `reports/audits/` (monorepo) as `{type}-{scope}-{YYYY-MM-DD}.md`.

---

## 3. Per-principle checklist

For each principle: what to **look for**, what to **verify**, and common **false positives**.

- **P1 — The agent is the product.** *Look for:* state, history, or cross-node correlation added to the per-node agent. *Verify:* heavy/stateful work lives in `tollwing-server`, the agent stays a collector. *False positive:* a small bounded local cache that is purely an optimization of a stateless read.
- **P2 — Near-zero node overhead.** *Look for:* maps/caches without a size bound or eviction policy; per-event userspace work; allocations in poll/parse hot paths. *Verify:* every cache has a documented ceiling; hot paths have benchmarks. *False positive:* an allocation on a cold startup path.
- **P3 — Portable, capability-probing data plane.** *Look for:* a hook/helper/map used on the required path without a `features.go` probe; missing minimum-kernel note; cgo or linux-only imports reachable from server/CLI. *Verify:* `CGO_ENABLED=0` server build succeeds; required vs optional features are probed. *False positive:* an optional feature guarded by its probe.
- **P4 — Honest, traceable cost.** *Look for:* a displayed dollar not derivable from `bytes × dated-rate`; an asserted accuracy/percentage; unmeasured spend not bucketed. *Verify:* trace a sample figure end-to-end; attributions conserve dollars. *False positive:* a clearly-labeled estimate in a what-if/simulation path.
- **P5 — Accurate attribution.** *Look for:* classification off the post-DNAT IP; unresolved zone coerced to `same_zone`; sidecar flows double-counted. *Verify:* `Unknown` is returned, not guessed; service attribution uses the pre-DNAT destination. *False positive:* a deliberate, documented fallback when intent is genuinely unrecoverable.
- **P6 — One canonical representation.** *Look for:* a double-quoted enum wire-string (`"cross_az"`) outside `pkg/classifier/traffic.go`; a second copy of an enum's value list. *Verify:* the value derives from `TrafficType.String()`. *False positive:* the ClickHouse `Enum8(...)` DDL (single-quoted, the storage side of the same SSOT) and tests asserting `String()` output. **Current state: 0 — the literals were cleaned up and the P6 check is now blocking (DEC-007); see §7.**
- **P7 — Forward-only storage.** *Look for:* an edited/reordered migration; a down-migration; `DROP`/`RENAME`/`MODIFY COLUMN`; non-idempotent SQL. *Verify:* `Migrate` is a no-op on second run; all DDL uses `IF [NOT] EXISTS`. *False positive:* `DROP` appearing only in a comment.
- **P8 — Safe, reversible actions.** *Look for:* an infra-mutating path with no approval gate or no rollback; a recommendation that bypasses its safety guard. *Verify:* approval + rollback are covered by tests; guards return reasons. *False positive:* a read-only recommendation that never mutates anything.
- **P9 — Stdlib-first.** *Look for:* stdlib `"log"`; cobra/viper/testify/zap/logrus; a new `go.mod` direct dep. *Verify:* the dep has an ADR. *False positive:* a grandfathered load-bearing dep (cilium/ebpf, clickhouse-go, aws-sdk, client-go, nats.go, x/net).
- **P10 — Multi-cloud is one abstraction.** *Look for:* `provider ==` branches in `classifier`/`cost`; AWS-only assumptions in shared code. *Verify:* provider specifics live in `pkg/cloud/<provider>` and rate cards. *False positive:* a provider branch inside a `pkg/cloud` implementation (that's where it belongs).
- **P11 — Compatible public contracts.** *Look for:* a changed HTTP API / CRD / proto / ClickHouse schema / CLI flag / metric without a version bump, deprecation, `CHANGELOG.md` entry, or ADR; a server that rejects N-1 agents. *Verify:* changes are additive or versioned; an N-1 agent still reports. *False positive:* a purely internal type with no external consumer. (See [`compatibility.md`](compatibility.md).)
- **P12 — Data minimization & protection.** *Look for:* capture beyond the attribution minimum (payloads, full cmdlines, secrets); sensitive fields logged at info; missing multi-tenant redaction/isolation. *Verify:* captured fields match [`data-handling.md`](data-handling.md); tenant isolation is tested. *False positive:* metadata already in the documented minimum.

---

## 4. Severity

| Severity | Meaning |
|---|---|
| **HIGH** | Directly defeats a principle's purpose: a wrong dollar figure shown to a user, an unsafe automated action, lost historical data, an undeployable agent. |
| **MEDIUM** | A real violation with a contained blast radius, or one mitigated elsewhere. |
| **LOW** | Drift / smell that will bite later (e.g. a P6 literal) but is not currently producing a wrong result. |
| **NOT-A-VIOLATION** | A scanner hit or suspicion that, on inspection, is correct. Record it so the next audit doesn't re-flag it. |

---

## 5. Remediation paths

Every finding gets exactly one recommended path:

1. **Fix now** — bring the code into compliance.
2. **Document an exception** — there's a good reason to violate the principle; write an ADR that names the principle, scopes the exception narrowly, and lists re-evaluation triggers. Code cites it `// Per DEC-NNN, …`; the scanner respects the citation.
3. **Propose an amendment** — the *principle* is wrong or too broad; amend `CONSTITUTION.md` (recorded as an ADR).
4. **Accept as tracked debt** — known, bounded, scheduled. Use sparingly: if more than ~20% of findings land here, the audit is rationalizing, not auditing.
5. **Rewrite / rebuild / kill** — the code can't be patched into compliance, or the feature shouldn't exist. The most disruptive path, and the one a biased audit avoids. Keep it on the table.

Decision tree: *Is the code wrong?* → Path 1, or Path 5 if unsalvageable. *Is the code right but the principle says no?* → Path 2 (narrow) or Path 3 (the principle is wrong). *Right, in conflict, but not now?* → Path 4, with a tracking note.

---

## 6. Report template

Write the report to `reports/audits/{type}-{scope}-{YYYY-MM-DD}.md`:

```markdown
# {Subsystem|Principle} Audit — {scope}

**Date:** YYYY-MM-DD
**Mode:** A | B | C | D
**Scope:** {files / principle}
**Auditor:** {name / agent id}
**Constitution version:** {e.g. 1.0.0}

## Summary
- Total findings: N  (HIGH: a, MEDIUM: b, LOW: c)
- Remediation split: fix N · exception N · amend N · debt N · rewrite N
- One-paragraph verdict. For Mode D: **GO / NO-GO**.

## Findings
### F1 — {title}  [HIGH] [P4]
- **Where:** path:line
- **What:** the violation, concretely.
- **Why it violates Pn:** …
- **Recommended path:** {1–5} — {what to do}

(repeat per finding)

## Cross-cutting patterns
{themes spanning findings}

## ADRs created or updated by this audit
{DEC-NNN links, if any}

## Next audit
{mode / scope / when}
```

---

## 7. Known debt

- **P6 traffic-type literals — DISCHARGED ([DEC-007](../../decisions/DEC-007-canonical-traffic-type-literals-p6-ratchet.md)).** Previously ~33 hardcoded traffic-type wire-strings sat outside `pkg/classifier/traffic.go` (in `alert`, `api`, `cost`, `recommend`, `servicegraph`, `terraform`) as warn-only debt. They are now resolved: genuine references derive from `classifier.TrafficType.String()`; the handful of coincidental tokens (Terraform resource categories; the `recommend.Category` JSON value `vpc_endpoint`) are annotated `// not a classifier.TrafficType (DEC-007)`; and the P6 check in `tools/governance/scan.go` is now **blocking**. `go run ./tools/governance scan` is clean (0 blocking, 0 warn), and a new uncited literal fails `scan -gate`.

The ratchet held: the count went to **zero** and is now enforced, never advisory. It must not climb back — a new P6 finding is a regression worth a finding of its own, and a genuinely-necessary exception takes an inline `// DEC-NNN` citation (the scanner's only opt-out), not a silent literal.

---

## See also

- [`../../CONSTITUTION.md`](../../CONSTITUTION.md) — the principles being audited.
- [`conventions.md`](conventions.md) — the concrete Go conventions.
- [`quarterly-review-TEMPLATE.md`](quarterly-review-TEMPLATE.md) — the periodic review.
- [`../../decisions/README.md`](../../decisions/README.md) — where findings become ADRs.
