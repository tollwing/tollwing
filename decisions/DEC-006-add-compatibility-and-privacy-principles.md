# DEC-006 — Amend the constitution: add P11 (compatible public contracts) and P12 (data minimization)

**Status:** ACCEPTED
**Date:** 2026-05-30
**Author(s):** Baris Erdem (with Claude Opus 4.8, supervising founder)

---

## Context

Shortly after adopting the constitution ([DEC-001]), a review of governance *completeness* found the system covered engineering conformance thoroughly but had two missing "legs" for a product like Tollwing:

1. **Compatibility.** Tollwing ships a privileged agent + control plane to customer fleets and exposes several contracts other systems depend on — the HTTP API, the CRDs, the NATS/protobuf wire format, the ClickHouse schema, CLI flags, Prometheus metric names, Helm values. Upgrades across a fleet are not atomic (an N-1 agent talks to a new server; a dashboard queries last month's schema). P7 governed only *storage* migration safety; nothing governed the rest. A silent breaking change is the highest-impact governance risk the system wasn't addressing.
2. **Data/privacy.** A privileged eBPF agent on every node can see everything, and the product strategy explicitly courts payload-adjacent features (TLS tap, LLM governance, DLP) while noting they "blow up the privacy posture." `SECURITY.md` listed the sensitive data but no *principle* governed what the agent may capture, redaction, retention, or per-tenant isolation.

Both are binding, cross-cutting rules with clear compliance tests — principle-worthy, not merely documentation.

## Decision

Amend the constitution to **v1.1.0**, adding two principles:

- **P11 — Public contracts are versioned and evolve compatibly.**
- **P12 — Capture only what attribution needs, and protect it.**

Operationalize them with [`docs/governance/compatibility.md`](../docs/governance/compatibility.md), [`docs/governance/data-handling.md`](../docs/governance/data-handling.md), and a `CHANGELOG.md`. This is the first exercise of the amendment process defined in `CONSTITUTION.md` (minor bump: additive clarification, no existing principle changed).

## Alternatives considered

### Alternative A — Keep compatibility and privacy as policy docs only, not principles

**Why not:** A policy doc not anchored to a numbered principle has no authority — nothing cites it, the audit playbook doesn't sweep it, and it drifts. These are binding rules, so they belong in the constitution. (The docs still exist, but as *operationalizations* of P11/P12, the way `conventions.md` operationalizes the others.)

### Alternative B — Fold compatibility into P7 and privacy into P4

**Why not:** P7 is specifically about *storage* forward-only migrations; stretching it to cover the API, CRDs, proto, CLI, and metrics dilutes a precise rule into a vague one. Privacy is orthogonal to P4's "traceable cost" — conflating "don't fabricate dollars" with "don't over-capture packets" weakens both. P11 *generalizes* P7's ethos to all contracts and explicitly names P7 as its storage special-case; that's cleaner than overloading P7.

### Alternative C — Add only compatibility now, defer privacy

**Why not:** Both gaps are real today, and the privacy guardrail must exist *before* the payload-capture features the strategy contemplates are built, not bolted on after. Adding them together is one coherent amendment.

## Consequences

### Positive

- The two highest-impact governance risks for a fleet-deployed product — breaking deployed clients, and over-capturing sensitive data — are now binding and auditable.
- Exercises and validates the amendment process from `CONSTITUTION.md`.

### Negative

- Twelve principles is more to hold in mind than ten.
- Required updating `P1–P10` references across the docs to `P1–P12` (PR template, CLAUDE.md, audit playbook, README).

### Neutral

- P11 and P12 are primarily **audit-enforced**, not fully mechanical (like P1–P5, P8, P10). A new P3 cgo-tagging scan check and `govulncheck` were added alongside this amendment but are independent of it.

## Constitutional principles touched

- **P11 (compatible public contracts):** establishes.
- **P12 (data minimization & protection):** establishes.
- **P7 (forward-only storage):** neutral — P11 generalizes its ethos; P7 remains the storage special-case.
- **P4 (honest, traceable cost):** neutral — P12 complements the same trust model from the privacy side.

## Re-evaluation triggers

- A public contract genuinely needs a breaking change → follow the deprecation process in `compatibility.md` and record the ADR.
- A payload-capture / TLS-tap feature is greenlit → it must pass a privacy review under P12.
- The principle count grows unwieldy → consider consolidating related principles.

## Related decisions

Amends the constitution adopted in [DEC-001]. [DEC-004] (ClickHouse forward-only migrations) is the storage special-case that P11 generalizes.

## References

- `CONSTITUTION.md` v1.1.0 — P11, P12, and the version-history table.
- [`docs/governance/compatibility.md`](../docs/governance/compatibility.md), [`docs/governance/data-handling.md`](../docs/governance/data-handling.md), `CHANGELOG.md`.

## Notes

This is the constitution's first amendment. It is *additive* (two new principles), so it's a minor version bump — no existing principle's meaning changed.
