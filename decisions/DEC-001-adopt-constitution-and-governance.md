# DEC-001 — Adopt a constitution, decision log, audit playbook, and Go-native governance tooling

**Status:** ACCEPTED
**Date:** 2026-05-30
**Author(s):** Baris Erdem (with Claude Opus 4.8, supervising founder)

---

## Context

Tollwing grew across fourteen feature sprints, each landing as a self-contained commit with its own `docs/<feature>.md`. The code carries a strong and consistent engineering culture — stdlib-first, honest about what it can measure, conservative about acting on customer infrastructure, careful about canonical representations — but that culture lived only in comments and habits. Nothing stated it, so nothing could be checked against it, and consequential decisions (why socket-level hooks, why forward-only migrations, why no down-migrations) were recorded only as inline comments and prose docs, scattered and un-indexed.

Sibling projects (`~/Playground/global-gazette`, `~/Playground/homebase`) had already established a governance practice — a constitution of binding principles, an append-only decision log of ADRs, an audit playbook, and mechanical enforcement tooling — and it worked well. We want the same discipline here, adapted to Tollwing.

## Decision

Adopt a governance system consisting of:

1. **`CONSTITUTION.md`** — ten binding, Tollwing-specific engineering/product principles (P1–P10), each with a compliance test.
2. **`decisions/`** — an append-only decision log following the ADR pattern (Michael Nygard / MADR), with a `TEMPLATE.md`, an auto-generated index in `README.md`, and `DEC-NNN-{slug}.md` files.
3. **`docs/governance/audit-playbook.md`** — a reproducible process for auditing code against the principles, plus `conventions.md` (the concrete Go conventions) and a quarterly-review template.
4. **`tools/governance/`** — governance tooling written in **Go, standard library only** (`index`, `scan`, `audit` subcommands), invoked as `go run ./tools/governance <cmd>`.
5. **Behavioral + review layers** — `CLAUDE.md` / `AGENTS.md` (agent operating protocol), `.github/PULL_REQUEST_TEMPLATE.md`, a CI `governance` job, and a warn-only pre-commit hook.

Principles get stable IDs and are cited inline in code and commits. The decision index and the violation scanner are *mechanical* (a CI gate), not a matter of discipline.

## Alternatives considered

### Alternative A — Keep implicit norms, enforce by code review (the status quo)

**Why not:** Implicit norms can't be cited, can't be checked mechanically, and don't transfer. A new contributor — increasingly an AI agent — has no way to inherit the reasoning, only the result. The scattered decision comments were direct evidence this doesn't scale.

### Alternative B — Governance docs in a wiki (Notion/Confluence)

**Why not:** Governance that lives outside the repo isn't versioned with the code it governs, drifts independently, and isn't readable by an agent working in the tree. In-repo markdown is reviewed in the same PR as the code.

### Alternative C — Copy the sibling projects verbatim (their principles and their `.mjs` tooling)

**Why not:** Two reasons. (1) Their principles are about LLM classification and data-source provenance; Tollwing's domain is eBPF cost attribution. Copying them would be *governance theater* — rules nobody's code follows. The principles here are derived from this codebase. (2) Their tooling is Node `.mjs`. Tollwing is a Go project whose own constitution is stdlib-first Go (**P9**). Shipping `.mjs` to enforce a Go constitution would itself violate that constitution. See the Go-tooling decision below.

### Alternative D — A heavier ADR toolchain (adr-tools, external ADR services, a docs site generator)

**Why not:** Adds a dependency and a build step to manage what is fundamentally a directory of markdown plus a parser. Stdlib Go keeps the whole system self-contained, CGO-free, and consistent with the rest of the repo.

## Consequences

### Positive

- Principles are stated, citable, and mechanically checkable for the regex-detectable subset.
- Consequential decisions are append-only, indexed, and carry their alternatives — no re-litigation.
- The system is self-contained: pure markdown + stdlib Go, versioned with the code.

### Negative

- Upfront authoring cost (this batch) and ongoing discipline to keep documents current — though "living-documents discipline" in the constitution makes that part of the work, not optional.
- One more CI job and one more thing a contributor must read.

### Neutral

- Governance tooling lives at `tools/governance/`, outside `cmd/`, so it is never built into a shipped product binary; CI runs it with `go run`.

## Constitutional principles touched

All twelve. This decision establishes the constitution itself; the constitution is the artifact (it was adopted with P1–P10; P11–P12 were added later by [DEC-006]). The choice of **Go, stdlib-only** for the tooling is specifically governed by **P9 (stdlib-first)** — the tools that enforce the constitution must themselves obey it.

## Re-evaluation triggers

- Governance becomes ceremony that produces no caught violations and no useful decisions over a couple of quarters — simplify or cut it.
- The scanner's false-positive rate makes contributors routinely bypass it.
- The project grows a team large enough that this lightweight process needs to become heavier (or a hosted ADR system earns its keep).

## Related decisions

[DEC-002], [DEC-003], [DEC-004], [DEC-005] — the first decisions recorded under this system, capturing architectural choices that predate it.

## References

- `CONSTITUTION.md`
- `docs/governance/audit-playbook.md`
- Sibling governance systems at `~/Playground/global-gazette` and `~/Playground/homebase` (pattern source).

## Notes

The principles, ADRs, and tooling were authored together as one batch. The seed ADRs (DEC-002…005) are *retroactive* — they document decisions already embedded in the code, so future readers get the reasoning. The decision backlog in `decisions/README.md` lists further decisions worth capturing over time.
