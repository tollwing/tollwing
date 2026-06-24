# Quarterly Governance Review — {YYYY Qn}

**Date:** YYYY-MM-DD
**Reviewer:** {name / agent id}
**Constitution version reviewed:** {e.g. 1.0.0}

A lightweight quarterly pass to keep the governance system honest and current. Copy this file to `reports/audits/quarterly-{YYYY}-q{n}.md` and fill it in. Per the "living documents discipline" in [`CONSTITUTION.md`](../../CONSTITUTION.md).

---

## 1. Principle sweep (rotate)

Pick the next principle in rotation and run a Mode C audit:

```sh
go run ./tools/governance audit -principle P{n}
```

- **Principle audited this quarter:** P{n} — {name}
- **Findings:** {count by severity; link the report in `reports/audits/`}
- **ADRs created:** {DEC-NNN, if any}

Rotation so far: {list which principles have been swept, so coverage is even.}

## 2. Constitution accuracy

The constitution's **Examples** cite `file:line`. Code moves; citations rot.

- [ ] Each principle's Examples still point at real, relevant code (spot-check the ones in subsystems that changed this quarter).
- [ ] Compliance tests still describe a runnable check.
- [ ] Any principle that reality has outgrown → propose an amendment (ADR).

## 3. Decision log health

- [ ] Index regenerated and in sync (`go run ./tools/governance index -check`).
- [ ] Any ACCEPTED decision now contradicted by the code → supersede or deprecate it (don't leave it stale).
- [ ] Backlog progress: which `decisions/README.md` backlog items got written this quarter? Re-prioritize the rest.

## 4. Mechanical-scan trend

```sh
go run ./tools/governance scan
```

- **Blocking:** {n} (must be 0)
- **Warn (P6 debt, etc.):** {n} — **vs last quarter: {↑/↓/=}**

The warn count should trend **down**. If it rose, that's a regression — open a finding. If a debt class reached 0, promote its check to blocking in `tools/governance/scan.go` (the ratchet).

## 5. Docs vs reality drift

- [ ] `ARCHITECTURE.md` still matches the system (note any section that lies).
- [ ] `docs/governance/conventions.md` still matches how code is actually written.
- [ ] CI `governance` job still runs `index -check` + `scan -gate`.

## 6. Actions

| Action | Owner | Path (fix / ADR / amend / debt / rewrite) | Due |
|---|---|---|---|
| | | | |

## 7. Verdict

One paragraph: is the governance system earning its keep, or becoming ceremony? Be willing to simplify or cut what isn't pulling weight — see [DEC-001](../../decisions/DEC-001-adopt-constitution-and-governance.md) re-evaluation triggers.
