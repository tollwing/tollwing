# DEC-NNN — [Short imperative title in active voice]

**Status:** [PROPOSED | ACCEPTED | SUPERSEDED BY DEC-XXX | DEPRECATED | WITHDRAWN]
**Date:** YYYY-MM-DD (the acceptance date; if it evolved over several days, use the date it was accepted)
**Author(s):** [name and/or agent identifier — e.g. "Baris Erdem (with Claude Opus 4.8, supervising founder)"]
**Reviewer(s):** [optional — who else weighed in]

---

## Context

What situation forces a decision? State the problem, the forces, and the constraints. Link to the code, the architecture section, or the audit that surfaced it. Enough that someone with no memory of this can understand *why* a choice was needed.

## Decision

The decision, in active voice: "We will …". Be specific and concrete — name the packages, the mechanism, the boundary.

## Alternatives considered

The heart of the ADR. This section is what protects a future contributor (human or agent) from re-litigating a settled question. List every alternative that was genuinely on the table — including the status quo — and say why it lost.

### Alternative A — [Name]

[One or two lines describing it.]
**Why not:** …

### Alternative B — [Name]

**Why not:** …

## Consequences

### Positive

### Negative

### Neutral

## Constitutional principles touched

List each relevant principle by ID and whether this decision **advances** it, is **neutral** to it, or **requires an exception**. (The index generator reads the `P1`–`P10` tokens from this section. Use "All ten" if the decision genuinely touches the whole constitution.)

- **Pn (name):** advances — …
- **Pn (name):** requires exception — … (and an exception MUST be justified here)

## Re-evaluation triggers

Concrete, observable signals that should reopen this decision. Not "if it stops working" — name the metric, the version, the capability, the scale.

## Related decisions

[DEC-XXX], [DEC-YYY] — and how they relate (supersedes, depends on, refines).

## References

Code paths (`pkg/...:line`), `ARCHITECTURE.md` sections, external docs.

## Notes

Anything that doesn't fit above — open questions, follow-ups, things deliberately left undecided.
