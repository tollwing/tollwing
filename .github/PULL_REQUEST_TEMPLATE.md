<!--
Before opening: read CONSTITUTION.md and scan decisions/README.md for ADRs that
bind the area you touched. Run `go run ./tools/governance scan` and (if you added
or edited an ADR) `go run ./tools/governance index`.
-->

## Summary

<!-- What changed and why, in a few lines. -->

## Constitutional principles touched

<!-- Which of P1–P12 does this advance, stay neutral to, or flex? Cite specifics.
e.g. "P5: classifies from the pre-DNAT ClusterIP (pkg/intent), not the backend IP."
e.g. "P9: no new dependencies." -->

-

## Decision log

- [ ] This change does **not** warrant an ADR — _or_ —
- [ ] I added/updated an ADR (`decisions/DEC-NNN-*.md`) and ran `go run ./tools/governance index`
- [ ] Any superseded ADR's status was updated in place

## Constitutional exception (only if applicable)

<!-- If this knowingly violates a principle: link the ADR documenting the exception,
and confirm the code cites it inline (// Per DEC-NNN, …). Delete this section if N/A. -->

## Compatibility & data

- [ ] No breaking change to a public contract (HTTP API, CRD, NATS/proto, ClickHouse schema, CLI flags, metrics) — or it's versioned, recorded in `CHANGELOG.md`, and has an ADR (P11)
- [ ] No new sensitive data captured — or it's the attribution minimum / has an ADR + privacy review (P12)

## Test plan

- [ ] `go test ./pkg/...` passes
- [ ] `go run ./tools/governance scan` introduces no new **blocking** findings
- [ ] New classification branches (P5) / safety-critical paths (P8) have tests
- [ ] `ARCHITECTURE.md` / `docs/` updated if behavior changed

<!-- How did you verify this end to end? -->
