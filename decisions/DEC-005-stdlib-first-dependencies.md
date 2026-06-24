# DEC-005 — Stdlib-first dependency posture; new third-party deps require an ADR

**Status:** ACCEPTED
**Date:** 2026-05-30
**Author(s):** Baris Erdem (with Claude Opus 4.8, supervising founder)

---

## Context

The codebase already lives by a stdlib-first ethos: 76 source files use `log/slog` and zero import the stdlib `"log"`; CLIs use `flag`; tests use stdlib `testing` (table-driven); there is no cobra, viper, testify, zap, or logrus. The agent is deployed on every node in a customer fleet, so every dependency is supply-chain attack surface, binary weight, and CGO/build risk. This norm is currently a habit; codifying it keeps it from eroding one convenient import at a time. This ADR records the norm and makes **P9** enforceable.

## Decision

Default to the standard library:

- **Logging:** `log/slog` only.
- **CLI/flags:** `flag` only.
- **Tests:** stdlib `testing`, table-driven; no assertion framework.

A new **third-party direct dependency** — including a different logger, CLI framework, or assertion/test library — requires an ADR that justifies it against the alternative of writing it on stdlib. `tools/governance scan` flags the stdlib `"log"` import and a banned-by-default list (cobra, viper, testify, zap, logrus, …). Genuinely necessary heavy dependencies that *do* earn their place — `cilium/ebpf`, `clickhouse-go`, `aws-sdk-go-v2`, `client-go`, `nats.go`, `golang.org/x/net` — are grandfathered as load-bearing.

## Alternatives considered

### Alternative A — Adopt the conventional ecosystem libraries (cobra/viper, testify, zap)

**Why not:** Better ergonomics, but for a fleet-deployed agent the costs dominate: larger binary, more attack surface, transitive-dependency drift, and CGO risk. The ergonomic gain doesn't clear that bar.

### Alternative B — No policy; decide per PR

**Why not:** Leads to dependency sprawl and inconsistency (two loggers, two flag libraries) precisely because each individual addition looks harmless. A stated default with an ADR gate stops the ratchet.

### Alternative C — Absolute zero third-party dependencies

**Why not:** Too rigid. `cilium/ebpf` (the data plane), cloud SDKs, `client-go`, and `clickhouse-go` are things stdlib genuinely cannot provide. The rule is "stdlib *first*, deps earn their place," not "no deps."

## Consequences

### Positive

- Small attack surface, fast CGO-free builds, one logging/flags/testing idiom across the repo (**P9**, **P1**, **P2**).

### Negative

- Sometimes more code (e.g., hand-rolled flag parsing instead of cobra's subcommand sugar).

### Neutral

- Existing heavy dependencies are explicitly grandfathered; this ADR is not a mandate to remove them.

## Constitutional principles touched

- **P9 (stdlib-first):** advances — this ADR is the codification.
- **P1 / P2 (lean agent, overhead budget):** advances — fewer/smaller dependencies keep the fleet-deployed binary lean.

## Re-evaluation triggers

- A specific stdlib gap becomes painful enough that a particular dependency clearly clears the ADR bar (record it as its own ADR).
- A grandfathered dependency is deprecated/unmaintained and needs replacing.

## Related decisions

Constrained by [DEC-001]; the governance tooling's "Go, stdlib-only" choice in [DEC-001] is an application of this principle.

## References

- `go.mod` (current dependency set).
- `tools/governance/` (the P9 scan).

## Notes

The scanner's banned list is a starting point, not exhaustive — extend it when a new "obvious" convenience dependency shows up in review.
