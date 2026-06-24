# Tollwing Compatibility & Deprecation Policy

**Status:** v1.0.0 — adopted 2026-05-30 per [DEC-006](../../decisions/DEC-006-add-compatibility-and-privacy-principles.md)

Operationalizes **P11** (public contracts are versioned and evolve compatibly). Tollwing ships to customer fleets where upgrades are not atomic, so the contracts below must evolve without breaking already-deployed clients.

> **Pre-1.0 caveat.** Tollwing is `0.x`. During `0.x`, a minor release *may* make a breaking change — but it is always announced in `CHANGELOG.md` with a deprecation note where feasible, and it still requires an ADR. At `1.0` the full guarantees below take effect.

---

## Public contracts

| Contract | Where | Versioned by | How it evolves |
|---|---|---|---|
| **HTTP API** | `/api/v1/*` (`pkg/api`) | URL path (`/v1`, `/v2`) | Add endpoints/fields freely; never remove or repurpose a field in `/v1`. Breaking → `/api/v2` alongside `/v1`. |
| **CRDs** | `tollwing.io/v1alpha1` (`deploy/.../crds`) | K8s `apiVersion` | Add optional fields; never make an existing CR invalid. Breaking → `v1alpha2`/`v1beta1` with a conversion path. |
| **Wire protocol** | NATS subjects + protobuf (`proto/*.proto`) | proto field numbers + subject names | Only add fields; **never reuse or renumber** a proto field. Add subjects; don't repurpose existing ones. |
| **ClickHouse schema** | `pkg/storage/clickhouse` | migration version | Forward-only, additive, idempotent (this is **P7**). |
| **CLI flags** | `cmd/*` (`flag`) | — | Add flags; deprecate before removing (keep accepting the old flag for one minor with a warning). |
| **Prometheus metrics** | `pkg/exporter` (`tollwing_*`) | metric name | Names/labels are a contract (dashboards + alerts depend on them). Add freely; a rename ships the new name alongside the old for one minor. |
| **Helm values** | `deploy/helm/*` | chart version (SemVer) | Add keys with safe defaults; a renamed key keeps an alias + deprecation note for one minor. |

## Agent ↔ server version skew (the critical rule)

Agents and the control plane are upgraded **independently** across a fleet — never assume lock-step.

- The control plane **must accept and correctly process** messages from any agent within the **last two minor releases** (N, N-1, N-2).
- Because the wire protocol is additive (proto ignores unknown fields), a **new server reading an old agent** is always safe; a **new agent talking to an old server** must degrade gracefully (the server ignores fields it doesn't know).
- Never ship a change that requires every agent to be upgraded before the server, or vice versa.

This is the highest-impact compatibility rule: a violation is a fleet-wide outage or a silent cost-data gap.

## Deprecation process

1. **Announce** — add a `Deprecated` entry to `CHANGELOG.md` naming the contract, the replacement, and the earliest removal version.
2. **Deprecate** — keep the old behavior working for **at least one minor release**, emitting a warning (log line / metric / API response header) when it's used.
3. **Remove** — no earlier than the next **major** (post-1.0) and only after the deprecation window. Record the removal in `CHANGELOG.md`.

| Contract | Deprecated in | Removed in | Replacement |
|---|---|---|---|
| _(none yet)_ | | | |

## Making a breaking change

A breaking change to any contract above requires **all** of:

- [ ] An **ADR** ([decisions/](../../decisions/)) explaining why, the migration path, and the deprecation window.
- [ ] A **version bump** of the affected contract (API path, CRD apiVersion, chart/product SemVer).
- [ ] A **`CHANGELOG.md`** entry under `Changed`/`Removed`/`Deprecated`.
- [ ] The **old behavior preserved** through the deprecation window (no flag-day removals).

If you can't satisfy these, it isn't ready to ship.

## Release GO / NO-GO checklist

Run before tagging a release (this is Mode D in the [audit playbook](audit-playbook.md)):

- [ ] `CHANGELOG.md` `[Unreleased]` section moved under the new version with the date.
- [ ] No undocumented breaking contract change (review each row of the contracts table).
- [ ] ClickHouse migrations are additive + idempotent; `Migrate` is a no-op on re-run (**P7**).
- [ ] **Skew tested:** an N-1 agent reports successfully to the new server.
- [ ] `go run ./tools/governance scan -gate` clean; `go run ./tools/governance index -check` clean.
- [ ] `govulncheck ./...` clean or findings triaged.
- [ ] Mode D audit run on the highest-risk changed subsystem.
- [ ] Version bumped per SemVer; tag created; artifacts built (`go build` agent amd64/arm64 + server).

**GO** only if every box is checked or has a documented exception.

## See also

- [`../../CONSTITUTION.md`](../../CONSTITUTION.md) — P11 (and P7, its storage special-case).
- [`../../CHANGELOG.md`](../../CHANGELOG.md) — where contract changes are recorded.
- [`audit-playbook.md`](audit-playbook.md) — Mode D pre-release audit.
