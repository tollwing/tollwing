# Tollwing Constitution

**Version:** 1.1.0
**Adopted:** 2026-05-30
**Status:** ACTIVE
**Authority:** This document is the source of truth on engineering and product principles for Tollwing. Code, eBPF programs, schemas, cost math, recommendations, and customer-facing behavior must conform to these principles. Violations require either (a) a documented exception with a good reason (an ADR in [`decisions/`](decisions/)), or (b) a constitutional amendment.

---

## Preamble

Tollwing grew fast. Fourteen sprints of features — classification, cost, storage, alerting, recommendations, a service-dependency graph, GPU telemetry, remediation — landed on top of one eBPF agent, each one a self-contained commit with its own design doc. The code carries a strong, consistent engineering culture in its comments and structure: stdlib-first, honest about what it can and cannot measure, conservative about acting on customer infrastructure, careful never to let the same concept drift across boundaries.

That culture was real but uncodified. Nothing stated it, so nothing could be checked against it, and nothing stopped a future change — human or agent — from quietly violating it. This constitution writes the culture down so that code, decisions, and product behavior can be measured against a stated standard, and so that the next contributor inherits the reasoning, not just the result.

It is adapted from the governance practice established in sibling projects, not copied from them. The *shape* (principles → decision log → audit) is borrowed; the *substance* is Tollwing's own, derived from this codebase. Principles that don't fit an eBPF cost-attribution platform were left out; principles that this codebase already lives by were written down.

---

## The Principles

Each principle has a stable ID (`P1`–`P12`). Cite them in code comments, commit messages, ADRs, and reviews.

### P1 — The agent is the product

**Statement.** The per-node eBPF agent is Tollwing's core asset — a kernel-level vantage point that no competitor re-deploys cheaply. Every feature is a SKU built on the agent's data, not a reason to expand the agent. Keep the agent lean and single-purpose; state, history, cross-node correlation, and heavy compute belong in the control plane.

**Rationale.** The strategic thesis is that the moat is the deployed agent fleet, not any one feature (`our internal design notes`). An agent that accretes per-feature logic becomes risky to deploy, expensive to run, and hard to reason about — eroding the very asset every SKU depends on.

**Practical implication.** New capabilities read the agent's existing flow/metadata streams or add a narrowly-scoped collector; they do not add stateful services, databases, or unbounded background work to the DaemonSet. If a feature needs cross-node or historical data, it lives in `tollwing-server`.

**Anti-examples.**
- A per-feature in-agent cache that grows with cluster size.
- Doing cost reconciliation or graph attribution inside the agent.
- Embedding a feature's business logic in the BPF data plane.

**Examples (adherence).**
- The agent ships flows to the control plane over NATS and lets `tollwing-server` / `pkg/servicegraph` do correlation and attribution.
- GPU telemetry is an opt-in collector behind a flag, not always-on (`cmd/tollwing-agent/main.go:36`).

**Compliance test.** For any agent-side change, ask: does this add unbounded state or cross-node logic to the per-node binary? If yes, it belongs in the control plane or needs an ADR.

### P2 — Near-zero node overhead is a hard budget

**Statement.** The agent runs on every node, so its CPU and memory cost is multiplied by the fleet. Target <1% CPU and a bounded, declared memory ceiling. Prefer in-kernel aggregation over per-event userspace work; every cache is bounded with an explicit eviction policy; nothing on a hot path allocates without need.

**Rationale.** Overhead on a monitoring agent is pure tax the customer pays just to observe their costs — an agent that itself costs real money is self-defeating, and a memory leak on a DaemonSet is a fleet-wide outage.

**Practical implication.** Set `GOMEMLIMIT` and `GOGC`; size BPF maps with LRU eviction; bound every userspace cache and choose its eviction policy deliberately; aggregate in-kernel (PERCPU_HASH) and poll on an interval rather than emitting per-event.

**Anti-examples.**
- An unbounded map keyed by connection / pod / domain.
- Emitting a userspace event per packet or per syscall.
- A cache whose size tracks cluster cardinality with no ceiling.

**Examples (adherence).**
- `GOMEMLIMIT` / `GOGC` set from flags with documented trade-offs (`cmd/tollwing-agent/main.go:41-50`).
- The DNS tracker uses a fixed-size ring-buffer LRU where the ring length *is* the capacity (`pkg/dns/tracker.go`).
- In-kernel `flow_aggregates` PERCPU_HASH flushed on a 5s tick (`ARCHITECTURE.md` §2.4).

**Compliance test.** Every new map/cache has a documented max size and eviction policy; `go test -bench` covers hot paths (`classifier`, `cost`, `dns`, `poller`); the agent's steady-state RSS stays under the declared limit in the local stack.

### P3 — Portable, capability-probing data plane

**Statement.** The agent must load and run across the kernel versions customers actually run. Compile BPF once with CO-RE against vendored BTF; probe every kernel feature at startup and degrade gracefully when one is missing; never hard-require a feature without a fallback. Cross-platform binaries build `CGO_ENABLED=0`; kernel- and GPU-specific code sits behind build tags.

**Rationale.** Kernel fragmentation is the default in real fleets. A tool that demands a recent kernel or fails to load is undeployable; graceful degradation is what makes "runs everywhere" true.

**Practical implication.** New hooks/maps get a probe in `features.go` and a documented minimum kernel; the loader checks required features and degrades or refuses cleanly with a clear error; per-arch objects are committed and `go:embed`-ed; Linux-only and GPU code carry `//go:build` tags so the server/CLI cross-compile.

**Anti-examples.**
- Calling a 6.4+ helper on the required path with no probe.
- Requiring kernel headers at runtime instead of CO-RE.
- Letting cgo creep into the server or CLI.
- A new hook with no minimum-kernel note.

**Examples (adherence).**
- `ProbeAll` splits required vs optional features and `CheckRequired` fails with the missing list (`pkg/ebpf/features.go:22,70`).
- `HaveCgroupConnect4` / `HaveSockOps` / `HaveFentry` capability probes (`pkg/ebpf/features.go:49-66`).

**Compliance test.** `CGO_ENABLED=0 GOOS=linux go build ./cmd/tollwing-agent` and a `CGO_ENABLED=0` server build both succeed; every new hook has a probe and a minimum-kernel comment.

### P4 — Cost numbers are honest and traceable

**Statement.** Every dollar Tollwing reports traces to a measured byte count multiplied by a dated rate card. Attribution that splits a shared cost is labeled as a *responsibility split, not proven causation*. Spend Tollwing cannot measure goes into an explicit "unaccounted" bucket, and reconciliation surfaces drift and an accuracy score. Never display a number you cannot derive and defend.

**Rationale.** Tollwing's entire value is that its numbers are trustworthy enough to act on — to move a service, change a budget, or page someone. A fabricated, asserted, or silently-approximated dollar figure is worse than no figure: it destroys the trust the product is built on.

**Practical implication.** Cost = measured bytes × rate-card rate, with the rate card's timestamp recorded; transitive/shared attributions conserve dollars and are documented as splits; unmeasured cost is bucketed and reconciled against the cloud bill, not hidden; an accuracy/drift figure is computed, not claimed.

**Anti-examples.**
- Emitting a cost for a flow whose zone is `Unknown`.
- Asserting "95% accurate" without reconciliation.
- An attribution that double-counts or invents dollars.
- A hardcoded rate with no source or date.

**Examples (adherence).**
- Transitive cross-AZ attribution is explicitly "a *responsibility* split, not proven causation … but it is conservative and conserves dollars" (`pkg/servicegraph/attribution.go:56-72`).
- Billing reconciliation computes drift and attributes unmatched spend to an "unmeasured" bucket with an accuracy score (`ARCHITECTURE.md` §5.3).

**Compliance test.** Trace any displayed dollar to `(bytes, rate, rate-date)`; confirm shared-cost attributions sum to the underlying cost; confirm `Unknown`/unmeasured inputs never produce an asserted dollar figure.

### P5 — Accurate attribution over convenient approximation

**Statement.** When the truth is recoverable, recover it. Capture pre-DNAT intent so traffic is attributed to the service the client dialed, not the post-DNAT backend; resolve zones deterministically and mark `Unknown` rather than guess; identify proxy/sidecar flows so a request isn't counted twice. Convenience is never a reason to attribute traffic to the wrong owner.

**Rationale.** Accurate, service-level, cross-AZ attribution is the differentiator versus tools that classify from post-DNAT IPs. Guessing erodes both the dollar figure (P4) and every recommendation built on it.

**Practical implication.** Use the two-phase capture (`cgroup/connect4` pre-DNAT + `sock_ops` post-DNAT) and the intent cache to recover the ClusterIP; when zone resolution fails, return `Unknown` and let it surface — don't fabricate `same_zone`; mark and dedup sidecar-to-sidecar flows.

**Anti-examples.**
- Attributing cross-AZ cost from the backend pod IP without recovering the original ClusterIP.
- Defaulting an unresolved zone to `same_zone` (the free, flattering answer).
- Counting `app→sidecar` and `sidecar→remote` as two independent charged flows.

**Examples (adherence).**
- Package `intent` "correlates post-DNAT flow snapshots back to the pre-DNAT destination — the ClusterIP the client originally dialed" (`pkg/intent/cache.go:1-3`).
- The classifier returns `Unknown` when zones are unresolved rather than guessing (`pkg/classifier/traffic.go:265`; tested by `TestClassify_UnknownWhenNoZones`, `pkg/classifier/classifier_test.go:147`).

**Compliance test.** A flow with unresolved zones classifies as `Unknown` (tested); service attribution uses the pre-DNAT destination; sidecar dedup is covered by a test.

### P6 — One canonical representation; no drift across boundaries

**Statement.** Each domain concept has exactly one source-of-truth representation, and every boundary — in-memory model, ClickHouse enum, Prometheus label, JSON API — derives from it. No parallel hardcoded literal of a value that an enum already owns.

**Rationale.** Tollwing's value depends on the same number meaning the same thing in the graph, the database, the metric, and the dashboard. Duplicated string/enum definitions drift silently and produce contradictory reports.

**Practical implication.** Traffic types, providers, and similar enums are defined once (with a `String()` method), and that method feeds the ClickHouse enum mapping, metric labels, and API responses; a new category is added in exactly one place.

**Anti-examples.**
- Writing the literal `"cross_az"` in a query or metric label instead of `CrossAZ.String()`.
- A second copy of the traffic-type list in the storage layer that can fall out of sync with the classifier.

**Examples (adherence).**
- `classifier.TrafficType` with a single `String()` returning the canonical wire strings (`same_zone`, `cross_az`, …) at `pkg/classifier/traffic.go:11-65`, reused by the storage enum, metrics, and the service graph.

**Compliance test.** `tools/governance scan` reports no hardcoded traffic-type string literals outside `traffic.go`; adding a `TrafficType` updates exactly one enum and propagates via `String()`.

### P7 — Storage is forward-only and additive

**Statement.** ClickHouse migrations only ever append. Never reorder or rewrite an applied migration; never ship a destructive down-migration; evolve schemas additively (`ADD COLUMN IF NOT EXISTS`). Migrations are idempotent and safe to run on every server start. Schema-engine choices reflect ClickHouse's real transaction semantics, not wishful thinking.

**Rationale.** Historical cost data is the product's memory; a destructive or reordered migration corrupts the record customers rely on for trend analysis and reconciliation. ClickHouse has no reliable multi-statement transactions, so idempotency is the only safe contract.

**Practical implication.** A new schema change appends a `Migration` with the next version and `IF NOT EXISTS` / `IF EXISTS` SQL; applied versions are tracked for skip-on-restart; `ReplacingMergeTree` + `FINAL` is used where dedup-on-merge is required.

**Anti-examples.**
- Editing an already-released migration's SQL.
- A `DROP COLUMN` / down migration.
- A migration that isn't idempotent and breaks on re-run.

**Examples (adherence).**
- "Never reorder, never rewrite history — always append. Down migrations are intentionally omitted" (`pkg/storage/clickhouse/migrations.go:18-20`).
- Idempotent apply-then-record because "ClickHouse doesn't support multi-statement transactions reliably" (`pkg/storage/clickhouse/migrations.go:124-128`).
- `schema_migrations` uses `ReplacingMergeTree` and is read with `FINAL` (`pkg/storage/clickhouse/migrations.go:63,103`).

**Compliance test.** `tools/governance scan` flags destructive or edited migrations; running `Migrate` twice is a no-op; every migration uses `IF [NOT] EXISTS`.

### P8 — Automated actions are safe and reversible

**Statement.** Anything that mutates customer infrastructure — remediation, the admission webhook, the cost-aware scheduler, topology recommendations — is approval-gated, guarded by explicit safety preconditions, bounded in blast radius, and reversible. Default to *recommend*; *act* only behind an approval and a rollback path.

**Rationale.** A cost tool that takes a wrong automated action can cause an outage costing far more than it ever saved. The product's license to automate is conditional on never making things worse.

**Practical implication.** Remediations move through an explicit lifecycle (pending → approved → applied → rollback/reject) and cannot apply without approval; recommendations that could harm (e.g., Topology-Aware Routing) run through a safety guard returning safe/gated/blocked *with reasons*; actions are bounded and record how to undo them.

**Anti-examples.**
- Auto-applying a remediation with no approval or no recorded rollback.
- Pushing a TAR hint without checking its failure modes (zone starvation, failover stampede, no HPA).
- An unbounded automated action.

**Examples (adherence).**
- The remediation controller refuses to `Apply` without `Approve`, and supports `Rollback`/`Reject`, with tests covering the approve→apply and rollback paths.
- The TAR guard "will not push a TAR recommendation through" without a safe/gated/blocked `Verdict` and explicit reasons (`pkg/topology/guard.go:1-40`).

**Compliance test.** Every infra-mutating path has an approval gate and a rollback/undo, both covered by tests; safety guards return reasons, not just booleans.

### P9 — Stdlib-first; dependencies earn their place

**Statement.** Reach for the standard library first. Logging is `log/slog`, flags are `flag`, tests are `testing`. A new third-party dependency — including a different logger, CLI framework, or test/assertion library — must be justified in a decision record before it lands.

**Rationale.** An agent deployed fleet-wide is a supply-chain surface and a binary-size concern; every dependency is attack surface, build risk, and drift. The stdlib is stable, audited, and CGO-free. This discipline is already the de-facto norm and is worth making binding. See [DEC-005](decisions/DEC-005-stdlib-first-dependencies.md).

**Practical implication.** Use `slog` for all logging; `flag` for CLIs; `testing` (table-driven) for tests; add a third-party module only with an ADR weighing the cost of the dependency against writing it on stdlib.

**Anti-examples.**
- Importing cobra/viper, testify, zap/logrus, or a heavyweight framework when stdlib suffices.
- Importing `"log"` instead of `"log/slog"`.

**Examples (adherence).**
- 76 source files use `log/slog`; zero import the stdlib `"log"`.
- CLIs use `flag` (`cmd/tollwing-agent/main.go:20-39`); tests are stdlib table-driven (e.g., `pkg/classifier/classifier_test.go`).

**Compliance test.** `tools/governance scan` flags any stdlib `"log"` import or banned dependency; a new direct dependency in `go.mod` has a corresponding ADR.

### P10 — Multi-cloud is one abstraction

**Statement.** Provider differences live behind the `cloud.Provider` interface and the rate-card model. The classifier, cost engine, and storage stay provider-neutral; AWS/GCP/Azure specifics (e.g., GCP's free intra-region traffic) are expressed as data and interface implementations, never as provider branches scattered through shared code.

**Rationale.** Three divergent codepaths become three half-maintained products. A single abstraction keeps behavior consistent and makes a new provider an implementation, not a refactor.

**Practical implication.** New topology/pricing/billing capability is added as a method on `cloud.Provider` with per-provider implementations; provider-specific pricing is a `RateCard`, not an `if provider ==` branch in the cost engine.

**Anti-examples.**
- `if provider == "gcp"` sprinkled through the classifier.
- AWS-only assumptions baked into shared cost code.
- A fourth provider requiring edits across unrelated packages.

**Examples (adherence).**
- `cloud.Provider` interface with `GetSubnetZoneMapping` / `GetRateCard` and per-provider implementations (`pkg/cloud/provider.go:15`).
- Pricing flows through `cost.RateCard` (e.g., `cost.DefaultAWSRateCard`) rather than provider conditionals.

**Compliance test.** Adding a provider touches only `pkg/cloud/<provider>` and rate-card data; grepping for `provider ==` / `== "aws"` in `classifier`/`cost` returns nothing.

### P11 — Public contracts are versioned and evolve compatibly

**Statement.** Every interface other systems depend on is a public contract: the HTTP API, the CRDs, the NATS/protobuf wire format, the ClickHouse schema, CLI flags, Prometheus metric names, and Helm values. Contracts change *additively* and are *versioned*; breaking one requires a version bump, a deprecation window, and an ADR. A new server must keep working with the agents already deployed in the fleet.

**Rationale.** Tollwing runs across a customer's fleet, and upgrades are not atomic — an old agent talks to a new server, a dashboard queries last month's schema, a CRD outlives the operator that created it. A silent breaking change is a fleet-wide outage or a cost-data gap, and it destroys the trust P4 depends on. P7 is the storage special-case of this principle.

**Practical implication.** Add fields, don't repurpose or renumber them; version the API path / CRD `apiVersion` / proto message; the server stays read-compatible with N-1/N-2 agents; deprecate before removing (announce → one minor with a warning → remove no earlier than the next major); record every breaking change in `CHANGELOG.md` and an ADR.

**Anti-examples.**
- Renaming or removing a JSON field, proto field number, or metric label in place.
- A CRD schema change that rejects already-applied custom resources.
- A server that refuses messages from an N-1 agent.
- Removing a CLI flag with no deprecation period.

**Examples (adherence).**
- ClickHouse migrations are additive and forward-only — the storage instance of this principle (P7, `pkg/storage/clickhouse/migrations.go`).
- The HTTP API is versioned under `/api/v1`; CRDs are `tollwing.io/v1alpha1`.

**Compliance test.** A changed public contract either has no behavior change for existing clients, or carries a version bump + a deprecation note + a `CHANGELOG.md` entry + an ADR; an N-1 agent still reports successfully to the current server. See [`docs/governance/compatibility.md`](docs/governance/compatibility.md).

### P12 — Capture only what attribution needs, and protect it

**Statement.** The agent sees everything on the node. It captures only what cost attribution requires — connection 4-tuples, byte counts, and `pid`→pod/zone/service metadata — and no more. Payload contents, full command lines, and secrets are not captured by default; anything beyond the attribution minimum (e.g. a TLS payload tap) requires an ADR and a privacy review. Sensitive data is redactable, access-controlled, retention-bounded, and isolated per tenant.

**Rationale.** A privileged eBPF agent on every node is the most sensitive component in a customer's environment. Over-capture is a breach waiting to happen, a compliance liability, and a betrayal of the access the customer granted. Restraint is what makes the agent deployable in regulated environments — and the strategy explicitly courts payload-adjacent features (LLM governance, DLP), so the guardrail must exist before the temptation does.

**Practical implication.** Default to metadata, not content; never log raw 4-tuples or cmdlines at info level; redact process cmdlines in multi-tenant mode; enforce per-tenant isolation at the query layer; bound retention; gate any new sensitive capture behind an ADR and the data-handling policy.

**Anti-examples.**
- Capturing or buffering packet payloads "just in case."
- Emitting full cmdlines or 4-tuples into shared logs at info level.
- A query path that can return another tenant's flows.
- Adding a TLS tap (or similar) without an ADR and a privacy review.

**Examples (adherence).**
- The agent captures 4-tuples + byte counts + `pid`→pod metadata (`ARCHITECTURE.md` §2.3/3.4), not payloads.
- `SECURITY.md` classifies process names/cmdlines as redactable in multi-tenant mode.

**Compliance test.** The agent's captured fields are the attribution minimum; no sensitive field is logged at info; multi-tenant redaction and per-tenant isolation are tested; any new capture cites an ADR. See [`docs/governance/data-handling.md`](docs/governance/data-handling.md).

---

## Amendment process

The constitution is versioned with [semantic versioning](https://semver.org/): `1.0.0 → 1.1.0` for additions or clarifications, `2.0.0` for a breaking change to a principle's meaning.

Anyone (human or agent) may propose an amendment. A proposal must state:

1. **The change** — exact new or revised principle text.
2. **Rationale** — why the current text is wrong, incomplete, or newly contradicted by reality.
3. **Impact on existing code** — what becomes compliant or non-compliant.
4. **Migration plan** — how existing violations are resolved (fix, exception, or grandfather).
5. **Version bump** — which part of the version changes, and why.

The amendment is **recorded as an ADR** in [`decisions/`](decisions/); the principle text is changed in place; the prior version lives in git history and the version-history table below records the bump. A clarification that *narrows* a principle is preferred over one that broadens it — narrowing fixes a real tension without weakening the rule everywhere else.

---

## Authority and enforcement

The constitution conforms to nothing higher; everything else conforms to it. Enforcement has four layers:

1. **Mechanical scan** — `tools/governance scan` flags the regex-detectable subset of violations (P3 cgo-tagging, P6, P7, P9) on every PR via the CI `governance` job, and `govulncheck` covers supply-chain (P9). It is a *floor, not a ceiling*: passing the scan does not mean compliant.
2. **Agent self-check** — AI agents read this document before significant work and follow the protocol in [`CLAUDE.md`](CLAUDE.md), citing principles in code and commits.
3. **Audits** — the [audit playbook](docs/governance/audit-playbook.md) defines a reproducible, human-or-agent process for finding violations the scan can't see (P1–P5, P8, P10–P12).
4. **Review** — the [PR template](.github/PULL_REQUEST_TEMPLATE.md) makes "principles touched" and "decision recorded?" explicit at review time.

**Constitutional exceptions.** A violation may be knowingly accepted when there's a good reason — but only with a documented exception: an ADR that names the principle, explains why the exception is warranted, scopes it narrowly, and lists re-evaluation triggers. Code that takes an exception cites the ADR inline (`// Per DEC-NNN, …`), and `tools/governance scan` respects that citation. An exception with no ADR is just a violation.

---

## Living documents discipline

Out-of-date governance is worse than none: it teaches the wrong thing with authority. These documents are living, and keeping them current is part of the work, not a follow-up.

- **Before** significant work: read this constitution; scan the [decision index](decisions/README.md) for decisions that bind the area you're touching.
- **During**: cite the principle you're serving or flexing in code comments and the commit message; when you hit a tension, stop and choose — revise the change, document an exception (ADR), or propose an amendment.
- **After**: if the change warranted a decision, write the ADR and regenerate the index; if it changed how a subsystem works, update the relevant `docs/` and `ARCHITECTURE.md`; if it touched a principle's examples, keep the `file:line` citations here accurate.
- **Periodically (quarterly)**: run the review in [`docs/governance/quarterly-review-TEMPLATE.md`](docs/governance/quarterly-review-TEMPLATE.md) — re-audit one principle across the codebase, check the examples still resolve, prune stale decisions.

Letting these documents drift is itself a violation of the spirit of P4 and P6: a governance doc that no longer matches reality is an untraceable, drifted claim.

---

## Version history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.1.0 | 2026-05-30 | Baris Erdem (with claude-opus-4-8) | Added P11 (public contracts versioned & compatible) and P12 (data minimization & protection) per [DEC-006](decisions/DEC-006-add-compatibility-and-privacy-principles.md). |
| 1.0.0 | 2026-05-30 | Baris Erdem (with claude-opus-4-8) | Initial adoption of all ten principles. |

---

## See also

- [`decisions/`](decisions/) — the decision log (ADRs), including [DEC-001](decisions/DEC-001-adopt-constitution-and-governance.md) which adopts this constitution.
- [`docs/governance/audit-playbook.md`](docs/governance/audit-playbook.md) — how to audit code against these principles.
- [`docs/governance/conventions.md`](docs/governance/conventions.md) — the concrete Go conventions these principles imply.
- [`CLAUDE.md`](CLAUDE.md) — the operating protocol for AI agents (and a good orientation for humans).
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — the system design these principles govern.
