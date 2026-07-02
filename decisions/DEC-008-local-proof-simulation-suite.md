# DEC-008 — Build a scenario-driven differential simulation suite, layered L0–L3

**Status:** ACCEPTED
**Date:** 2026-05-30
**Author(s):** Baris Erdem (with Claude Opus 4.8, supervising founder)

---

## Context

Tollwing's `storage → graph → API` path shipped with **three real bugs that every unit test passed over**, because the tests used in-memory fakes: the ClickHouse `database/sql` driver was never registered, the `flows` TTL used a form ClickHouse 24 rejects, and an API endpoint defaulted a `cluster` field and returned **$0** instead of the real attribution. All three surfaced only by running real ClickHouse + the real server against seeded data with a ground-truth assertion.

The charter (`docs/testing/simulation-research-prompt.md`, in the monorepo) asked for a comprehensive *local* proof that Tollwing does what it claims — correctly and well — runnable anytime, as the living safety net for every future change. A research-first design followed in `docs/testing/simulation-suite-design.md` (monorepo), grounded in a sweep of all ~55 `pkg/` packages, the eBPF data plane, and prior art (Cilium/DeepFlow/Inspektor-Gadget testing, OpenCost/Kubecost internals, eBPF substrates on this arm64 macOS box). This ADR records the architecture chosen there, so a future contributor inherits the reasoning rather than re-litigating it.

Verified constraints that shape the decision: Apple clang has no BPF backend; this box's Docker Desktop kernel (`5.15-linuxkit`) lacks `/sys/kernel/btf/vmlinux`, which CO-RE eBPF requires; `BPF_PROG_TEST_RUN` cannot exercise our cgroup/sock_ops/kprobe hooks; and the agent's *userspace* producer path is driveable with no kernel at all.

## Decision

We will build the suite as a **scenario-driven differential simulation harness**, not a unit-test pass. A single declarative **Scenario** (topology + traffic + expectations, YAML via the already-vendored `sigs.k8s.io/yaml`) drives every tier, and for each scenario **three independent computations must agree** within tolerance: (1) what the traffic generator *injected*, (2) what an **independent oracle** re-derives from first principles using the product's own dated rate cards but its own arithmetic, and (3) what the **real product** measured → classified → costed → stored → served. Divergence is a bug. Exact dollars and exact edges, not `200 OK`.

It is layered:

- **L0** — unit / property / golden, pure Go, runs on macOS (extends the existing tests).
- **L1** — real ClickHouse + the real `tollwing-server`, seeded two ways (storage-first via the real Writer; producer-first by driving the agent's userspace `handlePoll` with no kernel). The workhorse; runs on macOS.
- **L2a** — a real kind cluster with **real demo apps** (topogen oracle topology + OTel Astronomy Shop + Bookinfo-under-Istio) + the real control plane + the agent's real K8s enrichment, flows injected; runs on macOS Docker Desktop (kind needs no BTF — only the eBPF agent does).
- **L2b** — the same cluster with the **real eBPF agent** capturing real kernel bytes, plus the **differential vs OpenCost/Kubecost**; runs in a Lima Ubuntu-arm64 BTF VM (or CI).
- **L3** — scale (k6) / chaos (Chaos Mesh) / soak (agent RSS budget).
- **Differential** — the customer-facing head-to-head: deploys OpenCost + Kubecost's own `network-costs` daemon beside the real agent on the L2b cluster, captures all three tools' cross-AZ numbers on one identical workload, prints the table, and **asserts** the differential (`make sim-differential`). Version-pinned and self-checking so a competitor release that *closes* the gap fails the run loudly.

One entrypoint (`make sim`, tiered fast/full) and a coverage report (claim → tier → pass/fail → actual-vs-expected $). Tooling stays **stdlib-first** (P9): `os/exec` + Docker, `testing/quick`, golden files; any new third-party module (e.g. `testcontainers-go`, `pgregory.net/rapid`, vendoring `topogen`) requires its **own** ADR. The claim→coverage matrix is the source of truth, enforced by a coverage-gate tool in the spirit of `tools/governance`.

## Alternatives considered

### Alternative A — Mock-only / in-memory unit tests as the proof

Keep proving behavior with in-memory fakes.
**Why not:** this is exactly what let the three real bugs through. The product's value is trustworthy numbers against real infrastructure; a proof that never touches real ClickHouse / the real server / the real kernel cannot establish it.

### Alternative B — One monolithic full-cluster e2e as the only artifact

A single big kind-based end-to-end suite.
**Why not:** too slow and flaky for the inner loop, and impossible to run on macOS without the BTF substrate — so there would be no fast feedback at all. Layering (L0/L1 on macOS, L2/L3 on the heavy substrate) gives both a millisecond inner loop and a no-compromise e2e.

### Alternative C — Adopt a heavyweight test framework as the primary harness

Make Ginkgo/Gomega, kuttl, or Chainsaw the backbone.
**Why not:** P9 (stdlib-first). Stdlib `testing` + a thin Go harness asserts exact dollars naturally; the declarative YAML tools center on K8s-object assertions and add a dependency for less numeric expressiveness. We may still use Chainsaw as an *optional external CLI* for declarative cluster scenarios, but not as the core.

### Alternative D — Defer the real-cluster-with-demo-apps experience

Treat "run Tollwing against real apps" as a final, optional phase.
**Why not:** that experience *is* the point ("see how things look"). The insight that kind runs on Docker Desktop (only the agent needs BTF) lets it run on macOS today as **L2a**, so it is pulled forward, with the real-agent version layered on top as L2b.

## Consequences

### Positive

- Catches the class of bug that motivated the charter, and becomes the living safety net for every change (P4/P11).
- A macOS-runnable inner loop (L0/L1/L2a) plus a no-compromise real-agent proof (L2b).
- The cross-AZ **differential** gives a defensible, honest headline versus OpenCost/Kubecost.
- The oracle makes every asserted dollar traceable to `bytes × dated-rate` (P4) and keeps enum strings single-sourced (P6).

### Negative

- L2/L3 have long runtimes — mitigated by explicit fast/full tiers, never by faking the hard parts.
- L2a needs a small **test-only flow injector** — a sibling tool reusing `pkg/k8s` + `pkg/classifier` + `pkg/cost` that enriches injected flows against a *real* cluster's metadata (real ClusterIP→service, real pod-IP→zone) and persists them via the real storage Writer. Chosen over a `-no-ebpf` flag on the agent so the production agent stays entirely untouched (P1, the stronger choice): reading the agent confirmed a flag would thread conditionals through the BPF-coupled `Run()` and the PID-centric `handlePoll`. The injector has no eBPF dependency, so it develops and unit-tests on macOS (via a client-go fake clientset).
- Some realism (a *real* cloud bill, GPU telemetry) cannot be fully local; the suite simulates them (synthetic CUR/FOCUS, synthetic `nvidia-smi`) and flags them explicitly rather than overclaiming (P4).

### Neutral

- The L2b substrate is a Lima VM with a BTF kernel; if Docker Desktop later ships a BTF kernel on this box, L2b can collapse onto Docker Desktop and drop the Lima requirement.
- New third-party test dependencies are possible but each is gated by its own ADR (P9/[DEC-005]).

## Constitutional principles touched

- **P4 (honest, traceable cost):** advances — the oracle asserts every dollar re-derives from `bytes × dated-rate`, and surfaces simulated-vs-real billing explicitly.
- **P5 (accurate attribution):** advances — the headline scenarios prove cross-AZ / pre-DNAT / `Unknown` behavior against ground truth.
- **P6 (one canonical representation):** advances — the oracle and golden files derive enum strings from `TrafficType.String()`, never literals.
- **P11 (compatible public contracts):** advances — the suite regression-guards the HTTP API, ClickHouse schema, metric names, and CRDs against silent breaks.
- **P12 (data minimization):** advances — the suite uses only synthetic topologies/traffic/bills; no real payloads, cmdlines, or tenant data.
- **P8 (safe automated actions):** advances — safety-guard and remediation/admission scenarios assert the gates refuse to act unsafely.
- **P9 (stdlib-first):** advances — stdlib `testing`/`testing/quick`/golden + `os/exec`; each new dep gets its own ADR.
- **P2/P3 (overhead budget; portable data plane):** advances — L3 soak asserts the agent RSS ceiling; the L2b kernel-matrix exercises feature-probe degradation.
- **P1 (the agent is the product):** advances/neutral — the suite is entirely test-scope and the production agent is left untouched: L2a uses a separate test-only injector, not a `-no-ebpf` flag in the agent binary.

## Re-evaluation triggers

- The inner loop (L0/L1) stops being fast enough to run on every change → re-tier or split.
- An ADR for a proposed test dependency is rejected → adjust the tooling choice recorded here.
- Docker Desktop on the dev box gains a BTF kernel → L2b may move off Lima onto Docker Desktop.
- The BPF-less injection mode starts to diverge from the real producer path → fold it back or retire L2a's injection seam in favor of L2b.

## Related decisions

Implements the charter (`docs/testing/simulation-research-prompt.md`) and the design (`docs/testing/simulation-suite-design.md`), both in the monorepo. Proves the mechanisms of [DEC-002] (socket-level hooks) and [DEC-003] (two-phase pre-DNAT capture); asserts the storage contract of [DEC-004]; relies on [DEC-007]'s single-sourced traffic-type literals for golden stability; and is bound by [DEC-005] (stdlib-first) for every tooling choice.

## References

- `docs/testing/simulation-suite-design.md` (monorepo) — the full design (architecture, claim→coverage matrix, oracle strategy, substrate, scenario format, phased plan).
- The prior bug class: `pkg/storage/clickhouse/driver.go` (driver registration), `pkg/storage/clickhouse/schema.go` (TTL), `pkg/api` (cluster default).
- Oracle anchors: `pkg/classifier/traffic.go`, `pkg/cost/{engine,ratecard}.go`, `pkg/servicegraph/attribution.go`.

## Notes

L2a's flow injector and any new third-party test dependency are deliberately left as follow-ups, each recorded when taken (the dependency in its own ADR per [DEC-005]). The suite is implemented under `test/sim/`. **Refinement during implementation (2026-05-30):** L2a uses a *separate test-only injector* rather than the `-no-ebpf` agent flag the design first sketched — reading the agent showed the flag would be invasive (BPF-coupled `Run()`, PID-centric `handlePoll`) and untestable on macOS, whereas the injector reuses the cross-platform `pkg/k8s`/`classifier`/`cost` and leaves the production agent pristine (P1).

**Refinement (2026-05-30, live differential):** the L2b differential was run for real against **OpenCost 2.5.22** and **Kubecost's own `network-costs` daemon** (chart `2.5.3` / image `v0.17.6`) on one cluster, and productized as a repeatable, version-pinned, self-asserting tier (`make sim-differential`, `test/sim/differential/run.sh` in the monorepo). Measured: Tollwing attributes cross_az to the dialed Service ($0.0008+ on the flow, zero-config); OpenCost = **$0** (community chart ships no network daemon); Kubecost bills genuine cross-AZ as `same_zone`/**free** with no destination-Service field. It also surfaced two further gaps beyond the original claim — the daemon emits **nothing** without a `topology.kubernetes.io/region` label (Tollwing derives the region from the zone name), and it mislabels cross-AZ **Service (ClusterIP)** traffic as free **even after** per-AZ CIDR tuning because it keys on the post-DNAT tuple (the DEC-003 gap, reproduced inside the competitor). Full writeup in [`docs/testing/differential.md`](../docs/testing/differential.md).
