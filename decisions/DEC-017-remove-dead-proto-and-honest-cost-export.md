# DEC-017 — Remove the dead proto/ contract and re-scope opencost-plugin as an honest cost-export sidecar

**Status:** ACCEPTED
**Date:** 2026-07-02
**Author(s):** Baris Erdem (with Claude Fable 5, dead-surfaces workstream)

---

## Context

An audit of dishonest surfaces found two components whose claims did not match reality:

**1. `proto/` was a specification with no implementation.** `proto/flow.proto` and `proto/cost.proto` defined `FlowService`/`CostService` gRPC services and a `FlowRecord` wire format, with `option go_package = ".../pkg/api/pb"` — but no `pkg/api/pb` exists, no `protoc`/`buf` step exists in the Makefile or CI, and no Go file imports any generated code. Everything the protos describe actually runs as REST/JSON: the HTTP API under `/api/v1/*` (`pkg/api/server.go`) and the agent→server NATS path. `ARCHITECTURE.md` listed `proto/ # Protobuf definitions` as if a gRPC API existed. A contract file that nothing generates from or speaks is not a public contract (P11) — it is documentation drift with the authority of source code, and it duplicates the `TrafficType` enum that `classifier.TrafficType.String()` canonically owns (P6 drift waiting to happen: the proto listed 10 values that nothing keeps in sync).

**2. `opencost-plugin/` claimed to be an OpenCost plugin and mislabeled dollars.** The real OpenCost custom-cost integration (OpenCost ≥ 1.110, verified current as of 2026-07 against the [opencost-plugins developer guide](https://github.com/opencost/opencost-plugins) and [opencost.io plugin docs](https://opencost.io/docs/integrations/plugins/)) is a **hashicorp/go-plugin gRPC subprocess**: OpenCost discovers an architecture-specific plugin binary plus a config file from `PLUGIN_EXECUTABLE_DIR`/`PLUGIN_CONFIG_DIR`, launches it, and calls the `CustomCostSource` interface (`GetCustomCosts(CustomCostRequest) []CustomCostResponse`, protobuf types from opencost core) on an hourly/daily ingestion schedule. Our component implemented none of that: it was a plain `net/http` server with invented `/costs`, `/cost/total`, and `/config` endpoints that OpenCost never calls.

Worse, it violated P4 twice in `/cost/total`:

- **Agent scrape mode** summed the agent's `tollwing_cost_usd_total` Prometheus counters — which are **cumulative since agent start** — and returned that figure labeled with whatever `window` the caller requested (`Window: "24h"` on a since-boot total).
- **Server mode** parsed the window with `time.ParseDuration` and on failure **silently defaulted to 24h** while echoing the requested string — so `window=7d` (the conventional cost-tool spelling, unparseable by `ParseDuration`) returned 24 hours of dollars labeled "7d".

A third, quieter mislabel: `/costs` interpolated `start`/`end` into the upstream URL unencoded, so an RFC3339 timezone offset (`+02:00`) decoded to a space server-side, failed `time.Parse` in `parseTimeRange`, and made tollwing-server silently substitute its default window — again returning dollars for a window other than the one asked.

## Decision

**We will delete `proto/` entirely, and re-scope `opencost-plugin/` as what it actually is: a standalone FOCUS-aligned JSON cost-export sidecar — while fixing every path where a returned dollar could be labeled with a window it does not cover.**

Concretely:

- `proto/flow.proto` and `proto/cost.proto` are removed. If a gRPC transport is ever adopted, its protos will be written then, generated in CI, and derived from `classifier.TrafficType` — not resurrected from these files.
- `opencost-plugin/` keeps its endpoints but drops the OpenCost-plugin claim in its package docs, `/config` self-description, Dockerfile, and a new `opencost-plugin/README.md` that states the real OpenCost contract and why we don't implement it today.
- **Window honesty (P4):**
  - Agent scrape mode refuses `window=…` with `400` and labels its response `cumulative_since_agent_start`. A cumulative counter total is never presented as a windowed figure.
  - Server mode parses windows as Go durations plus a `d` day suffix (`7d` = 168h); an unparseable or non-positive window is a `400`, never a silent 24h default.
  - `/costs` validates `start`/`end` as RFC3339 and rejects malformed bounds with `400` (instead of forwarding garbage that upstream silently replaces), URL-encodes them properly (`url.Values`), generates defaults in UTC, and echoes the exact window covered in the response body.
- The component follows repo conventions it previously skipped: `Config` + `setDefaults()`, table-driven stdlib tests covering each original bug.
- The directory keeps the `opencost-plugin/` name for now because `deploy/helm/tollwing-agent` (sidecar image `ghcr.io/tollwing/tollwing-opencost-plugin`), `tools/publish-oss/publish-oss.sh` (`ASSET_DIRS`), and the Dockerfile build path all reference it; those files are owned by other workstreams. Renaming directory + image (e.g. to `cost-export`) is a recorded follow-up (see Notes).

## Alternatives considered

### Alternative A — Keep `proto/` as the "future gRPC API"

Leave the files as aspirational documentation of a v2 transport.
**Why not:** A contract nothing implements can only drift. It already duplicated the `TrafficType` enum outside `TrafficType.String()`'s ownership (P6), and it misled `ARCHITECTURE.md` into describing a gRPC API that does not exist — governance docs teaching the wrong thing with authority. Deleting is free: the files are in git history, and a real gRPC adoption would regenerate protos from the canonical enum anyway. Removing a never-generated, never-imported, never-shipped spec breaks no deployed consumer, so P11's version-bump/deprecation machinery is not triggered.

### Alternative B — Implement the real OpenCost plugin contract now

Build a proper `CustomCostSource` gRPC subprocess plugin (hashicorp/go-plugin) that serves Tollwing network costs into OpenCost's ingestion pipeline.
**Why not (today):** It requires three new dependency trees — `hashicorp/go-plugin`, `google.golang.org/grpc`, `protobuf` — each needing its own DEC-005/P9 justification, in a repo whose entire dependency posture is stdlib-first. The plugin would also have to live against OpenCost's protobuf types and release cadence, and upstream plugins are expected to be contributed to the `opencost-plugins` repo with their own `go.mod`. No customer has asked for OpenCost ingestion; the differential test (`test/sim/differential/run.sh`) exists to show OpenCost *can't* see this traffic, not to feed it. Deferred behind a re-evaluation trigger, not rejected forever.

### Alternative C — Delete `opencost-plugin/` entirely

Treat it like `proto/`: a dead surface, remove it.
**Why not:** Unlike `proto/`, it is shipped and wired: the Helm chart deploys it as an opt-in sidecar (`opencostPlugin.enabled`) and `publish-oss.sh` publishes the directory. A FOCUS-aligned JSON export of network cost is genuinely useful to external cost tooling regardless of OpenCost. The dishonesty was in the *label*, not the function — so fix the label and the P4 bugs, keep the function.

### Alternative D — Keep mislabeling but document it

Add a README caveat that agent-mode windows are approximate.
**Why not:** P4 is explicit — never display a number you cannot derive and defend. A documented lie is still a lie; "the dollar shown is not the dollar of the window asked" is the exact anti-pattern. Rejecting with an honest error costs the caller one query-parameter change.

## Consequences

### Positive

- No governance doc can any longer point at `proto/` as evidence of a gRPC API; the repo's only transport claims are ones that run.
- Every `/cost/total` and `/costs` response now states exactly the window its dollars cover, or fails loudly. `window=7d` now returns 7 days of cost instead of 24h mislabeled.
- One fewer parallel copy of the `TrafficType` enum (P6).
- The component now has tests (previously zero).

### Negative

- Callers that relied on the lenient behavior break: `window=<garbage>` and agent-mode `window=…` now return `400` instead of a 200 with wrong-window dollars. This is deliberate — the old 200 was the bug (see P11 note below).
- `git log` archaeology for the protos now requires looking at deleted paths.

### Neutral

- The `opencost-plugin/` directory name and image name still say "opencost" until the coordinated rename lands (Notes).
- The public `README.md` / `ARCHITECTURE.md` "OpenCost-compatible plugin" and `proto/` mentions are corrected by the docs workstream, not this change.

## Constitutional principles touched

- **P1 (the agent is the product):** advances — removes a dead surface (`proto/`) and keeps the sidecar a thin re-exposure of existing data rather than growing a second API stack.
- **P2 (near-zero node overhead):** advances — the sidecar runs per-node in the agent DaemonSet; refusing to grow it into a gRPC plugin host keeps the per-node footprint flat, and deleting `proto/` removes pressure to embed a second wire stack in the agent.
- **P4 (cost numbers are honest and traceable):** advances — this is the core of the decision: a dollar figure is never labeled with a window it does not cover; unanswerable queries are errors, not approximations.
- **P6 (one canonical representation):** advances — deletes the only out-of-tree duplicate of the `TrafficType` value list.
- **P9 (stdlib-first):** advances — explicitly declines `hashicorp/go-plugin` + `grpc` + `protobuf` until a demand-backed re-evaluation.
- **P11 (public contracts versioned and compatible):** neutral, with justification — `proto/` was never generated, imported, or spoken by any deployed component, so its removal breaks no consumer and needs no deprecation window. The `/cost/total` behavior change converts silently-wrong 200s into 400s: per P4 the old responses were defects, not contract; the JSON shapes are otherwise unchanged and `/costs` gains only an additive `window` field. The `/config` self-description version is bumped to 1.1.0.

## Re-evaluation triggers

- A customer or prospect asks to see Tollwing network costs inside OpenCost/Kubecost dashboards → revisit Alternative B (real `CustomCostSource` plugin, with the P9 dependency ADRs it needs).
- OpenCost ships an HTTP-native custom-cost ingestion contract (no go-plugin subprocess) → the existing endpoints may become adaptable cheaply.
- Tollwing adopts gRPC for any transport (e.g. agent→server) → write fresh protos generated in CI from the canonical enums; do not restore the deleted files.
- The Helm chart / publish-oss / image-name owners are ready to coordinate → execute the `opencost-plugin` → `cost-export` rename below.

## Related decisions

- [DEC-005](DEC-005-stdlib-first-dependencies.md) — the dependency bar that makes Alternative B an ADR-sized cost (refines).
- [DEC-007](DEC-007-canonical-traffic-type-literals-p6-ratchet.md) — the P6 ratchet the proto enum duplicate was quietly violating (advances).
- [DEC-011](DEC-011-float-cost-accumulation-round-at-emit.md) — prior P4 fix in the same metric family (`tollwing_cost_usd_total`); this decision fixes the consumer-side mislabel of those counters (depends on).

## References

- `opencost-plugin/main.go` — re-scoped component; window handling in `parseWindow`, `handleCostTotal`, `handleCosts`.
- `opencost-plugin/main_test.go` — regression tests for each original bug (mislabel, silent default, unencoded bounds).
- `opencost-plugin/README.md` — honest component description.
- `pkg/exporter/prometheus.go:388-393` — the cumulative `tollwing_cost_usd_total` counters agent-scrape mode sums.
- `pkg/api/server.go` (`parseTimeRange`) — upstream silent-default behavior that made forwarding malformed bounds a mislabel.
- Deleted: `proto/flow.proto`, `proto/cost.proto` (git history).
- OpenCost plugin contract: [opencost/opencost-plugins](https://github.com/opencost/opencost-plugins), [opencost.io/docs/integrations/plugins](https://opencost.io/docs/integrations/plugins/), [Introducing OpenCost Plugins](https://opencost.io/blog/introducing-opencost-plugins/).

## Notes

**Follow-ups owned by other workstreams (recorded here so they don't get lost):**

1. **Docs workstream:** `README.md` line 60/70 ("OpenCost-compatible plugin") and `ARCHITECTURE.md` line 1140 (`proto/`) / line 1185 ("OpenCost | Compatible Prometheus metrics") must be corrected. Wording that is now true: *"a standalone cost-export sidecar exposing Tollwing network costs as FOCUS-aligned JSON over HTTP"* — not "OpenCost plugin", not "OpenCost-compatible plugin". ("FOCUS-aligned" is accurate; "OpenCost" may only appear in the sense that the *differential demo* deploys OpenCost to compare against.)
2. **Deploy/tools owners:** coordinated rename `opencost-plugin/` → `cost-export/` touching `deploy/helm/tollwing-agent/values.yaml` (`opencostPlugin.*`, image `tollwing-opencost-plugin`), `deploy/helm/tollwing-agent/templates/daemonset.yaml`, and `tools/publish-oss/publish-oss.sh` `ASSET_DIRS`. Until then the directory name is a known, documented misnomer.
3. This ADR is **not yet in the index**; regenerate `decisions/README.md` with `go run ./tools/governance index` (index owner).
