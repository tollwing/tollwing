# DEC-013 — Publish the open core as a generated public repo; define the boundary by allow-list

**Status:** ACCEPTED
**Date:** 2026-07-02
**Author(s):** Baris Erdem (with Claude Fable 5, supervising founder)

---

## Context

The pre-launch publish plan (`PUBLISH-PLAN.md`, an internal launch document held off-repo) recommended the opposite of what we did. Its analysis: the repo already implements open-core via `pkg/license` (offline Ed25519 licenses, community tier when unlicensed), so **ship the whole monorepo public under that license-gate** — one repo, Apache-2.0 core plus license-gated commercial packages — and explicitly "do NOT split the whole commercial surface — not worth the maintenance."

We split anyway. On 2026-06-19 (`cab34aa` and follow-ups), `tools/publish-oss/publish-oss.sh` was built and used to assemble a public tree from the monorepo — the exact Go dependency closure of the public binaries (`cmd/tollwing-agent`, `cmd/tollwing-terraform`, `test/sim/demo`) plus an explicit asset list, with a private-package deny pattern (`PRIVATE_RE`) asserted against the closure — and publish it to `github.com/tollwing/tollwing`. The public repo is live and has external users (stars, an external fork carrying an IPv6 branch).

This was a one-way door walked through without an ADR: the Apache-2.0 grant on everything published is irrevocable, and external users now depend on the public tree. Reversing a written recommendation is exactly case 3 of "when to record" (`decisions/README.md`), and a repo boundary is case 7 (hard to reverse). This ADR records the decision retroactively — the same debt-repayment the seed ADRs (DEC-002…005) performed — and, together with the new `OPEN-CORE.md`, fixes the boundary it created.

## Decision

We will:

1. **Keep one development tree** — the private monorepo — containing the agent, the Enterprise control plane, and internal strategy documents. The public repo is **generated**, never developed in place.
2. **Assemble the public tree by allow-list**, not deny-list: the Go dependency closure of the public roots, copied one package-directory level deep, plus an explicit `ASSET_DIRS`/`ROOT_FILES` list. `PRIVATE_RE` is asserted against the closure before anything is copied, so a private package reaching the closure fails the publish rather than leaking.
3. **Ship the public tree 100% Apache-2.0.** Enterprise-tagged files are dropped and the `!enterprise` build tag is stripped, so the public tree builds with no special tags and carries no license-gated source.
4. **Define the boundary twice, deliberately**: human-readable in [`OPEN-CORE.md`](../OPEN-CORE.md) (the contract, including the no-rug-pull commitment and the placement rule for new features) and mechanical in the publish script plus the public repo's own `oss-guard` CI job, which fails if a private package, binary, or Enterprise marker ever appears in the public tree. If they disagree, `OPEN-CORE.md` wins and the script has a bug.
5. **Verify every publish**: the assembled tree must build, vet, and pass the demo/sim suites standalone, and pass leak and secret gates, before `--push` is reachable.

The license-gate itself (DEC-012) survives — but as a product gate on private Enterprise code, not as a source boundary inside a public repo.

## Alternatives considered

### Alternative A — One public repo, license-gated features (the PUBLISH-PLAN recommendation)

Publish the entire monorepo; the free/paid split is enforced at runtime by `pkg/license`.
**Why not:** A repository whose `LICENSE` file says Apache-2.0 grants every reader the right to build, modify, and redistribute *everything in it* — including removing the gate. The "gate" would be a courtesy, not a boundary, and the entire commercial surface (CUR reconciliation, recommendations, remediation, multi-cluster) would be free software in fact regardless of what the pricing page said. Mixing per-package proprietary carve-outs into an Apache-labeled repo is legally murky for us and hostile to contributors, who could not tell what license their PR lands under. Finally, the monorepo carries strategy documents and unreleased product work that must not be public; publishing "everything" was never actually on the table once that was weighed.

### Alternative B — BSL headers on the crown-jewel packages only (PUBLISH-PLAN's optional hardening)

Same single repo, but `pkg/cost` reconciliation and GCP/Azure providers carry BSL headers.
**Why not:** Inherits Alternative A's mixed-license confusion while adding BSL's own complexity for users and distributors. A per-file boundary erodes under routine refactoring — moving a function across a package boundary becomes a licensing event nobody notices until it matters.

### Alternative C — Two independently developed repos

Develop the open agent in public, the Enterprise code separately.
**Why not:** Doubles the maintenance surface for a solo maintainer and lets the trees drift — the agent and the control plane share contracts (wire format, enums, rate cards) that the constitution requires to have one canonical representation (P6). Generation from one tree keeps a single source of truth while the public repo self-defends via `oss-guard`.

### Alternative D — Publish binaries only, no source

**Why not:** Contradicts the strategy (the deployed install base is the moat, and open source is how the agent earns installs) and destroys auditability: Tollwing asks customers to run a privileged eBPF agent on every node, and the credible answer to "what does it capture?" is *read the source* (P12). A closed agent forfeits the trust the product depends on (P4).

### Alternative E — Deny-list publish (copy everything, delete the private paths)

**Why not:** Fails open. A new private package leaks by default the day someone forgets to add it to the delete list. The allow-list fails closed: nothing publishes unless it is reachable from the public roots or explicitly listed, and the `PRIVATE_RE` assertion plus the public repo's `oss-guard` job catch drift from both sides.

## Consequences

### Positive

- The public tree is uniformly Apache-2.0 — a clean legal story for users and contributors, with no gated source to un-gate.
- Internal strategy, unreleased product work, and Enterprise source stay private by construction, not by discipline.
- The boundary is enforced from both sides (allow-list publish in the monorepo; `oss-guard` + secret scanning in the public repo's CI).
- The OSS story is small and coherent: the agent, standalone, is the product's free tier (P1), not a crippled build of something bigger.

### Negative

- **Contribution friction.** Public PRs cannot be merged with the merge button; they are reviewed on GitHub, ported into the monorepo preserving authorship, and land via the next publish. This is documented in `CONTRIBUTING.md` so nobody is surprised, but it is real friction and a real asymmetry.
- The public git history is publish commits, not the development history.
- The boundary needs maintenance: `PRIVATE_RE`, the asset lists, `//oss:strip` markers, and the drop lists must track the tree as it grows.
- The decision was executed ~2 weeks before it was recorded — process debt this ADR repays, and a failure mode to not repeat (the door was walked through before the alternatives were written down).

### Neutral

- ADRs that document Enterprise-only components (currently DEC-012) are excluded from the public decision log via `PRIVATE_ADRS`; the public index is regenerated per publish to reflect the public set. This ADR itself publishes — the split is not a secret, it is a disclosure.
- The community cluster-cap and license logic remain purely server-side; the public agent tree contains no license code at all.

## Constitutional principles touched

- **P1 (the agent is the product):** advances — the free/commercial boundary now *is* the agent/control-plane boundary; the split makes P1's architectural line a repository line.
- **P11 (public contracts):** advances — the public repository becomes a versioned public contract in its own right, with `OPEN-CORE.md` as its statement; boundary changes now require an ADR, and the no-rug-pull commitment is P11's spirit applied to the license.
- **P12 (capture minimum, protect it):** advances — the privileged agent's full source (including the BPF programs and their build inputs) is publicly auditable.
- **P9 (stdlib-first):** neutral — the publish verifies the OSS tree builds standalone under the same posture (it even drops a test-only transitive `testify` requirement to keep the DEC-005 gate clean).

## Re-evaluation triggers

- External contribution volume makes the port-by-hand PR flow a real bottleneck (multiple community PRs per week) — revisit developing the public tree in place with a private overlay, i.e. inverting the sync direction.
- A second maintainer joins (see `GOVERNANCE.md`) — the publish/push authority model needs restating.
- Boundary disputes recur — if free-vs-Enterprise placement is contested more than a couple of times per quarter, the placement rule in `OPEN-CORE.md` is too vague and needs tightening.
- Legal review contradicts the mixed-license analysis above, or the company adopts a hosted offering (which `OPEN-CORE.md` currently, truthfully, says does not exist).

## Related decisions

- DEC-012 — the offline license issuer this split protects; it gates the private Enterprise server, not any public source. (That ADR ships only in the private monorepo's decision log.)
- [DEC-001](DEC-001-adopt-constitution-and-governance.md) — the governance system; this ADR follows its retroactive-recording pattern for decisions that predate their write-up.
- [DEC-005](DEC-005-stdlib-first-dependencies.md) — the dependency posture the published tree is verified against.

## References

- `tools/publish-oss/publish-oss.sh` — `ROOTS`, `PRIVATE_RE`, `ASSET_DIRS`, `ROOT_FILES`, `PRIVATE_ADRS`, the verification gates, and `--push` (private monorepo).
- [`OPEN-CORE.md`](../OPEN-CORE.md) — the boundary contract this ADR anchors.
- [`GOVERNANCE.md`](../GOVERNANCE.md), [`CONTRIBUTING.md`](../CONTRIBUTING.md) — the generated-repo disclosure and the contributor flow.
- `PUBLISH-PLAN.md` — the internal launch document (off-repo) whose single-repo recommendation this decision reverses.
- Monorepo commits `cab34aa` (2026-06-19, split prep stages 1–3) through `fc77b5c` (leak/secret gates) — the execution this ADR records.

## Notes

The public repo already has organic signal (stars, an external fork with an IPv6 branch), which both validates the split and raises its stakes: the fork means external code now exists against the public tree, so the contribution flow in `CONTRIBUTING.md` (DCO, port-with-authorship) stops being theoretical. Left deliberately undecided: whether the public repo ever becomes the development tree (see re-evaluation triggers).
