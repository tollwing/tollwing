# Tollwing Project Governance

**Status:** ACTIVE — adopted 2026-07-02
**Scope:** How decisions are made, who makes them, and how the public repository relates to the private monorepo. Engineering rules themselves live in [`CONSTITUTION.md`](CONSTITUTION.md); the commercial boundary lives in [`OPEN-CORE.md`](OPEN-CORE.md).

This document is deliberately honest about what Tollwing's governance is today — a solo-maintainer project attached to a company — rather than describing the governance of a project we might become. Out-of-date or aspirational governance is worse than none (see "Living documents discipline" in the constitution).

---

## Maintainer model

Tollwing has **one maintainer**: Baris Erdem (founder). This is a BDFL model — the maintainer has final say on everything, holds write access to both repositories, and runs the publish that produces the public tree.

That concentration is stated, not hidden, because it is the fact that everything below qualifies.

## Decision rights

Decisions split into two kinds with different rules:

- **Engineering decisions** are governed by the constitution and the decision log. [`CONSTITUTION.md`](CONSTITUTION.md) (P1–P12) binds all code — the maintainer's included; consequential choices are recorded as ADRs in [`decisions/`](decisions/) with alternatives considered; CI mechanically enforces the scannable subset. Anyone, contributor or maintainer, human or agent, may propose a constitutional amendment through the process in the constitution, and anyone may challenge a change by citing a principle. The maintainer arbitrates, but arbitrates *against the written rules*, in writing.
- **Product and commercial decisions** — what lands free versus Enterprise, pricing, roadmap, priorities — are the maintainer's alone, made as business judgments. They are informed by GitHub issues and discussions, and constrained by the public commitments in [`OPEN-CORE.md`](OPEN-CORE.md) (notably: shipped free features never move behind the license), but they are not community votes. Boundary-moving decisions are still recorded as ADRs (e.g. [DEC-013](decisions/DEC-013-open-core-repo-split-allow-list-boundary.md)).

## Adding a maintainer

There is no second maintainer today. One would be added like this:

1. **Track record first** — sustained, high-quality contributions over several months, demonstrated fluency with the constitution and the ADR discipline (governance here is load-bearing, not ceremony).
2. **Invitation by the existing maintainer(s)**, recorded in this file and announced in the repository.
3. **Scope is explicit at invitation**: a maintainer gets review and merge authority over the open-source tree and a voice in engineering decisions under the constitution. Authority over the commercial boundary, licensing, and the Enterprise codebase stays with the company and is not conferred by maintainership — saying this up front is fairer than implying otherwise.

If maintainership ever grows past two or three people, this document gets replaced with something with real structure (voting, areas of ownership), via an ADR.

## The public repository is generated

Transparency contributors are owed: **the public repo ([github.com/tollwing/tollwing](https://github.com/tollwing/tollwing)) is not developed in place.** It is assembled from a private monorepo by an allow-list publish script and pushed as sync commits. Concretely:

- Development happens in the private monorepo, which also contains the Enterprise source and internal strategy documents. The publish computes the Go dependency closure of the public binaries, copies exactly that plus an explicit asset list, verifies the result builds, vets, and passes its demo standalone, gates on leak and secret scans, and pushes.
- The public repo's own CI (`oss-guard`) independently fails if any private package or Enterprise marker ever appears, so the public tree self-defends rather than trusting the publish.
- Consequences you will notice: the public git history is publish commits, not the raw development history; pull requests are reviewed on GitHub but land via the sync (see [CONTRIBUTING.md](CONTRIBUTING.md) — authorship is preserved); a small number of ADRs that document Enterprise-only components exist in the private decision log and are excluded from the public one.

Why this model was chosen over the alternatives — and what it costs — is recorded in [DEC-013](decisions/DEC-013-open-core-repo-split-allow-list-boundary.md).

## Code of conduct

The project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md). Reports go to **conduct@tollwing.com** and are handled by the maintainer.

The honest limitation of a solo-maintainer project: there is no independent enforcement body, and a report about the maintainer's own conduct would be reviewed by its subject. If that is your situation, say so in the report and we will bring in a mutually acceptable third party to review it; if the project gains a second maintainer, CoC reports move to whichever maintainer is not involved.

## Security

Vulnerabilities go through the process in [`SECURITY.md`](SECURITY.md): GitHub private vulnerability reporting on the public repo, or **security@tollwing.com**. Never public issues.

## Changes to this document

Changes land by PR like any other doc. Changes that alter decision rights, the maintainer model, or the repo-sync model additionally require an ADR in [`decisions/`](decisions/).
