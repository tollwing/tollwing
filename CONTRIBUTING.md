# Contributing to Tollwing

Thanks for contributing. Tollwing is an eBPF network-cost platform with a small, deliberate engineering culture — please take a few minutes with the governance docs before a non-trivial change.

## Read first

- **[`CONSTITUTION.md`](CONSTITUTION.md)** — twelve binding engineering/product principles (P1–P12). Code conforms to these or documents an exception.
- **[`OPEN-CORE.md`](OPEN-CORE.md)** — what is open source and what is Enterprise, and the commitments around that boundary. **[`GOVERNANCE.md`](GOVERNANCE.md)** — who decides what, and how the public repo relates to the private monorepo (it is generated — see "How your PR lands" below).
- **[`decisions/`](decisions/)** — why things are the way they are. Scan the index for ADRs that bind your area.
- **[`docs/governance/conventions.md`](docs/governance/conventions.md)** — the concrete Go style.
- **a GitHub issue** — propose new features here first; **[`docs/governance/compatibility.md`](docs/governance/compatibility.md)** governs changes to public contracts.
- **[`CLAUDE.md`](CLAUDE.md)** — the working protocol (the "before/during/after" checklist applies to humans too).

## Build and test

```sh
# Terraform cost estimator (cross-platform, CGO_ENABLED=0):
go build ./cmd/tollwing-terraform

# Agent (Linux + eBPF): compile the BPF objects first, then build on Linux:
make -f pkg/ebpf/bpf/Makefile bpf-all CLANG=clang LLVM_STRIP=llvm-strip
go build ./cmd/tollwing-agent

# Test (the race detector runs in CI):
go test ./pkg/...
go test -race -count=1 ./pkg/...

# Lint is `go vet` (no golangci-lint). Because go vet walks the go:embed of the
# compiled BPF objects, compile BPF first and vet as linux — same as CI:
GOOS=linux GOARCH=amd64 go vet ./...
```

## Before you open a PR

```sh
go run ./tools/governance scan     # no new blocking findings
go run ./tools/governance index    # only if you added/edited an ADR
```

The CI `governance` job will fail if the decision index is stale or there's a blocking constitutional violation. The [PR template](.github/PULL_REQUEST_TEMPLATE.md) asks which principles you touched and whether a decision was recorded — please fill it in.

## How your PR lands (the public repo is synced)

The public repo ([github.com/tollwing/tollwing](https://github.com/tollwing/tollwing)) is **generated from a private monorepo** by an allow-list publish script (see [`GOVERNANCE.md`](GOVERNANCE.md) and [DEC-013](decisions/DEC-013-open-core-repo-split-allow-list-boundary.md)). So a public PR does not land via the merge button. The flow, so nobody is surprised:

1. **Open your PR against the public repo.** Review happens there, on GitHub, in the open — CI, comments, iterations, all normal.
2. **On approval, the maintainer ports your commits into the private monorepo**, preserving your authorship: `git am` of your patches where they apply cleanly, or a `Co-authored-by:` trailer with your name and email where the change had to be adapted or squashed. Your `Signed-off-by:` travels with the commit.
3. **Your change lands back in the public repo with the next publish sync.** Your PR is then closed with a comment linking the sync commit that contains it. GitHub will show the PR as "closed", not "merged" — the code is merged; the button just can't say so.

If your change touches something that only exists in the private monorepo (the publish tooling itself, Enterprise code paths), the maintainer will say so on the PR and carry the private half.

## Sign-off required (Developer Certificate of Origin)

Every commit must be signed off:

```sh
git commit -s      # adds "Signed-off-by: Your Name <you@example.com>"
```

The sign-off certifies the [Developer Certificate of Origin 1.1](https://developercertificate.org/) — that you wrote the change or otherwise have the right to submit it under the project's license. It must carry your real name and a reachable email matching the commit author. No CLA and no copyright assignment: you keep your copyright; the DCO is a statement of provenance, which matters here because your commit is ported across two repositories (above) and ships in commercial builds (below).

PRs with unsigned commits will be asked to rebase with `git rebase --signoff` before they are ported.

## Commit conventions

Conventional Commits with a **package scope**:

```
feat(servicegraph): transitive cross-AZ attribution
fix(clickhouse): register database/sql driver
perf(dns): ring-bound eviction
docs(strategy): synthesize product directions
ci: …
```

- Types: `feat` · `fix` · `perf` · `refactor` · `docs` · `test` · `ci` · `chore`.
- Scope: a `pkg/` package name (`ebpf`, `dns`, `cost`, `classifier`, `servicegraph`, …), or `ci`/`deploy`.
- Cite a decision when a commit implements one: `feat(servicegraph): … (DEC-006)`.

## Adding a dependency

Stdlib-first (P9). A new third-party direct dependency needs an ADR justifying it against the stdlib — see [DEC-005](decisions/DEC-005-stdlib-first-dependencies.md). `slog`/`flag`/`testing`, not zap/cobra/testify.

## Recording a decision

If your change is architecturally consequential, cross-cutting, hard to reverse, or constrains future work, write an ADR: copy [`decisions/TEMPLATE.md`](decisions/TEMPLATE.md) to `DEC-NNN-{slug}.md`, fill in the **Alternatives considered** and **Constitutional principles touched** sections, and run `go run ./tools/governance index`. See [`decisions/README.md`](decisions/README.md) for when (and when not) to record.

## License

Inbound = outbound: by contributing, you agree your contributions are licensed under the project's [Apache 2.0](LICENSE) license, the same license you receive the code under. There is no CLA and no copyright assignment.

One disclosure, stated plainly because Apache-2.0 permits it and you should know before contributing: Tollwing is an open-core project, and your Apache-2.0 contribution to the agent may also be built into **Tollwing Enterprise** (the commercial control plane shares the agent and its packages). What is and stays open source — including the commitment that shipped free features never move behind the license — is written down in [`OPEN-CORE.md`](OPEN-CORE.md).

Report security issues privately — see [`SECURITY.md`](SECURITY.md).
