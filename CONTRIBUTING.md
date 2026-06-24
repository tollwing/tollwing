# Contributing to Tollwing

Thanks for contributing. Tollwing is an eBPF network-cost platform with a small, deliberate engineering culture — please take a few minutes with the governance docs before a non-trivial change.

## Read first

- **[`CONSTITUTION.md`](CONSTITUTION.md)** — twelve binding engineering/product principles (P1–P12). Code conforms to these or documents an exception.
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

By contributing, you agree your contributions are licensed under the project's [Apache 2.0](LICENSE) license. Report security issues privately — see [`SECURITY.md`](SECURITY.md).
