# Tollwing Engineering Conventions

**Status:** v1.0.0 — adopted 2026-05-30 per [DEC-001](../../decisions/DEC-001-adopt-constitution-and-governance.md)

The concrete Go conventions Tollwing already follows, written down so they're enforceable and inheritable. These are the *how*; [`CONSTITUTION.md`](../../CONSTITUTION.md) is the *why*. Where a convention implements a principle, it's tagged (e.g. **[P9]**).

---

## Language and dependencies — **[P9]**

- **Go**, module `go 1.24.1` (CI pins `1.24`). C for eBPF (CO-RE).
- **Stdlib-first.** Logging is `log/slog`; flags are `flag`; tests are `testing`. No cobra/viper, testify, zap, or logrus.
- A new third-party direct dependency requires an ADR ([DEC-005](../../decisions/DEC-005-stdlib-first-dependencies.md)). Grandfathered load-bearing deps: `cilium/ebpf`, `clickhouse-go`, `aws-sdk-go-v2`, `client-go`, `nats.go`, `golang.org/x/net`.

## Logging

- `log/slog` everywhere — structured key/value: `log.Info("migration applied", "version", m.Version, "description", m.Description)`.
- Pass a `*slog.Logger` (or a level) through `Config`; don't reach for a package global.
- Level from a flag (`-debug` → `slog.LevelDebug`); JSON output behind a flag for production.

## Errors

- Wrap with context and `%w`: `fmt.Errorf("migration v%d (%s): %w", m.Version, m.Description, err)`. ~248 sites do this.
- Check sentinels with `errors.Is`; never compare error strings.
- Errors carry the operation, not just the cause — a reader should know *what* failed from the message.

## Configuration idiom

- A package's public entry point takes a `Config` struct with a private `setDefaults()` method that fills zero values:

  ```go
  func (o *AttributeOpts) setDefaults() {
      if o.MaxIterations <= 0 { o.MaxIterations = 100 }
      if o.Epsilon <= 0 { o.Epsilon = 1e-9 }
      if o.TopN == 0 { o.TopN = 10 }
  }
  ```

  (See `pkg/servicegraph/attribution.go`, `pkg/dns`, `pkg/ebpf`.) Defaults live in code, documented on the field.

## Build-tag discipline — **[P3]**

- The whole data plane is `//go:build linux` (agent, ebpf, dns, poller, enricher, exporter, intent-adjacent, spot). The server, API, CLI, and analysis packages are cross-platform.
- Cross-platform binaries build `CGO_ENABLED=0`.
- Compiled per-arch `.bpf.o` objects are committed and `go:embed`-ed (`pkg/ebpf/amd64.go`, `arm64.go`); `go vet ./...` and the build require a prior `make -f pkg/ebpf/bpf/Makefile bpf-all`.

## Testing

- Stdlib `testing`, **table-driven**, `t.Fatalf`/`t.Errorf` with descriptive messages. No assertion library.
- The race detector is part of CI: `go test -race -count=1 ./pkg/...`.
- **Benchmarks** for hot paths (`classifier`, `cost`, `dns`, `poller`) — `go test -bench=. -benchmem` — because **[P2]** is a measurable budget.
- Integration / chaos / load tests are build-tag-gated (`pkg/servicegraph/integration_test.go`, `pkg/api/chaos_test.go`, `load_test.go`).
- Safety-critical paths (remediation approval/rollback, the TAR guard) must have tests **[P8]**.

## Canonical representations — **[P6]**

- An enum is defined once with a `String()` method (`classifier.TrafficType`), and the ClickHouse enum, Prometheus labels, the service graph, and API responses all derive from it. Never re-type a wire-string literal that an enum owns.

## Storage — **[P7]**

- ClickHouse migrations are forward-only, additive, idempotent (`IF [NOT] EXISTS`), tracked in `schema_migrations`. No down-migrations. See [DEC-004](../../decisions/DEC-004-clickhouse-forward-only-migrations.md).

## Package layout

- `cmd/<binary>/main.go` is a thin wrapper: parse flags, build a `Config`, delegate to a `pkg`.
- `pkg/<concern>` is flat, one concern per package, with a package-doc comment on the first line of the first file. **No `doc.go` files.**
- Lifecycle is `Start(ctx)` / `Stop()`; concurrency via `sync.RWMutex` + `context.Context` cancellation + `sync.WaitGroup`.

## Commits — Conventional Commits with package scopes

The history is standardizing on `type(scope): summary`, where **scope is the package/subsystem**:

```
feat(servicegraph): transitive cross-AZ attribution
fix(clickhouse): register database/sql driver
docs(strategy): synthesis of product directions
ci: fix lint + pre-existing test bugs
```

- Types: `feat` · `fix` · `perf` · `refactor` · `docs` · `test` · `ci` · `chore`.
- Scope: a `pkg/` package name (`ebpf`, `dns`, `cost`, `servicegraph`, …) or `ci`/`deploy`.
- When a commit implements or exercises a decision, cite it: `feat(servicegraph): … (DEC-006)`.
- The em-dash elaboration style after the subject is welcome; honesty/safety framing ("honest", "OOM-aware") is a feature of this codebase's commit voice — keep it.

## See also

- [`../../CONSTITUTION.md`](../../CONSTITUTION.md) · [`audit-playbook.md`](audit-playbook.md) · [`../../CLAUDE.md`](../../CLAUDE.md) · [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md)
