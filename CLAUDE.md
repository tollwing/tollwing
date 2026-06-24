# Tollwing — Agent Operating Protocol

> ⚖️ **Read first, before significant work:** [`CONSTITUTION.md`](CONSTITUTION.md) — twelve binding principles (P1–P12).
> 📚 **Read second:** [`decisions/`](decisions/) — the decision log (ADRs). Scan the index for decisions that bind the area you're touching.
> 🔁 **These are living documents.** Keeping them current is part of the work, not a follow-up.

This file is the operating protocol for AI agents working in Tollwing (and a fast orientation for humans). Following it is how you stay aligned with the constitution; **not** following it is itself a violation of the "living documents discipline."

---

## What this project is

Tollwing is **eBPF-based network-cost attribution and optimization for Kubernetes**. A per-node eBPF agent attributes every byte to a pod/service, classifies it by cost type, and turns it into dollars; a control plane stores, aggregates, alerts, and recommends. See [`ARCHITECTURE.md`](ARCHITECTURE.md).

The north star (P1): **the agent is the product** — every feature is a SKU on top of one lean, fleet-deployed agent.

Layout: `cmd/<binary>/main.go` are thin wrappers; the work is in flat `pkg/<concern>` packages. Binaries: `tollwing-agent` (DaemonSet, linux+eBPF), `tollwing-server` (control plane), `tollwing-cli`, `-terraform`, `-mcp`, `-slack`, `-admission`. Governance tooling is `tools/governance` (run with `go run`, never shipped).

## Working commands

```sh
# Build the cross-platform tool (CGO_ENABLED=0):
go build ./cmd/tollwing-terraform

# The agent needs Linux + compiled BPF objects:
make -f pkg/ebpf/bpf/Makefile bpf-all CLANG=clang LLVM_STRIP=llvm-strip
go build ./cmd/tollwing-agent      # on Linux

# Test (race detector is on in CI):
go test ./pkg/...
go test -race -count=1 ./pkg/...

# Lint = go vet. NOTE: vet walks the go:embed of the compiled .bpf.o, so compile
# BPF first and vet as linux (this is what CI does):
GOOS=linux GOARCH=amd64 go vet ./...

# Governance:
go run ./tools/governance scan          # before opening a PR (warn-only)
go run ./tools/governance index         # after adding/editing an ADR
```

There is no `golangci-lint`; `go vet` + a `go mod tidy` drift check are the gate.

## The protocol

### Before work
1. Read `CONSTITUTION.md` end to end (mandatory the first time; refresh the relevant principles each session).
2. Scan the [decision index](decisions/README.md); read any ADR that binds your area (e.g. touching storage → read [DEC-004](decisions/DEC-004-clickhouse-forward-only-migrations.md); touching hooks → [DEC-002](decisions/DEC-002-socket-level-ebpf-hooks.md)/[DEC-003](decisions/DEC-003-two-phase-pre-dnat-capture.md)).
3. Note which principles your change touches.
4. For a **new feature or SKU**, write a proposal first (a GitHub issue) — it forces the P1/P2/P11/P12 questions before code exists.

### During work
- **Cite the principle** you're serving (or flexing) in code comments and the commit message, e.g.
  `// Per P5, classify from the pre-DNAT ClusterIP recovered in pkg/intent, not the backend pod IP.`
- When you hit a tension with a principle, **stop and choose**: revise the change, document an exception (write an ADR; cite it inline as `// Per DEC-NNN, …` — the scanner respects that), or propose an amendment.
- Obey the conventions in [`docs/governance/conventions.md`](docs/governance/conventions.md): `slog` (never `"log"`), stdlib `flag`/`testing`, `fmt.Errorf("…: %w")`, `Config`+`setDefaults()`, build tags, table-driven tests, and **derive enum strings from `TrafficType.String()` — never hardcode `"cross_az"`**.

### After work — checklist
- [ ] Did this warrant a decision (see "When to record" in [`decisions/README.md`](decisions/README.md))? If so, copy [`decisions/TEMPLATE.md`](decisions/TEMPLATE.md) → `DEC-NNN-{slug}.md` and fill in **Alternatives considered** + **Constitutional principles touched**.
- [ ] Regenerate the index: `go run ./tools/governance index` (commit `decisions/README.md` in the same PR).
- [ ] Updated any superseded ADR's status in place.
- [ ] `go run ./tools/governance scan` introduces **no new blocking findings** (and ideally no new warnings).
- [ ] Updated `ARCHITECTURE.md` / `docs/` if a subsystem's behavior changed; kept any `file:line` citation you invalidated accurate.
- [ ] Tests pass (`go test ./pkg/...`); safety-critical paths (P8) and new classification branches (P5) have tests.

## What NOT to do

- Don't add unbounded state, cross-node logic, or heavy compute to the agent (P1/P2).
- Don't add a third-party dependency without an ADR (P9).
- Don't hardcode an enum wire-string that `TrafficType.String()` already owns (P6).
- Don't edit/reorder a released migration or add a down-migration (P7).
- Don't make an automated infra change without an approval gate and a rollback path (P8).
- Don't let a displayed dollar figure be untraceable to `bytes × dated-rate` (P4).
- Don't break a public contract (API, CRD, proto, schema, CLI, metrics) without a version bump + deprecation + ADR (P11).
- Don't capture or log more than cost attribution needs (P12).
- Don't let governance docs drift from reality — fix them in the same PR.

## Pointers

| Want to… | Go to |
|---|---|
| Know the rules | [`CONSTITUTION.md`](CONSTITUTION.md) |
| See why a choice was made | [`decisions/`](decisions/) |
| Audit code against the rules | [`docs/governance/audit-playbook.md`](docs/governance/audit-playbook.md) |
| Match the code style | [`docs/governance/conventions.md`](docs/governance/conventions.md) |
| Evolve a public contract safely | [`docs/governance/compatibility.md`](docs/governance/compatibility.md) |
| Know what data may be captured | [`docs/governance/data-handling.md`](docs/governance/data-handling.md) |
| Propose a new feature | a GitHub issue |
| Understand the system | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
