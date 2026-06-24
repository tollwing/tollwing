# DEC-009 — Define one canonical byte order for BPF-delivered IP fields (fix cross-AZ misclassification)

**Status:** ACCEPTED
**Date:** 2026-05-30
**Author(s):** Baris Erdem (with Claude Opus 4.8, supervising founder)

---

## Context

The L2b real-agent tier ([DEC-008](DEC-008-local-proof-simulation-suite.md)) ran the real eBPF agent against real kernel bytes for the first time — every prior check was build/vet-only — and immediately found a correctness bug: **every private/in-cluster flow on a little-endian host (all x86 and arm64) was misclassified as `internet_egress`** instead of `cross_az` / `same_zone` / `intra_node`. A client pod `10.244.2.2` dialing the echo ClusterIP `10.96.14.74` produced agent logs with `src 2.2.244.10 → dst 74.14.96.10` (both byte-reversed) and `traffic_type=internet_egress`.

Root cause: the codebase was **internally inconsistent about how a `uint32` IP field is decoded** — one concept with three conventions, a textbook P6 drift.

- The BPF C stores IPv4 addresses in **network byte order** and writes them into the map/event structs **without `ntohl`** (`pkg/ebpf/bpf/tollwing.bpf.c:145-146,395-396,469-470`: `skops->local_ip4`, `ctx->user_ip4`). Ports get `bpf_ntohl` (host order); byte counters are host order. The BPF side is correct (`bpf_htonl(0x7F000001)` vs network-order `local_ip4`).
- Userspace reads those structs **native-endian**: `binary.Read(…, binary.NativeEndian, …)` in `pkg/poller` and `pkg/ebpf/iterator.go`, and an `unsafe.Pointer` cast in the `pkg/ebpf` ringbuf reader. So on a little-endian host the `uint32` holds the network-order bytes reinterpreted as a little-endian integer — the address octets, reversed as a number.
- The decoders then disagreed:
  - `pkg/classifier.nboToAddr` and `pkg/ebpf` `ipPort`/`FormatIPPort` decoded the `uint32` as a **big-endian value** → reversed octets → the classifier saw a public-looking IP → `internet_egress`.
  - `pkg/agent.ipFromUint32` decoded **little-endian** → correct on LE hosts (so DNS / pod-IP / ClusterIP lookups happened to work).
  - `pkg/enricher.IsLoopback` compared the raw `uint32` against the big-endian constant `0x7f000001` → never matched the native-endian-loaded value, so userspace loopback dedup silently never fired.

The bytes themselves were captured correctly (`tollwing_tx_bytes_total` totals were right) — only the IP **decode** was wrong. The unit and simulation tests all missed it because their helpers built big-endian-**value** `uint32` constants (e.g. `FormatIPPort(0x0A000001)`, `ipToNBO`/`nboFromAddr`/`addrToNBO` via `binary.BigEndian`) that matched the big-endian decoder — self-consistent, but bypassing the real native-endian BPF load. Only L2b, with real kernel bytes, exercised the true path.

## Decision

We will fix the inconsistency at its root by defining **one canonical contract** and routing every decoder through it.

**The contract.** A `uint32` IP field delivered by the BPF data plane holds the address's **network-order bytes as loaded native-endian**. It is decoded back to a `netip.Addr` by writing those bytes out with the **same native endianness** and reading them as the dotted quad:

```go
var b [4]byte
binary.NativeEndian.PutUint32(b[:], v)
addr := netip.AddrFrom4(b)
```

Because the load and the decode use the *same* native endianness, the on-wire byte sequence round-trips on any host (little- or big-endian). The intermediate integer is **not** a meaningful value and must never be compared against a hardcoded host-order or big-endian constant.

**Where it lives.** `pkg/ebpf.AddrFromU32` is the single canonical decoder for the linux/BPF side; `ipPort`/`FormatIPPort` and `pkg/agent.ipFromUint32` delegate to it. `pkg/classifier.nboToAddr` and `pkg/enricher` (`IsLoopback`, now expressed via `netip.Addr.IsLoopback()` over 127/8) carry **documented cross-platform mirrors** of the same three lines, because those packages are cross-platform and must not import the linux-only `pkg/ebpf`. Each mirror cites this ADR and is told to stay in sync.

**Tests made faithful.** Every test/sim helper that fabricates a `uint32` IP now builds it the way the kernel delivers it — `binary.NativeEndian.Uint32(addr.As4())` — so the unit, L0, L1, and L2a tiers exercise the real decode contract instead of a self-consistent big-endian shortcut. New regression tests (`classifier.TestClassify_RealBPFByteOrder`, `ebpf.TestAddrFromU32_RealByteOrder`) assert that the in-cluster ClusterIP `10.96.14.74` decodes to `10.96.14.74` and classifies as in-cluster, not `internet_egress`.

**The BPF C is unchanged** — it was already correct. The bug and the fix are entirely in Go userspace.

## Alternatives considered

### Alternative A — Point-patch the one wrong decoder (`nboToAddr`)

Flip only the classifier's decoder and move on.
**Why not:** leaves three conventions for one concept. The next decoder added (or the next struct read) drifts again — which is exactly how this bug was born. It treats the symptom, not the P6 drift.

### Alternative B — Canonicalize on a big-endian network-order *value*

Byte-swap the IP fields at every BPF read site (`pkg/poller.sumPerCPU`/`pollQuic`, the iterator, every ringbuf event, the `original_dst` map) so that by the time anything sees the `uint32` it is a true big-endian network value; keep `nboToAddr`/`ipPort` and the `IsLoopback` constant and the existing big-endian tests as-is.
**Why not:** it scatters byte-swaps across many hot-path read sites; **missing any one silently reintroduces the bug** (the original sin), and it adds per-flow work on the agent's hot path (P2). The only upsides — keeping the existing tests and the loopback constant — are bookkeeping, not correctness, and don't outweigh the fragility.

### Alternative C — Centralize byte order in the addr decoders (chosen)

Keep every raw `uint32` exactly as loaded (opaque, never reinterpreted as an integer) and put the byte-order knowledge in the `uint32 → netip.Addr` decoders, using native-endian extraction that matches the native-endian load.
**Why chosen:** the contract lives in one place per consumer; a new BPF struct with an IP field "just works" as long as it decodes through a helper; no hot-path swaps (P2); and it matches the half of the code that already worked (`ipFromUint32`). It is the least fragile direction.

### Alternative D — A single shared cross-platform decode package

Put the canonical decoder in a new low-level cross-platform package imported by `pkg/ebpf`, `pkg/classifier`, `pkg/enricher`, and `pkg/agent` — one literal copy, the strictest P6 reading.
**Why not (now):** a new package and new import edges across the codebase for a three-line function, forced by the build-tag split (`pkg/ebpf`/`pkg/agent` are linux-only; `pkg/classifier`/`pkg/enricher` are cross-platform and cannot import them). We chose one canonical linux-side decoder plus two **documented** cross-platform mirrors that cite this ADR, guarded by a regression test that feeds the real native-endian representation (so any drift in any copy fails CI). If a fourth mirror ever appears, promote to this shared package (see re-evaluation triggers).

## Consequences

### Positive

- In-cluster traffic classifies correctly (`same_zone` / `cross_az` / `cross_region` / `intra_node`) on every little-endian host; agent logs and metrics show correct IPs.
- Cost becomes honest (P4): same-zone / intra-node traffic is no longer charged at the internet-egress per-GB rate it was being mislabeled into.
- The decode is endianness-portable — `binary.NativeEndian` makes it correct on big-endian hosts too (P3).
- The simulation now faithfully reproduces the BPF representation, so even the macOS-runnable L0 would catch a decode regression — the suite is strictly stronger.
- The contract is written down and cited at every decoder, so it cannot silently drift again.

### Negative

- The canonical decoder is mirrored in three places (one canonical + two documented cross-platform copies) rather than the structurally-impossible single copy. Mitigated by the inline "keep in sync" notes citing this ADR and the faithful regression tests.

### Neutral

- **No public-contract change (P11):** no wire/proto, ClickHouse schema, HTTP API, CLI flag, CRD, or metric *name* changes. Only the *values* of classification labels become correct — traffic that was reported as `internet_egress` now reports as `cross_az`/`same_zone`/`intra_node`. That is the intended bug fix, not a breaking change; it is recorded under **Fixed** in `CHANGELOG.md`.
- No BPF recompile and no storage migration are required.

## Constitutional principles touched

- **P5 (accurate attribution over convenient approximation):** advances — recovers the true in-cluster, cross-AZ classification instead of mislabeling all private traffic as internet egress.
- **P6 (one canonical representation; no drift across boundaries):** advances — replaces three divergent IP-decode conventions with one documented contract that every decoder cites. This bug *was* a P6 violation.
- **P4 (cost numbers are honest and traceable):** advances — cost now attaches to the correct traffic type; free same-zone/intra-node bytes are no longer billed at the internet-egress rate.
- **P3 (portable, capability-probing data plane):** advances — the decode is now endianness-portable via `binary.NativeEndian` rather than a hardcoded little-endian shift.
- **P2 (near-zero node overhead):** neutral/advances — the chosen approach adds no per-flow work on the agent hot path (no byte-swaps at read sites).
- **P11 (public contracts versioned and compatible):** neutral — no public contract changes; label values become correct. Recorded in `CHANGELOG.md`.

## Re-evaluation triggers

- A **fourth** cross-platform mirror of the decoder is needed → promote the contract to a single shared package (Alternative D).
- A **big-endian** deployment target is actually supported → add a CI check that the `NativeEndian` round-trip holds on a BE host (the contract is designed for it but is currently only exercised on LE).
- The ringbuf reader or the poller switches decode strategy (e.g. an explicit `binary.BigEndian` read, or a generated decoder) → re-verify that IP fields still arrive as native-endian-loaded network bytes.

## Related decisions

- [DEC-008](DEC-008-local-proof-simulation-suite.md) — the simulation suite whose L2b real-agent tier found this; this is L2b's headline finding.
- [DEC-002](DEC-002-socket-level-ebpf-hooks.md) / [DEC-003](DEC-003-two-phase-pre-dnat-capture.md) — the socket-level hooks and two-phase capture that produce these IP fields.
- [DEC-007](DEC-007-canonical-traffic-type-literals-p6-ratchet.md) — single-sourced enum literals; the same P6 "no drift" family as this fix.

## References

- `pkg/ebpf/maps.go` — `AddrFromU32` (canonical decoder), `ipPort`, `FormatIPPort`.
- `pkg/classifier/traffic.go` — `nboToAddr` (cross-platform mirror); `FlowInfo.SrcIP/DstIP` field contract.
- `pkg/agent/agent.go` — `ipFromUint32` (delegates to `bpf.AddrFromU32`).
- `pkg/enricher/sidecar.go` — `IsLoopback` (native decode + `netip.Addr.IsLoopback()`).
- `pkg/ebpf/bpf/tollwing.bpf.c:145-152,180-181` — BPF stores network byte order and matches loopback via `bpf_htonl` (already correct; unchanged).
- Regression tests: `pkg/classifier/classifier_test.go` `TestClassify_RealBPFByteOrder`; `pkg/ebpf/maps_test.go` `TestAddrFromU32_RealByteOrder`.
- `pkg/poller/poller.go`, `pkg/ebpf/iterator.go`, `pkg/ebpf/loader.go` (`unsafe.Pointer` ringbuf decode) — the native-endian load sites the contract is defined against.

## Notes

The deeper lesson for the suite (DEC-008): a differential harness only catches what its *inputs* faithfully reproduce. The sim ran the real classifier but fed it big-endian-value IPs, so it was blind to a decode bug for the same reason the unit tests were. Building sim/test IP inputs as `binary.NativeEndian.Uint32(addr.As4())` — exactly what `binary.Read` does to the kernel's bytes — closes that gap; only the real-kernel L2b tier could have closed it otherwise.
