# DEC-016 — Remove dormant cgroup-storage, sk-storage-iterator, and conntrack NAT machinery from the data plane

**Status:** ACCEPTED
**Date:** 2026-07-02
**Author(s):** Baris Erdem (with Claude Fable 5, eBPF data-plane audit workstream)
**Reviewer(s):** —

---

## Context

A data-plane audit found three subsystems in `pkg/ebpf` that looked like live features but did no useful work in any build, while two of them charged real per-packet kernel cost:

1. **CGRP_STORAGE cost accumulator — compiled out of every build, masked as a kernel limitation.** `bpf/maps.h` and `bpf/tollwing.bpf.c` guarded the `cgroup_cost_storage` map and its helpers with `#ifdef BPF_MAP_TYPE_CGRP_STORAGE`. That identifier is an **enum constant** in the generated `vmlinux.h`, never a preprocessor macro, so the `#ifdef` was false on every compile — the helpers were empty stubs everywhere. Userspace (`cgroup_reader.go:97`) then logged "cgroup_cost_storage map not available, cgroup reader disabled", reporting a code bug as a kernel capability gap. Compounding it: even had the guard worked, `update_cgroup_cost_tx/rx` had **no call sites** (only `cgroup_cost_new_conn` was called), and the feature probe `HaveCgroupStorageMap` probed `BPF_MAP_TYPE_CGROUP_STORAGE` (type 19, kernel 4.19) instead of `BPF_MAP_TYPE_CGRP_STORAGE` (type 32, kernel 6.3).
2. **sk-storage iterator — zero consumers.** `iter.bpf.c` (`SEC("iter/bpf_sk_storage_map")`), the `sk_cost_storage` map populated on every TCP establish, and the Go `Iterator`/`CgroupReader` types had no callers anywhere in the repo — `pkg/agent` never constructed them.
3. **Conntrack NAT resolution — per-packet work into a map nobody reads.** `fentry/nf_conntrack_confirm` (+ kprobe fallback) and the `SEC("netfilter")` kfunc program both populated `nat_mappings` on the packet path, with **incompatible key schemes** (an XOR-fold of the original tuple vs. an OR-composition that drops `dst_ip` entirely), and the kfunc program declared `bpf_skb_ct_lookup`/`bpf_ct_release` without ever calling them. No userspace code read `nat_mappings`. Pre-DNAT intent already comes from the two-phase capture ([DEC-003]), which is the primary mechanism; DEC-003 explicitly relegated conntrack to an optional augmentation — one that never materialized past writing into a dead map.

The forces: P1 says the agent is the product and must stay lean; P2 gives it a hard overhead budget — a netfilter hook and an fentry on the conntrack confirm path run per packet/per connection on every node in the fleet, spending cycles to produce nothing. Dead-but-plausible code is also an attribution hazard (P5): a future contributor could "wire up" `nat_mappings` and inherit two writers that disagree on the key.

## Decision

We will **remove** the dormant machinery rather than fix it:

- **C:** delete `cgroup_cost_storage` + `struct cgroup_cost` + helpers, `sk_cost_storage` + `struct sk_cost_meta` + `populate_sk_cost_meta`, `iter.bpf.c`, `nat_mappings` + `struct nat_mapping`, `conntrack_confirm_common` + both conntrack programs, and `conntrack_kfunc.bpf.c`.
- **Go:** delete `cgroup_reader.go`, `iterator.go` (and their tests), the `CgroupCostBPF`/`SkCostMeta` mirrors, the `HaveCgroupStorageMap`/`HaveNetfilterProg`/`HaveIterator` probes, the conntrack attach tiers in the loader, and the `NatMappings` map-size knob.
- **Probes:** `HaveTCX` now performs a real TCX link-create probe (ENODEV on a deliberately nonexistent ifindex ⇒ supported) instead of probing `SchedCLS`, which exists since kernel 4.1 and said "TCX supported" everywhere.

Resurrection path: everything removed is one `git log --diff-filter=D -- pkg/ebpf` away. A resurrected per-cgroup accumulator must (a) test the CGRP_STORAGE **map type at runtime** (probe map creation of type 32), never an `#ifdef` on a vmlinux enum, (b) ship with its userspace consumer in the same PR, and (c) come in through a feature proposal that answers the P1/P2 questions. A resurrected conntrack path must have a single canonical key scheme and a named consumer before the first hook attaches.

## Alternatives considered

### Alternative A — Fix the `#ifdef` and wire up consumers

Make the CGRP_STORAGE block compile (guard on a runtime probe / unconditional definition), call the tx/rx helpers from the byte-counting hooks, and plumb `CgroupReader`/`Iterator` into the agent.
**Why not:** That is building a new feature, not fixing a bug. Nothing consumes the output today — the flow → PID → cgroup → pod path already attributes correctly. Per P1/P2 a feature must justify its fleet-wide kernel cost through a proposal, not sneak in as a repair of code that never ran.

### Alternative B — Keep the code, gate it behind a build tag or config flag

**Why not:** The cost of dead code here is not only bytes: it is per-packet hooks that attach when "enabled", a map with two incompatible writers, and probes that lie about why things are off. A flag preserves all of those hazards and the maintenance burden, for a feature with no user.

### Alternative C — Remove only the conntrack programs, keep cgroup-storage/iterator "for later"

**Why not:** The cgroup-storage block is provably unreachable in every build and its Go reader logs a misleading capability warning on every start. "For later" is what the git history is for.

### Alternative D — Status quo

**Why not:** Every node pays for `nf_conntrack_confirm` tracing and a netfilter hook that write into a map nobody reads; operators read "map not available, cgroup reader disabled" and blame their kernels. Both violate the honesty the constitution demands of the agent (P2, P4).

## Consequences

### Positive

- Removes two per-packet/per-connection kernel code paths with zero output — direct P2 win on every node.
- Removes ~600 lines of C+Go that could mislead future work (incompatible `nat_mappings` keys, no-op helpers).
- Feature probes now tell the truth: no more "cgrp_storage" probe of the wrong map type, no more TCX-on-4.1 false positive.
- The BPF object shrinks (netfilter, iter, and two conntrack program sections gone).

### Negative

- If a real customer case ever needs conntrack-level NAT resolution (hairpin NAT, external LB) beyond the two-phase capture, it must be rebuilt — deliberately, with a consumer.
- Per-cgroup in-kernel accounting (a genuinely nice 6.3+ optimization) is no longer half-present as a starting point; it starts from a proposal instead.

### Neutral

- DEC-003's framing ("the optional `fentry/nf_conntrack_confirm` hook augments this in-kernel; it is not the primary mechanism") loses its optional augmentation; the primary mechanism is unchanged.
- DEC-002 listed `fentry/nf_conntrack_confirm` among "optional, probed" hooks; that list item is now historical.

## Constitutional principles touched

- **P1 (agent is the product):** advances — the agent sheds machinery that serves no SKU.
- **P2 (overhead budget):** advances — removes per-packet netfilter/fentry work and three maps' worth of kernel memory that produced nothing.
- **P3 (capability probing / graceful degradation):** advances — the probes that remain (`HaveTCX`, sk_storage) now test the actual capability they claim to test.
- **P5 (accurate attribution):** advances — eliminates a dead NAT map whose two writers disagreed on the key, waiting to corrupt a future consumer.

## Re-evaluation triggers

- A funded SKU or customer case requires per-cgroup in-kernel byte accounting (fleet minimum kernel ≥ 6.3) — resurrect the CGRP_STORAGE accumulator per the resurrection path above.
- The two-phase capture ([DEC-003]) is shown insufficient for a concrete traffic pattern (measured, not hypothesized — e.g. hairpin NAT through an external LB misattributing >1% of bytes on a real cluster) — resurrect conntrack resolution with one key scheme and a consumer.
- cilium/ebpf exposes a first-class TCX feature probe — replace the local ENODEV probe in `pkg/ebpf/features.go`.

## Related decisions

[DEC-002] (socket-level hook strategy — the optional conntrack hook it listed is removed; the core strategy is untouched), [DEC-003] (two-phase pre-DNAT capture — remains the sole NAT/intent mechanism, as it already was in practice).

## References

- `pkg/ebpf/bpf/tollwing.bpf.c` (removal markers citing this decision), `pkg/ebpf/bpf/maps.h`, `pkg/ebpf/features.go`, `pkg/ebpf/loader.go`.
- Deleted in this change: `pkg/ebpf/bpf/conntrack_kfunc.bpf.c`, `pkg/ebpf/bpf/iter.bpf.c`, `pkg/ebpf/cgroup_reader.go`, `pkg/ebpf/iterator.go` (+ tests).
- Audit trail: eBPF data-plane audit, 2026-07 (compiled-out features, dead per-packet machinery, wrong feature probes).

## Notes

The same audit also fixed adjacent counting bugs that did not warrant their own ADR: QUIC/UDP double counting (poller-side dedup on destination), lossy read-then-delete drains (now atomic lookup-and-delete), half-close undercounting (close accounting deferred to `TCP_CLOSE`), a UDP `connections`-map leak (cleaned via `cgroup/sock_release`), truthful drop instrumentation (kernel `drop_counters` map feeding `tollwing_ringbuf_drops_total` and the new `tollwing_map_update_drops_total`), and the `flow_aggregates` default sizing (16K → 128K to match `ARCHITECTURE.md` and the compiled object). Those are behavior corrections toward documented intent, with regression tests, not new decisions.
