# DEC-002 — Attribute traffic at the socket layer (sock_ops + cgroup/connect + kprobes), not XDP/tc

**Status:** ACCEPTED
**Date:** 2026-05-30
**Author(s):** Baris Erdem (with Claude Opus 4.8, supervising founder)

---

## Context

Tollwing's job is to attribute every byte of network traffic to the process / pod / service that caused it, and to classify it for cost. The eBPF hook *layer* determines what's attributable: packet-layer hooks see bytes but not the owning process; socket-layer hooks see the process but fire less often. This is the foundational data-plane decision — everything downstream (classification, cost, the service graph) depends on the granularity it produces. (Retroactive: this choice was made early and is documented in `ARCHITECTURE.md` §2.1.)

## Decision

Attribute at the **socket layer**, using a layered, capability-probed hook strategy:

- `sock_ops` — connection lifecycle (establish/close), 4-tuple + socket cookie.
- `cgroup/connect4` / `connect6` — pre-DNAT destination capture (see [DEC-003]).
- `kprobe/tcp_sendmsg` + `kprobe/tcp_cleanup_rbuf` — per-socket byte counting.
- Optional, probed: `fentry/nf_conntrack_confirm`, `tracepoint/sock/inet_sock_set_state`.

Explicitly **do not** use XDP or tc/cls_bpf for attribution.

## Alternatives considered

### Alternative A — XDP

Packet-level hook at the driver/early path.
**Why not:** XDP fires before a packet is associated with a socket, so traffic cannot be attributed to a process — fatal for cost attribution. Copying full packets is also unacceptable overhead (violates **P2**).

### Alternative B — tc / cls_bpf

Traffic-control classifier hook.
**Why not:** Same attribution problem as XDP — no process context. Useful only for header inspection, which we don't need at this layer.

### Alternative C — Userspace pcap / conntrack polling

**Why not:** High overhead, no per-process tie without heavy correlation, and it can't recover pre-DNAT intent reliably. Defeats both **P2** (overhead) and **P5** (accuracy).

## Consequences

### Positive

- Per-process / per-pod / per-service attribution is possible because socket hooks carry `pid`/`cgroup`.
- Enables the pre-DNAT capture that recovers service intent ([DEC-003]).
- Low overhead: byte counting accumulates in-kernel and is polled (**P2**).

### Negative

- Requires cgroup v2 and kernel 5.8+ for the required hooks; more hook types to probe and degrade across (**P3**).

### Neutral

- Mirrors the hook model proven in the sibling `gecit` project.

## Constitutional principles touched

- **P5 (accurate attribution):** advances — the socket layer is the only place process identity and traffic meet.
- **P3 (capability-probing data plane):** advances — each hook is probed (`pkg/ebpf/features.go`) with a documented minimum kernel.
- **P1 (agent is the product):** advances — keeps the kernel vantage point lean; correlation happens in the control plane.
- **P2 (overhead budget):** advances — enables in-kernel aggregation instead of per-packet work.

## Re-evaluation triggers

- A kernel mechanism appears that attributes at the packet layer *with* process identity at acceptable overhead.
- XDP gains usable socket/cgroup context.

## Related decisions

[DEC-003] (the pre-DNAT capture built on these hooks). Constrained by [DEC-001].

## References

- `ARCHITECTURE.md` §2.1 (Hook Selection and Rationale), §2.4 (Performance Budget).
- `pkg/ebpf/features.go` (the probes for these hooks).

## Notes

The "NOT using XDP / NOT using tc" reasoning is also stated inline in `ARCHITECTURE.md`; this ADR makes it a citable decision.
