# DEC-003 — Recover service intent with two-phase pre-DNAT capture (the ClusterIP problem)

**Status:** ACCEPTED
**Date:** 2026-05-30
**Author(s):** Baris Erdem (with Claude Opus 4.8, supervising founder)

---

## Context

In Kubernetes, a client dials a Service's ClusterIP (e.g. `10.96.0.15:80`), but kube-proxy DNATs that to a backend pod IP (e.g. `10.244.3.7:8080`, possibly in another zone) *before* `sock_ops` observes the established connection. A tool that classifies from the post-DNAT pod IP loses the service-level intent and can misattribute cross-AZ cost. Recovering the original ClusterIP — the thing the client actually asked for — is the core differentiator versus tools like Kubecost. (Retroactive: `ARCHITECTURE.md` §2.2; implemented in `pkg/intent`.)

## Decision

Use a **two-phase capture**:

1. **Phase 1 — `cgroup/connect4` (pre-DNAT):** record `socket_cookie → original_dst (ClusterIP:port)` in a short-lived BPF map. This hook fires *before* kube-proxy DNAT.
2. **Phase 2 — `sock_ops` establish (post-DNAT):** observe the actual backend `dst` and look up the cookie to recover the original ClusterIP.

`pkg/intent` correlates the post-DNAT flow snapshots back to the pre-DNAT destination using the same 5-tuple + pid carried on the sock_ops ring-buffer events, recovering "service intent" with **no kernel change** beyond these two hooks. For service meshes, the same approach works because `cgroup/connect4` fires before the sidecar's iptables redirect; where an eBPF mesh (Cilium) is present, we detect it and read its identity maps.

## Alternatives considered

### Alternative A — Classify from the post-DNAT pod IP only

**Why not:** Loses service-level attribution entirely and produces wrong cross-AZ classification when the backend is in a different zone than the service abstraction implies. Directly violates **P5**.

### Alternative B — Parse conntrack NAT mappings from userspace

**Why not:** Race-prone (the mapping may be gone by the time userspace looks), higher overhead, and still reconstructs intent after the fact rather than capturing it at the source. The optional `fentry/nf_conntrack_confirm` hook augments this in-kernel; it is not the primary mechanism.

### Alternative C — Require a service mesh / Cilium for service identity

**Why not:** Not universal; would make the core feature conditional on the customer's mesh choice. We *use* mesh identity when present but must not *depend* on it.

## Consequences

### Positive

- Accurate service-level and cross-AZ attribution — the product's headline differentiator (**P5**).
- Works through mesh sidecars; degrades cleanly without a mesh.

### Negative

- Requires a short-lived `cookie_to_original_dst` map. Connections that `connect()` but never establish would leak entries, so the map is a bounded LRU with TTL — stale entries auto-evict (**P2**).

### Neutral

- Adds a second required hook (`cgroup/connect4`) to the probe/degrade matrix (**P3**).

## Constitutional principles touched

- **P5 (accurate attribution):** advances — this is the canonical implementation of "recover the truth when it's recoverable."
- **P1 (agent is the product):** advances — the kernel captures the fact; the control plane correlates.
- **P4 (honest cost):** advances — correct cross-AZ dollars depend on knowing the *real* backend zone behind the ClusterIP.
- **P2 (overhead budget):** neutral — the extra map is bounded with LRU + TTL.

## Re-evaluation triggers

- kube-proxy is replaced (cluster-wide) by a dataplane that preserves the ClusterIP to the socket layer.
- eBPF service meshes become universal enough that reading mesh identity is always available.

## Related decisions

Builds on [DEC-002] (socket-level hooks). Constrained by [DEC-001].

## References

- `ARCHITECTURE.md` §2.2 (The ClusterIP Problem and the Solution).
- `pkg/intent/cache.go:1-3` (package doc: correlating post-DNAT snapshots back to the pre-DNAT ClusterIP).

## Notes

The cookie→original_dst map's TTL/eviction is itself a P2 concern; if the establish-race rate ever grows, revisit the TTL rather than the map size.
