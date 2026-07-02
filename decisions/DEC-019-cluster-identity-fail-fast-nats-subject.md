# DEC-019 — Derive cluster identity from the kube-system UID and fail fast on invalid NATS subjects

**Status:** ACCEPTED
**Date:** 2026-07-02
**Author(s):** Baris Erdem (with Claude (Fable 5), agent-userspace workstream)
**Reviewer(s):** —

---

## Context

The agent ships flow batches to the control plane on the JetStream subject
`tollwing.flows.{cluster}.{node}` (`pkg/nats/publisher.go`). `-cluster`
defaulted to `""`, so a default deployment built the subject
`tollwing.flows..{node}`. NATS rejects subjects with empty tokens **per
publish**, and the agent's only reaction was a `slog.Warn` in the poll loop —
every flow batch from every node was dropped, forever, with nothing but a
repeating warning that nobody pages on. An audit flagged this as silent data
loss: the deployment looks healthy (metrics endpoint up, poll logs flowing)
while zero bytes reach the control plane.

Two forces shape the fix:

1. **Identity must exist and be valid before the first publish.** Anything
   discovered at publish time is too late — the failure mode is per-message
   and silent.
2. **Multi-cluster deployments need the identity to be unique and stable**
   across agent restarts and node churn, or the control plane double-counts
   or merges clusters.

## Decision

We will resolve the NATS identity **once, at agent startup**, and refuse to
start publishing with a broken one:

- If `-cluster` is set, it is validated as a NATS subject token and used as-is.
- If `-cluster` is empty and the Kubernetes informer is available, the agent
  derives the cluster identity from the **kube-system namespace UID**
  (`pkg/k8s.Informer.ClusterUID`): unique per cluster, constant for the
  cluster's lifetime (kube-system cannot be deleted or recreated), readable
  with the informer's existing RBAC-level access, and a valid subject token
  by construction (a UUID).
- If neither is available, `Run` returns a fatal error naming the flag to
  set. A crashloop with a clear message is the loud failure we want.
- Independently, `pkg/nats.NewPublisher` validates cluster/node tokens at
  construction (`ValidateSubjectToken`) so no caller can reconstruct the
  silent per-publish drop. Empty tokens, empty dot-delimited parts,
  whitespace/control characters, and the `*`/`>` wildcards are rejected.
  Interior dots remain legal: dotted hostnames (`ip-10-0-1-5.ec2.internal`)
  already publish fine because consumers subscribe with `tollwing.flows.>`
  and batch identity travels in the JSON body, so rejecting them would break
  working deployments.

## Alternatives considered

### Alternative A — Default the cluster name to a constant (e.g. `"default"`)

One-line fix; every deployment publishes immediately.
**Why not:** Two clusters shipped to one control plane with the default flag
silently merge into a single logical cluster — corrupting attribution is
worse than dropping data loudly. It also hides the misconfiguration instead
of surfacing it.

### Alternative B — Derive identity from IMDS (instance/account ID)

Works without Kubernetes API access.
**Why not:** IMDS identifies the *node/account*, not the *cluster*; two
clusters in one account would collide, and kind/on-prem clusters have no
IMDS at all. The kube-system UID is exactly cluster-scoped, and the informer
client is already there. IMDS remains a possible future fallback for
`-kubeconfig disable` deployments (see re-evaluation triggers).

### Alternative C — Sanitize instead of validate (replace bad characters, substitute a placeholder for empty)

Never fails; always publishes something.
**Why not:** Sanitizing an empty or mangled identity manufactures a fake one
— same merging hazard as Alternative A, plus the published identity no longer
matches what the operator configured, which makes debugging worse.

### Alternative D — Status quo (warn per publish)

**Why not:** That *is* the bug: an unbounded stream of warnings nobody
watches while 100% of flow data is dropped. Cost data that silently
evaporates violates the honesty principle (P4).

## Consequences

### Positive

- A default `-cluster` deployment now either derives a correct, stable
  identity or crashloops with an actionable message — no silent zero-data
  state.
- Multi-cluster identity is unique and stable without operator effort.
- The publisher-level validation protects future callers, not just the agent.

### Negative

- Deployments that today "run" with `-nats` set, an empty `-cluster`, and no
  Kubernetes API will now fail at startup. They were shipping nothing —
  but the failure becomes visible, which may surprise operators.
- The derived identity is a UUID, less human-readable than a chosen name in
  control-plane views. Operators who care set `-cluster`.

### Neutral

- Node identity keeps its hostname default; it is now validated the same way.
- `FlowBatch` (the JSON wire format) is unchanged; only pre-publish
  validation and the default cluster value are new (no P11 contract break).

## Constitutional principles touched

- **P4 (Cost numbers are honest and traceable):** advances — measured bytes
  can no longer silently vanish between agent and control plane; the failure
  mode is a loud startup error instead of dropped data.
- **P1 (The agent is the product):** neutral — identity resolution is one
  API GET at startup; no new state or background work in the DaemonSet.
- **P3 (Portable, capability-probing data plane):** neutral/advances — the
  degraded path (no K8s, no flag) refuses cleanly with a clear error rather
  than degrading dishonestly.
- **P11 (Public contracts):** neutral — subject scheme and batch format are
  unchanged; previously-dropped publishes cannot regress consumers.

## Re-evaluation triggers

- Support for `-kubeconfig disable` plus NATS publishing on non-K8s hosts
  becomes a real deployment target → add the IMDS-derived fallback
  (Alternative B) behind the same validation.
- The control plane grows a cluster-registration/handshake flow → identity
  should come from that handshake, not from local derivation.
- NATS subject-token rules change or the subject scheme gains tokens
  (`tollwing.flows.{cluster}.{node}.{...}`) → revisit `ValidateSubjectToken`
  and the interior-dot allowance.

## Related decisions

[DEC-010] — the flow batches whose delivery this decision protects feed the
control-plane cross-AZ dedup described there.

## References

- `pkg/nats/publisher.go` — `ValidateSubjectToken`, `PublisherConfig.validate`.
- `pkg/agent/config.go` — `resolveClusterName`, `resolveNodeName`.
- `pkg/k8s/informer.go` — `Informer.ClusterUID`.
- Audit finding: default `-cluster ""` → `tollwing.flows..host` → warn-and-drop
  forever (`pkg/nats/publisher.go:152`, `pkg/agent/agent.go:766` pre-fix).

## Notes

The shutdown-ordering fix (poller final flush before NATS drain) and the
per-slice EndpointSlice bookkeeping landed in the same change set; both are
bug fixes within existing decisions' boundaries and did not warrant ADRs.
