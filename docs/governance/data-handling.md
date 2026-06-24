# Tollwing Data-Handling Policy

**Status:** v1.0.0 — adopted 2026-05-30 per [DEC-006](../../decisions/DEC-006-add-compatibility-and-privacy-principles.md)

Operationalizes **P12** (capture only what attribution needs, and protect it). A privileged eBPF agent on every node can see everything; this policy defines the line between what cost attribution *requires* and what it must *not* take. Complements [`../../SECURITY.md`](../../SECURITY.md) (the disclosure/hardening policy).

---

## What the agent captures (the attribution minimum)

| Data | Why attribution needs it | Sensitivity |
|---|---|---|
| Connection 4-tuple (src/dst IP:port) | Classify traffic type + resolve zone | Medium — reveals topology |
| Pre-DNAT destination (ClusterIP) | Service-level intent (P5) | Medium |
| Byte counts (tx/rx), connection counts | The quantity being costed (P4) | Low |
| `pid` → container → pod/namespace/labels | Attribute cost to a workload | Medium |
| Zone / node / cluster | Cross-AZ / cross-region classification | Low |
| Process name (`comm`) | Distinguish app vs. sidecar (P5 dedup) | Medium |

That is the whole list. If a feature needs something not here, it is a **new capture** (see below).

## What the agent does NOT capture by default

- **Packet payloads / message bodies.** Byte *counts*, never byte *contents*.
- **TLS-decrypted content.** Out of scope by default; a TLS tap is the canonical example of a capture that needs an ADR + privacy review.
- **Full command lines (`cmdline`) in multi-tenant mode.** `cmdline` can carry secrets/args; it is redacted when tenants share a view.
- **Secrets, env vars, file contents, request/response bodies.**

## Logging discipline

- Never log raw 4-tuples or `cmdline` at `info`. Sensitive fields go to `debug` only, and even then prefer identifiers (pod, namespace) over raw IPs/cmdlines.
- `slog` structured fields must not smuggle payloads or secrets.
- Metrics and API responses expose aggregates and identifiers, not raw connection contents.

## Multi-tenant mode

- **Redaction:** process names / cmdlines are redacted to the owning tenant's view; another tenant sees the workload identity, not its command line.
- **Isolation:** tenant scoping is enforced at the **query layer** — a query can only ever return the caller's tenant's flows. A path that can return another tenant's data is a **HIGH** P12 violation.
- Isolation is covered by tests; treat it like the safety guards under P8.

## Retention

(From `ARCHITECTURE.md` §12.4 — encrypted at rest throughout.)

| Tier | Retention | Notes |
|---|---|---|
| Flow-level records | 30 days (configurable) | The most granular / sensitive tier |
| Service/namespace aggregates | 1 year | De-identified down to workload, not connection |
| Billing reconciliation | 2 years | For compliance |

Shorter retention is always acceptable; lengthening the flow tier is a privacy decision (ADR).

## Adding a new data capture (the gate)

Capturing anything beyond the attribution minimum — a new field, a payload tap, deeper process introspection — requires **all** of:

- [ ] An **ADR** ([decisions/](../../decisions/)) stating what is captured, why attribution needs it, and why a less-invasive option won't do.
- [ ] A **privacy review**: sensitivity, default on/off (sensitive captures default **off**), redaction, retention, tenant isolation.
- [ ] If it changes a stored/wire schema, it's also a **P11** change → `CHANGELOG.md` + [`compatibility.md`](compatibility.md).
- [ ] Tests for redaction and isolation where applicable.

Default posture for any sensitive capture: **opt-in, off by default, documented.**

## See also

- [`../../CONSTITUTION.md`](../../CONSTITUTION.md) — P12 (and P4, the shared trust model).
- [`../../SECURITY.md`](../../SECURITY.md) — sensitive-data classification + agent hardening + disclosure.
- [`compatibility.md`](compatibility.md) — when a capture also changes a public schema.
