# Security Policy

Tollwing runs a privileged eBPF agent on every node and handles sensitive cost and topology data. We take its security posture seriously.

## Reporting a vulnerability

Please report security issues **privately**, not via public GitHub issues:

- Preferred: **GitHub private vulnerability reporting** — [Security → "Report a vulnerability"](https://github.com/tollwing/tollwing/security/advisories/new) on the public repo.
- Or email **security@tollwing.com** with subject `Tollwing security: <short title>`.
- Include affected component/version, reproduction steps, and impact.
- We aim to acknowledge within 3 business days and to coordinate a fix and disclosure timeline with you.

Please give us reasonable time to remediate before any public disclosure.

## Supported versions

Tollwing is pre-1.0 and evolving. Security fixes target the `main` branch and the latest tagged release. Pin a release and watch for advisories.

## Sensitive data Tollwing handles

(See [`ARCHITECTURE.md`](ARCHITECTURE.md) §12 for the full model.)

| Data | Sensitivity | Handling |
|---|---|---|
| Connection 4-tuples / IPs | Medium | Reveal topology. Restrict API access; encrypt at rest. |
| Process names / cmdlines | Medium | May reveal architecture. Redact in multi-tenant mode. |
| Cloud billing data | High | Account-level cost data. Strict RBAC. |
| Cloud API credentials | Critical | Use workload identity / IAM roles — never static keys. |
| eBPF programs | Low | Open source; embedded in the binary, not loaded from disk at runtime. |

## Agent hardening

The agent is privileged by necessity (it loads eBPF), so it is scoped tightly:

- Only `CAP_BPF` + `CAP_SYS_ADMIN` (for cgroup attachment); drop everything else. No write access to any workload resource.
- Read-only root filesystem; seccomp profile; no egress except to the control plane (NetworkPolicy).
- BPF objects are compiled, committed, and `go:embed`-ed into the binary — not fetched or compiled at runtime.
- RBAC: the agent ServiceAccount may only `get/list/watch` pods, services, endpoints, nodes, namespaces.

## Scope

This policy covers the open-source Tollwing agent and tooling, and also the Tollwing Enterprise components (control-plane server, CLI), whose source lives in the private monorepo (see [`OPEN-CORE.md`](OPEN-CORE.md)) — report Enterprise issues through the same channels. Issues in third-party dependencies (e.g. `cilium/ebpf`, `clickhouse-go`, cloud SDKs) should also be reported to their upstreams.
