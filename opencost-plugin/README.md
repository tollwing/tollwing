# Tollwing cost export (formerly "OpenCost plugin")

A standalone HTTP sidecar that re-exposes Tollwing network-cost data as
FOCUS-aligned JSON, for external cost tooling to poll.

## What this is NOT (per DEC-017)

**This is not an OpenCost plugin, and OpenCost never calls it.** The real
OpenCost custom-cost integration (OpenCost ≥ 1.110, still current as of
2026-07) is a [hashicorp/go-plugin](https://github.com/hashicorp/go-plugin)
gRPC *subprocess* that implements the `CustomCostSource` interface — one
required method, `GetCustomCosts(CustomCostRequest) []CustomCostResponse`
over protobuf — discovered from `PLUGIN_EXECUTABLE_DIR`/`PLUGIN_CONFIG_DIR`
and launched by the OpenCost process itself. See the
[opencost-plugins developer guide](https://github.com/opencost/opencost-plugins)
and [opencost.io plugin docs](https://opencost.io/docs/integrations/plugins/).

This component implements none of that. It is a plain `net/http` server
with its own REST endpoints. Implementing the real contract would pull in
`hashicorp/go-plugin`, `grpc`, and `protobuf` — each needing a DEC-005/P9
dependency decision — and is deliberately deferred until a customer asks
for OpenCost ingestion (re-evaluation trigger in DEC-017).

## What it actually does

Two upstream modes:

- **Server mode** (default): queries `tollwing-server`'s REST API
  (`/api/v1/cost/breakdown`, `/api/v1/overview`) and reshapes the result.
- **Agent scrape mode** (`AGENT_METRICS_URL` set): scrapes an agent's
  Prometheus `/metrics` and sums the `tollwing_cost_usd_total` counters.
  Counters are **cumulative since agent start**; this mode cannot answer
  windowed queries and will refuse them (see below).

## Endpoints

| Endpoint | Description |
|---|---|
| `GET /costs?start=RFC3339&end=RFC3339` | FOCUS-aligned cost rows grouped by service. Defaults to the last 24h (UTC). Malformed bounds are rejected with `400`. The response echoes the exact `window` it covers. |
| `GET /cost/total?window=24h\|7d` | Total cost for the window (server mode). Windows parse as Go durations plus a `d` day suffix; an unparseable window is a `400`, never a silent default. In agent scrape mode a `window` parameter is a `400` and the response is labeled `cumulative_since_agent_start`. |
| `GET /config` | Self-description of this endpoint. |
| `GET /healthz` | Liveness. |

Per P4, the dollar returned is always the dollar of the window stated:
requests this component cannot answer honestly are errors, not
approximations.

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `LISTEN_ADDR` | `:9992` | HTTP listen address. |
| `TOLLWING_API` | `http://tollwing-server:8080` | tollwing-server base URL. |
| `AGENT_METRICS_URL` | *(unset)* | Enables agent scrape mode for `/cost/total`. |

## History

This directory was written as an aspirational "OpenCost plugin" before the
actual OpenCost plugin contract was checked. DEC-017 renamed its claims to
match reality and fixed a P4 violation (cumulative dollars labeled with a
requested window). The directory keeps its `opencost-plugin/` name for now
because the Helm chart, `tools/publish-oss`, and the container image name
reference it; renaming is a follow-up recorded in DEC-017.
