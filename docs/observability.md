# Observability

**Status:** Active · **Implements:** [productionization-plan.md](productionization-plan.md) M3.2

## Endpoints

| Path | Pipeline | Purpose |
|---|---|---|
| `GET /health/live` | `:api` | Liveness. Process-only — 200 whenever the VM can route a request. The compose healthcheck and any orchestrator restart policy point here. |
| `GET /health/ready` | `:api` | Readiness. 200 when Postgres answers `SELECT 1` and (unless `READINESS_REQUIRE_UPSTREAMS=false`) every registered upstream is reachable; 503 + JSON detail otherwise. Point a load balancer / external monitor here. |
| `GET /health` | `:api` | Back-compat alias of `/health/live`. |
| `GET /metrics` | `:api` | Prometheus scrape (text `0.0.4`). Optionally gated by `METRICS_TOKEN` (`Authorization: Bearer <token>`); otherwise open — keep it on an internal network. |

`/metrics` and `/health*` are excluded from the prod `force_ssl` redirect so they
can be scraped/polled over plain HTTP inside the deployment network.

## Metrics

Defined in [`PhoenixElxirBeamWeb.Telemetry`](../lib/phoenix_elxir_beam_web/telemetry.ex),
fed by the `[:mcp, ...]` events from
[`PhoenixElxirBeam.MCP.Telemetry`](../lib/phoenix_elxir_beam/mcp/telemetry.ex).

| Series | Type | Labels | Meaning |
|---|---|---|---|
| `mcp_pipeline_run_stop_duration` | histogram | `phase`, `verdict` | plugin-chain phase latency (ms) + count |
| `mcp_plugin_run_stop_duration` | histogram | `plugin`, `phase`, `outcome` | per-plugin evaluation latency; `outcome` ∈ `ok\|timeout\|crash\|bad_return` |
| `mcp_upstream_request_stop_duration` | histogram | `transport`, `outcome` | upstream MCP server request latency; `outcome` ∈ `ok\|error` |
| `mcp_decision_count` | counter | `verdict`, `phase` | policy decisions |
| `mcp_alert_count` | counter | `key`, `severity` | operational alerts raised (see below) |
| `mcp_sessions_count` | gauge | — | live downstream MCP sessions |
| `mcp_holds_pending` | gauge | — | parked approval holds |
| `mcp_servers_count` / `mcp_servers_unreachable` | gauge | — | registered upstreams, live vs. failed |

Gauges refresh on the `:telemetry_poller` period (10s). The poller also runs the
readiness probe (disabled in `:test`).

## Alerts

`PhoenixElxirBeam.MCP.Alerts.emit/3` is the single alert path. Every alert:

1. writes a structured `mcp.alert <key> (<severity>): <detail>` error log line —
   ship these to a SIEM / Loki via the JSON console output (the app's
   `StructuredLogSink` plugin emits the same shape for policy events);
2. broadcasts to the `"mcp:alerts"` PubSub topic → the dashboard's amber banner;
3. increments `mcp_alert_count{key,severity}`.

There is **no built-in Alertmanager / webhook / email routing** — that was the
explicit M3.2 decision. Downstream routing is whatever consumes the logs or
scrapes `mcp_alert_count`. [`deploy/prometheus/alert.rules.yml`](../deploy/prometheus/alert.rules.yml)
turns the series into Prometheus alerts; wire Alertmanager to those if you want
paging.

Alert keys: `audit_integrity` (M2.3 chain check failed), `plugin_fail_open` (a
`fail_open` plugin errored and the call proceeded unchecked), `sidecar_circuit_open`
(a sidecar breaker tripped), `upstream_unreachable` (readiness probe transition).

## Running the stack

```bash
docker compose -f docker-compose.yml -f compose.observability.yml up -d
```

Adds `prometheus` (:9090, scrapes `app:4000/metrics`, loads the alert rules) and
`grafana` (:3000, Prometheus datasource + the **MCP Security Proxy** dashboard
pre-provisioned; set `GRAFANA_USER` / `GRAFANA_PASSWORD`). Already run a
Prometheus? Skip the overlay and add a scrape job for `app:4000/metrics` — see
[`deploy/prometheus/prometheus.yml`](../deploy/prometheus/prometheus.yml).

### Dashboard

[`deploy/grafana/provisioning/dashboards/mcp-security-proxy.json`](../deploy/grafana/provisioning/dashboards/mcp-security-proxy.json)
is provisioned automatically (file-backed, `allowUiUpdates: true` — edit it in
the Grafana UI, or edit the JSON and it reloads within 30s). 13 panels:
live-session / pending-hold / server-count stats, decision + alert rates,
pipeline / upstream / HTTP endpoint latency (p50/p95/p99), per-plugin failure
rate, upstream error rate, and BEAM VM memory + run-queue length — one panel
per series in the table above, plus the standard Phoenix/VM metrics. Verified
by actually provisioning it against a live Grafana 11.4.0 and querying
`GET /api/dashboards/uid/mcp-security-proxy` back.

### Logs (optional overlay)

```bash
docker compose -f docker-compose.yml -f compose.observability.yml -f compose.loki.yml up -d
```

Adds `loki` (:3100, filesystem storage, 7-day retention) and `promtail`
(discovers every container on the host via the Docker socket and ships
stdout/stderr to Loki, labeled `compose_service` / `compose_project` /
`container` — filter to the app with `{compose_service="app"}` in Grafana
Explore). A matching Loki datasource is provisioned into the same Grafana
whenever `compose.observability.yml` is up; it just errors on query until
this overlay is also running. See
[`deploy/loki/loki-config.yml`](../deploy/loki/loki-config.yml) and
[`deploy/promtail/promtail-config.yml`](../deploy/promtail/promtail-config.yml).
Targets a Linux Docker host (the container-log mount path differs on Docker
Desktop for Mac/Windows). This is log *shipping*, not the audit record — the
hash-chained `policy_events` table is (`docs/deployment.md#retention--backups`).

## Not covered here

Load/latency budget + the `mcp_pipeline_run_stop_duration` SLO is M3.3
(`docs/latency-budget.md`). Per-alert operator response is the M4.4 runbook.
Alertmanager routing (email/Slack/PagerDuty) remains out of scope by design —
see Alerts above.
