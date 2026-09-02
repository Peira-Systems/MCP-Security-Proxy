# Deployment guide

**Status:** Active · **Implements:** [productionization-plan.md](productionization-plan.md) M4.4

Single-node Docker Compose. Multi-node / k8s / HA are explicit non-goals
(ADR-0002) — restart survivability comes from Postgres, not from running two app
nodes.

## Topology

```
                         ┌────────────────────── host / private network ──────────────────────┐
   agents ──TLS──▶  reverse proxy ──▶  app (mcp-security-proxy)  ──▶  registered MCP servers
                    (Caddy / nginx)          │        ▲                   (http or stdio)
                                             ▼        │
                                        postgres:17   │  /metrics
                                        (pg_data vol) │
                                                      └──  prometheus + grafana  (compose.observability.yml)
   volumes: pg_data, audit_checkpoints  (audit checkpoint file is deliberately NOT on the DB volume)
```

- **The app must not be exposed directly.** Put a reverse proxy (or the cloud LB)
  in front for TLS. `/health/*` and `/metrics` are plain-HTTP on the private
  network (excluded from the prod `force_ssl` redirect).
- **Postgres is not published** beyond the compose network in a real deployment
  (drop the `ports:` mapping; it's there for local `psql`).
- **Registered MCP servers** sit on the private network or are reached over
  outbound TLS. A `localhost` MCP server on the host is reachable from the
  container via `host.docker.internal`.

## Prerequisites

- Docker + Docker Compose v2.
- A DNS name and TLS cert for the reverse proxy.
- `ghcr.io/<owner>/<repo>` pull access (or build locally).

## Configuration

Two kinds of config:

**`.env`** (non-secret — copy from `.env.example`): `PHX_HOST`, `ADMIN_EMAIL` /
`ADMIN_PASSWORD` (first-run seed only), `POSTGRES_USER` / `POSTGRES_DB`, ports,
`METRICS_TOKEN`, `READINESS_REQUIRE_UPSTREAMS`.

**`secrets/*.txt`** (Docker secret files, gitignored, mounted at `/run/secrets/`):

```bash
mkdir -p secrets
openssl rand -hex 64    > secrets/secret_key_base.txt        # or: mix phx.gen.secret
openssl rand -hex 32    > secrets/audit_checkpoint_key.txt   # STABLE across deploys
openssl rand -base64 24 > secrets/postgres_password.txt
```

- `audit_checkpoint_key.txt` must not change between deploys — a rotated key
  invalidates older audit checkpoints.
- `TAINT_MARKER_KEY` is optional; it's derived from `SECRET_KEY_BASE` if unset.
- To have Bandit terminate TLS itself instead of a reverse proxy, set
  `SSL_CERT_PATH` / `SSL_KEY_PATH` / `SSL_PORT`.

## Bring it up

```bash
docker compose up -d
```

`app` waits for `postgres` healthy, runs `Release.migrate()`, then starts.
Verify:

```bash
curl -fsS http://localhost:4000/health/live     # 200 always if the VM is up
curl -fsS http://localhost:4000/health/ready     # 200 iff DB + upstreams OK
```

Then sign in at `https://<host>/login` and follow [runbook.md](runbook.md).

## Observability

```bash
docker compose -f docker-compose.yml -f compose.observability.yml up -d
```

Adds Prometheus (:9090, scrapes `app:4000/metrics`, loads the alert rules) and
Grafana (:3000, the **MCP Security Proxy** dashboard pre-provisioned). Point
them at an existing stack instead by dropping the overlay and adding a scrape
job — see [observability.md](observability.md). Optionally add
`-f compose.loki.yml` for Loki + Promtail (ships every container's logs to
Loki, labeled by compose service — a lighter-weight alternative to your SIEM
for a single-node deploy). Either way, ship the app's JSON logs (`mcp.alert
…`, `mcp.audit.integrity …`, `StructuredLogSink` policy events) to your SIEM
for anything that needs to outlive the deployment.

## Sizing

Starting point for light-to-moderate traffic (tens of concurrent agent
sessions):

| Component | CPU | Memory | Notes |
|---|---|---|---|
| app | 1–2 vCPU | 512 MB–1 GB | BEAM; scales with concurrent sessions + sidecars. `POOL_SIZE` (default 10) bounds DB concurrency. |
| postgres | 1 vCPU | 512 MB–1 GB + disk for `pg_data` | The audit log (`policy_events`) grows unbounded — see retention below. |
| prometheus | 0.5 vCPU | 512 MB | 15-day retention in the overlay. |
| loki + promtail | 0.5 vCPU combined | 512 MB combined | optional (`compose.loki.yml`); 7-day retention, filesystem storage. |
| sidecars | 0.25 vCPU each | `as_mb` cap (prod: 512 MB) | one Python process for the injection scanner. |

The policy pipeline adds **< 1 ms p99**; end-to-end latency is dominated by the
upstream and per-request DB work — see [latency-budget.md](latency-budget.md).
Run `bench/load.exs` against a staging copy to size for your traffic.

## Retention & backups

- **Postgres:** back up `pg_data` (or `pg_dump`) on your normal schedule. This
  is the audit record — treat backups as evidence.
- **Audit checkpoint file** (`audit_checkpoints` volume): back it up *with* the
  DB and from a consistent point — it's the anchor for detecting a truncated
  log. Losing it weakens tamper-evidence but not the chain itself.
- **`policy_events` growth — opt-in retention.** Set `AUDIT_RETENTION_DAYS`
  (unset by default — the log grows unbounded until you do) to have
  `MCP.AuditRetention` prune rows older than that, on every `AuditIntegrity`
  cycle (default every 15 min). It only ever deletes rows *before* the row
  the newest signed checkpoint anchors on — `verify_chain` is anchor-aware
  (it trusts the oldest surviving row's own stored `prev_hash` rather than
  requiring true genesis), so a pruned table keeps verifying correctly, and
  pruning can never delete anything an ongoing check still needs. This is
  deletion, not archival — don't turn it on until Postgres backups and/or
  `StructuredLogSink` → SIEM shipping are actually in place to hold what
  gets pruned. See `MCP.AuditRetention` and `MCP.AuditIntegrity` moduledocs.

## Upgrades & rollback

See [ci-cd.md](ci-cd.md) and [runbook.md](runbook.md#deploy-a-new-version).
Tag `v*` → CI builds + pushes the image → on the host `docker compose pull app
&& up -d app`. Rollback is the same with the previous tag.
