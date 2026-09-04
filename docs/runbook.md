# Operator runbook

**Status:** Active · **Implements:** [productionization-plan.md](productionization-plan.md) M4.4

Day-to-day operation and incident response for the MCP Security Proxy. Assumes
the deployment in [deployment.md](deployment.md) is up.

## Contents

- [First-run setup](#first-run-setup)
- [Register an MCP server](#register-an-mcp-server)
- [Classify tools](#classify-tools)
- [Issue / revoke an agent key](#issue--revoke-an-agent-key)
- [Change policy at runtime](#change-policy-at-runtime)
- [Responding to alerts](#responding-to-alerts)
- [Investigate an audit-chain failure](#investigate-an-audit-chain-failure)
- [Deploy a new version](#deploy-a-new-version)
- [Roll back](#roll-back)

## First-run setup

1. Deploy per [deployment.md](deployment.md). `ADMIN_EMAIL` / `ADMIN_PASSWORD`
   in `.env` seed an admin **on every boot, unless that email already has an
   account** — existing accounts (including a renamed/demoted seed admin) are
   never modified.
2. Sign in at `https://<host>/login`. Change the password (Users panel), and
   create per-person accounts — `viewer` for read-only, `operator` for policy
   changes, `admin` for user + key management.
3. Confirm `/health/ready` returns `200` and `/metrics` scrapes (from the
   Prometheus host only — it may require `METRICS_TOKEN`).

## Register an MCP server

Dashboard → **Servers** → *Register*. Give a name and either a base URL
(`:http`) or a command (`:stdio`). The proxy does a live `initialize` +
`tools/list` handshake; tools appear **unclassified**.

- An `:http` upstream must be reachable from the proxy container. A `localhost`
  URL on the host is reachable via `host.docker.internal` (the compose file
  wires `MCP_HOST_LOOPBACK_ALIAS`).
- Registration is persisted; the server is re-handshaked on every proxy restart.
  An upstream that's unreachable at boot is logged and skipped (the record is
  kept) and shows as unreachable on `/health/ready`.
- Optional per-server **Timeout (ms)** and **Skip TLS verify** fields override the
  proxy-wide defaults for just that server — leave both blank to inherit them.
  Skip TLS verify only for a self-signed dev/test upstream you trust.

## Classify tools

With default-deny on (prod ships `UnclassifiedGuard` in `hold` mode), **calls to
an unclassified tool are parked** until you tag it.

Dashboard → expand the server → per tool, toggle **sensitive read** /
**network egress**. Where the name/description heuristics have a suggestion,
an **apply suggested** button assigns them in one click. Every tag change is
written to the audit chain.

- `:sensitive_read` — the tool returns credentials, config, or private data.
- `:network_egress` — the tool sends data somewhere you can't see.

A tool that is neither (a pure computation, a read of non-sensitive data) can be
left with an explicit empty classification by toggling a tag on then off, or by
switching `UnclassifiedGuard` to `off` once curation is done (config change,
redeploy — or a runtime plugin toggle, below).

## Issue / revoke an agent key

Dashboard → **Client keys** (admin). *Issue* takes an `agent_id` and a scope
(`all_servers`, or specific servers). **The token is shown once.** Hand it to
the agent as `Authorization: Bearer mcpk_<id>.<secret>`.

*Revoke* takes effect on the agent's next request (mid-session too).

## Change policy at runtime

Dashboard → **Plugins** (operator). Enable / disable / reorder plugins without a
redeploy; state persists across restarts. Each change is audited and appears in
**Policy changes** with a one-click **revert**.

`RuleEngine` rule edits and `UnclassifiedGuard` mode currently need a config
change + redeploy.

## Responding to alerts

Alerts show as a red/amber banner on the dashboard and as `mcp.alert <key>`
error lines in the logs (ship these to your SIEM). If Prometheus + the alert
rules ([deploy/prometheus/alert.rules.yml](../deploy/prometheus/alert.rules.yml))
are wired, they also page.

| Alert `key` | Meaning | Do this |
|---|---|---|
| `audit_integrity` | the audit hash chain failed verification | **Treat as an incident.** See [below](#investigate-an-audit-chain-failure). |
| `sidecar_provenance` | a sidecar plugin's code/manifest digest ≠ its pin | The sidecar is **down**. Confirm the change was intentional (a deploy). If yes, recompute the pin (command in `config/prod.exs`) and redeploy. If no — the plugin binary/script changed unexpectedly — isolate the host. |
| `sidecar_circuit_open` | a sidecar failed 5× in a row; breaker tripped | Check the sidecar's stderr in the app logs. Usually a crash or a dependency issue. The breaker half-opens after 30 s; a persistent failure means the plugin is effectively off — decide whether to run degraded or stop traffic. |
| `plugin_fail_open` | a `fail_open` plugin errored and the call proceeded **without its check** | A coverage gap occurred. Check which plugin and why (log line has the detail). Fix the plugin; consider `fail_closed` if the check is load-bearing. |
| `upstream_unreachable` | a registered upstream failed the readiness probe | Check the upstream. `/health/ready` is `503` while any upstream is down (set `READINESS_REQUIRE_UPSTREAMS=false` to make it advisory). Remove the server registration if it's gone for good. |

Other Prometheus-only alerts: `ProxyDown` (scrape failing), `PluginErrorsElevated`,
`UpstreamErrorRateHigh`, `PipelineLatencyHigh` (see [latency-budget.md](latency-budget.md)),
`SessionTableGrowth`.

## Investigate an audit-chain failure

An `audit_integrity` alert means `EventLog.verify_chain/0` found a broken link,
**or** the live head disagrees with the newest off-DB checkpoint (a truncated
log that still verifies internally).

1. **Do not restart the app** — capture state first.
2. Dashboard → **verify audit chain** button, or in a release console:
   ```
   bin/phoenix_elxir_beam eval 'PhoenixElxirBeam.MCP.AuditIntegrity.check_now()'
   ```
   The detail says whether it's a broken row (`row <id> at <time>`) or a
   truncation (`log has N rows; checkpoint recorded M`).
3. **Truncation** — rows were deleted. Compare `policy_events` row count and
   max `id` against the checkpoint file (`AUDIT_CHECKPOINT_PATH`, on its own
   volume). Restore Postgres from a backup taken before the gap; the checkpoint
   file is the anchor for what "before the gap" means.
4. **Broken row** — a row was altered. `EventLog.verify_chain/0` names the first
   bad row; everything after it is suspect. Preserve the DB, restore from
   backup, and investigate how a write bypassed `PolicyEngine` (the only
   sanctioned writer).
5. Rotate `AUDIT_CHECKPOINT_KEY` only if you believe it leaked — a rotation
   invalidates older checkpoints.

## Deploy a new version

See [ci-cd.md](ci-cd.md). Short version, on the host:

```bash
# docker-compose.yml points `app` at artifact-keeper.peirasystems.com/mcp-security-proxy:<new-tag>
docker compose pull app
docker compose up -d app
```

`docker-entrypoint.sh` runs migrations before `start`. Brief downtime is
expected (stop → migrate → start) — single-node, no rolling deploy.

## Roll back

```bash
# point `app` back at the previous tag, then:
docker compose pull app
docker compose up -d app
```

If a migration must be undone, do it **before** starting the older image:

```bash
docker compose run --rm app /app/bin/phoenix_elxir_beam eval \
  'PhoenixElxirBeam.Release.rollback(PhoenixElxirBeam.Repo, <version>)'
```

Keep migrations backward-compatible with the previous image where possible to
avoid this.
