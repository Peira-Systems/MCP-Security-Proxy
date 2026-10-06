# MCP Security Proxy — Product Guide

**Status:** Active · **Audience:** operators, platform engineers, and agent developers
deploying or integrating with the proxy.

This is the end-to-end guide: what the product is, how to deploy it, how to
configure it, and how to use it day to day. It is the entry point — deeper
topics link out to the focused documents in [`docs/`](.).

| I want to… | Go to |
|---|---|
| Understand what this is and how it works | [Overview](#1-overview) · [Architecture](#2-architecture) |
| Run it locally | [Quick start](#3-quick-start-local) |
| Deploy it for real | [Deployment](#4-deployment) · full detail in [deployment.md](deployment.md) |
| Configure it | [Configuration reference](#5-configuration-reference) |
| Connect an agent / MCP client | [Using the proxy](#6-using-the-proxy) |
| Tune the policy pipeline | [The plugin pipeline](#7-the-plugin-pipeline) |
| Monitor it | [Observability](#8-observability) · [observability.md](observability.md) |
| Operate it / respond to incidents | [Operations](#9-operations) · [runbook.md](runbook.md) |
| Know what it does and does not defend | [Security model](#10-security-model) · [threat-model.md](threat-model.md) |
| Write a plugin | [Extending with plugins](#11-extending-with-plugins) · [plugin-protocol.md](plugin-protocol.md) |

---

## 1. Overview

### What it is

The MCP Security Proxy is a **policy-enforcing reverse proxy on the MCP tool-call
path**. An AI agent (an MCP client) connects to the proxy instead of directly to
its MCP servers. The proxy:

1. **Terminates the MCP session** — it answers `initialize` itself, mints its own
   `mcp-session-id`, and never trusts a client-supplied session id as identity.
2. **Authenticates every request** with a signed API key; the agent's identity is
   a property of the key, not a header the client asserts.
3. **Runs every method through a plugin pipeline** — policy decisions, content
   scanners, and tamper-evident audit — before forwarding to the registered
   upstream. A blocked call never reaches the upstream server.
4. **Records every decision** to a hash-chained, off-database-checkpointed audit
   log.

A LiveView **dashboard** visualizes traffic in real time (turning red when a call
is blocked) and lets an operator curate policy: register servers, classify tools,
issue keys, enable/disable plugins, and approve held calls.

### The threat it targets

The primary attack is **tool-chaining exfiltration**: an agent is manipulated (by
a prompt injection in a document, web page, tool description, or tool response)
into chaining a *"read something sensitive"* call into a *"send it somewhere"*
call. The proxy catches this with:

- **Tag-based chaining rules** — deny egress after a sensitive read.
- **Session taint tracking** — a leaked credential is fingerprinted with per-session
  HMAC markers; a later call whose arguments carry that secret (or a base64/hex/
  URL-encoded copy) is blocked.
- **Response scanning & redaction** — credentials are stripped out of tool
  responses before the agent sees them.
- **Streaming early-cut** — an oversized response is cut mid-transfer.
- **Behavioural baselining** — deny once the rate of watched calls exceeds a baseline.
- **Human-in-the-loop approval** — park egress for operator sign-off.
- **Prompt-injection detection** — a maintained regex ruleset over tool
  descriptions and responses.
- **Default-deny** — a call to a tool the operator has not classified is held.

Full mapping of defence → mechanism → milestone is in [threat-model.md](threat-model.md).

### What it is not

- **Not multi-node / HA.** Single-node by design. A host failure is an outage;
  restart survivability (all durable state in Postgres) is the guarantee. Deploys
  have a brief downtime window.
- **Not a firewall for the agent↔model channel.** The proxy sees tool
  descriptions and tool responses, never the agent's prompt or the model's
  reasoning.
- **Not a general-purpose MCP gateway.** It mediates a curated set of MCP methods
  (see the [method disposition table](#a-mcp-method-disposition)); unknown and
  server→client methods are refused.

### Stack

Phoenix 1.8 · LiveView · Bandit · Ecto/Postgres 17. HTTP via `Req`. Python 3 for
the one shipped sidecar plugin. Packaged as a single OCI image; deployed with
Docker Compose.

---

## 2. Architecture

```
                    ┌──────────────────────── proxy pipeline ─────────────────────────┐
 MCP client ─bearer─▶ ApiKeyAuth → RequestLimits → RateLimit                           │
 (agent)            │        │                                                          │
                    │        ▼   initialize / notifications/initialized (proxy answers) │
                    │  SessionStore  ── mints mcp-session-id, binds to key_id ──        │
                    │        │                                                          │
                    │        ▼   tools/call                                             │
                    │  MethodPolicy.disposition → :police                               │
                    │        │                                                          │
                    │        ▼                                                          │
                    │  pre_call:  policy plugins (ordered, short-circuit on deny/hold)  │
                    │        │  allow / deny / hold                                     │
                    │        ▼                                                          │
                    │  forward to upstream ──▶ registered MCP server (http or stdio) ──▶ files / net / …
                    │        │  (http: incremental read → chunk-phase scan → early cut) │
                    │        ▼  response                                                │
                    │  post_call: scanner + policy plugins (concurrent)                 │
                    │             redactions applied, or whole response withheld        │
                    │        │                                                          │
                    │        ▼                                                          │
                    │  PolicyEngine → every auditSink (EventLog hash chain, JSON log)   │
                    └────────┼──────────────────────────────────────────────────────────┘
                             ▼
                    response (or JSON-RPC error) to the client

 discovery phase runs off the request path, at server registration / re-handshake:
   ServerRegistry → initialize + tools/list handshake → discovery scanners
   (rug-pull hash check, prompt-injection scan, tag inference) → quarantine / tag
```

### Key modules

| Module | Role |
|---|---|
| `PhoenixElxirBeamWeb.MCP.ProxyController` | `POST/DELETE /mcp/proxy/:server_id`. Terminates the session, dispatches by method. |
| `MCP.SessionStore` / `MCP.Session` | Downstream MCP session lifecycle — mint id, handshake state, TTL/idle GC, key binding. |
| `MCP.MethodPolicy` | The single disposition table for every non-handshake method. |
| `MCP.Pipeline` | Runs the plugin phases (`discovery` / `pre_call` / `post_call` / `chunk`). |
| `MCP.PolicyEngine` | Canonical per-session state (tags, taint, call log); the **sole** audit-event broadcaster and `EventLog` writer. |
| `MCP.ServerRegistry` / `MCP.ServerStore` | Registered upstreams; live tool discovery; rug-pull re-handshake; Postgres-backed. |
| `MCP.StreamProxy` | Incremental read of an `:http` upstream response; runs the `chunk` phase; relays progress notifications over SSE. |
| `MCP.HoldRegistry` / `MCP.HoldStore` | Parks calls awaiting operator approval; boot-time orphan reaping. |
| `MCP.EventLog` / `MCP.AuditIntegrity` / `MCP.AuditCheckpoint` | Hash-chained audit log; scheduled verification; off-DB signed checkpoints. |
| `MCP.Plugin.Registry` | Config-seeded plugin registry; runtime enable/disable/reorder; sidecar supervision + provenance. |
| `Plugs.ApiKeyAuth` / `Plugs.RateLimit` / `Plugs.RequestLimits` | The `:mcp_api` pipeline — auth, per-key rate limit, body-size cap. |

### Data model (Postgres)

| Table | Holds | Notes |
|---|---|---|
| `policy_events` | the audit hash chain — every verdict, hold, session marker, policy change | `prev_hash` + `hash` per row; grows unbounded unless retention is enabled |
| `policy_sessions` | per-session policy state (tags, taint markers, call count) | write-through cache; source of truth for restart survival |
| `server_registrations` | registered upstreams + per-tool overlay (tags, quarantine, pinned hash) | tool descriptions always come fresh from the live handshake |
| `api_keys` | issued client keys — `sha256(secret)` only, `agent_id`, grants | |
| `users` / `user_tokens` | operator accounts + sessions | `viewer < operator < admin`, pbkdf2 |
| `plugin_states` | runtime plugin enable/position overlay | overlays the config defaults on boot |
| `pending_holds` | minimal row per open approval hold | reaped/finalized `:orphaned` on boot |

---

## 3. Quick start (local)

Needs a Postgres. The compose file ships one; or use a local Postgres on `:5432`.

```bash
docker compose up -d postgres     # or point PG* env at your own
mix setup                         # deps + create/migrate DB + build assets
mix phx.server                    # http://localhost:4000
```

- Dashboard: <http://localhost:4000/mcp/dashboard> (redirects to `/login`).
- Proxy endpoint: `POST http://localhost:4000/mcp/proxy/:server_id`.
- In dev there is **no seeded admin** — create one from an IEx session:

  ```bash
  iex -S mix
  ```
  ```elixir
  PhoenixElxirBeam.Accounts.create_user(%{
    email: "you@example.com", password: "a-long-dev-password", role: :admin
  })
  ```

Dev defaults: `UnclassifiedGuard` is `off` (untagged tools flow), the
prompt-injection sidecar is skipped with a warning if `python` is not on `PATH`,
and the Repo connects to `postgres:postgres@localhost:5432/phoenix_elxir_beam_dev`
(override with `PGHOST` / `PGPORT` / `PGUSER` / `PGPASSWORD` / `PGDATABASE`).

`mix precommit` (compile warnings-as-errors + format + test) is the local gate;
`mix ci` adds `deps.audit` + `dialyzer` and matches what CI enforces.

---

## 4. Deployment

Single-node **Docker Compose**: one `app` container + one `postgres` container,
optional observability sidecars. Multi-node / Kubernetes / HA are explicit
non-goals. This section is the fast path; [deployment.md](deployment.md) has the
full topology, sizing, TLS, retention, and backup detail.

### 4.1 Topology

```
 agents ──TLS──▶ reverse proxy ──▶ app (mcp-security-proxy) ──▶ registered MCP servers
                (Caddy / nginx)          │       ▲                (http or stdio)
                                         ▼       │ /metrics, /health/*
                                    postgres:17  └── prometheus + grafana (optional overlay)
 volumes: pg_data, audit_checkpoints (the checkpoint file is deliberately NOT on the DB volume)
```

- **The app must not be exposed directly.** Put a reverse proxy or cloud LB in
  front for TLS. `/health/*` and `/metrics` are served over plain HTTP on the
  private network (excluded from the prod HTTPS redirect).
- **Postgres is not published** beyond the compose network in a real deployment
  (drop the `ports:` mapping — it's there for local `psql`).
- A `localhost` MCP server on the host is reachable from the container via
  `host.docker.internal` (the compose file wires `MCP_HOST_LOOPBACK_ALIAS`).

### 4.2 Prerequisites

- Docker + Docker Compose v2.
- A DNS name and TLS cert for the reverse proxy.
- Pull access to the image registry (`ghcr.io/<owner>/<repo>`), or
  build locally with `docker compose build`.

### 4.3 Configure

Two kinds of configuration — **non-secret** in `.env`, **secret** in files:

```bash
cp .env.example .env
# edit .env: PHX_HOST, ADMIN_EMAIL, ADMIN_PASSWORD, POSTGRES_USER/DB, ports, …

mkdir -p secrets
openssl rand -hex 64    > secrets/secret_key_base.txt        # or: mix phx.gen.secret
openssl rand -hex 32    > secrets/audit_checkpoint_key.txt   # STABLE across deploys
openssl rand -base64 24 > secrets/postgres_password.txt
```

The three real secrets are **Docker secret files** mounted at `/run/secrets/*` —
they never appear in `.env` or `docker inspect`. `runtime.exs` reads the file,
falling back to an env var of the same (upper-case) name.

> **`audit_checkpoint_key.txt` must not change between deploys.** A rotated key
> invalidates every older audit checkpoint. Only rotate it if you believe it
> leaked.

Full variable reference: [§5](#5-configuration-reference).

### 4.4 Bring it up

```bash
docker compose up -d
```

`app` waits for `postgres` healthy, runs `Release.migrate()` (via
`docker-entrypoint.sh`), then starts. Verify:

```bash
curl -fsS http://localhost:4000/health/live      # 200 whenever the VM is up
curl -fsS http://localhost:4000/health/ready     # 200 iff Postgres + upstreams OK
```

On every boot, an admin is seeded from `ADMIN_EMAIL` / `ADMIN_PASSWORD` unless
that email already has an account — existing accounts are never modified, so
it's safe to leave both set across deploys. Sign in at `https://<host>/login`,
change the password, then follow [§6.1](#61-first-run-setup).

### 4.5 Observability overlay (optional)

```bash
docker compose -f docker-compose.yml -f compose.observability.yml up -d
```

Adds Prometheus (`:9090`, scrapes `app:4000/metrics`, loads the alert rules) and
Grafana (`:3000`, the **MCP Security Proxy** dashboard pre-provisioned; set
`GRAFANA_USER` / `GRAFANA_PASSWORD`). Add `-f compose.loki.yml` for Loki +
Promtail log shipping. See [observability.md](observability.md).

### 4.6 Upgrade & rollback

CI builds and pushes an image on every `v*` tag. On the host:

```bash
# docker-compose.yml (or the deploy .env) points `app` at the desired tag
docker compose pull app
docker compose up -d app       # stop → migrate → start; brief downtime, single-node
```

Rollback is the same command with the previous tag. If a migration must be
undone, do it **before** starting the older image:

```bash
docker compose run --rm app /app/bin/phoenix_elxir_beam eval \
  'PhoenixElxirBeam.Release.rollback(PhoenixElxirBeam.Repo, <version>)'
```

Keep migrations backward-compatible with the previous image where possible.
Details: [ci-cd.md](ci-cd.md), [runbook.md](runbook.md#deploy-a-new-version).

---

## 5. Configuration reference

### 5.1 Secrets (`secrets/*.txt`, mounted at `/run/secrets/`)

| File / env var | Required | Purpose |
|---|---|---|
| `secret_key_base.txt` / `SECRET_KEY_BASE` | **yes (prod)** | Signs/encrypts cookies and tokens. ≥ 64 bytes. |
| `audit_checkpoint_key.txt` / `AUDIT_CHECKPOINT_KEY` | **yes (prod)** | HMAC key for off-DB audit checkpoints. **Stable across deploys.** |
| `postgres_password.txt` / `POSTGRES_PASSWORD` | yes, unless `DATABASE_URL` set | Postgres password; `DATABASE_URL` is built from `POSTGRES_*` + this. |
| `TAINT_MARKER_KEY` | no | HMAC key for taint markers. Derived from `SECRET_KEY_BASE` if unset. |

### 5.2 `.env` (non-secret)

| Variable | Default | Purpose |
|---|---|---|
| `PHX_HOST` | `example.com` | Public hostname for URL generation. |
| `PORT` | `4000` | Port the app listens on (host mapped 1:1 by compose). |
| `ADMIN_EMAIL` | `admin@example.com` | Admin login seeded on **every** boot if this email has no account yet. Existing accounts (password, role) are never modified. |
| `ADMIN_PASSWORD` | — | Password used only when seeding a new account for `ADMIN_EMAIL`. |
| `POSTGRES_USER` | `mcp_proxy` | DB user; part of the built `DATABASE_URL`. |
| `POSTGRES_DB` | `mcp_proxy` | DB name. |
| `POSTGRES_HOST` | `postgres` | DB host (compose service name). |
| `POSTGRES_PORT` | `5432` | Host port the `postgres` service is published on (local `psql` only). |
| `DATABASE_URL` | built from `POSTGRES_*` | Full connection URL; wins if set. |
| `POOL_SIZE` | `10` | Ecto connection pool size — bounds DB concurrency. |
| `PG_STATEMENT_TIMEOUT_MS` | `15000` | Postgres `statement_timeout`. |
| `ECTO_IPV6` | — | `true`/`1` to use an IPv6 DB socket. |
| `METRICS_TOKEN` | — | Optional bearer token for `GET /metrics`. Unset ⇒ endpoint open (keep it on an internal network). |
| `READINESS_REQUIRE_UPSTREAMS` | `true` | `false` makes upstream reachability advisory (DB-only readiness). |
| `SSL_CERT_PATH` / `SSL_KEY_PATH` / `SSL_PORT` | — | Set all to have Bandit terminate TLS itself instead of a reverse proxy. |
| `AUDIT_CHECKPOINT_PATH` | `/checkpoints/audit.log` | Off-DB checkpoint file — keep on a volume separate from Postgres. |
| `AUDIT_RETENTION_DAYS` | unset (off) | Prune `policy_events` older than N days (anchor-safe). See [§9.4](#94-retention--backups). |
| `MCP_HOST_LOOPBACK_ALIAS` | `host.docker.internal` (compose) | Lets a registered `localhost` upstream URL be dialed from inside the container. |
| `DNS_CLUSTER_QUERY` | — | Leave blank for single-node. |
| `GRAFANA_USER` / `GRAFANA_PASSWORD` | — | Grafana admin creds (observability overlay). |
| `OIDC_ISSUER_URL` | — | OpenID Connect issuer URL. Unset ⇒ SSO disabled (default). **Required to enable SSO.** See [§6.2](#62-operator-sso-oidcoauth2). |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | — | OAuth2 client credentials registered with the IdP. Required when `OIDC_ISSUER_URL` is set; boot raises otherwise. |

### 5.3 Compile-time config (`config/*.exs` — needs a rebuild to change)

| Key | Where | Default | Purpose |
|---|---|---|---|
| `MCP.RateLimiter` `window_ms` / `max_per_window` | `config.exs` | `1000` / `20` | Per-key fixed-window rate limit. |
| `Plugs.RequestLimits` `max_body_bytes` | `config.exs` | `1_048_576` | Proxy request body cap → `413`. |
| `:upstream_tls_verify` | `config.exs` | `true` | Proxy-wide TLS verification for `:http` upstreams. |
| `MCP.AuditIntegrity` `interval_ms` | `config.exs` | `900_000` | Audit-chain verification cadence (15 min). |
| `MCP.AuditRetention` `retention_days` | `runtime.exs` (prod) | `nil` | Set via `AUDIT_RETENTION_DAYS`. |
| `PhoenixElxirBeam.MCP` `plugins:` | `config/{dev,test,prod}.exs` | see [§7](#7-the-plugin-pipeline) | The full plugin pipeline for that env. |
| `:approval_gate_alert` `rate` / `min_samples` / `window` | `config.exs` | `0.9` / `10` / `50` | Threshold for the `:approval_gate_fatigue` alert — approval rate over the trailing window of resolved holds, below `min_samples` never alerts. |
| `force_ssl` exclude list | `prod.exs` | `/health*`, `/metrics`, loopback | Paths served over plain HTTP. |

The `plugins:` list is set **once per environment** — `Config` merges
keyword-shaped lists by key, so there is no base list to override.

---

## 6. Using the proxy

### 6.1 First-run setup

1. Deploy per [§4](#4-deployment). Sign in at `https://<host>/login` with
   `ADMIN_EMAIL` / `ADMIN_PASSWORD`.
2. **Change the admin password** and create per-person accounts. Account
   management is via the **release console** (there is no user-management UI yet):

   ```bash
   docker compose exec app /app/bin/phoenix_elxir_beam remote
   ```
   ```elixir
   alias PhoenixElxirBeam.Accounts
   Accounts.create_user(%{email: "alice@example.com", password: "…", role: :operator})
   Accounts.list_users()
   Accounts.change_user_role(Accounts.get_user_by_email("bob@example.com"), :viewer)
   Accounts.set_user_disabled(user, true)     # kills their sessions immediately
   ```

   Roles: `viewer` (read-only), `operator` (policy changes, approve/deny holds),
   `admin` (+ key management, `/dev` routes).
3. Confirm `/health/ready` is `200` and Prometheus can scrape `/metrics`.

### 6.2 Operator SSO (OIDC/OAuth2)

**Optional.** If you operate your own identity provider or have federated access
via an enterprise auth system, SSO is available for operator login and pre-provisioned accounts.

#### Setup

Three environment variables govern SSO, read at **boot** (`config/runtime.exs`) —
toggling them only needs a restart, never a rebuild:

- `OIDC_ISSUER_URL` — the OpenID Connect issuer (e.g.
  `https://auth.example.com`). **Required to enable SSO.**
- `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` — OAuth2 client credentials registered
  with the provider.

Set them in `.env` (or secret files, like other deployment secrets), then restart
the app (no rebuild required — these are read at boot, not compiled in):

```bash
docker compose up -d
```

Register this redirect URI with your IdP:

```
https://<host>/auth/operator_sso/callback
```

When SSO is enabled, the login page shows a **"Sign in with SSO"** link; when
disabled, the page is unchanged (password login only) and any `/auth/*`
request is redirected to `/login`.

#### Pre-provisioning accounts

SSO does not auto-provision operators. An account must exist in Postgres *before*
an operator can sign in via SSO — it is always a pre-provisioning step:

```bash
# Release console
docker compose exec app /app/bin/phoenix_elxir_beam remote
```

```elixir
alias PhoenixElxirBeam.Accounts
# Each operator must be created first
{:ok, _user} = Accounts.create_sso_user(%{email: "alice@example.com", role: :operator})
```

Only accounts with `auth_source: :sso` can log in via SSO — password login is
disabled for them. Accounts with `auth_source: :local` (or created before SSO was
added) can only log in with a password, never SSO, even if their email matches an
IdP account.

Password-based login always remains available for local accounts, independent of
SSO's enabled status.

### 6.3 Register an MCP server

**Dashboard → Servers & tools → Register.** Give a name and the upstream's
**Streamable HTTP base URL** (e.g. `http://host.docker.internal:9000/mcp`).
Optional per-server **Timeout (ms)** and **Skip TLS verify** override the
proxy-wide defaults for that server only (leave blank to inherit).

The proxy does a live `initialize` + `tools/list` handshake; discovered tools
appear **unclassified**. Registration is persisted and re-handshaked on every
restart — an upstream unreachable at boot is logged and skipped (record kept) and
shows as unreachable on `/health/ready`.

**stdio upstreams** (a locally spawned MCP server process) are registered from the
release console or seeded in config, not the dashboard form:

```elixir
PhoenixElxirBeam.MCP.ServerRegistry.register_stdio_server(
  "notes", "npx", ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
)
```

### 6.4 Classify tools

With default-deny on (prod ships `UnclassifiedGuard` in `hold` mode), **a call to
an unclassified tool is parked** until an operator classifies it.

**Dashboard → expand the server → per tool, toggle:**

- **`sensitive read`** (`:sensitive_read`) — the tool returns credentials,
  config, or private data.
- **`network egress`** (`:network_egress`) — the tool sends data somewhere you
  can't see.
- **`untrusted source`** (`:untrusted_source`) — the tool's response should be
  treated as untrusted regardless of content (an unvetted upstream, a web
  scraper, anything that can return a prompt-injection payload with nothing
  credential-shaped in it for `SecretLeak` to catch). Tagging it taints the
  session the same way a leaked secret does — opt-in, nothing is untrusted by
  default. See [threat-model.md](threat-model.md) "Provenance taint tracking".

Where the name/description heuristics have a suggestion, an **apply suggested**
button assigns tags in one click. A tool that is neither (a pure computation, a
read of non-sensitive data) is left with an explicit empty classification — toggle
a tag on then off, or switch `UnclassifiedGuard` to `off` once curation is done.

**Every tag change is written to the audit chain** (actor, before → after) and is
one-click revertible from the **Policy changes** panel.

### 6.5 Issue an agent key

**Dashboard → Client keys (admin) → Issue.** Provide:

- **Principal** — a human-readable label ("ci-runner deploy bot").
- **Agent id** — the cryptographic identity threaded into every audit row
  (e.g. `agent://ci-runner`). Rules match on this.
- **Scope** — `all servers`, or an explicit list of server ids.

**The token is shown once.** Hand it to the agent as:

```
Authorization: Bearer mcpk_<key-id>.<secret>
```

**Revoke** takes effect on the agent's next request — mid-session too (the session
is also bound to its `key_id`, so another key cannot drive it).

#### Verified per-agent identity (optional)

An API key's `agent_id` is a *default* — every agent sharing that key is
otherwise stamped with the same identity for policy matching. To let distinct
agents behind one shared key assert their own identity, issue each one an
`AgentCredential` and have it present an `X-Agent-Credential` header:

```elixir
# from a release console (no dashboard UI yet — same bootstrap caveat as
# issuing the first admin account: this runs with full application access)
{:ok, _cred, token} =
  PhoenixElxirBeam.MCP.AgentCredential.issue(%{agent_id: "agent://specific-bot"})
# token is "agent://specific-bot.<secret>" — shown once, like an API key's token
```

The agent then sends both headers on every request:

```
Authorization: Bearer mcpk_<id>.<secret>
X-Agent-Credential: agent://specific-bot.<secret>
```

When `X-Agent-Credential` is present and valid, its `agent_id` overrides the
API key's own default for that session — so a RuleEngine rule scoped to
`agent://specific-bot` matches the verified identity, not whatever the shared
key happened to default to. A missing header falls back to the key's default
exactly as before; a present but invalid header is rejected with 401 (it
never silently falls back — that would let an attacker probe for valid
`agent_id` strings for free). Revoke with
`PhoenixElxirBeam.MCP.AgentCredential.revoke(agent_id)`.

Presenting the header is opt-in, not enforced: an agent sharing a key with
others can simply omit `X-Agent-Credential` and fall back to that key's own
default `agent_id`, escaping any deny rule scoped to its verified identity. A
rule written against `agent://specific-bot` only binds a client that actually
presents that credential. If you issue one API key to multiple agents, set
that key's own default `agent_id` to the **most restrictive** identity
appropriate for the whole group — per-agent rules only protect the agents
that opt in.

### 6.6 Point an MCP client at the proxy

The proxy speaks **JSON-RPC 2.0 over the MCP Streamable HTTP transport** at
`POST /mcp/proxy/:server_id`. A conforming MCP client needs only:

- Base URL: `https://<host>/mcp/proxy/<server_id>`
- Header: `Authorization: Bearer mcpk_<id>.<secret>`
- Header: `Accept: application/json, text/event-stream`

Most MCP clients (Claude Desktop, MCP Inspector, the SDKs) take a URL + a bearer
token directly.

#### Worked example (curl)

```bash
BASE=https://proxy.example.com/mcp/proxy/notes
AUTH="Authorization: Bearer mcpk_ab12cd34.s3cr3t-256-bits"

# 1. initialize — the proxy answers, and returns the session id in a header
curl -sD- -o/dev/null -X POST "$BASE" -H "$AUTH" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
       "params":{"protocolVersion":"2025-06-18","capabilities":{},
                 "clientInfo":{"name":"curl","version":"0"}}}'
# → HTTP/1.1 200 ... mcp-session-id: 7f3c9a...

SID="7f3c9a..."           # from the mcp-session-id response header

# 2. complete the handshake (202, no body)
curl -s -X POST "$BASE" -H "$AUTH" -H "mcp-session-id: $SID" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# 3. list tools (forwarded verbatim)
curl -s -X POST "$BASE" -H "$AUTH" -H "mcp-session-id: $SID" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'

# 4. call a tool — runs the full policy pipeline
curl -s -X POST "$BASE" -H "$AUTH" -H "mcp-session-id: $SID" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call",
       "params":{"name":"read_file","arguments":{"path":"notes/todo.md"}}}'

# 5. close the session
curl -s -X DELETE "$BASE" -H "$AUTH" -H "mcp-session-id: $SID"
```

#### What you get back when policy fires

| Situation | Response |
|---|---|
| Allowed | the upstream's result, with any secrets redacted in place |
| Chain / rule / baseline / unclassified **deny** | JSON-RPC error `-32001` with the reason |
| Held for approval | the request **blocks** until an operator approves/denies on the dashboard (or the hold times out → `-32001`) |
| `post_call` response withheld (size guard, injection block) | JSON-RPC error `-32002` |
| Quarantined tool (rug-pull / drift) | JSON-RPC error `-32003` |
| Method not permitted through the proxy | JSON-RPC error `-32601` |
| No/!bad bearer token | HTTP `401` + `WWW-Authenticate: Bearer` |
| Body over `max_body_bytes` | HTTP `413` |
| Over the per-key rate budget | HTTP `429` + `Retry-After` |
| Would have denied/held, but in **dry-run mode** (§6.8) | the upstream's result, delivered normally — logged as `would block` / `would hold` instead |

If the client's `Accept` header includes `text/event-stream` and the upstream
emits `notifications/progress`, the proxy relays those frames live over a chunked
SSE response and delivers the fully-scanned result as the terminal frame.

### 6.7 The dashboard

`/mcp/dashboard` (also `/`). Header shows server / session / plugin counts, the
audit-chain status pill, and the signed-in identity.

| Panel | Role | Who |
|---|---|---|
| **Tool graph + live feed** | real-time visualization of calls flowing agent → gate → server; pulses red on a block | all |
| **Operational alerts / Approval required** banners | active `MCP.Alerts` and parked holds with Approve / Deny | operator resolves holds |
| **Event history** | filterable, sortable, paginated audit history; **verify audit chain** button; a blocked/held row has a collapsed **chain** disclosure listing the session's prior calls that led to it | all |
| **Plugins** | every plugin + each sidecar's health; enable / disable / ▲▼ reorder; global dry-run toggle + per-plugin mode pin (§6.8) | operator |
| **Policy changes** | every runtime change (actor, before → after) with one-click **revert** | operator reverts |
| **Client keys** | issued keys; **Issue** / **Revoke** | admin |
| **Servers & tools** | register / remove servers; expand to classify tools, re-handshake, clear a quarantine | operator classifies; admin registers |

### 6.8 Change policy at runtime

**Dashboard → Plugins (operator).** Enable / disable / reorder plugins without a
redeploy; state persists across restarts (`plugin_states` overlays the config
defaults on boot). Each change is audited and appears in **Policy changes** with a
revert button.

Still needs a config change + redeploy: `RuleEngine` rule edits, and the
`UnclassifiedGuard` `mode`.

### 6.9 Dry-run mode

**Dashboard → Plugins (operator).** Turns the proxy's enforcement into
observe-only: a plugin's `deny`/`hold` is logged instead of acted on, and the
call proceeds exactly as an `allow` would. Use it to see what a new rule, or
the whole pipeline, *would* do against real traffic before it can actually
block anything.

- **Global switch + per-plugin override.** The header toggle
  (Enforcing / Dry-run) sets the default for every plugin. Any single plugin
  can still be pinned to `enforcing` or `dry-run` from its row, regardless of
  the global switch — roll out one new rule in shadow mode while everything
  else keeps enforcing, or vice versa. A plugin left on "inherit" follows the
  global switch.
- **What shows up.** A call that would have been denied or held appears in the
  live feed and event history as `would block` / `would hold` (amber, not
  red) instead of `blocked` / `held` — the reason is the same one the plugin
  would have given for real. The response is still delivered, or the stream
  still completes, exactly as if nothing had objected.
- **Durable, not best-effort.** A dry-run verdict is receipted to the same
  hash-chained audit log as a real one, so "how often would this have fired
  over the last week" is a real query against `policy_events`, not something
  you have to have been watching live to catch.
- **Persists across restarts.** Both the global switch and any per-plugin pin
  are stored the same way plugin enable/disable state already is
  (`plugin_states` / a `proxy_settings` row) — no redeploy needed to flip it,
  and it survives one.
- Every flip is audited in **Policy changes** with actor, before → after, and
  a revert button, same as any other runtime policy edit.

---

## 7. The plugin pipeline

Every environment sets its own full `plugins:` list. `pre_call` **policy** plugins
run in list order and short-circuit on the first `deny`/`hold`; `post_call` and
`discovery` plugins run concurrently. Net verdict: `deny` > `hold` > `allow`.

### 7.1 Shipped plugins

| Plugin | Phase / kind | What it does | Key config |
|---|---|---|---|
| **RuleEngine** | `pre_call` policy | Verdicts from operator-written rules — `match` on `agent` / `agent_prefix` / `tool` / `server` / `tool_tags_any` / `after_sensitive_read` / `if_tainted`; `action` `deny`/`allow`/`hold`; first match wins. | `config: %{"rules" => [...]}` |
| **UnclassifiedGuard** | `pre_call` policy (all calls, fail-closed) | Default-deny: an untagged tool is `off` / `deny` (→ `-32001`) / `hold` (park for sign-off). Prod: `hold`. | `config: %{"mode" => "hold"}` |
| **TaintedArgGuard** | `pre_call` policy (all calls) | Blocks a call whose arguments carry a secret seen earlier this session — matches HMAC markers for the raw secret **and** its base64/hex/URL-encoded forms. | — |
| **BaselineGuard** | `pre_call` policy (all calls, fail-open) | Denies once the session exceeds a rate of watched-tag calls in a window ("6 sensitive_read in 10s, limit 5"). | `config: %{"window_ms", "max_calls", "watch_tags"}` |
| **LoopGuard** | `pre_call` policy (all calls, fail-open) | **Operational safety net, not a security control**: denies once a session looks like a stuck agent — the same tool called with identical arguments past a limit (a genuine retry loop), or the same tool thrashed with any arguments past a looser limit (e.g. hammering a search call). Does not consider whether calls succeeded or failed — a planned future extension. **False-positive risk is real**: ordinary status polling or a no-argument tool called repeatedly looks identical to a stuck loop from here. Registered **disabled** in prod by default (unlike most plugins) — an operator must tune the thresholds for their own traffic and enable it from the Plugins panel, ideally pinned to dry-run first, rather than have it start enforcing against a workload it's never seen. | `config: %{"window_ms", "max_identical_calls", "max_same_tool_calls"}` |
| **ApprovalGate** | `pre_call` policy | Human-in-the-loop: `hold` egress after a sensitive read for operator sign-off; `on_timeout` → deny. | `config: %{"timeout_ms" => 120_000}` |
| **ChainExfil** | `pre_call` policy (`:network_egress` only) | Hard block: egress denied iff a `:sensitive_read` occurred earlier this session. (Test env; dev/prod use `ApprovalGate`.) | — |
| **TaintGuard** | `pre_call` policy (`:network_egress` only) | Coarse backstop: deny any egress once **any** secret has flowed this session (catches leaks the operator's tags missed). | — |
| **MetadataEgressGuard** | `pre_call` policy (`:network_egress` only) | SSRF guard: resolves every `http(s)://` host in a call's arguments and denies if it lands in loopback, link-local (incl. the cloud metadata address), or RFC1918 — no prior sensitive read required. Registered enabled, not dry-run-pinned by default — pin it from the Plugins panel before trusting it to enforce. | — |
| **RugPull** | `discovery` scanner | Pins each tool's `description_hash` at registration; quarantines a tool whose definition changed on re-handshake (→ `-32003`). | — |
| **SecretLeak** | `post_call` scanner | Finds credentials in a tool/resource/prompt response, redacts them in place, and records HMAC taint markers (never the raw secret). | — |
| **ProvenanceTaint** | `post_call` scanner | Taints the session whenever a tool tagged `:untrusted_source` returns a response, independent of content — catches what `SecretLeak`'s regexes can't (paraphrase, un-fingerprintable payloads). | — |
| **ResponseSizeGuard** | `post_call` policy | Withholds a response whose text content exceeds a byte budget (→ `-32002`) — blunt bulk-exfil guard. | `config: %{"max_bytes" => 4000}` |
| **StreamGuard** | `chunk` policy | The streaming analogue of ResponseSizeGuard — cuts an `:http` response mid-transfer once the running byte count passes a budget. | `config: %{"max_bytes" => 1200}` |
| **EventLogSink** | `auditSink` | Persists every `AuditEvent` to the hash-chained `policy_events` table. | — |
| **StructuredLogSink** | `auditSink` | One JSON line per event on the logger at `:info`, prefixed `mcp.audit` — for a log shipper → SIEM. | — |
| **prompt-injection-scanner** | `:sidecar` (stdio, Python) | Regex ruleset over tool descriptions (`discovery` — quarantine) and responses (`post_call` — finding + hidden-instruction redaction). | `pin`, `grants`, `limits`, ruleset path |

### 7.2 The prompt-injection sidecar

A **maintained regex ruleset**, not an ML model or an external service:

- [`priv/plugins/injection_rules.json`](../priv/plugins/injection_rules.json) — the
  rules (`{id, category, pattern, severity, confidence}`). **Edit this**, not the
  scanner.
- [`priv/plugins/prompt_injection_scanner.py`](../priv/plugins/prompt_injection_scanner.py) — the sidecar.
- [`priv/plugins/corpus/injection_corpus.jsonl`](../priv/plugins/corpus/injection_corpus.jsonl) — labelled samples.
- [`priv/plugins/score_injection.py`](../priv/plugins/score_injection.py) — scores the
  ruleset against the corpus; **gates CI** at recall ≥ 0.85, precision ≥ 0.90,
  FP ≤ 0.05.

After editing the script or ruleset, recompute the provenance pin in
`config/prod.exs` (command in the comment there) — the sidecar refuses to start if
its bytes don't match the pin. Coverage limits (paraphrase, multilingual, heavy
obfuscation) are measured and disclaimed in
[injection-detection.md](injection-detection.md).

### 7.3 Tuning notes

- The policy pipeline adds **< 1 ms p99** at 50 concurrent sessions — it is not
  the latency bottleneck (per-request DB work is). See
  [latency-budget.md](latency-budget.md).
- Sidecars get best-effort `prlimit` caps (`limits: [as_mb:, cpu_s:, nproc:]`) and
  a circuit breaker (5 failures / 60 s → auto-disabled + alert). A third-party
  sidecar should run as its own container. See
  [plugin-supply-chain.md](plugin-supply-chain.md).

---

## 8. Observability

### 8.1 Endpoints

| Path | Purpose |
|---|---|
| `GET /health/live` | Liveness — 200 whenever the VM can route a request. Container healthcheck points here. |
| `GET /health/ready` | Readiness — 200 iff Postgres answers and (unless `READINESS_REQUIRE_UPSTREAMS=false`) every registered upstream is reachable; else 503 + JSON detail. Point a load balancer here. |
| `GET /health` | Back-compat alias of `/health/live`. |
| `GET /metrics` | Prometheus text `0.0.4`. Optionally gated by `METRICS_TOKEN`. |

### 8.2 Key metrics

| Series | Type | Meaning |
|---|---|---|
| `mcp_pipeline_run_stop_duration{phase,verdict}` | histogram | plugin-chain phase latency + count |
| `mcp_plugin_run_stop_duration{plugin,phase,outcome}` | histogram | per-plugin latency; `outcome` ∈ `ok\|timeout\|crash\|bad_return` |
| `mcp_upstream_request_stop_duration{transport,outcome}` | histogram | upstream MCP request latency |
| `mcp_decision_count{verdict,phase}` | counter | policy decisions |
| `mcp_alert_count{key,severity}` | counter | operational alerts raised |
| `mcp_sessions_count` / `mcp_holds_pending` | gauge | live sessions / parked holds |
| `mcp_servers_count` / `mcp_servers_unreachable` | gauge | registered upstreams, live vs failed |

### 8.3 Alerts

`MCP.Alerts.emit/3` is the single path: it writes an `mcp.alert <key> (<severity>):
<detail>` error log line (ship to your SIEM), broadcasts to the dashboard banner,
and increments `mcp_alert_count`. **There is no built-in Alertmanager / webhook /
email** — that was a deliberate decision; wire Alertmanager to
[`deploy/prometheus/alert.rules.yml`](../deploy/prometheus/alert.rules.yml) if you
want paging.

App alert keys: `audit_integrity`, `sidecar_provenance`, `sidecar_circuit_open`,
`plugin_fail_open`, `upstream_unreachable`, `approval_gate_fatigue`, `rug_pull`.
Per-alert response: [runbook.md](runbook.md#responding-to-alerts).

### 8.4 Grafana + Loki

The observability overlay pre-provisions a 13-panel **MCP Security Proxy**
dashboard (`allowUiUpdates: true`). Add `-f compose.loki.yml` for Loki + Promtail,
which ships every container's stdout to Loki labeled by compose service — filter
to the app with `{compose_service="app"}` in Grafana Explore. Log shipping is not
the audit record; ship the JSON logs to your SIEM for anything that must outlive
the deployment. See [observability.md](observability.md).

---

## 9. Operations

Day-to-day operation and incident response is [runbook.md](runbook.md). The
essentials:

### 9.1 Deploy / roll back

See [§4.6](#46-upgrade--rollback).

### 9.2 Audit chain

Rows in `policy_events` are hash-linked (`hash = sha256(prev_hash <> canonical(row))`).
`MCP.AuditIntegrity` runs `EventLog.verify_chain/0` every 15 min **and** compares
the live head against the newest off-DB signed checkpoint — so a truncated log
that still verifies internally is still caught.

An **`audit_integrity` alert is an incident.** Do not restart the app; capture
state first. `EventLog.verify_chain/0` names the first bad/missing row.
Investigation procedure:
[runbook.md](runbook.md#investigate-an-audit-chain-failure).

```bash
# from a release console
docker compose exec app /app/bin/phoenix_elxir_beam eval \
  'PhoenixElxirBeam.MCP.AuditIntegrity.check_now()'
```

### 9.3 Held calls

A `hold` parks the client's HTTP request (it stays open). The dashboard shows an
Approve / Deny card; **approve = allow** (the rest of the plugin chain is not
re-run). No operator action within the hold's timeout applies `on_timeout`
(deny). A restart fails an in-flight hold closed and writes a terminal
`:orphaned` audit event.

### 9.4 Retention & backups

- **Postgres** is the audit record — back up `pg_data` (or `pg_dump`) on your
  normal schedule and treat backups as evidence.
- **The audit checkpoint file** (`audit_checkpoints` volume) — back it up *with*
  the DB from a consistent point; it's the anchor for detecting a truncated log.
- **`policy_events` grows unbounded** until you set `AUDIT_RETENTION_DAYS`.
  Retention only deletes rows *before* the row the newest signed checkpoint
  anchors on, and `verify_chain` is anchor-aware, so a pruned table keeps
  verifying. **Do not enable retention until Postgres backups and/or SIEM log
  shipping are in place** — it is deletion, not archival. Detail:
  [deployment.md](deployment.md#retention--backups).

### 9.5 Sidecar provenance

A `sidecar_provenance` alert means a sidecar's code or manifest digest ≠ its pin —
the plugin is **down**. Confirm the change was intentional (a deploy); if yes,
recompute the pin and redeploy; if no, isolate the host. See
[plugin-supply-chain.md](plugin-supply-chain.md).

---

## 10. Security model

Full detail: [threat-model.md](threat-model.md). Summary:

### In scope

- **Tool-chaining exfiltration** (the primary threat) — tags, taint markers,
  response scanning, streaming cut, baselining, approval, injection detection,
  default-deny.
- **Unauthenticated access** — every request needs a signed API key; the dashboard
  needs an operator account.
- **A malicious or swapped MCP server** — tools hashed at registration;
  re-verified at every re-handshake; drift → quarantine.
- **A tampered or swapped plugin** — sidecars provenance-pinned; mismatch stops
  the plugin and alerts.
- **Audit tampering** — hash-chained rows, scheduled verification, off-DB signed
  checkpoints.
- **Resource exhaustion** — body cap (413), per-key rate limit (429), per-stream
  buffer ceiling + deadline, sidecar `prlimit`, DB queue fail-fast.
- **Unauthorised policy change** — runtime changes require `operator`; every change
  audited and revertible.

### Explicitly out of scope

- Availability under node failure (single-node by design).
- A compromised upstream *after* a clean handshake (caught only by response
  scanning, not provenance).
- The agent↔model channel — an injection that never touches tool I/O is invisible.
- Untrusted third-party plugins (plugins are first-party / vendored).
- Novel / obfuscated prompt injection — the ruleset is regex over a maintained
  corpus; paraphrase, multilingual, and heavy obfuscation are partial coverage at
  best.
- Splitting a secret across multiple calls / arguments.
- A compromised `admin` account (mitigation is the off-DB-checkpointed audit
  chain, not prevention).
- Side channels, physical security, and the Postgres instance's own hardening.

### Trust boundaries

| Boundary | Untrusted side | Control |
|---|---|---|
| agent → proxy | agent (may be manipulated) | API key auth, rate limit, body cap |
| proxy → upstream | upstream MCP server | tool hashing, response scanning, TLS verify |
| proxy → sidecar plugin | sidecar (out-of-process) | provenance pin, `prlimit`, circuit breaker |
| operator → dashboard | operator (authorised, audited) | session auth, RBAC, change auditing |

---

## 11. Extending with plugins

The proxy is extended with **plugins** — units of detection/enforcement logic.
Two bindings, identical capabilities and semantics:

- **In-process** — an Elixir module implementing the `Policy` / `Scanner` /
  `AuditSink` behaviour, compiled into the release.
- **Sidecar** — a subprocess in any language, spoken to as JSON-RPC 2.0 over
  stdio (HTTP transport is specified but not yet built).

A plugin declares a **manifest**: which capabilities and phases it provides, the
`dataNeeds` it reads (the proxy sends nothing else), its `timeoutMs` / `failMode`,
and what mutations/blocks it wants. The operator's `grants:` block at registration
caps that regardless of what the plugin asks for.

Minimum viable in-process policy:

```elixir
defmodule MyApp.MCP.Plugins.NoWeekendEgress do
  @behaviour PhoenixElxirBeam.MCP.Plugin.Policy
  alias PhoenixElxirBeam.MCP.{Decision, Plugin.Manifest}

  @impl true
  def manifest do
    %Manifest{
      plugin: %{name: "no-weekend-egress", version: "0.1.0"},
      capabilities: %{
        policy: %{
          phases: [:pre_call],
          tool_tags: ["network_egress"],
          data_needs: [],
          timeout_ms: 50,
          fail_mode: :fail_closed
        }
      }
    }
  end

  @impl true
  def evaluate(:pre_call, _ctx) do
    if Date.day_of_week(Date.utc_today()) in [6, 7] do
      %Decision{verdict: :deny, severity: :medium, reason: "no egress on weekends"}
    else
      %Decision{verdict: :allow}
    end
  end
end
```

Register it by adding `{MyApp.MCP.Plugins.NoWeekendEgress, []}` to the `plugins:`
list in `config/prod.exs`. Full protocol — data model, aggregation rules, failure
handling, the wire schema, sidecar skeletons, worked JSON examples:
[plugin-protocol.md](plugin-protocol.md). Architecture rationale:
[adr/0001-plugin-architecture.md](adr/0001-plugin-architecture.md).

---

## Appendix

### A. MCP method disposition

Set by `MCP.MethodPolicy`. No method reaches an upstream without an explicit
decision here.

| Method(s) | Disposition | Behaviour |
|---|---|---|
| `initialize`, `notifications/initialized`, `ping` | (handled by the controller) | proxy answers directly; mints/marks the session |
| `tools/call` | `:police` | full `pre_call` pipeline → forward → `post_call` scan |
| `resources/read`, `prompts/get` | `:scan_response` | forward untouched → `post_call` content scan + redaction + taint |
| `tools/list`, `resources/list`, `resources/templates/list`, `resources/subscribe`, `resources/unsubscribe`, `prompts/list`, `completion/complete`, `logging/setLevel` | `:forward` | pass through verbatim |
| `notifications/*` (from the client) | `:ack` | accept with `202`, do not forward |
| `sampling/createMessage`, `elicitation/create`, `roots/list`, **any unknown method** | `:refuse` | JSON-RPC `-32601` |

### B. JSON-RPC error codes

| Code | Meaning |
|---|---|
| `-32001` | tool chain blocked by policy (deny / rule / baseline / unclassified / forbidden / no session / no server) |
| `-32002` | response withheld by policy (`post_call` deny, or a stream cut) |
| `-32003` | tool quarantined by a discovery scan (rug-pull / drift) |
| `-32601` | method not permitted through the proxy |
| `-32000` | upstream MCP server error |

### C. Document map

| Document | Covers |
|---|---|
| **This guide** | end-to-end: deploy, configure, use |
| [deployment.md](deployment.md) | topology, sizing, TLS, retention, backups |
| [runbook.md](runbook.md) | first-run, register, classify, keys, per-alert response, audit-chain investigation, deploy/rollback |
| [threat-model.md](threat-model.md) | assets, defences, non-goals, trust boundaries |
| [observability.md](observability.md) | endpoints, metrics, alerts, Grafana/Loki |
| [latency-budget.md](latency-budget.md) | the request-path latency budget and where time goes |
| [ci-cd.md](ci-cd.md) | pipelines, runners, registry, cutting a release |
| [plugin-protocol.md](plugin-protocol.md) | the full plugin contract (v0.1) |
| [plugin-supply-chain.md](plugin-supply-chain.md) | sidecar provenance pinning, resource limits, dependency audit |
| [injection-detection.md](injection-detection.md) | the injection ruleset, its corpus, budget, and measured limits |
| [productionization-plan.md](productionization-plan.md) | M0–M4 execution history |
| [adr/0001-plugin-architecture.md](adr/0001-plugin-architecture.md) · [adr/0002-productionization.md](adr/0002-productionization.md) | architecture decisions |
