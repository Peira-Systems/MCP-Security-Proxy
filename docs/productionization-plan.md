# Productionization plan

**Status:** Active · **Date:** 2026-08-28 · **Implements:** [ADR-0002](adr/0002-productionization.md)

This is the execution plan for ADR-0002. The ADR records *what* would have to change and
*why*; this document sequences it into shippable milestones with acceptance criteria.

## Decisions locked (ADR-0002 required these before Phase 1)

1. **Clean cut to production.** The demo scaffolding is deleted, not gated behind a runtime
   profile. No `demo` profile is carried. The dashboard-narrative demo (mock servers,
   scenario buttons, `MockDrift`, simulated streaming, preset "+ filesystem" / "+ fetch"
   buttons) is retired. If the demo is ever needed again it lives on a tag / branch, not in
   `main`.
2. **Deployment target: Docker + Docker Compose, single node.** One `app` container + one
   `postgres` container + optional observability sidecars, deployed with
   `docker compose up -d`. This is a real deployment in front of real MCP traffic, but it
   is **single-node**.
3. **Downstream client auth: signed API keys** (Ed25519/HMAC, hashed at rest,
   admin-issued). mTLS is an opt-in reverse-proxy layer; OAuth2/OIDC is out of scope.
   See M1.4.

### Explicit non-goals

- **Multi-node clustering / HA.** ADR-0002 §2.4 (DNSCluster, rolling deploy without
  dropping sessions, distributed state consistency) is **out of scope**. Restart
  survivability (state in Postgres) is in scope; running two app nodes at once is not.
  Deploys have a brief downtime window (stop, migrate, start) — acceptable for single-node.
- **Kubernetes**, service mesh, operators.
- **Untrusted third-party plugins.** Plugins are first-party or vendored; the Wasm
  sandboxing path (ADR-0001 §3) stays deferred.

---

## Milestone map

| Milestone | ADR-0002 phase | Goal | Rough size |
|---|---|---|---|
| **M0 — Strip the scaffolding** | Phase 1.6 (moved first) | The codebase is the real shape: no mock server, no scenario harness, no simulated transport. | ~1 week |
| **M1 — Real proxy** | Phase 1.1–1.5 | Correctly mediates a real MCP client↔server session; nothing unauthenticated reaches it. | ~4–5 weeks |
| **M2 — Survivable** | Phase 2.1–2.3 | A restart or audit spike does not drop session state or lose audit records. | ~3 weeks |
| **M3 — Operable** | Phase 3 | Deploy, observe, load-test, and change policy without a redeploy; every change audited. | ~3–4 weeks |
| **M4 — Close mission gaps** | Phase 4 | Security coverage matches the threat model, not what was demoable. | ~3 weeks |

Do not reorder M1→M2→M3. M4 items can be pulled forward opportunistically but are gated on
their noted dependencies. Total: ~3–4 months, matching the ADR estimate.

---

## M0 — Strip the scaffolding

Rationale: every later milestone touches the request path. Doing the deletion first means
M1–M4 are written against the real shape once, not adapted twice.

### M0.1 — Delete the mock server path
- **Remove:** `MockServerController`, `ToolCatalog`, `Demo`, `MockDrift`, the
  `POST /mcp/servers/:server_id` route, `ProxyController.fetch_from_mock/2`, the
  `Demo`-driven scenario buttons and their LiveView handlers.
- **Rework:** `ProxyController.fetch/2` no longer falls back to a mock when
  `ServerRegistry.get_server/1` returns `nil` — an unregistered `server_id` is a `404` /
  JSON-RPC error, not a mock lookup.
- **Rework:** `ProxyController.tool_tags/2` drops the `ToolCatalog` branch; tags come only
  from `ServerRegistry`.
- **Acceptance:** `grep -ri "mock\|MockDrift\|ToolCatalog\|Demo\." lib/` is clean; the
  dashboard loads with zero registered servers and no scenario buttons; `mix precommit`
  green.

### M0.2 — Delete the simulated streaming path
- **Remove:** `ProxyController.stream_and_scan/6`, `stream_notice/3`,
  `maybe_flag_terminated/2`, and the `result.chunks` branch of `call_and_scan/6`.
- **Keep:** `Pipeline.run_chunk/2`, `StreamGuard`, `Registry.active_chunk/1` — the `chunk`
  phase contract stays; it is re-wired to a real transport in **M1.3**. Mark them
  `@doc "unwired pending M1.3"` so nothing looks production-ready that isn't.
- **Acceptance:** no code path constructs or consumes `result["chunks"]`; `chunk`-phase
  unit tests still pass against synthetic chunks.

### M0.3 — Retire the dashboard demo affordances
- **Remove:** "+ filesystem" / "+ fetch" preset buttons and the `MCP_FILESYSTEM_CMD` /
  `MCP_FETCH_CMD` env wiring in `MCPDashboardLive`; the corresponding stdio-server installs
  in the `Dockerfile` (`mcp-node` stage, `mcp-server-fetch` venv, `MCP_*_CMD` ENV).
- **Replace with:** server registration via a `POST /admin/servers` API (auth in M1.4) and
  a config-seeded list for boot-time servers — see **M2.2 / ServerRegistry persistence**.
- **Acceptance:** the runtime image no longer ships Node or a Python venv; image size drops;
  `docker compose build` succeeds.

### M0.4 — Documentation sync
- Update `Project.md` (or replace it) — the "visualization / education demo" framing is no
  longer accurate. `README.md` gets a real "what this is / deploy it" section.
- ADR-0001 gets a header note: the plugin architecture is unchanged, but the demo context
  it was written in is retired; see this plan.
- **Acceptance:** no doc still describes the mock servers or scenario buttons as current.

---

## M1 — Real proxy

### M1.1 — Downstream MCP session lifecycle — **done** (`MCP.Session`, `MCP.SessionStore`)
- Handle `initialize` / `notifications/initialized` from the downstream client: protocol
  version check, capability negotiation, `serverInfo` passthrough from the upstream.
- Issue proxy-owned `mcp-session-id` values; never trust the inbound header as identity.
  Maintain a `proxy_session ↔ {upstream_server, upstream_session}` map.
- Session table: TTL, idle GC, explicit teardown on `notifications/cancelled` / transport
  close; hard cap on table size with oldest-idle eviction + audit row on eviction.
- Reject `tools/call` (and every non-handshake method) that arrives before a completed
  handshake → JSON-RPC error.
- **Files:** new `MCP.Session` + `MCP.SessionStore` (in-memory for M1, Postgres-backed in
  M2.2), `ProxyController` handshake branch, `PolicyEngine.ensure_session/2` keyed on the
  proxy session id.
- **Acceptance:** a real MCP client (e.g. MCP Inspector) completes `initialize` →
  `tools/list` → `tools/call` through the proxy; a `tools/call` with no prior handshake is
  refused; an idle session is GC'd and a later call on it fails closed.
- **Deferred to M1.5:** per-client *upstream* sessions for `:http` servers — the proxy
  still reuses the one upstream `mcp-session-id` captured at registration. `:stdio`
  upstreams share their one process regardless. The downstream session abstraction is in
  place; only the upstream leg is shared.

### M1.2 — Full method coverage — **done** (`MCP.MethodPolicy`, `MCP.ResponseContent`)
- `resources/read`, `prompts/get`: forwarded, then their content is normalised and run
  through the `post_call` scan (redaction + taint accumulation) — resource / prompt content
  is a taint source and an injection surface. `resources/list` / `prompts/list` forward.
- `completion/complete`, `logging/setLevel`, `tools/list`, `resources/*` (list/templates/
  subscribe/unsubscribe) forward. `sampling/createMessage`, `roots/list`,
  `elicitation/create` and every unknown method are **refused** (`-32601`, default-deny).
  `notifications/*` acked (202). `initialize` / `notifications/initialized` / `ping` handled
  directly by the controller.
- **Files:** `MCP.MethodPolicy` (the disposition table), `MCP.ResponseContent` (normalise
  the 3 result shapes ↔ scannable content list), `ProxyController` dispatch generalised
  (`forward_and_scan` replaces the `tools/call`-only `call_and_scan`).
- **Deferred:** routing `resources/list` / `prompts/list` through `discovery` for list-drift
  detection (needs `ServerRegistry` to track+hash resources/prompts like it does tools) —
  folded into M4.1 / a later pass.
- **Acceptance:** `method_policy_test` enumerates every method's disposition;
  `resources/read` / `prompts/get` of content carrying a credential is scanned, the secret
  redacted in place (keeping `uri`/`mimeType`/`role`), and the session tainted; unknown and
  server→client methods refused; no method reaches an upstream without an explicit decision.

### M1.3 — Real streaming transport — **done** (`MCP.StreamProxy`)
- Scanned methods (`tools/call`, `resources/read`, `prompts/get`) against a `:http` upstream
  read the response body **incrementally** through `MCP.StreamProxy` and run
  `Pipeline.run_chunk/2` over each real socket slice (JSON body or SSE frames — content-type
  detected). A `chunk`-phase `deny` stops the read (`{:halt}` from the `Req` `into`
  collector), the rest of the payload never crosses, the client gets `-32002`, and a
  `:blocked` audit row is written with the byte count.
- Backpressure: a per-stream **buffer ceiling** (`max_buffer_bytes`, default 8 MB) and a
  **stream deadline** (`deadline_ms`, default 30 s), both enforced in `StreamProxy.feed/2`
  independent of any plugin.
- `chunk` → session-taint: `Pipeline.run_chunk/2` now returns `taint_sources`; `StreamProxy`
  accumulates them and the controller folds them into the session via
  `record_response_scan`.
- **Files:** `MCP.StreamProxy`, `ProxyController.forward_and_scan` / `fetch_streamed`,
  `Pipeline.run_chunk` return shape (+ `pipeline_chunk_test`), `MCPHTTPTestServer` gained a
  chunked large-response tool.
- **Not done (deferred):** downstream SSE passthrough and progress-notification relay — the
  client still gets one JSON response (or one error), never a partial. Real MCP `tools/call`
  results are not chunked at the content level, so incremental *inspection* + early cut is
  the security-relevant part; downstream streaming + the standalone GET SSE endpoint are a
  separate surface (revisit if a real client needs server→client messaging).
- **Acceptance:** `stream_proxy_test` + `proxy_streaming_test` — a small response reassembles
  and still runs `post_call`; `StreamGuard` (500-byte test budget) cuts a ~20 KB chunked
  response to `-32002` mid-transfer; the buffer ceiling stops a flood before any verdict;
  the tool-chaining policy still fires across streamed calls.

### M1.4 — Authentication & authorization — **done** (`MCP.ApiKey`, `Plugs.ApiKeyAuth`)
- **Downstream client auth: signed API keys.** `Authorization: Bearer mcpk_<id>.<secret>`;
  only `sha256(secret)` stored (the secret is 256 bits of entropy — nothing to brute-force —
  compared constant-time via `Plug.Crypto.secure_compare`). `Plugs.ApiKeyAuth` on the
  `:mcp_api` pipeline: no unauthenticated path to `POST`/`DELETE /mcp/proxy/:server_id`
  (`401` + `WWW-Authenticate: Bearer`). Issued/revoked from the dashboard "Client keys"
  panel; `MCP.ApiKey.issue/1` is also callable from IEx / a release.
- **Agent identity** is a property of the key (`agent_id`, required at issuance) — the
  `mcp-agent-id` header is gone. Captured onto the session at `initialize`, threaded into
  every `CallContext` / audit row.
- **Authorization:** each key carries `all_servers` or an explicit `granted_server_ids`
  list. Checked at `initialize` (`403`-equivalent JSON-RPC error) and re-checked on every
  request in `with_session` (a mid-session revoke takes effect at once). A session is also
  bound to its `key_id` — another key cannot drive it.
- **Dashboard + `/dev`** sit behind HTTP Basic auth (`config :phoenix_elxir_beam,
  :dashboard_auth`, from `DASHBOARD_USER` / `DASHBOARD_PASSWORD` in prod). **Full session
  login + RBAC roles (`viewer`/`operator`/`admin`) deferred to M3.4** (runtime policy
  management, which already owns operator-facing controls + change auditing).
- **Files:** `MCP.ApiKey` (schema + context), `20260829160900_create_api_keys` migration,
  `PhoenixElxirBeamWeb.Plugs.ApiKeyAuth`, router pipeline split (`:mcp_api`,
  `:dashboard_auth`), `Session.key_id`, an internal boot-time `mcpk_dashboard` key for the
  dashboard's manual "Call tool" flow, `test/support/mcp_proxy_helpers.ex`.
- **Acceptance:** `api_key_test` + the auth/authz sections of `proxy_controller_test` —
  no token / bogus token / revoked key → `401`; a key not granted the target server →
  refused at `initialize`; a session used by a different key → refused; agent id in the
  broadcast/audit event comes from the key, not a header. `curl` verified: dashboard +
  `/dev` `401` without Basic auth, proxy `401` without a bearer, `/health` open.

### M1.5 — Transport hardening — **done** (`MCP.RateLimiter`, `Plugs.RequestLimits` / `RateLimit`)
- **Proxy endpoint limits** — `Plugs.RequestLimits` rejects a body over `max_body_bytes`
  (default 1 MiB) with `413` *before* it is buffered; `Plug.Parsers` has a 2 MB backstop;
  `runtime.exs` pins Bandit `max_header_length` + Thousand Island `max_connections`.
- **Per-principal rate limiting** — `MCP.RateLimiter`: fixed-window counter per
  `{key_id, window}` in a `write_concurrency` ETS table via atomic `:ets.update_counter`,
  swept periodically. `Plugs.RateLimit` (after `ApiKeyAuth`, keyed on the authenticated
  `key_id`) → `429` + `Retry-After` over budget (config `window_ms` / `max_per_window`).
- **Upstream `:http`** — TLS verification is on by default (Req/Finch against the system CA
  store); `HttpTransport.connect_options/0` exposes a `config :upstream_tls_verify, false`
  opt-out for one self-signed dev server, threaded through `discover` / `StreamProxy` /
  `forward_to_upstream`. A single `receive_timeout` constant lives in `HttpTransport`.
- **TLS termination** — `runtime.exs` gains an env-driven `https` listener
  (`SSL_CERT_PATH` / `SSL_KEY_PATH`, `cipher_suite: :strong`); the reference Compose setup
  puts a reverse proxy in front instead. `prod.exs` `force_ssl: [hsts: true, …]` with
  `/health` and loopback excluded.
- **Deferred:** per-server `timeout_ms` / `tls_verify` in the registration record (waits on
  M2.2's durable `ServerRegistry`); retry-with-jitter (a POST retry can double-execute a
  `tools/call` — needs per-method safety classification first); explicit Finch pool tuning
  (Req's default pool is adequate at single-node scale).
- **Acceptance:** `rate_limiter_test` + `proxy_controller_test` — a 1.2 MB body → `413`
  before parsing; a key over a 2/window budget → `429` + `Retry-After ≥ 1`; separate keys
  have separate budgets; a new window resets.

---

## M2 — Survivable

### M2.1 — SQLite → Postgres — **done**
- `docker-compose.yml`: `postgres:17-alpine` service with `pg_data` named volume,
  `pg_isready` healthcheck; `app` has `depends_on: {postgres: {condition: service_healthy}}`
  and gets a `DATABASE_URL` built from `POSTGRES_*`.
- `{:ecto_sqlite3}` → `{:postgrex}`; `Repo` adapter → `Ecto.Adapters.Postgres`. All four
  migrations ran clean on PG unchanged (`{:array, :string}` / `{:array, :map}` / `:binary` /
  `:text` map natively). `runtime.exs`: `url: DATABASE_URL` (required in prod) + `pool_size`,
  `queue_target` / `queue_interval`, `statement_timeout` parameter, optional `:inet6`.
  dev/test read discrete `PG*` env with `postgres:postgres@localhost:5432` defaults.
- `event_log_test` + `event_log_sink_test` back to `async: true` (the SQLite single-writer
  serialisation is gone). The proxy endpoint suites stay `async: false` — unrelated: the
  Bandit request process needs the shared sandbox connection to read `api_keys`.
- `Dockerfile`: dropped `build-essential` (postgrex is pure Elixir), the `/data` volume, and
  `DATABASE_PATH`. `docker-entrypoint.sh` already runs `Release.migrate()` before `start`.
- **Verified:** `PGPORT=5433 mix test` green (248) against a real Postgres 17; migrations
  create + apply clean.

### M2.2 — Durable session / taint / registry state

**M2.2a — PolicyEngine session state → Postgres — done** (`MCP.PolicyStore`, `MCP.PolicySession`)
- Write-through cache: `PolicyEngine` keeps its in-memory `sessions` map; `policy_sessions`
  (session_id PK, `agent_id`, `tags`, `taint`, `call_count`) is the source of truth. A
  `record_call` / `ensure_session` / `record_response_scan` for a session not in the cache
  **rehydrates it from Postgres** before deciding; only a session unknown to both fails
  closed. Persist is fail-soft (logged, not raised).
- **Not persisted:** the 60 s `call_log` (ephemeral, `BaselineGuard` re-warms) and the raw
  `secret` bytes on a taint source (stripped on write — `TaintedArgGuard`'s byte match
  degrades to `TaintGuard`'s coarse check for a restart-recovered session until M4.1).
- Consistency model: single-node, so "prior call on another node" is out of scope; the
  requirement is **restart survival**, which the write-through cache gives. `PolicyEngine`
  runs an hourly sweep of `policy_sessions` rows idle > 24 h (backstop for `SessionStore`'s
  GC → `drop_session/2` → row delete).
- **Acceptance:** `policy_engine_durability_test` — kill + restart the engine, then a
  `tools/call` on a pre-restart session still sees its tag / taint and is blocked; the
  persisted row holds strings, never the raw secret; `drop_session` deletes the row; the
  sweep removes stale rows.

**M2.2b — ServerRegistry → Postgres — done** (`MCP.ServerStore`, `MCP.ServerRegistration`)
- `server_registrations` table: identity + connection (`base_url`, or `command` / `args` for
  stdio) + a per-tool `tool_state` overlay (`tags`, `quarantined`, `quarantine_reason`,
  pinned `hash`). Fresh tool descriptions/schemas always come from the live handshake — only
  the overlay is stored.
- `put_and_broadcast` persists write-through; `remove_server` deletes. `ServerRegistry.init`
  returns `{:continue, :restore}` → reload every record, re-handshake `:http` /
  re-spawn `:stdio`, merge the overlay back by name, re-run the discovery scanners against
  the pinned hashes. An unreachable server on boot is logged and skipped (record kept), not
  fatal. All DB calls fail-soft.
- **Acceptance:** `server_registry_durability_test` — an `:http` server + its operator tags,
  and a re-spawned `:stdio` server + its quarantine, survive a registry restart;
  `remove_server` deletes the row; an unreachable server on boot doesn't crash the registry.

**Deferred:** `SessionStore` (the MCP-handshake session table) → Postgres — lower value, a
restart drops the client connection anyway; `HoldRegistry` persistence — a restart already
fails parked holds closed; plugin `Registry` toggle state → **M3.4** (bundled with its UI).

### M2.3 — Audit durability & tamper-evidence — **done** (`MCP.AuditIntegrity`, `MCP.AuditCheckpoint`)
- **Scheduled verification + alerting** — `MCP.AuditIntegrity` GenServer runs
  `EventLog.verify_chain/0` every `interval_ms` (default 15 min) and compares the live head
  against the newest checkpoint. On failure: a structured `mcp.audit.integrity` error line
  (for the SIEM) + `{:audit_integrity, :broken, detail}` on the `"mcp:audit"` PubSub topic →
  a red banner on the dashboard. `status/0` + `check_now/0` (the "verify audit chain" button
  routes through this).
- **Off-DB checkpoint anchoring** — `MCP.AuditCheckpoint` appends a signed
  `{event_id, hash, count, verified_at, HMAC}` line to a file on a volume separate from
  Postgres (`AUDIT_CHECKPOINT_KEY` / `AUDIT_CHECKPOINT_PATH`, a `checkpoints` compose
  volume). Catches a **truncated** log that still verifies internally (count drop, or a
  checkpointed head hash that is gone); a forged checkpoint fails the HMAC and is ignored.
- New `EventLog.head/0` + `hash_present?/1`; `EventLog.record` chain semantics unchanged.
- **Deferred:** retention / archival — deleting old rows breaks `verify_chain` from genesis,
  so it needs an anchor-aware verifier (start from a signed retention anchor). Small
  follow-up; the external log shipper (M3.2) covers long-term retention meanwhile.
  `verify_chain` also still loads every row into memory — verify-from-checkpoint is the
  scaling fix, same follow-up.
- **Acceptance:** `audit_integrity_test` — a tampered row is caught, a truncated-but-valid
  log is caught via the checkpoint, a forged checkpoint is ignored, `status` reports the last
  result, a clean chain writes a fresh checkpoint.

---

## M3 — Operable

### M3.1 — CI/CD — **done** (`.github/workflows/`, `docs/ci-cd.md`)
- `ci.yml`: on every PR + push to `main`/`master` — `deps.unlock --check-unused`,
  `format --check-formatted`, `compile --warnings-as-errors`, `mix deps.audit`, `mix test`
  (against a `postgres:17` service container), plus `mix dialyzer` in a parallel job. Deps +
  `_build` + PLT are cached on `mix.lock`. Elixir/OTP pinned to the Dockerfile args.
- `release.yml`: on a `v*` tag — `docker/build-push-action` builds the runtime image and
  pushes it to `ghcr.io/<owner>/<repo>` (`:<version>`, `:<major>.<minor>`, `:latest`) with
  GHA layer cache.
- `security-review.yml`: PR touching `mcp/**` / `priv/plugins/**` / `config/**` →
  `anthropics/claude-code-security-review`, posted as PR comments. Job is skipped unless an
  `ANTHROPIC_API_KEY` repo secret exists (forks/clones stay green).
- New deps `:mix_audit` + `:dialyxir` (`only: [:dev, :test], runtime: false`); `mix ci`
  alias = the local equivalent of the gate; `dialyzer` config in `mix.exs` (PLT →
  `priv/plts`, gitignored). Deploy + rollback commands documented in `docs/ci-cd.md`.
- **Deferred:** branch-protection *enforcement* of the checks is a repo setting, not code;
  auto-deploy onto the node (no server access from CI) — deploy stays a documented manual
  `docker compose pull && up -d` on the host.
- **Acceptance:** a red `mix test` / `dialyzer` fails the `CI` workflow; a `v*` tag produces
  a pushed GHCR image; `docs/ci-cd.md` has the one-command rollback (`docker compose pull
  app && up -d app` on the prior tag).

### M3.2 — Observability — **done** (`MCP.Telemetry`, `MCP.Alerts`, `MCP.Health`, `docs/observability.md`)
- Metrics: `telemetry_metrics_prometheus_core` reporter in `PhoenixElxirBeamWeb.Telemetry`,
  scraped as Prometheus text at `GET /metrics` (`MetricsController`, optional `METRICS_TOKEN`
  bearer). `MCP.Telemetry` defines the `[:mcp, ...]` event taxonomy; the pipeline emits
  per-phase spans (`mcp_pipeline_run_stop_duration` by phase/verdict) + per-plugin spans
  (`mcp_plugin_run_stop_duration` by plugin/phase/outcome ok|timeout|crash|bad_return);
  the proxy controller emits `mcp_upstream_request_stop_duration` (transport/outcome);
  `mcp_decision_count`, `mcp_alert_count`; poller gauges `mcp_sessions_count` /
  `mcp_holds_pending` / `mcp_servers_{count,unreachable}`.
- Health split: `GET /health/live` (process-only, compose healthcheck) + `GET /health/ready`
  (`MCP.Health` — `SELECT 1` + concurrent upstream probe; 503 + JSON detail; upstream
  strictness via `READINESS_REQUIRE_UPSTREAMS`). `/health` kept as a live alias.
- Alerts: `MCP.Alerts.emit/3` — structured `mcp.alert` log line + `"mcp:alerts"` PubSub →
  dashboard amber banner + `mcp_alert_count` counter. Keys: `audit_integrity` (wired from
  M2.3), `plugin_fail_open`, `sidecar_circuit_open`, `upstream_unreachable` (probe
  transition, deduped via `:persistent_term`). **No Alertmanager/webhook/email** — routing
  is left to log consumers / the Prometheus rules (locked decision).
- Compose: `compose.observability.yml` overlay (prometheus + grafana),
  `deploy/prometheus/{prometheus.yml,alert.rules.yml}`, `deploy/grafana/provisioning/`.
- **Deferred:** Grafana dashboard JSON not checked in; Loki/promtail overlay (structured
  logs are SIEM-ready, shipping is deployment-specific); OTLP exporter (Prometheus chosen).
- **Acceptance:** `metrics_controller_test` (`/metrics` renders the MCP series, token gate),
  `health_controller_test` (live 200 always; ready 200, and 503 with per-upstream detail
  when a stdio upstream is killed), `alerts_test`, `pipeline_telemetry_test` (phase +
  per-plugin + decision events, `:timeout` outcome). Suite green at 271.

### M3.3 — Load & latency — **done** (`bench/load.exs`, `docs/latency-budget.md`, `load.yml`)
- `bench/load.exs` — Elixir `Task.async_stream` driver (user's choice over k6). Boots the
  app with the endpoint serving (watchers/reloader stripped so it runs under `MIX_ENV=dev`
  in CI), registers the stdio catalog fixture, issues one key per worker, drives the full
  session lifecycle (initialize → N × tools/call → DELETE) over real HTTP with `Req`.
  Reports end-to-end percentiles + per-phase latency read from the
  `mcp_pipeline_run_stop_duration` / `mcp_upstream_request_stop_duration` histograms.
- **Budget:** `pipeline pre_call` p99 ≤ **10 ms** at 50 concurrent sessions (measured ≤ 1 ms
  — generous headroom for CI noise). Enforced by the driver with `LOAD_ENFORCE=true`.
- **Finding:** the policy pipeline is *not* the bottleneck (<1 ms p99). End-to-end latency
  (~230 ms p50 @ 50 conc) is per-request DB work outside the pipeline — `ApiKeyAuth`
  SELECT, `PolicyEngine.record_call` write-through, the serial audit-chain INSERT
  (`EventLogSink`), `SessionStore` GenServer. Documented in `docs/latency-budget.md`.
- **Deferred:** decision cache (pipeline already fast — buys nothing); the flagged
  follow-up is a short-TTL **API-key auth cache** (one DB round-trip per request);
  HTTP sidecar transport (stdio sidecars fine at this scale).
- `.github/workflows/load.yml` — nightly (04:00 UTC) + `workflow_dispatch`, **non-blocking**
  (publishes numbers to the run summary; fails only on >1% error rate).
- **Acceptance:** `bench/load.exs` runs green locally at 20/30/50 concurrent; the nightly
  workflow publishes results; budget documented.

### M3.4 — Runtime policy management

Decisions (2026-08-30): full session login + RBAC (not a Basic-auth role gate); **no**
approval flow — apply immediately + audit + one-click rollback; secrets → Docker Compose
secrets (not an external manager).

**M3.4a — Operator accounts + RBAC — done** (`PhoenixElxirBeam.Accounts`, `UserAuth`)
- `users` + `user_tokens` tables; `Accounts.User` (`viewer < operator < admin`, `pbkdf2`
  hashed — pure Elixir, no NIF), `Accounts.UserToken` (opaque 32-byte session tokens,
  30-day validity, deleted on logout / user-disable). `Accounts` context: create / role /
  password / disable / delete, session-token round-trip, `role_at_least?/2`, `seed_admin/0`
  (from `ADMIN_EMAIL` / `ADMIN_PASSWORD` when the table is empty, run as a boot Task).
- `PhoenixElxirBeamWeb.UserAuth` — `fetch_current_user`, `require_authenticated_user`,
  `require_admin` / `require_operator`, `redirect_if_user_is_authenticated`, `log_in_user` /
  `log_out_user` (broadcasts `disconnect` to the LiveView socket), `on_mount` hooks.
  `SessionController` + `SessionHTML` login page. Router: `/login` `/logout`, dashboard
  behind `:require_authenticated` + `live_session` `:ensure_authenticated`, `/dev` behind
  `:require_admin_role`. HTTP Basic auth (`:dashboard_auth`, `DASHBOARD_*`) removed; the
  internal `mcpk_dashboard` API key (manual Call-tool flow) is unrelated and stays.
- Dashboard header shows the signed-in email + role + a log-out link.
- **Tests:** `accounts_test` (hashing, uniqueness, disable kills sessions, seed idempotence),
  `user_auth_test` (login rejects bad creds, real login sets a token, anon → `/login`,
  authed reaches the dashboard, logout clears the token, `require_admin` gate). Suite 284.

**M3.4b — plugin registry runtime control + persistence — done**
- `plugin_states` table + `Plugin.PluginState` + `Plugin.StateStore` (write-through, all
  fail-soft). `Plugin.Registry` gained `persist?` (true only for the singleton): on boot
  `handle_continue` overlays persisted `enabled` + `position` on the config defaults;
  `set_enabled` / `reorder` write through. Dashboard Plugins panel gained `operator`-gated
  enable/disable + ▲▼ reorder controls (`with_operator/2` gate; read-only banner for
  viewers). Tests: `plugin_state_persistence_test`.

**M3.4c — policy-change auditing + rollback — done**
- `MCP.PolicyChange.record/1` → routes through `PolicyEngine.record_policy_change/2` (a new
  `:policy_change` Event status) so it lands on the same serial `EventLog` hash chain as
  verdicts; stores `actor / kind / target / before → after` in the row's `decisions`.
  Broadcasts `{:policy_change, _}` on `"mcp:policy"`. Every dashboard mutating op
  (plugin toggle/reorder) records one. `PolicyChange.recent/1` + a "Policy changes"
  dashboard panel with per-change **revert** (plugin_enabled / plugin_order). Tests:
  `policy_change_test` (chain stays valid, broadcast, recent/summary).

**M3.4d — Docker Compose secrets — done**
- `SECRET_KEY_BASE` / `AUDIT_CHECKPOINT_KEY` / Postgres password are Docker secret files
  (`secrets/*.txt`, gitignored) mounted at `/run/secrets/*`. `runtime.exs` `fetch_secret/1`
  reads the file, falling back to the env var. `DATABASE_URL` is built from `POSTGRES_*` +
  the password secret when unset. `docker-compose.yml` `secrets:` block; postgres uses
  `POSTGRES_PASSWORD_FILE`. `.env.example` / README updated.
- **Fixed in passing:** `config/prod.exs` `force_ssl: [exclude: fn …]` — Plug 1.20's
  `Plug.SSL` requires `:exclude` to be a list, not a function; the prod build had not
  compiled since the plug bump. Now `exclude: [hosts: […], paths: […]]`. Added a
  `MIX_ENV=prod mix compile --warnings-as-errors` step to `ci.yml`.

- **Acceptance:** an operator disables a plugin from the dashboard and the next call
  reflects it, with an audit row naming the operator; reverting the change from the change
  log restores prior behaviour; no signing secret is readable in `docker inspect` /
  `.env` on the host.

### M3.5 — Plugin supply chain — **done** (`MCP.Plugin.Provenance`, `docs/plugin-supply-chain.md`)
- **Provenance pinning:** `Provenance.verify/2` computes a **code digest** (command string +
  sha256 of each arg that resolves to a real file — the plugin script/binary, path-independent)
  and a **manifest digest** (canonical JSON of the handshake `Manifest`). A sidecar spec's
  `pin: [code:, manifest:]` is checked in `SidecarRunner.init` after handshake: mismatch →
  `{:stop, {:provenance_mismatch, _}}` + a `:sidecar_provenance` **critical** alert, the
  plugin stays down; unpinned → starts but `warning`-logs the computed digests. `prod.exs`
  ships the prompt-injection sidecar pinned (`code:`).
- **Resource limits:** `limits: [as_mb:, cpu_s:, nproc:]` on a sidecar spec wraps the command
  in `prlimit` (util-linux, added to the Dockerfile runner) — kernel-enforced address-space /
  CPU-time / process caps. Best-effort (no-op + `warning` where `prlimit` is absent).
  Container-per-sidecar documented as the production-grade path for third-party sidecars.
- **Dependency audit gate:** `ci.yml` runs `mix deps.audit` (advisories) + `mix hex.audit`
  (retired packages) on every PR; both also in `mix ci`. Lockfile review expectation
  documented.
- **Deferred:** signing the release *image* hash itself (that's a registry/cosign concern,
  not app code); a runtime "re-verify now" button (the check is startup-only — a running
  sidecar's script can't change under it without a restart).
- **Acceptance:** `plugin_provenance_test` — code digest is content-sensitive + stable,
  manifest digest stable, matching pin starts / wrong pin refuses via `SidecarRunner` with
  the alert; `mix hex.audit` + `mix deps.audit` green. Suite 294.

---

## M4 — Close mission gaps

### M4.1 — Taint fidelity (HMAC markers)
- Replace the retained-raw-secret substring match with real HMAC markers: HMAC the secret
  under a per-session key, store only the marker, match by tokenising call arguments and
  HMACing candidates. Defeats base64 / encoding / chunking / reformatting evasion.
- Taint sources from `resources/read` and `prompts/get` content (**depends on M1.2**).
- `chunk` → taint accumulation (**done in M1.3**).
- **Files:** `MCP.TaintMarker`, `SecretLeak` + `TaintGuard` + `TaintedArgGuard` rewritten
  against markers, per-session key in `SessionStore`.
- **Acceptance:** a secret leaked then re-sent base64-encoded in a later call's arguments is
  caught; the raw secret is never persisted or held in memory beyond the marking step.

### M4.2 — Default-deny posture
- Discovered tools start untagged, so most policies are inert until an operator curates
  tags. Add a default-deny mode: an untagged tool is denied (or held) until classified.
- Tag inference at discovery time (name + description heuristics, optionally a classifier)
  to make curation tractable.
- **Files:** `Pipeline.run_discovery/2` default-deny flag, `MCP.TagInference`,
  dashboard "unclassified tools" queue.
- **Acceptance:** with default-deny on, a newly discovered untagged tool is held on first
  call until an operator classifies it; tag suggestions are shown at discovery.

### M4.3 — Scanner quality
- The prompt-injection scanner is a demo-grade matcher. Decide the real approach:
  maintained ruleset, ML classifier, or a dedicated service. Set a false-positive budget
  and measure against a labelled corpus.
- **Acceptance:** a documented detection approach with measured precision/recall on a test
  corpus; the false-positive rate is within budget on a benign traffic sample.

### M4.4 — Documentation
- **Threat model:** what this proxy defends against and what it explicitly does not
  (single-node availability, untrusted plugins, side channels, a compromised upstream after
  handshake, …).
- **Operator runbook:** deploy, register a server, assign tags, respond to each alert type,
  investigate an audit-chain failure, roll back.
- **Deployment guide:** reference compose topology, sizing (Postgres, app memory, sidecar
  count), network placement (where the proxy sits relative to agents and MCP servers), TLS
  setup.
- **Acceptance:** a new operator can deploy and register a server from the guide alone; each
  alert in M3.2 has a runbook entry.

---

## Dependency graph

```
M0 ─┬─> M1.1 ─┬─> M1.2 ──────────────> M4.1, M4.2
    │         ├─> M1.3 ──────────────> (taint accum done here)
    │         └─> M1.4 ─> M1.5 ─┐
    │                            ├─> M2.1 ─> M2.2 ─> M2.3
    └────────────────────────────┘             │
                                               ├─> M3.1
                                               ├─> M3.2 ─> M3.3
                                               ├─> M3.4  (needs M2.2 + M1.4 RBAC)
                                               └─> M3.5
M3.2 alerting ──> M2.3 alerting hook
M4.3, M4.4 ── no hard deps; M4.4 threat model best written after M1–M3
```

## Definition of done ("productionized")

- No mock / demo / simulation code in `main`.
- Every proxy request is authenticated and authorized; agent identity is cryptographic.
- Full MCP method coverage with a documented decision per method.
- Real streaming passthrough with an enforced latency budget.
- Session, taint, hold, and registry state survive `docker compose restart`.
- Audit chain is checkpointed off-DB and verified on a schedule with alerting.
- One-command deploy + one-command rollback, migrations automatic.
- Metrics scraped, dashboards live, alerts wired.
- Policy changeable at runtime by an authorized operator, every change audited.
- Threat model, operator runbook, and deployment guide published.
