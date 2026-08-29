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

### M1.2 — Full method coverage
- `resources/list`, `resources/read`, `resources/subscribe`: route through `discovery`
  (list-drift) and a `post_call`-equivalent content scan — resource content is a taint
  source and an injection surface.
- `prompts/list`, `prompts/get`: same treatment.
- `completion/complete`, `logging/setLevel`, `roots/*`, `notifications/*`,
  `sampling/createMessage`: one documented decision per method — forward / police / refuse
  — in a single `method_policy/1` table, not scattered `case` fallthrough.
- **Files:** `ProxyController` method dispatch → `MCP.MethodPolicy`; `Pipeline` phases
  generalised so `post_call` scanning is not `tools/call`-only.
- **Acceptance:** a table test enumerating every MCP method asserts the routed behaviour;
  `resources/read` of a doc containing a hidden-instruction block is scanned and the block
  redacted; no method reaches an upstream without an explicit decision.

### M1.3 — Real streaming transport
- Replace the removed simulation with Streamable-HTTP / SSE passthrough: stream upstream →
  `Pipeline.run_chunk/2` per real SSE event → stream downstream. Bandit supports chunked
  responses; use `Plug.Conn.chunk/2` or a `Stream` sink.
- Backpressure: bounded buffered bytes per stream; the request deadline applies across the
  whole stream, not per chunk; handle upstream disconnect mid-stream (flush what's
  delivered, audit, close).
- A `chunk`-phase `deny` closes the downstream connection cleanly + writes a `:blocked`
  audit row — not an appended text notice.
- `chunk` → session-taint accumulation (was deferred; wire it here).
- **Files:** new `MCP.StreamProxy`, `ProxyController` streaming branch, `HttpTransport`
  gains an SSE-aware request mode, `PolicyEngine.accumulate_taint/3` called from the chunk
  fold.
- **Acceptance:** a real streaming tool response passes through chunk-by-chunk with
  measured added latency < budget; `StreamGuard` cuts a 1 MB response after ~2 KB and the
  client sees a closed connection; killing the upstream mid-stream produces a clean
  downstream close + audit row.

### M1.4 — Authentication & authorization
- **Downstream client auth: signed API keys** (decided 2026-08-28). Ed25519 or HMAC-SHA256,
  `key_id` + secret, presented as `Authorization: Bearer <key_id>.<secret>`; keys stored
  hashed (Argon2/bcrypt) in Postgres, issued/revoked via the admin API + dashboard. mTLS
  stays available as an opt-in in front of the app via a reverse-proxy compose service, not
  built into Bandit. OAuth2/OIDC is out of scope. No unauthenticated path to
  `POST /mcp/proxy/:server_id`.
- **Agent identity:** replace the trusted `mcp-agent-id` header with a signed token (JWT or
  PASETO) or a value derived from the client cert. Every `RuleEngine` / audit-attribution
  path depends on this.
- **Authorization:** a `principal → [server_id]` grant table — which authenticated caller
  may reach which registered server.
- **Dashboard + `/dev` routes:** move behind auth (session login + RBAC roles
  `viewer` / `operator` / `admin`). `/dev` LiveDashboard = `admin` only.
- **Files:** new `MCPWeb.Auth` plug pipeline, `MCP.ApiKey` + `MCP.Principal` schemas,
  `MCP.AgentToken` verifier, router pipeline split (`:mcp_authed`, `:dashboard_authed`),
  `RRBAC` on LiveView `on_mount`.
- **Acceptance:** every proxy request without a valid key → `401`; a valid key for
  principal A calling a server only granted to principal B → `403` + audit row; the
  dashboard redirects anonymous users to login; agent id in audit rows is
  cryptographically bound, not caller-asserted.

### M1.5 — Transport hardening
- TLS: terminate at the `app` container (Bandit `https` keyfile/certfile from
  `runtime.exs`) **or** document a reverse-proxy (Caddy/nginx) compose service doing it.
  `force_ssl: [hsts: true]`.
- Limits on the proxy endpoint: request body size, header count/size, max concurrent
  connections, per-principal rate limit (distinct from `ResponseSizeGuard` / `BaselineGuard`
  which police tool semantics, not HTTP).
- Upstream `:http` / `:stdio` transports: connection pooling (Finch pool for `:http`),
  retry policy with jitter, TLS cert verification **on** for upstream `:http`, per-server
  connect/receive timeouts from `ServerRegistry` config.
- **Files:** `Endpoint` plug additions, new `MCP.RateLimiter` (token bucket in ETS, or
  `Hammer`), `HttpTransport` / `StdioServer` pool + retry config, `ServerRegistry` schema
  gains `timeout_ms` / `tls_verify`.
- **Acceptance:** a 100 MB request body is rejected before buffering; a principal over its
  rate limit gets `429` + `Retry-After`; an upstream with a self-signed cert is refused
  unless explicitly trusted in its registration; `nmap`/`testssl` against the endpoint
  shows TLS-only + HSTS.

---

## M2 — Survivable

### M2.1 — SQLite → Postgres
- Add a `postgres` service to `docker-compose.yml` (named volume, healthcheck, pinned
  major version). `app` waits on `postgres` healthy.
- Migrate `Repo` to `Ecto.Adapters.Postgres`; port every migration; `DATABASE_URL` in
  `runtime.exs`; pool size, `queue_target` / `queue_interval`, statement timeout.
- Revisit the `async: false` test suites forced by SQLite's single writer — most can go
  back to `async: true` under the SQL sandbox.
- Deploy migration strategy: `bin/phoenix_elxir_beam eval "Release.migrate()"` runs in the
  entrypoint before the app boots (already partly present in `docker-entrypoint.sh` — point
  it at Postgres).
- **Acceptance:** `mix test` green with Postgres, most suites `async: true`;
  `docker compose up` brings up Postgres then app then passes healthcheck; a migration runs
  automatically on deploy.

### M2.2 — Durable session / taint / baseline / registry state
- Move `PolicyEngine` per-session state (`tags`, `taint` provenance, `call_log`,
  `call_count`) out of GenServer memory into Postgres (write-through: GenServer keeps a
  cache, Postgres is the source of truth). A `tools/call` decision **must** see this
  session's own prior taint after a proxy restart.
- `HoldRegistry`: parked calls persisted. On restart, a parked hold is either re-driven or
  fails closed per its `on_timeout`. (Single-node, so "operator on node B" from the ADR
  doesn't apply — but restart survival does.)
- `ServerRegistry`: registered servers persisted in Postgres + optionally seeded from
  config at boot. No more hand re-registration after every deploy. This replaces the
  removed preset buttons (M0.3).
- Plugin `Registry`: runtime enable/disable/reorder state persisted (feeds M3.4).
- **Files:** `MCP.SessionStore` Postgres impl, `sessions` / `session_taint` /
  `session_calls` tables, `MCP.Hold` schema, `MCP.Server` schema + `ServerRegistry` load
  path, `MCP.PluginState` schema.
- **Acceptance:** `docker compose restart app` mid-session → the next `tools/call` on that
  session still sees prior taint and is blocked accordingly; a registered server survives a
  restart; a parked hold survives a restart or resolves per `on_timeout`.

### M2.3 — Audit durability & tamper-evidence
- Audit records written to append-only storage in addition to Postgres: an external log
  stream (M3.2 `StructuredLogSink` → shipper) **or** a WORM object-store sink. At minimum,
  the hash chain is checkpointed: every N events or T minutes, write
  `{last_hash, count, timestamp, signature}` to a separate volume / object store so a
  Postgres compromise can't silently rewrite history.
- `EventLog.verify_chain/0` runs on a schedule (`Oban` cron or a `GenServer` timer) with
  alerting on failure — not just a dashboard button.
- Retention / rotation / export policy: documented, and enforced by a scheduled job
  (archive events older than X to cold storage, keep the chain contiguous).
- **Files:** new `MCP.Plugins.CheckpointSink` (or extend `EventLogSink`),
  `MCP.ChainVerifier` scheduled job, `MCP.AuditRetention` job, alert hook (M3.2).
- **Acceptance:** tampering with a `policy_events` row in Postgres is caught by the next
  scheduled `verify_chain` and raises an alert; a checkpoint file exists off the app DB and
  matches the chain head; events past the retention window are archived, not deleted
  in-place.

---

## M3 — Operable

### M3.1 — CI/CD
- CI pipeline (GitHub Actions or equivalent): `mix precommit` + `mix test` +
  `mix deps.audit` + `mix dialyzer` + the `security-review` step on every PR touching
  `lib/phoenix_elxir_beam/mcp/`.
- Release automation: build + push the image on tag; `docker compose pull && up -d` with
  the migration step; rollback = redeploy the previous image tag (document the exact
  commands in the runbook, M4.4).
- **Acceptance:** a red `mix test` blocks merge; a tagged commit produces a pushed image;
  a documented one-command rollback restores the previous version.

### M3.2 — Observability
- Metrics exporter: `TelemetryMetricsPrometheus` (scrape endpoint) **or** an OTLP exporter,
  fed from the existing `telemetry_metrics`. Series: per-phase pipeline latency
  (p50/p99), verdict counts by plugin, plugin failure / circuit-breaker state, session
  table size, hold-queue depth, upstream request latency + error rate.
- Optional compose sidecars: `prometheus` + `grafana` + `loki` + `promtail`, or point at an
  external stack. `StructuredLogSink` output shipped to Loki / a SIEM; document the JSON
  schema.
- Genuine OTLP `auditSink` (protocol §18 open item) only if the SIEM story needs spans over
  log lines — otherwise `StructuredLogSink` + promtail is enough.
- Readiness probe: checks Postgres + each registered upstream reachable. Liveness: separate,
  process-only. Wire both into the compose healthcheck / an external monitor.
- Alerting rules: circuit breaker opened, `verify_chain` failed, a `fail_open` plugin
  actually fired open, session table growth rate, upstream unreachable.
- **Files:** `MCPWeb.MetricsController` or OTLP exporter in `application.ex`,
  `PhoenixElxirBeamWeb.Telemetry` new metrics, `compose.observability.yml` overlay,
  `HealthController` split into `/health/live` + `/health/ready`, alert rules file.
- **Acceptance:** `/metrics` scrapes clean; a Grafana dashboard shows per-phase latency
  under load; killing an upstream flips `/health/ready` to `503` and fires an alert;
  forcing a `verify_chain` failure fires an alert.

### M3.3 — Load & latency
- Load-test the request path: p50/p99 added latency per phase, behaviour at N concurrent
  sessions, the `Task.Supervisor` fan-out under sustained load, sidecar plugin latency
  under load.
- Establish and enforce a request-path latency budget. If the budget demands it, land the
  decision cache + per-plugin circuit-breaker tuning (protocol §18) here.
- HTTP sidecar transport (protocol §5.2, not built) only if stdio sidecars don't hold up.
- **Files:** `bench/` load scripts (`k6` or a Elixir `Task.async_stream` driver),
  `MCP.Pipeline` decision cache if needed, `docs/latency-budget.md`.
- **Acceptance:** a documented budget (e.g. "< 15 ms p99 added latency at 200 concurrent
  sessions, in-process plugins only"); the load test runs in CI nightly and fails on
  regression; sidecar latency characterised with a go/no-go on HTTP transport.

### M3.4 — Runtime policy management
- Dashboard UI for the plugin `Registry` (protocol §18): enable / disable / reorder /
  re-verify without redeploy — the GenServer already supports the ops, the panel is
  read-only today. State persisted (M2.2).
- Every policy change (plugin toggle, `RuleEngine` rule edit, tag assignment) is itself
  audited into the same tamper-evident chain — who, when, old value, new value.
- A change log with one-click rollback per change; approval flow optional for single-node.
- Secrets: move from `.env` to a secrets manager or at least Docker secrets — no plaintext
  `.env` with `SECRET_KEY_BASE` / API signing keys on the host.
- **Files:** `MCPDashboardLive` plugin-admin panel + `operator` RBAC gate,
  `MCP.PolicyChange` schema feeding an `auditSink`, `MCP.Plugins.RuleEngine` runtime rule
  editing, `docker-compose.yml` secrets block.
- **Acceptance:** an operator disables a plugin from the dashboard and the next call
  reflects it, with an audit row naming the operator; reverting the change from the change
  log restores prior behaviour; no signing secret is readable in `docker inspect` /
  `.env` on the host.

### M3.5 — Plugin supply chain
- Manifest signing (protocol §18): verify sidecar plugin provenance (command + image hash +
  manifest hash recorded at registration, re-verified on start — the mechanism exists for
  MCP servers; extend it to sidecars).
- Resource limits on sidecar subprocesses beyond supervisor restart caps: a container per
  sidecar (compose service) with CPU/memory limits, or cgroup limits on the spawned
  process.
- Pin + audit in-process plugin dependencies (`mix deps.audit` in CI already; add a
  lockfile review gate for `lib/phoenix_elxir_beam/mcp/plugins/`).
- **Acceptance:** a sidecar whose binary hash changed since registration refuses to start +
  alerts; a runaway sidecar is OOM-killed at its limit without affecting the app;
  dependency audit is a CI gate.

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
