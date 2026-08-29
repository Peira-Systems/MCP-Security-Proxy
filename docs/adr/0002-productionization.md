# ADR 0002 — Productionization roadmap

**Status:** Proposed · **Date:** 2026-08-28 · **Supersedes:** —

## Context

The proxy as built through ADR-0001 roadmap step 7j is a **single-node, self-contained
demonstrator**. Much of its design exists to be legible on the dashboard rather than to run
in front of real agent traffic: mock MCP servers, "Run X" scenario buttons, `MockDrift`,
a simulated streaming shape (`result.chunks` reassembled into one reply), in-memory session
state, SQLite, and no authentication on any endpoint.

`Project.md` and ADR-0001 both frame this explicitly as "a visualization / education demo,
not a production security service." This ADR records what would have to change if
**production deployment in front of real MCP traffic** becomes the goal, and in what order.

> **Scope decision required before starting.** Productionization pulls hard against the
> demo goal. The mock servers, scenario buttons, `MockDrift`, and simulated streaming are
> load-bearing for the dashboard narrative, and removing or hiding them is part of Phase 1.
> If both audiences must be served, that is itself a design constraint to settle first
> (e.g. a `demo` runtime profile that keeps the mocks and scenario harness, vs. a `prod`
> profile that disables them). Do not begin Phase 1 until this is decided.

Constraints that shape the plan:

- The proxy is a policy **decision and enforcement point** on the request path of every
  call. Availability, latency, and fail-mode behaviour are security properties, not just
  ops concerns.
- Losing session state (tags, taint provenance, baseline call log) is not a clean restart —
  `PolicyEngine` fails closed on the next call for every affected session
  (`policy_engine.ex`, `record_call/5`). State durability is on the critical path.
- The existing plugin architecture (ADR-0001) is sound and is **not** what this ADR
  changes. This ADR is about everything around it: the transport, identity, state,
  persistence, and operations.

## Decision

Four phases, in order. Each phase is independently shippable and leaves the system in a
more defensible state than it found it. Do not reorder: later phases assume the guarantees
of earlier ones (e.g. Phase 3 load testing is meaningless before Phase 2's real state
store).

### Phase 1 — Make it a real proxy

Goal: the proxy correctly and completely mediates a real MCP client ↔ server session, and
nothing unauthenticated can reach it.

### Phase 2 — Make it survivable

Goal: a restart, a node loss, or an audit-volume spike does not drop session state, lose
audit records, or take the proxy down.

### Phase 3 — Make it operable

Goal: the proxy can be deployed, observed, load-tested, and have its policy changed by an
operator without a redeploy — and every such change is itself audited.

### Phase 4 — Close mission gaps

Goal: the security coverage matches the threat model rather than what was demonstrable.

## Consequences

**Positive**

- A credible security product rather than a portfolio piece.
- The plugin architecture (ADR-0001) carries over unchanged — the investment is preserved.

**Negative / costs**

- Large effort — estimated 3–4 months of focused work across the four phases.
- Diverges from the demo. Either the demo narrative is retired or a dual-profile design is
  carried as ongoing complexity.
- SQLite → Postgres, in-memory state → distributed state, and simulated → real streaming
  are each a rewrite of a subsystem, not an incremental change.

**Neutral**

- `docs/plugin-protocol.md` §18 open items (HMAC markers, real streaming transport, HTTP
  sidecar transport) are folded into the phases below rather than tracked separately.

---

## Phase 1 — Make it a real proxy

### 1.1 MCP session lifecycle (downstream client side)
- [ ] Handle `initialize` / `initialized` from the downstream client: capability
      negotiation, protocol-version check, server-info passthrough.
- [ ] Issue and track proxy-owned `mcp-session-id` values instead of trusting the header;
      map proxy session ↔ upstream session per registered server.
- [ ] Session expiry, idle GC, and explicit teardown; bound the session table.
- [ ] Reject `tools/call` and other methods that arrive before a completed handshake.

### 1.2 Full method coverage
- [ ] `resources/list`, `resources/read`, `resources/subscribe` — route through `discovery`
      (list-drift) and a `post_call`-equivalent content scan; resource content is a taint
      source and an injection surface.
- [ ] `prompts/list`, `prompts/get` — same treatment; prompt content is an injection
      surface.
- [ ] `completion/complete`, `logging/setLevel`, `roots/*`, `notifications/*`, sampling
      (`sampling/createMessage`) — decide per method: forward, police, or refuse.
      Document the decision for each.
- [ ] Define policy/scanner phases for non-`tools/call` methods, or explicitly exempt them
      in one place rather than by falling through `ProxyController.handle/2`.

### 1.3 Real streaming transport
- [ ] Replace the `result.chunks` simulation with real Streamable-HTTP / SSE passthrough:
      stream upstream → run `Pipeline.run_chunk/2` per real chunk → stream downstream.
- [ ] Backpressure: bound buffered bytes, apply the request deadline across the whole
      stream, handle upstream disconnect mid-stream.
- [ ] A `chunk`-phase `deny` cuts the real stream cleanly (connection close + audit row),
      not just an appended notice.
- [ ] `chunk` → session-taint accumulation (currently deferred).

### 1.4 Authentication & authorization on the proxy
- [ ] Authenticate the downstream client: mTLS, or OAuth2/OIDC bearer tokens, or signed
      API keys. No unauthenticated path to `POST /mcp/proxy/:server_id`.
- [ ] Verify agent identity instead of trusting the `mcp-agent-id` header — signed token
      (JWT/PASETO) or derived from the client cert. Every identity-based policy
      (`RuleEngine`, audit attribution) depends on this.
- [ ] Authorize: which authenticated principal may reach which registered server.
- [ ] Authenticate the dashboard and `/dev` LiveDashboard routes (RBAC — see Phase 3).

### 1.5 Transport hardening
- [ ] TLS termination config wired (`runtime.exs`), `force_ssl` + HSTS.
- [ ] Request body size limit, header limits, connection count limits on the proxy
      endpoint.
- [ ] Per-principal rate limiting on the proxy endpoint (distinct from
      `ResponseSizeGuard` / `BaselineGuard`, which police tool traffic, not HTTP).
- [ ] Upstream `:http` / `:stdio` transports: connection pooling, retry policy, TLS
      cert verification, per-server timeouts.

### 1.6 Retire or profile the demo scaffolding
- [ ] Decide: remove mock servers + scenario harness + `MockDrift`, or gate them behind a
      `demo` runtime profile that is off by default.
- [ ] `ProxyController.fetch_from_mock/2` (proxy calling itself over HTTP) goes away in the
      `prod` profile.

---

## Phase 2 — Make it survivable

### 2.1 Datastore: SQLite → Postgres
- [ ] Migrate `Repo` to Postgres; keep SQLite only for the `demo` profile if it survives.
- [ ] Revisit the `async: false` test suites made necessary by SQLite's single writer.
- [ ] Connection pool sizing, statement timeout, migration strategy for zero-downtime
      deploys.

### 2.2 Session / taint / baseline state
- [ ] Move `PolicyEngine` session state (tags, `taint` provenance, `call_log`,
      `call_count`) out of the single GenServer's memory into a store that survives a
      restart and is readable by every node — Postgres, or a distributed cache with a
      durable backing.
- [ ] Define the consistency model: a `tools/call` decision must see this session's own
      prior taint even if the prior call landed on another node.
- [ ] `HoldRegistry` — parked calls must survive a restart or be re-driven; an operator
      approval on node B must resolve a hold parked on node A.
- [ ] `ServerRegistry` — registered real servers persisted, not re-registered by hand
      after every deploy.

### 2.3 Audit durability & tamper-evidence
- [ ] Audit records written to append-only / WORM storage or an external log, not only the
      app's own Postgres.
- [ ] Anchor the `prev_hash` chain externally (periodic checkpoint to object storage or a
      transparency log) so a DB compromise cannot rewrite history undetected.
- [ ] Retention, rotation, and export policy for audit data.
- [ ] `EventLog.verify_chain/0` runs as a scheduled integrity check with alerting, not just
      a dashboard button.

### 2.4 Clustering
- [ ] `DNSCluster` actually forms a cluster; decide what is global (plugin registry,
      server registry) vs. per-node.
- [ ] Rolling deploy without dropping in-flight sessions or holds.
- [ ] Deliberate, documented fail-mode per deployment for every `fail_open` plugin
      (`BaselineGuard`, `StreamGuard`) — is fail-open acceptable in this environment?

---

## Phase 3 — Make it operable

### 3.1 CI/CD
- [ ] CI pipeline: `mix precommit` + `mix test` + `mix deps.audit` + Dialyzer + a
      security-review step on every PR.
- [ ] Release automation: build, migrate, deploy, rollback.
- [ ] `security-review` skill (or equivalent) wired into the pipeline for changes touching
      `lib/phoenix_elxir_beam/mcp/`.

### 3.2 Observability
- [ ] Metrics exporter — Prometheus or OTLP — fed from the existing `telemetry_metrics`.
      Per-phase pipeline latency, verdict counts, plugin failure/circuit-breaker state,
      session table size, hold queue depth.
- [ ] Ship `StructuredLogSink` output to a real SIEM / log pipeline; document the schema.
- [ ] A genuine OTLP exporter as an `auditSink` (protocol §18 open item), if the SIEM story
      needs spans rather than log lines.
- [ ] Readiness probe checks Postgres + each registered upstream server; liveness separate.
- [ ] Alerting rules: circuit breaker opened, audit-chain verification failed, fail-open
      triggered, session table growth, upstream server unreachable.

### 3.3 Load & latency
- [ ] Load test the request path: p50/p99 added latency per phase, behaviour at N
      concurrent sessions, the pipeline's `Task.Supervisor` fan-out under sustained load.
- [ ] Establish and enforce a request-path latency budget; the circuit breaker + decision
      cache (protocol §18 open item) land here if the budget demands them.
- [ ] Sidecar plugin latency under load; HTTP sidecar transport (protocol §5.2, not built)
      if stdio sidecars don't scale.

### 3.4 Runtime policy management
- [ ] Dashboard UI for the plugin registry (protocol §18 open item): enable / disable /
      reorder / re-verify without redeploy — the `Registry` GenServer already supports the
      operations, the UI is read-only today.
- [ ] Policy changes (plugin toggles, `RuleEngine` rule edits, tag assignments) are
      themselves audited — who, when, old value, new value — in the same tamper-evident
      chain.
- [ ] Review/approval flow for policy changes, or at minimum a change log with rollback.
- [ ] Secrets via a secrets manager (Vault / cloud KMS), not env vars.

### 3.5 Plugin supply chain
- [ ] Manifest signing (protocol §18 open item) — verify sidecar plugin provenance.
- [ ] Resource limits / sandboxing on sidecar subprocesses beyond supervisor restart caps
      (cgroups, seccomp, or a container per sidecar).
- [ ] Pin and audit in-process plugin dependencies.

---

## Phase 4 — Close mission gaps

### 4.1 Taint fidelity
- [ ] Real HMAC taint markers (protocol §18, ADR-0001 item 1): HMAC the secret with a
      per-session key, store only the marker, match by tokenising call arguments and
      HMACing candidates. Replaces the raw-secret substring match, which is defeated by
      base64 / encoding / chunking / reformatting.
- [ ] Taint sources from `resources/read` and `prompts/get` content (depends on Phase 1.2).
- [ ] `chunk` → taint accumulation (depends on Phase 1.3).

### 4.2 Default-deny posture
- [ ] Discovered tools currently start untagged, so most policies are inert until an
      operator hand-curates tags. Add a default-deny mode: an untagged tool is denied (or
      held) until classified.
- [ ] Tag inference / suggestion at discovery time (name + description heuristics, or a
      classifier) to make curation tractable.

### 4.3 Scanner quality
- [ ] The prompt-injection scanner is a demo-grade matcher. Decide the real detection
      approach (maintained ruleset, ML classifier, or a dedicated service) and its
      false-positive budget.

### 4.4 Documentation
- [ ] Threat model document — what this proxy defends against and what it explicitly does
      not.
- [ ] Operator runbook — deploy, register a server, assign tags, respond to each alert
      type, investigate an audit-chain failure.
- [ ] Deployment guide — reference architecture, sizing, network placement.

## References

- `docs/adr/0001-plugin-architecture.md` — the plugin architecture this ADR builds on.
- `docs/plugin-protocol.md` §18 — open protocol items folded into Phases 1, 3, and 4.
- `Project.md` — the original demo framing this ADR proposes to move beyond.
