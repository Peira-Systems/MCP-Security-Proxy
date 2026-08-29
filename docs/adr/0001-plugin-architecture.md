# ADR 0001 — Plugin architecture for proxy extensions

**Status:** Accepted (design) · **Date:** 2026-08-27 · **Supersedes:** —

## Context

The proxy currently enforces exactly one hardcoded rule in
`PhoenixElxirBeam.MCP.PolicyEngine` (`:sensitive_read` → `:network_egress` block). We want
to grow it toward a credible agent-tool control plane by adding recognized MCP-security
capabilities (rug-pull / tool-drift detection, content scanning, real data-flow/taint
tracking, human-in-the-loop approval, declarative policy, agent identity, behavioural
baselining, tamper-evident audit, OpenTelemetry/SIEM export).

Adding each as bespoke code in `PolicyEngine` / `ProxyController` does not scale and offers
no path for third-party contributions. We evaluated how to make these **plugins**.

Constraints that shaped the decision:

- The proxy sits on the request path of every `tools/call`. Evaluation must be bounded —
  a plugin must never hang or crash a call.
- This is a visualization / education demo, not a production security service
  (`Project.md`). Favour capabilities that are **demonstrable and legible** over
  comprehensive coverage.
- The codebase already speaks newline-delimited JSON-RPC over an Erlang port to real MCP
  servers (`PhoenixElxirBeam.MCP.StdioServer`). Reusing that machinery is close to free.
- Elixir has no idiomatic runtime plugin loading. The idiomatic "plugin" is a
  behaviour-implementing module registered via application config (cf. Plug, Ecto
  adapters, Logger backends, Swoosh adapters).

## Decision

### 1. Three extension points, as behaviours

A plugin provides one or more **capabilities**:

| Capability | Role | Can block? |
|---|---|---|
| `policy` | decide allow / deny / hold / annotate for a `tools/call` | yes |
| `scanner` | inspect tool descriptions, arguments, responses; emit findings | no (opt-in `canBlock`) |
| `auditSink` | receive the finalized event + finding stream for storage/export | n/a |

Invoked at three **phases**: `discovery` (server registration / re-handshake, off the
request path), `pre_call`, `post_call`.

`Transport` (pluggable upstream MCP transports) and `Panel` (pluggable dashboard UI) are
recognized as future extension points but are **out of scope for the first iteration**.

### 2. One contract, two bindings

The wire schema (`CallContext`, `Decision`, `Finding`, `AuditEvent`, the manifest) and the
evaluation semantics are defined once in [`docs/plugin-protocol.md`](../plugin-protocol.md)
and are identical for:

- **in-process** plugins — Elixir modules implementing `MCP.Plugin.{Policy,Scanner,AuditSink}`;
- **out-of-process (sidecar)** plugins — any language, spoken to over JSON-RPC.

### 3. Sidecar-first for polyglot; Wasm later; NIFs never (for third-party)

- **Sidecar over JSON-RPC (stdio or HTTP)** is the primary polyglot mechanism. Rationale:
  the transport already exists (`StdioServer`), crash isolation is free (separate OS
  process / container), it works for remote plugins, and a sidecar can itself be an
  MCP-shaped service — a pleasing dogfooding property. Cost: per-call IPC latency
  (sub-ms to low-ms locally), accepted because evaluation is already bounded by timeouts.
- **WebAssembly (via `wasmex`/Wasmtime)** is deferred. It is the right answer for
  *untrusted, latency-sensitive* plugins (capability-sandboxed, ~10–100 µs, in-process)
  but adds a runtime dependency and a maturing interface-definition story. Revisit once a
  concrete "untrusted fast policy" need exists.
- **Native NIFs / `rustler`** are rejected for third-party plugins — a NIF crash or
  infinite loop threatens the VM. Acceptable only for first-party, performance-critical,
  fully-trusted code.

### 4. The proxy owns canonical session state

`seenTags`, taint markers, and counters live in the proxy (today: `PolicyEngine`'s
GenServer state; durably: `EventLog`). Plugins are **stateless with respect to
correctness** — they may cache internally keyed by `sessionId` but must behave correctly on
a cold start (proxy restart, first-seen session). Plugin state mutations
(`addTags`, `addTaintSources`, `redactResponse`) are **proposals**; the proxy applies them
only for fields the operator granted.

Rationale: keeps restart, sidecar pooling, and load-balancing safe; keeps the audit trail
authoritative regardless of plugin behaviour.

### 5. Operator `grants` cap the manifest

A plugin's manifest *requests* mutation rights, blocking, and network access. Registration
config carries a `grants` block that *caps* those requests. Installing a plugin never
silently confers blocking or egress. The same supply-chain hardening the proxy applies to
MCP servers (record command + binary/image hash + manifest hash, re-verify on start)
applies to sidecar plugins.

### 6. Bounded, fail-safe evaluation

- Per-capability `timeoutMs` and `failMode` (`fail_open` for scanners, `fail_closed` for
  policies) declared in the manifest, overridable by the operator.
- A circuit breaker auto-disables a plugin after N consecutive failures.
- The request-path deadline is enforced **by the proxy**, not by plugin cooperation.
- Only the `pre_call` `policy` chain is order-sensitive (configured order, short-circuit on
  first `deny`). Scanners and `post_call` work run concurrently.

### 7. Registration: config-seeded, runtime-toggleable

Static list under `config :phoenix_elxir_beam, PhoenixElxirBeam.MCP, plugins: [...]`.
A `PhoenixElxirBeam.MCP.Plugin.Registry` GenServer (ETS-backed, seeded from config at boot,
added to the supervision tree after `ServerRegistry`) lets the dashboard enable / disable /
reorder / re-verify plugins without a redeploy. Sidecars are supervised like `StdioServer`
instances under a dynamic supervisor.

## Consequences

**Positive**

- Each new capability from the roadmap becomes a self-contained module, not a change to
  core request-handling code.
- Third parties contribute a Hex package (in-process) or a container image (sidecar) plus
  one config line.
- The one-rule → control-plane story is a strong portfolio narrative.

**Negative / costs**

- Up-front refactor: introduce `CallContext` + `Pipeline`, move the existing rule behind
  it (ADR-tracked as roadmap step 2). Pure refactor — existing tests must pass unchanged.
- Sidecar plugins add per-call latency and an ops surface (process lifecycle, health).
- The spec (`docs/plugin-protocol.md`) is draft `0.1` and will change as it meets its
  first implementation. Expect churn until ~2 real plugins exist.

**Neutral**

- Streaming tool responses have a `chunk` phase over a simulated transport (step 7j); a
  real streaming transport, taint-marker normalization, and manifest signing remain
  deliberately unresolved (see `docs/plugin-protocol.md` §18).

## Roadmap (implementation order)

1. **This ADR.** ✔
2. **Enabling refactor** — `CallContext` + `Pipeline`; port `ChainExfil` to a `Policy`
   plugin; no behaviour change; existing tests green. ✔ (full skeleton: all three
   behaviours + `Plugin.Registry` + bounded `timeout_ms`/`fail_mode`; tags kept as atoms
   internally; circuit breaker deferred to step 5.)
3. **Rug-pull / tool-drift scanner** — first non-trivial plugin; exercises `discovery` +
   `ServerRegistry`; stores `descriptionHash` per tool; dashboard alert on mismatch. ✔
   (`MCP.ToolHash`, `MCP.Plugins.RugPull`, `Pipeline.run_discovery/2`,
   `ServerRegistry.rehandshake/2` + tool quarantine, `ProxyController` `-32003`, red
   dashboard card + re-handshake / simulate-drift buttons, `MockDrift` demo switch.)
4. **Extract `AuditSink`** — move `EventLog` behind the behaviour; add `prev_hash`
   chaining to `PolicyEvent`. ✔ (`MCP.AuditEvent`, `MCP.Plugins.EventLogSink`,
   `Registry.active_sinks/1`, synchronous fan-out from `PolicyEngine`, `decisions` /
   `findings` + `prev_hash` / `hash` columns, `EventLog.verify_chain/0`, dashboard
   deciding-plugin pill + "verify audit chain" button. Test DB switched to WAL; the
   write-heavy suites made `async: false`.)
5. **Sidecar transport** — out-of-process JSON-RPC runner; ship the Python example from
   `docs/plugin-protocol.md` §17.1 running end-to-end. ✔ (stdio only: `Plugin.SidecarRunner`
   + `Plugin.Wire` + `Manifest.from_wire/1`; `Registry` spawns runners in `handle_continue`;
   `Pipeline` dispatches on `entry.impl`; `priv/plugins/prompt_injection_scanner.py`
   registered in dev/prod; circuit breaker in the runner; read-only dashboard Plugins panel.
   HTTP transport deferred.)
6. **`hold` verdict + approval UI** — LiveView-native; third verdict through the pipeline.
   ✔ (`MCP.HoldRegistry` parks the request; `MCP.Plugins.ApprovalGate` replaces `ChainExfil`
   in dev/prod; `ProxyController` blocks on `HoldRegistry.await/3` then
   `PolicyEngine.finalize_hold/6`; dashboard amber Approve/Deny banner + graph pause at the
   gate; `:held` event status. Approve = allow, chain not resumed — §9.4 deviation noted.)
7. Incremental, no new infrastructure: taint tracking, prompt-injection scanner,
   declarative policy, agent identity, behavioural baselining, OTel/SIEM sinks.
   - 7a. **`post_call` phase + response scanning.** ✔ (`Pipeline.run_post_call/2` runs the
     `post_call` `scanner` + `policy` set concurrently; `Registry.active_post_call/1`;
     `MCP.Redaction` applies `redactResponse` mutations; `MCP.Plugins.SecretLeak` redacts
     credentials in a tool response before the agent sees them; `ProxyController` forwards
     then scans, withholding the whole response as `-32002` on a `policy` / `canBlock`
     `deny`; `Event` carries `findings`, shown as pills in the live feed + history.
     Taint tracking and a shipped withholding policy still deferred.)
   - 7b. **Taint tracking (session provenance).** ✔ (`SecretLeak` also proposes an
     `addTaintSources` mutation; `run_post_call/2` returns `taint_sources`;
     `PolicyEngine` keeps per-session `taint` provenance (`accumulate_taint`, deduped),
     threads it into the `pre_call` `CallContext`; `MCP.Plugins.TaintGuard` — `pre_call`
     `policy`, `toolTags: [network_egress]` — denies egress once the session has handled a
     secret, catching leaks the operator's tags missed. New "Run untagged exfil" demo
     (`files/read_config`, untagged, leaks a key → redacted + tainted → `post_webhook`
     blocked). `Wire` carries `session.taint` / `addTaintSources` for sidecar parity.
     Byte-level HMAC markers into later call args still deferred.)
   - 7c. **Agent identity.** ✔ (`mcp-agent-id` request header → recorded on the session the
     first time seen, never overwritten; threaded into `CallContext.call.agentId`, live
     `Event`, `AuditEvent`, and a new `policy_events.agent_id` column — kept outside the
     hash chain as request metadata. Demo scenarios send an agent id; dashboard feed +
     history show it.)
   - 7d. **Declarative policy rules.** ✔ (`MCP.Plugins.RuleEngine` — a `pre_call` `policy`
     whose allow/deny/hold verdicts come from operator-written `rules` in its registration
     `config:`. `match` predicates: `agent` / `agent_prefix` / `tool` / `server` /
     `tool_tags_any` / `after_sensitive_read` / `if_tainted`; first match wins; unknown
     predicate fails closed. Ships enabled in all envs with an `agent://ci-runner`
     egress-deny rule; "Run restricted agent" demo; Plugins panel shows the rule count.)
   - 7e. **Byte-level taint.** ✔ (`SecretLeak` records the raw matched secret + a redacted
     `hint` on each taint source — raw value in-memory only, never persisted / broadcast /
     wired. `record_call` threads `params.arguments` into the `pre_call` `CallContext`.
     `MCP.Plugins.TaintedArgGuard` (`pre_call` `policy`, no tag filter) denies a call whose
     stringified arguments contain a tracked secret, with a `tainted_argument` critical
     finding. "Run secret-in-arg exfil" demo. Real HMAC markers still stand-in'd by
     substring match.)
   - 7f. **Second audit sink.** ✔ (`MCP.Plugins.StructuredLogSink` — `@behaviour AuditSink`,
     emits each `AuditEvent` as one `mcp.audit {…}` JSON line on `Logger` at `:info` for a
     log shipper to forward to a SIEM / the OTel Collector. Runs alongside `EventLogSink`;
     proves the fan-out is genuinely multi-sink with zero core change — two `plugins:`
     entries. Verdict metadata only, no raw evidence.)
   - 7g. **Withholding `post_call` policy.** ✔ (`MCP.Plugins.ResponseSizeGuard` — a
     `post_call` `policy` that denies a response whose text exceeds a byte budget
     (`plugin_config["max_bytes"]`, default 4 KB), the first shipped plugin to exercise the
     `post_call` deny → `-32002` path. `record_response_scan`'s `withheld?` boolean became a
     `withheld` reason string so the audit row / feed carry the real reason. New
     `files/export_all` mock tool (~6 KB) + "Run bulk exfil" demo.)
   - 7h. **`post_call` sidecar invocation.** ✔ (`priv/plugins/prompt_injection_scanner.py`
     now declares `phases: ["discovery", "post_call"]` + `dataNeeds: ["response.content"]`
     and handles `call/inspectResponse`: on a hidden-instruction hit in a tool response it
     returns `verdict: annotate` + a `prompt_injection` finding + a `redactResponse`
     mutation that strips the `<IMPORTANT>…</IMPORTANT>` block before the agent sees it.
     Exercises the previously-dead `Pipeline` sidecar `post_call` path end to end. New
     `net/fetch_page` mock tool (page text carrying an injection) + `Demo.run_response_injection/0`
     + "Run response injection" demo button. Node fixture `sidecar_scanner.js` gained the
     same `post_call` handler for hermetic tests.)
   - 7i. **Behavioural baselining.** ✔ (PolicyEngine keeps a bounded per-session recent-call
     log — `%{tags, at}`, last 50 within 60s — and threads it into every `pre_call`
     `CallContext` as `session.recent_calls`, plus `session.calls_so_far` (session-lifetime
     count). `MCP.Plugins.BaselineGuard` — `pre_call` `policy`, no tag filter, `fail_open`,
     `data_needs: ["session.recentCalls"]` — applies its own operator-configured
     `window_ms` / `max_calls` / `watch_tags` and denies once the session's rate of watched
     calls exceeds the baseline. Keys off the rate of a *sequence*, unlike every other
     guard. `Wire` sends `session.callsSoFar` always, `session.recentCalls` gated. New
     `Demo.run_rapid_probing/0` (8 rapid `read_secrets`) + "Run rapid probing" button.)
   - 7j. **Streaming `chunk` phase.** ✔ (a **new pipeline phase** that runs once per chunk of
     a streamed tool response. Scope: simulated transport — the mock returns
     `result.chunks: [...]`, `ProxyController.stream_and_scan/6` folds over them running
     `Pipeline.run_chunk/2` (concurrent `policy` + `scanner` with `:chunk` phase) per chunk,
     and re-assembles into one JSON-RPC reply; no SSE / backpressure. A `chunk` `:deny`
     **cuts the stream** — delivered chunks kept, a termination notice appended,
     `result.streamTerminated: true`, a `:blocked` audit row. `MCP.Plugins.StreamGuard` —
     `chunk` `policy`, `fail_open` — is the streaming analogue of `ResponseSizeGuard`: cuts
     once the running byte count passes a budget (after ~1–2 KB, not the whole payload).
     New `files/stream_export` mock tool (24 chunks) + `Demo.run_stream_exfil/0` + "Run
     stream exfil" button. `Registry.active_chunk/1`; `Pipeline` sidecar dispatch generalised
     to `call/inspectChunk` (wired, unused). Still deferred: a real streaming transport,
     `chunk` → session-taint accumulation.)

The plugin architecture is functionally complete at 7j. Remaining items are optional, low
value for a visualization demo, and each needs a decision before starting:

  1. **Real HMAC taint markers** — 7e retains the raw secret and substring-matches; the
     proper form HMACs it and matches tokenised arguments.
  2. **Real OTLP exporter** — `StructuredLogSink` (7f) covers the SIEM story via log lines;
     a genuine OpenTelemetry exporter is a real dependency + collector.

## References

- `docs/plugin-protocol.md` — the contract this ADR points to.
- OWASP MCP Top 10; CSA "MCP Security Crisis" (2026-05); NSA MCP Security Design guidance
  (2026-06); Microsoft "Securing MCP: A Control Plane for Agent Tool Execution";
  Invariant Labs MCP-Scan (tool pinning / rug-pull detection);
  PipeLab "State of MCP Security 2026" (defense-coverage gaps).
