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

- Streaming tool responses, taint-marker normalization, and manifest signing are
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
   chaining to `PolicyEvent`.
5. **Sidecar transport** — out-of-process JSON-RPC runner; ship the Python example from
   `docs/plugin-protocol.md` §17.1 running end-to-end.
6. **`hold` verdict + approval UI** — LiveView-native; third verdict through the pipeline.
7. Incremental, no new infrastructure: taint tracking, prompt-injection scanner,
   declarative policy, agent identity, behavioural baselining, OTel/SIEM sinks.

## References

- `docs/plugin-protocol.md` — the contract this ADR points to.
- OWASP MCP Top 10; CSA "MCP Security Crisis" (2026-05); NSA MCP Security Design guidance
  (2026-06); Microsoft "Securing MCP: A Control Plane for Agent Tool Execution";
  Invariant Labs MCP-Scan (tool pinning / rug-pull detection);
  PipeLab "State of MCP Security 2026" (defense-coverage gaps).
