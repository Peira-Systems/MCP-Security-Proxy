# Threat model

**Status:** Active · **Implements:** [productionization-plan.md](productionization-plan.md) M4.4

What the MCP Security Proxy defends against, and — just as important — what it
explicitly does not.

## What it is

A policy-enforcing reverse proxy on the MCP tool-call path. An AI agent (MCP
client) connects to the proxy instead of directly to its MCP servers; the proxy
terminates the MCP session, authenticates the client, runs every method through
a plugin pipeline (policy decisions, content scanners, tamper-evident audit),
and only then forwards to the registered upstream.

```
agent ──API key──▶ proxy ──▶ policy pipeline ──▶ upstream MCP server
                     │              │
                  sessions      audit chain (Postgres, hash-linked,
                  (Postgres)     off-DB checkpoints)
```

## Assets

1. **Credentials / sensitive data** that flow through tool responses (files,
   config, DB rows, API keys).
2. **The agent's action authority** — its ability to call tools that write,
   send, or spend.
3. **The audit record** — the evidence of what happened.
4. **Operator control** — who can change policy.

## Primary threat: tool-chaining exfiltration

An agent is manipulated (by a prompt injection in a document, a web page, a
tool description, or a tool response) into chaining a *read something sensitive*
call into a *send it somewhere* call.

| Defence | Milestone | Mechanism |
|---|---|---|
| Tag-based chaining rules | pre-existing | `ChainExfil` / `RuleEngine` deny egress after a `:sensitive_read`, per operator tags |
| Session taint tracking | pre-existing + M4.1 | `SecretLeak` marks a leaked credential with per-session **HMAC markers**; `TaintedArgGuard` blocks a later call whose arguments carry that secret *or a base64/hex/URL-encoded copy*; `TaintGuard` is the coarse backstop (any egress after any leak) |
| Provenance taint tracking | new | `ProvenanceTaint` taints the session whenever a tool tagged `:untrusted_source` returns a response, **independent of content**. Value-fingerprinting (above) is blind to a paraphrased secret and to untrusted content that was never credential-shaped to begin with (a prompt-injection payload in a scraped page); tagging the *source* instead of the value closes that gap. Operator opt-in per tool/server, same place tool tags are already assigned — nothing is untrusted by default |
| Response scanning | pre-existing + M1.2 | `SecretLeak` redacts credentials out of `tools/call` / `resources/read` / `prompts/get` content before the agent sees them |
| Streaming early-cut | M1.3 | `StreamGuard` inspects an `:http` response incrementally and cuts the stream mid-transfer once a budget is exceeded — the rest never crosses |
| Behavioural baseline | pre-existing | `BaselineGuard` denies once the rate of watched calls exceeds a baseline |
| Human-in-the-loop | pre-existing | `ApprovalGate` parks egress for operator sign-off. `HoldFatigueMonitor` watches the resolution rate and raises `:approval_gate_fatigue` once approvals get sustained and high — the gate is only a control as long as it's reviewed, not rubber-stamped |
| Prompt-injection detection | M4.3 | maintained ruleset over tool descriptions (`discovery`, quarantines) and responses (`post_call`, finding + redaction) — see [injection-detection.md](injection-detection.md) |
| Default-deny | M4.2 | `UnclassifiedGuard` (prod: `hold`) parks calls to tools the operator has not classified |

**Dry-run mode is a rollout tool, not a weaker mode of these defences.** An
operator can put the whole pipeline, or a single plugin, into observe-only
mode to see what it *would* have blocked against real traffic before trusting
it to enforce — every would-be verdict is still durably audited
(`shadow_blocked` / `shadow_held` on the same hash chain as a real one). While
a plugin is in dry-run, though, it provides **no actual protection** — a call
it would have denied still reaches the upstream, or a response it would have
withheld is still delivered. Nothing here is in dry-run by default; a plugin
stays enforcing unless an operator explicitly turns dry-run on globally or
pins that plugin to it (see [product-guide.md §6.8](product-guide.md)).

## Other threats in scope

- **Unauthenticated access.** Every proxy request needs a signed API key
  (`Authorization: Bearer mcpk_…`); agent identity is a property of the key, not
  a client-asserted header (M1.4). The dashboard / `/dev` need an operator
  account (`viewer` < `operator` < `admin`, M3.4a).
- **A malicious or swapped MCP server.** Tools are hashed at registration;
  discovery scanners (`RugPull`) re-check on every re-handshake and quarantine a
  tool whose description/schema drifted, and raise a `:rug_pull` alert
  separate from the quarantine — a changed tool definition is its own kind of
  incident, not just one more row in the event feed.
- **A tampered or swapped plugin.** Sidecar plugins are provenance-pinned (code
  digest + manifest digest); a mismatch stops the plugin and alerts (M3.5).
- **Audit tampering.** Rows are hash-chained; `AuditIntegrity` verifies the
  chain every 15 min and against an off-DB signed checkpoint, so a truncated log
  is caught even if it verifies internally (M2.3).
- **Tracing a block back to its cause.** A `blocked` / `held` / `shadow_blocked`
  / `shadow_held` row carries a `call_chain` — the session's prior calls (tool,
  tags, timestamp) in the 60s/50-call window `BaselineGuard` already tracks —
  so an operator doesn't have to manually correlate `session_id` across the raw
  log to see what led to the block. Excluded from the hash chain (it's context
  for a verdict, not an input the verdict depended on) and only attached to
  block/hold-shaped events, not every `ok`.
- **Resource exhaustion.** Body-size cap (413), per-key rate limit (429),
  per-stream buffer ceiling + deadline, sidecar `prlimit` caps, DB queue
  fail-fast (M1.5 / M3.5).
- **Runaway / compromised sidecar.** Circuit breaker fast-fails; `prlimit`
  address-space + CPU-time caps; supervisor restart limits.
- **Unauthorised policy change.** Runtime changes require `operator`; every
  change is written to the audit chain (who, when, old → new) and is revertible
  (M3.4c).
- **Secrets on the host.** `SECRET_KEY_BASE` / `AUDIT_CHECKPOINT_KEY` / DB
  password are Docker secret files, not in `.env` or `docker inspect` (M3.4d).
- **SSRF via an agent-controlled destination.** An agent (manipulated or not)
  calls an egress-tagged tool with a URL targeting the cloud metadata address,
  loopback, or an internal RFC1918 host. `MetadataEgressGuard` resolves every
  `http(s)://` host in a call's arguments and denies if it lands in a
  disallowed range — independent of `ChainExfil`'s session-taint logic above,
  since this risk exists on the very first call, with no prior sensitive read
  required.

## Explicitly out of scope (non-goals)

- **Availability under node failure.** Single-node by design (ADR-0002). A host
  failure is an outage; restart survivability (state in Postgres) is the
  guarantee, not HA. Deploys have a brief downtime window.
- **A compromised upstream *after* the handshake.** Tools are re-verified at
  re-handshake, not per call. An upstream that serves a clean `tools/list` then
  behaves maliciously at call time is caught only by response scanning, not by
  provenance.
- **The agent↔model channel.** The proxy sees tool descriptions and tool
  responses, never the agent's prompt or the model's reasoning. A prompt
  injection that never touches tool I/O is invisible to it.
- **Untrusted third-party plugins.** Plugins are first-party / vendored. The
  Wasm sandbox path (ADR-0001 §3) stays deferred; a third-party sidecar should
  run as its own container with limits.
- **Novel / obfuscated prompt injection.** The ruleset is regex over a
  maintained corpus — paraphrase, multilingual, and heavy obfuscation are
  partial coverage at best (see [injection-detection.md](injection-detection.md)).
- **Splitting a secret across multiple calls / arguments.** Taint markers catch
  encodings of a whole secret, not a secret chunked into pieces reassembled
  downstream.
- **DNS rebinding between check and request.** `MetadataEgressGuard` resolves
  a hostname at `pre_call` time; a resolver that returns a public address on
  that lookup and a private one moments later (TTL-based rebinding) is not
  caught. Closing this needs the resolved address pinned through to the
  actual upstream request, which the proxy does not currently do.
- **A compromised operator account with `admin`.** An admin can disable every
  plugin and issue keys. The mitigation is the audit chain (the actions are
  recorded and checkpointed off-DB), not prevention.
- **Side channels** — timing, response-size correlation beyond `ResponseSizeGuard`,
  cache state.
- **Physical / infrastructure security** of the host and the Postgres volume.
- **The Postgres instance itself** — network isolation, at-rest encryption, and
  backups are the deployment's responsibility (see [deployment.md](deployment.md)).

## Trust boundaries

| Boundary | Trusted side | Untrusted side | Control |
|---|---|---|---|
| agent → proxy | proxy | agent (may be manipulated) | API key auth, rate limit, body cap |
| proxy → upstream | proxy | upstream MCP server | tool hashing, response scanning, TLS verify |
| proxy → sidecar plugin | proxy | sidecar (out-of-process) | provenance pin, `prlimit`, circuit breaker |
| operator → dashboard | proxy | operator (authorised, audited) | session auth, RBAC, change auditing |
| proxy → Postgres | both trusted | — | network isolation is the deployment's job |
