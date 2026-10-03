# Per-agent identity propagation — design spec

Date: 2026-10-02

## Correcting the roadmap's framing

The build-out roadmap describes this gap as "API key = tenant," implying
there is no agent-level identity concept today. Reading the code shows
that's not quite right, and the real gap is narrower:

- `PhoenixElxirBeam.MCP.ApiKey` already has a distinct `agent_id` field
  (`lib/phoenix_elxir_beam/mcp/api_key.ex:38`), separate from `principal`.
- `RuleEngine` already matches rules against `agent_id`
  (`lib/phoenix_elxir_beam/mcp/plugins/rule_engine.ex:131`,
  `agent(ctx), do: ctx.call[:agent_id]`) — the example rule in that file's
  own moduledoc, `%{"agent" => "agent://ci-runner", ...}`, is a real,
  working per-agent rule today.
- `agent_id` is threaded from `key.agent_id` into `SessionStore.open/2` and
  `PolicyEngine.ensure_session/2` at session-open time
  (`lib/phoenix_elxir_beam_web/controllers/mcp/proxy_controller.ex:143-151`).

So per-agent *policy matching* already exists and already works. The actual
gap: **`agent_id` is a fixed string an admin types in when issuing an API
key, not a claim the calling agent proves.** One API key always resolves to
exactly one `agent_id` for the life of every session opened with it,
regardless of which real agent process, service account, or workload is
actually holding and using that key. Two consequences:

1. If a team shares one API key across multiple distinct agents/services (a
   common real-world pattern — one key per *team*, not per *bot*), every
   session from every one of those agents is attributed to the same
   `agent_id`, even though they may have meaningfully different risk
   profiles. A rule written to allow `agent://reporting-bot` network egress
   but deny it for everything else silently also allows it for anything
   else sharing that same key.
2. `agent_id` is operator-asserted at key-issuance time with no independent
   verification — an admin typing the wrong string, or a key accidentally
   issued with an overly-trusted `agent_id`, has no secondary check.

## Goal

Let the calling agent assert (and have verified) its own identity per
session, distinct from which API key authenticated the connection — so a
single API key can authorize *access* (which servers it may reach, same as
today) while the agent's own identity drives *policy matching*, verified
rather than merely operator-typed.

## Decisions

### Mechanism: OAuth 2.0 client-credentials-style agent identity, scoped to Phase 1 only

Full workload-identity federation (SPIFFE/SPIRE, cloud-native workload
identity) is its own roadmap item later in Phase 1 and is **not** this
spec's job — that's a separate, larger integration (trusting an external
identity provider's workload attestation). This spec is narrower and
self-contained: let an agent register its own `(agent_id, client_secret)`
pair independently of any API key, present it per-session, and have the
proxy verify it — so `agent_id` becomes a verified claim instead of a
same-process operator assumption, without yet integrating an external IdP.

### Backward compatibility: additive, not a breaking change

An API key's existing `agent_id` field and behavior are unchanged — a
client that does not present agent credentials continues to get the
key-level `agent_id`, exactly as today. A new, optional
`X-Agent-Credential: <agent_id>.<agent_secret>` header, checked only if
present, lets a client *upgrade* to a verified, independently-asserted
`agent_id` for that session. This means: zero impact on any existing
deployment or integration that doesn't opt in, and a key issued with
`all_servers: true` can still be shared across multiple distinct agents
safely, since each agent now has its own, separately-revocable identity
layered on top.

### Storage: a new `agent_credentials` table, independent of `api_keys`

Agent credentials are not API keys — they don't grant server access on
their own (an `X-Agent-Credential` header with no valid `Authorization`
bearer token is still rejected by the existing `ApiKeyAuth` plug,
unchanged). They exist purely to let an already-authenticated connection
assert a verified `agent_id`. Modeled the same way `ApiKey` already is
(`key_id`/secret pair, only the secret's hash stored, `Plug.Crypto.secure_compare`
verification) since that pattern is already proven in this codebase.

## Out of scope

- SPIFFE/SPIRE or cloud-native workload identity federation — later Phase 1
  roadmap item, a materially larger integration surface (trusting an
  external attestation service).
- On-behalf-of token exchange, delegation chains, or any multi-hop identity
  propagation — this spec is "the directly-connecting agent asserts its own
  verified identity," nothing more.
- Any change to `ApiKey`'s existing `agent_id` field, `authorize?/2`, or
  server-grant model — access control stays exactly as it is; this spec
  only affects which `agent_id` string flows into `ctx.call[:agent_id]` for
  policy matching.
- Revoking/rotating agent credentials via the dashboard UI — the plan below
  adds the data model and verification path; a dashboard management UI is a
  reasonable fast-follow but isn't required for the core capability to
  exist (an admin can issue one via `mix run -e` initially, same bootstrap
  pattern this repo already uses for other one-off provisioning tasks like
  `mix mcp.rules.backfill_suggested_tags`).

## Changes

### 1. `AgentCredential` schema + issuance/verification module

Mirrors `ApiKey`'s shape: `agent_id` (string, unique), `token_hash`
(`sha256`, only the hash stored), `disabled_at`. `issue/1` returns the full
secret once, same as `ApiKey.issue/1`.

### 2. `AgentCredentialAuth` — a new plug, after `ApiKeyAuth` in the `:mcp_api` pipeline

Reads `X-Agent-Credential: <agent_id>.<secret>` if present; on a valid,
non-disabled match, assigns `conn.assigns.verified_agent_id`. On a
*present but invalid* header (malformed, unknown agent_id, wrong secret),
the request is rejected the same way a bad API key is today — a client
that attempts to assert an identity it can't prove must fail closed, not
silently fall back to the key's default `agent_id` (that fallback would let
an attacker probe for valid `agent_id` strings with no cost, since a wrong
guess would otherwise just quietly succeed at the lower trust level). When
the header is absent entirely, the plug is a no-op — `verified_agent_id`
stays unset and session-open falls back to `key.agent_id`, exactly as
today.

### 3. `ProxyController.handle_initialize/4` prefers `verified_agent_id` over `key.agent_id`

`agent_id: conn.assigns[:verified_agent_id] || key.agent_id` at the two
call sites currently hardcoded to `key.agent_id`
(`proxy_controller.ex:146`, and the second `session.agent_id` passthrough
at `:287` for an already-open session — confirm at implementation time
whether `:287`'s `session.agent_id` already reflects what was chosen at
`:146`'s `SessionStore.open/2` call, since if so `:287` needs no separate
change, it would just be reading back what Task 2 already stored).

## Testing strategy

- Unit tests on `AgentCredential.issue/1` and `.authenticate/1` mirroring
  `ApiKey`'s existing test shape.
- Plug tests on `AgentCredentialAuth`: valid header sets
  `verified_agent_id`; absent header is a no-op; invalid header (bad
  secret, unknown agent_id, disabled credential) halts the request with
  401, same shape as `ApiKeyAuth`'s existing denial.
- Integration test on `ProxyController`'s `initialize` handling: a key with
  `agent_id: "agent://shared-team-key"` plus a valid
  `X-Agent-Credential: agent://specific-bot.<secret>` header results in a
  session whose `agent_id` is `"agent://specific-bot"`, not the key's
  default — and that a `RuleEngine` rule scoped to `agent://specific-bot`
  now actually matches it (an end-to-end proof the policy-matching gap
  this spec exists to close is actually closed, not just that a field got
  set).
