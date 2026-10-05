# Provenance-tagged taint, call-chain on block alerts, approval-gate fire-rate, rug-pull alert channel — design note

**Status:** Complete (P1–P5 all done) · **Date:** 2026-10-01

Source: feedback on the r/MCPservers launch thread (see `docs/threat-model.md` for the
existing taint model this extends). Four items, bundled because the first two touch the
same session-state plumbing and the last two are both thin wrappers around
`PhoenixElxirBeam.MCP.Alerts`, which already exists and does not need to change.

## Why

Today's taint model (`PhoenixElxirBeam.MCP.TaintMarker`, `Plugins.SecretLeak`,
`Plugins.TaintGuard`, `Plugins.TaintedArgGuard`) is **value-fingerprinting**: a
`post_call` scanner regex-matches a response for credential-shaped strings, HMACs the
match and its common encodings, and blocks any later call whose arguments collide with
one of those markers. This is real coverage — it defeats base64/hex/URL-encoding
evasion, which most naive "grep the args for the secret" approaches miss — but it has
two structural blind spots a reviewer called out:

1. **Paraphrase.** If the agent restates the secret in its own words, reformats it, or
   launders it through a transform we don't enumerate (gzip, a cipher, splitting across
   calls), there is no marker collision. The fingerprint never existed for a value we
   never literally observed.
2. **Untrusted content with nothing to fingerprint.** `SecretLeak` only tags taint when
   its four regexes find something credential-shaped. A prompt-injection payload sitting
   in a scraped webpage or a third-party tool's description is never a "secret" by that
   definition — it produces no taint source at all today, regardless of what the agent
   does with it afterward.

Both gaps share a fix: tag the **source**, not just values extracted from it. If a
response is known to originate somewhere untrusted — an external document, a scraped
page, a tool description from a server the operator hasn't vetted — mark the session
itself, and gate egress on that mark independently of whether any specific value inside
it looks like a credential. `Plugins.TaintGuard` already has exactly this shape (a
coarse "any secret flowed through this session" gate distinct from
`TaintedArgGuard`'s per-value marker match) — it just only ever gets fed by
`SecretLeak`'s regex hits. This plan adds a second feed: tool-level trust tags that
produce the same kind of taint source independent of content inspection.

Separately, three smaller gaps came up that don't touch taint at all:

- A blocked call's audit record carries only that one call (`AuditEvent` has no notion
  of "what led here"), so tracing a block back to the injection that caused it means
  manually correlating `session_id` across the raw event log.
- `ApprovalGate`'s hold is only as good as its fire rate — if it pops for routine traffic,
  operators learn to click through, and the whole pipeline degrades to decoration. There
  is currently no visibility into how often it fires or how operators resolve it.
- `Plugins.RugPull` findings flow through the same `Finding`/`Event` path as every other
  scanner. A changed tool definition is categorically different from a blocked call (it
  usually means a vetted integration got compromised or swapped, not that an agent did
  something wrong) and deserves to interrupt an operator the way `MCP.Alerts` already
  interrupts them for audit-chain failures or a tripped circuit breaker — not just show up
  as one more row in the event feed.

## Scope decisions (locked)

1. **Provenance taint is a new, independent source type, not a replacement for
   value-fingerprinting.** `TaintedArgGuard`'s marker matching stays exactly as is — it's
   the more precise of the two nets for the cases it covers. Provenance adds a coarser
   net for the cases markers structurally cannot cover (paraphrase, un-fingerprintable
   untrusted content). Both read the same `session.taint.sources` list; they just
   populate it from different triggers.
2. **Provenance is tagged at the tool/server level by the operator, not inferred from
   content.** A tool (or a whole upstream server) is marked `trust: :untrusted` in its
   registration/config, the same place tools already get tagged `:sensitive_read` /
   `:network_egress`. Every `post_call` response from an `:untrusted`-tagged tool adds a
   taint source, unconditionally — no scanning, no heuristic, no false-negative surface.
   This is deliberately conservative: it catches "did untrusted content flow into this
   session," not "did this specific untrusted response contain something dangerous."
3. **Call-chain attachment extends the existing `recent_calls` window — it does not add
   a new store.** `PolicyEngine`'s per-session `call_log` (currently `%{tags, at}`,
   50-entry/60s window, already threaded into `CallContext.session.recent_calls` for
   behavioral baselining) gains `tool_name` and `call_id`. `AuditEvent` gains a
   `call_chain` field populated from that same window at block time. No new table, no
   new GenServer — the window already exists and already has the right lifetime
   semantics (bounded, session-scoped, already pruned).
4. **Approval-gate fire-rate gets a resolution-outcome counter + a rate alert, not a
   dashboard redesign.** `[:mcp, :decision]` telemetry already counts every `:hold`
   verdict, so raw fire-rate is already a derivable Prometheus series today
   (`rate(mcp_decisions_total{verdict="hold"}[1h])`). The actual gap is **resolution
   outcome** (approved vs. denied vs. timed-out) is not captured anywhere past
   `HoldRegistry`, and there's no alert on the pattern that actually predicts fatigue:
   a high and climbing *approval* rate on a gate that's supposed to be rare. This plan
   adds the missing counter and one `MCP.Alerts` threshold check; it does not touch the
   dashboard's hold-approval UI.
5. **Rug-pull gets its own alert key, using `MCP.Alerts.emit/4` exactly as documented** —
   no new alert infrastructure. `Plugins.RugPull` keeps producing `Finding`s (that part
   of the pipeline is unaffected; operators still see it in the event/finding feed), and
   additionally the pipeline raises an `:rug_pull` alert the moment a `rug_pull` finding
   is produced, same as `:sidecar_provenance` already fires alongside its own
   finding/log line.

## What does *not* change

- `TaintMarker`'s HMAC marker scheme, `TaintedArgGuard`'s matching logic, and
  `SecretLeak`'s regex patterns are untouched. Provenance taint sources carry no markers
  (there's no specific value to fingerprint) — `TaintedArgGuard` simply has nothing to
  match against them, which is correct: that plugin's job stays "did this specific
  tracked value come back," and `TaintGuard`'s job stays "has *anything* tainted flowed
  through this session."
- `AuditEvent.from_event/2`'s call sites (`PolicyEngine.receipt/2`) don't change their
  calling convention — `call_chain` is just another field threaded through the same
  `opts` keyword list pattern every other `AuditEvent` field already uses.
- `ApprovalGate.evaluate/2` is untouched — it still returns the same `Decision.hold/2`.
  Resolution-outcome counting happens where holds are already resolved
  (`HoldRegistry`/`PolicyEngine`'s hold-resolution path), not inside the plugin.
- `Plugins.RugPull.scan/2` keeps returning `{:ok, findings, updates}` exactly as today.
  The alert is raised by the pipeline/scanner-runner on seeing a `rug_pull`-typed
  finding, not by the plugin itself — same separation `MCP.Alerts`'s moduledoc already
  describes ("raised from anywhere an operator needs to know").

## Design

### 1. Provenance taint sources

**Tool/server trust tag.** Extend the existing tool-tag vocabulary
(`:sensitive_read`, `:network_egress`, …) with `:untrusted_source`. An operator sets it
in the same registration config that already carries tags — per-tool, or (common case)
once on the server registration so every tool an unvetted upstream exposes inherits it.
No schema change beyond adding the atom to wherever tags are validated/documented
(`docs/plugin-protocol.md` tag table).

**New scanner: `Plugins.ProvenanceTaint`** (`post_call`, mirrors `SecretLeak`'s shape):

```elixir
@impl true
def scan(:post_call, %CallContext{call: call} = ctx) do
  if :untrusted_source in (call[:tags] || []) do
    {:ok, [], %Decision{verdict: :annotate, mutations: %{add_taint_sources: [source(ctx)]}}}
  else
    {:ok, [], %Decision{verdict: :annotate, mutations: %{}}}
  end
end

defp source(%CallContext{call: call}) do
  %{
    origin_tool: call[:tool_name],
    finding_type: "untrusted_provenance",
    at: DateTime.utc_now(),
    markers: [],          # nothing to fingerprint — provenance taint has no marker set
    hint: "untrusted response"
  }
end
```

This is intentionally almost identical to `SecretLeak`'s `taint_mutation/2` — same
`add_taint_sources` mutation shape, same `session.taint.sources` list, same consumer
(`TaintGuard`). `TaintGuard.reason/2` already renders whatever `origin_tool` /
`finding_type` it's given, so no change needed there; a provenance-sourced block reads
as "network egress blocked: this session handled a secret via `scrape_page`" today —
worth a small message tweak (`finding_type`-aware wording: "handled untrusted content
via" vs. "handled a secret via") so the operator isn't told there was a credential when
there wasn't one.

`TaintedArgGuard` already no-ops correctly on a source with `markers: []` (`markers_of/1`
returns `[]`, `Enum.any?` over an empty list is `false`) — confirmed by reading the
plugin, no change needed there.

**Does this create a new false-positive surface?** Yes, deliberately — any
`:network_egress`-tagged call in a session that touched an `:untrusted_source`-tagged
tool now blocks (or, under `ApprovalGate`, holds) regardless of content. That's the
point: it's the net for the content `SecretLeak` cannot inspect. Operators who find this
too aggressive for a given integration un-tag it or scope the tag to the specific tools
that actually return untrusted content rather than the whole server — same knob that
already exists for `:sensitive_read` today.

### 2. Call-chain on block alerts

**Extend `PolicyEngine`'s call log.** Currently (`policy_engine.ex`):

```elixir
call_log = prune_call_log([%{tags: tags, at: now} | session.call_log], now)
```

Add the two fields needed to reconstruct a human-readable chain without a second
lookup:

```elixir
call_log = prune_call_log(
  [%{call_id: call_id, tool_name: tool_name, tags: tags, at: now} | session.call_log],
  now
)
```

`call_id` is already generated per-call (`generate_id()` at the `ctx` build site) — just
captured into the log entry instead of only the `CallContext`. No change to
`@call_log_window_ms` / `@call_log_max` (60 s / 50 entries) — that bound is exactly the
right shape for "what led to this block," and widening it is a separate, unrelated
tuning question if it ever comes up.

**`AuditEvent` gains `call_chain`:**

```elixir
defstruct [
  # ...
  call_chain: []
]

@type t :: %__MODULE__{
  # ...
  call_chain: [%{call_id: String.t(), tool_name: String.t(), tags: [atom()], at: DateTime.t()}]
}
```

**Populate it at the two block-producing call sites** (`reply_verdict/5` for
`:blocked`/`:shadow_blocked`, `reply_hold/4` for `:held`) by passing the session's
current `call_log` (pre-prepend, i.e. everything *before* this call) through `opts` into
`AuditEvent.from_event/2`, same pattern `:decisions` and `:findings` already use. For an
`:ok`/`:allow` event, `call_chain` stays `[]` — there's no "how did we get here" question
to answer for a call that wasn't blocked, and shipping it on every event would double
the audit sink's per-event payload for no benefit.

**Dashboard / audit export:** the block/hold card already shows `reason` and
`tool_name`; add a collapsed "chain" disclosure listing `call_chain` entries
(tool name + tags + relative time), same visual pattern the event feed already uses for
findings. SIEM-bound structured log lines (`Plugin.StructuredLogSink`) get the field for
free once it's on `AuditEvent`, since that sink already serializes the whole struct.

**What this does not solve:** `call_chain` is bounded to the 60s/50-call window and to
*this session* — a chain that spans a session boundary (closed/reopened) or predates the
window is not reconstructed. That's an acceptable v1 limit; the window already exists
for a different purpose (baselining) and happens to be the right shape for "recent
context," not a guarantee of complete provenance. If that gap matters later, it's a
retention-policy question for the audit store, not this plan.

### 3. Approval-gate fire-rate instrumentation

**Resolution-outcome telemetry.** Wherever a hold is resolved today — approved, denied,
or timed out (`HoldRegistry` / the `PolicyEngine` path that reads `HoldRegistry`'s
outcome and replays the pipeline verdict) — emit one new counter event:

```elixir
:telemetry.execute(
  [:mcp, :hold, :resolved],
  %{count: 1},
  %{outcome: outcome, tool_name: tool_name}  # outcome ∈ :approved | :denied | :timeout
)
```

Documented in `MCP.Telemetry`'s moduledoc table alongside `[:mcp, :decision]`, same
`[:mcp, ...]` prefix convention. This is the one new piece of data that doesn't already
exist: `[:mcp, :decision]` tells you a hold *fired*, this tells you what happened to it.

**The alert.** A gate that's supposed to be rare and is instead getting approved
constantly is the fatigue signal the reviewer flagged — not raw hold *count* (a busy
proxy legitimately holds more in absolute terms), but a **high and sustained approval
rate**. Add a periodic check (same `measurements/0` poller that already emits the
`[:mcp, :holds]` pending gauge) that tracks a rolling approval ratio over, e.g., the
trailing hour and calls:

```elixir
MCP.Alerts.emit(
  :approval_gate_fatigue,
  :warning,
  "approval-gate: #{pct}% of holds approved in the last hour (#{n} holds) — " <>
    "operators may be rubber-stamping; consider reviewing the gating rule",
  %{approval_rate: pct, sample_size: n}
)
```

Threshold and window are operator-tunable config (`plugin_config` on `ApprovalGate`,
or a small dedicated config key — `config :phoenix_elxir_beam, :approval_gate_alert,
rate: 0.9, min_samples: 10` is enough for v1; exact numbers are a product-guide
question, not an architecture one). Guard against noise on a quiet proxy with
`min_samples` so one approved hold out of one doesn't fire a 100%-rate alert.

**What this does not do:** it does not auto-disable or auto-tighten the gate. The
alert is advisory, same as every other `MCP.Alerts` key — it tells an operator to look,
it doesn't act unilaterally on their policy.

### 4. Rug-pull alert channel

Smallest of the four. Wherever `Plugins.RugPull`'s findings are consumed after a
`discovery` scan runs (the scanner-runner / `ServerRegistry` re-handshake path that
already applies the `quarantine: true` update), add:

```elixir
for finding <- findings, finding.type == "rug_pull" do
  MCP.Alerts.emit(
    :rug_pull,
    :critical,
    finding.title,
    %{server_id: server.id, tool_name: finding.locator.path, evidence: finding.evidence}
  )
end
```

`:critical` (not `:warning`) because the quarantine update already means the tool is
held pending operator review — this is already an active incident, not a
heads-up. This gets the same three guarantees every `MCP.Alerts.emit/4` call gets for
free, per its own moduledoc: structured `mcp.alert` log line for the SIEM, PubSub
broadcast to the dashboard's red banner, and a `[:mcp, :alert]` counter
(`mcp_alerts_total{key="rug_pull"}`) an operator can put its own alert rule on. No new
plumbing — this is one `emit/4` call at the one place rug-pull findings already surface.

## Milestones

### P1 — Provenance taint
- `:untrusted_source` tag added to the tag vocabulary / docs.
- `Plugins.ProvenanceTaint` scanner (new file, `post_call`), registered alongside
  `SecretLeak` in the default plugin set.
- `TaintGuard.reason/2`: `finding_type`-aware wording (credential vs. untrusted-content
  phrasing).
- **Acceptance:** fixture test — a tool tagged `:untrusted_source` returns a response
  with no credential-shaped content; a later `:network_egress`-tagged call in the same
  session is still blocked by `TaintGuard`, and `TaintedArgGuard` does not spuriously
  fire (no markers to match). A second fixture: the same tool *without* the tag does not
  taint the session.

### P2 — Call-chain on block alerts
- `call_log` entries gain `call_id`, `tool_name`.
- `AuditEvent` gains `call_chain`; `reply_verdict/5` and `reply_hold/4` thread it through
  `opts`.
- Dashboard: collapsed chain disclosure on blocked/held event cards.
- **Acceptance:** a policy-engine test — three calls in a session, the third one
  blocked, asserts the resulting `AuditEvent.call_chain` contains the prior two with
  correct `tool_name`/`tags`/ordering, and is empty on a separate `:ok` event in the same
  session.

### P3 — Approval-gate fire-rate
- `[:mcp, :hold, :resolved]` telemetry event at the hold-resolution site(s).
- Rolling approval-rate check in `measurements/0` (or a small dedicated GenServer if the
  windowed-rate bookkeeping doesn't fit cleanly into a stateless poller tick —
  implementor's call once P3 starts, flag if the poller route turns out awkward).
- `MCP.Alerts` key `:approval_gate_fatigue`, config for threshold/window/min_samples.
- **Acceptance:** unit test driving `HoldRegistry` resolution outcomes synthetically,
  asserting the alert fires once the configured approval rate/sample size is crossed and
  not before.

### P4 — Rug-pull alert channel
- `MCP.Alerts.emit(:rug_pull, :critical, ...)` at the discovery-scan consumption site.
- **Acceptance:** a `ServerRegistry`/discovery test — re-handshake with a drifted tool
  description asserts both the existing `quarantine` update/finding *and* a `:rug_pull`
  alert in `MCP.Alerts.recent/1`.

### P5 — Docs
- `docs/threat-model.md`: document provenance taint as the second taint-source feed,
  explicit about what it catches that marker-matching doesn't (and the converse).
- `docs/product-guide.md`: `:untrusted_source` tag in the tag-vocabulary table;
  `:approval_gate_fatigue` and `:rug_pull` in whatever alert-key reference already
  exists there (mirroring how `:audit_integrity` / `:sidecar_provenance` are documented
  today per `MCP.Alerts`'s moduledoc).

## Open questions for review before P1 starts

- Should `:untrusted_source` be a tag an operator sets, or should it default-apply to
  any tool from a server with no explicit trust configuration (secure-by-default, opt
  tools *out* of provenance taint rather than opting them in)? Leaning toward
  opt-in for v1 to avoid a flood of false positives on day one of adoption for an
  operator migrating an existing fleet of servers — but this is the one decision in this
  plan that most changes the proxy's default posture, worth a explicit sign-off rather
  than inferring it from precedent.
- P3's alert is a rate over a fixed trailing window. Is a fixed window (e.g. "last
  hour") good enough for v1, or does this need the same kind of per-plugin
  config surface `ApprovalGate` already has for `timeout_ms`? Recommend fixed window +
  one global config for v1; per-gate tuning is a natural follow-up once there's real
  resolution data to look at, same reasoning the dry-run plan used to defer its own
  summary view.
- P4 fires `:rug_pull` once per drifted tool per re-handshake. If a compromised
  upstream flips its description back and forth across repeated handshakes, should
  repeat alerts for the *same* tool within some cooldown be suppressed (to avoid
  alert-fatiguing the operator on the exact failure mode P3 is trying to catch for
  holds)? No existing `MCP.Alerts` key does dedup/cooldown today, so this would be new
  surface — flagging rather than deciding, since it cuts against this plan's own
  "no new infra" scoping for item 4.
