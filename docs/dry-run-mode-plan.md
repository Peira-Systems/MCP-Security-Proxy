# Dry-run mode — implementation plan

**Status:** Proposed · **Date:** 2026-09-30

## Why

Every policy verdict today is enforced live: `:deny` blocks the call, `:hold` parks it,
`:allow` lets it through (`Pipeline.run/3`, `PolicyEngine.handle_call/3` for `:record_call`).
There is no way to turn on a new plugin, or the proxy as a whole, and watch what it *would*
have done without it actually gating production traffic. An operator's first rollout of a new
rule (or the whole proxy, in front of a live agent) is a live-fire test. That's the single
biggest thing standing between "interesting project" and "I'd actually put this in front of my
agents."

This plan adds an observe-only mode: the pipeline still runs every plugin and computes a real
verdict, but a `:deny` / `:hold` is downgraded to "would have blocked" — the call proceeds,
the verdict is recorded and shown distinctly, nothing is actually withheld.

## Scope decisions (locked)

1. **Global toggle + per-plugin override.** One dashboard switch puts the whole proxy in
   observe-only mode. Independently, any single plugin can be pinned to `enforcing` or
   `dry_run` regardless of the global setting — so an operator can roll out one new rule in
   shadow mode while everything else stays enforcing, or vice versa.
2. **Dashboard-controlled, persisted like existing plugin state.** No env var / restart
   required. Follows the exact `Plugin.Registry` + `Plugin.StateStore` pattern already used
   for `enabled` / `order` / `config` overrides (ETS for the hot path, Postgres overlay
   applied at boot, ETS write-through on change).
3. **New event statuses**, not a bolted-on flag: `:shadow_blocked` and `:shadow_held`. A
   dry-run verdict is never mixed into `:blocked` / `:held` — the dashboard needs to render
   "this would have blocked" distinctly (amber, not red) from "this actually blocked," and a
   downstream audit query must be able to tell the two apart without inspecting a side field.

## What does *not* change

- Plugin `evaluate/2` implementations are untouched. A plugin has no idea whether it is
  running enforcing or dry-run — it still returns a real `Decision`. Downgrading a verdict is
  the pipeline's job, done once, in one place.
- `post_call` / `chunk` response-withholding and streaming-cut behavior get the same
  treatment (see M3) — dry-run is a pipeline-wide concept, not a `pre_call`-only one.
- Scanners' `can_block` grant, mutation grants (`add_tags`, `redact_response`,
  `add_taint_sources`) are unaffected: mutations from an `:allow`/`:annotate` still apply
  normally in dry-run (a shadow-blocked call didn't happen, but the plugins that *did* allow it
  still ran for real, since the point is to see the whole chain's real behavior up to the
  point something would have stopped it — see M1 for the exact cutoff semantics).

## Design

### 1. Per-entry `mode` field (`Plugin.Registry`)

Add `mode: :enforcing | :dry_run` to the plugin entry map (`base_entry/1` default:
`:enforcing`), alongside the existing `enabled` field. Same shape as `enabled`:

- `Plugin.Registry.set_mode/2` (`GenServer.call({:set_mode, name, mode})`), mirroring
  `set_enabled/2`.
- `Plugin.StateStore.put_mode/2`, mirroring `put_enabled/2` — one more nullable column
  (`mode: :string`, `nil` meaning "no override, use config default") on `plugin_states`, one
  more migration, one more branch in `apply_persisted_overlay/1`.
- `PluginState` schema gains `field :mode, :string`.

### 2. Global mode (new, small GenServer or piggyback on `Plugin.Registry`)

A single persisted boolean/enum, `proxy_mode: :enforcing | :dry_run`, stored the same way
(`plugin_states` is per-plugin, so this needs its own tiny table or a reserved row —
recommend a one-row `proxy_settings` table rather than overloading `plugin_states` with a
sentinel name). Exposed as `Plugin.Registry.proxy_mode/0` and `set_proxy_mode/1`, read once
per pipeline run (not per plugin) since it's the outer switch.

### 3. Effective mode resolution

```elixir
defp effective_mode(entry, global_mode) do
  case entry.mode do
    :enforcing -> :enforcing
    :dry_run -> :dry_run
    nil -> global_mode  # no per-plugin override → inherit the global switch
  end
end
```

Per-plugin `mode` defaults to `nil` (inherit), not `:enforcing` — so flipping the global
switch actually moves every plugin that hasn't been explicitly pinned. An explicit
`:enforcing` or `:dry_run` on the entry always wins over the global switch (that's the
override in "global toggle + per-plugin override").

### 4. Pipeline changes (`Pipeline.evaluate_chain/4`, `run_post_call/2`, `run_chunk/2`)

This is the one place enforcement actually happens, so it's the one place that needs to
downgrade a verdict. Current `evaluate_chain/4`:

```elixir
case decision.verdict do
  :deny -> {:deny, %{decision | deciding_plugin: entry.name, findings: findings}, findings}
  :hold -> {:hold, %{decision | deciding_plugin: entry.name, findings: findings}, findings}
  verdict when verdict in [:allow, :annotate] ->
    evaluate_chain(rest, phase, apply_mutations(ctx, entry, decision), findings)
end
```

New shape: compute `effective_mode(entry, global_mode)`. If the raw verdict is `:deny` or
`:hold` **and** `effective_mode == :dry_run`, do not short-circuit — record a
`would_have: verdict` marker on the decision (a new `Decision` field, `shadow_verdict:
:deny | :hold | nil`, default `nil`) and continue the chain as if the plugin had returned
`:allow`, still applying any mutations from that decision that are valid for the verdict type.
Because the real plugin returned `:deny`, there are no `add_tags`/`redact_response` mutations
to apply from it in practice (only `:allow`/`:annotate` carry mutations today) — so "continue
as if allow" is just "don't stop the chain," no mutation semantics to invent.

Only the **first** plugin that would have denied/held sets `shadow_verdict` — once set, later
plugins in the chain still run (so the operator sees the whole chain's real behavior, not just
up to the first would-be block), but `deciding_plugin` / the shown reason stays pinned to the
first one, matching how enforcing mode already treats `:deny` as final via first-match.
`evaluate_chain/4` therefore keeps a `shadow` accumulator alongside `findings` through the
recursion instead of returning early.

`run_post_call/2` and `run_chunk/2` need the same treatment: a `:deny` that would have withheld
the response / cut the stream instead notes `shadow_verdict` and lets the response/chunk
through, `results` already being built with `Enum.map` over independent plugin runs rather than
a short-circuiting reduce, so this is a smaller change there — replace
`Enum.find(results, &(&1.verdict == :deny))` with a split into "real denial" (enforcing-mode
verdict) vs "shadow denial" (dry-run-mode verdict) and thread both through to the caller.

### 5. `Decision` struct

Add `shadow_verdict: :deny | :hold | nil` (default `nil`). Set by the pipeline, never by a
plugin — a plugin's `evaluate/2` return is unaware of mode, full stop.

### 6. `PolicyEngine` / `Event`

`Event.status` gains `:shadow_blocked` and `:shadow_held` to the `@type status`. In
`handle_call({:record_call, ...})`, `pipeline_verdict` needs a third branch: if
`decision.shadow_verdict` is set (regardless of the real `pipeline_verdict`, which will now be
`:allow` per M4's "continue as if allow"), record the shadow status and let the call proceed
exactly like a real `:allow` — same `accumulate_tags`, same taint accumulation, same
`{:reply, {:allow, event}, state}` — except `event.status` is `:shadow_blocked` /
`:shadow_held` and `event.reason` carries the shadow decision's reason so the operator sees
*why* it would have been blocked.

`reply_hold/4`'s hold-registry parking is skipped entirely in shadow mode — there is nothing to
approve, the call already went through. `HoldRegistry.park/2` is only invoked for a real
`:hold`.

### 7. Dashboard (`MCPDashboardLive`)

- A global "Dry-run mode" toggle near the existing plugin controls, wired to
  `Plugin.Registry.set_proxy_mode/1` and recorded as a `:policy_change` event (existing
  `record_policy_change/2` path — `kind: :dry_run_mode`, `before`/`after` the enum values),
  same as every other operator action already is.
- Per-plugin mode gets a third control next to each plugin's enable/disable switch: a
  three-way `Enforcing / Dry-run / (inherit)` selector, same visual language as
  `unclassified-guard`'s existing `mode` select field in `ConfigSchema` (off/deny/hold) — this
  is not a new UI pattern, it's the same one applied one level up.
- Event feed / call chain view: `:shadow_blocked` / `:shadow_held` get their own color (amber)
  distinct from `:blocked` (red) / `:held` (also currently distinct) / `:ok` (green), plus a
  label like "would block" so it reads unambiguously in a live traffic view. `tag_pill_class/1`
  and friends in `mcp_dashboard_live.ex` already do exactly this kind of status→class mapping
  for tags; the same table gets two more rows for statuses.
- Somewhere visible (header bar, next to the connection status) shows current global mode —
  an operator should never have to open settings to find out the proxy is quietly not
  enforcing anything.

### 8. Audit / receipts

No change to the receipt mechanism itself (`PolicyEngine.receipt/3`) — `:shadow_blocked` /
`:shadow_held` events flow through the exact same `AuditEvent.from_event/2` → sink fan-out
path as every other status. This is important: shadow-mode decisions must be just as durable
and hash-chained as real ones, since the whole point is to audit "what would this rule have
done" over a real traffic window before trusting it.

## Milestones

### D1 — Data model + registry plumbing
- Migration: `plugin_states.mode` (nullable string), new `proxy_settings` table (one row,
  `mode` string, default `"enforcing"`).
- `PluginState` schema, `Plugin.StateStore.put_mode/2`, `.get_proxy_mode/0`,
  `.put_proxy_mode/1`.
- `Plugin.Registry`: entry gains `mode`, `set_mode/2`, `proxy_mode/0`, `set_proxy_mode/1`,
  `apply_persisted_overlay/1` restores both.
- **Acceptance:** unit tests — setting/persisting/restoring per-plugin mode and global mode
  survive a registry restart, same shape as the existing `enabled`/`order` persistence tests.

### D2 — Decision + Pipeline
- `Decision` struct: `shadow_verdict` field.
- `Pipeline.evaluate_chain/4`: effective-mode resolution, shadow downgrade, chain continues
  past a would-be deny/hold, first shadow verdict wins for `deciding_plugin`/`reason`, later
  plugins still evaluated.
- `Pipeline.run_post_call/2`, `run_chunk/2`: same downgrade, split real-vs-shadow denial.
- **Acceptance:** pipeline unit tests — a fixture chain where plugin A would deny and plugin B
  (later, dry_run-inherited) would also deny: assert final verdict is `:allow`,
  `shadow_verdict == :deny`, `deciding_plugin` is A (first), and B still ran (its finding, if
  any, is present). Mirror for `:hold`, and for a global-dry-run + one plugin pinned
  `:enforcing` (that one plugin's deny *does* block for real, proving override precedence).

### D3 — PolicyEngine + Event
- `Event.status` gains `:shadow_blocked`, `:shadow_held`.
- `record_call` branch: shadow verdict → allow-shaped reply with shadow status; real `:hold`
  still parks; real `:deny` still blocks.
- `record_policy_change` used for the global toggle flip.
- **Acceptance:** `policy_engine_test.exs` cases for: shadow-blocked call still accumulates
  tags/taint as an allow would; a real hold with an unrelated dry-run-pinned plugin elsewhere
  in the chain still parks correctly; audit sink receives the shadow event.

### D4 — Dashboard
- Global toggle, per-plugin three-way mode control, event-feed color/label for the two new
  statuses, header indicator for current global mode.
- **Acceptance:** LiveView test — toggling global dry-run via the dashboard element, a
  subsequent simulated call chain that would deny shows as `shadow_blocked` in the feed with
  the "would block" treatment, not `blocked`.

### D5 — Docs
- `docs/product-guide.md`: new "Dry-run mode" section next to the existing plugin-table
  explanation (`ApprovalGate` / `ChainExfil` / `TaintGuard` rows) — this is the thing an
  operator reads before turning any of that on for real, so document scope decisions 1–3
  from the top of this plan there, in operator language, not implementation language.
- `docs/threat-model.md`: note that dry-run does not reduce coverage of existing controls in
  their own right — it's a rollout tool, not a weaker mode of the detectors.

## Open questions for review before D1 starts

- Should a `:hold` in dry-run still notify whoever monitors `ApprovalGate` holds (e.g. a
  Slack ping), just without actually parking the call? Leaning no for v1 — a dry-run hold is
  already visible in the dashboard feed as `:shadow_held`; wiring notification sinks for a
  no-op approval adds surface area without a clear rollout benefit. Flag if that's wrong.
- Retention/reporting: is a running "would have blocked N times over the last 24h" summary
  per plugin in scope for D4, or is the raw event feed enough for v1? Recommend deferring a
  dedicated summary view — it's a straightforward follow-up once `:shadow_blocked` events
  exist to aggregate, and building it before there's real shadow-mode traffic to look at is
  premature.
