# LoopGuard: Runaway Agent-Loop Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `PhoenixElxirBeam.MCP.Plugins.LoopGuard`, a `pre_call` policy that denies a call once the session shows signs of a stuck agent — the same tool called too many times too fast, with the same (or near-identical) arguments, optionally weighted by recent failures — independent of whether any individual call looks malicious. This is an operational-safety gap, not a security-detection gap: nothing in the proxy today distinguishes "an agent thrashing on a bad loop" from normal call volume.

**Why now:** competitive research (`docs/superpowers/plans/` fundraising/competitive-analysis work, 2026-10-05) turned up `mcp-guardian` (archived, 0-star, but real design) implementing exactly this — a "convergence gate" (same tool+target K times in a window) plus "constraint learning" (block retries of a call that just failed). Checking this proxy's own plugins (`BaselineGuard`, `RateLimiter`) confirmed neither covers it: `RateLimiter` is raw per-API-key HTTP volume (DoS-shaped, not semantic), and `BaselineGuard` keys off *tag* volume regardless of which specific tool/arguments were involved or whether the call succeeded. There is no existing plugin here that would catch an agent retrying the identical failing `write_file` call twenty times in ten seconds.

**Scope split (read this before Task 1):** full failure-aware constraint-learning (deny retries of a call that *just failed*) needs an outcome signal — `response.isError` — fed back from `post_call` into the session's call history, which does not exist today (`isError` reaches `post_call` plugins per `docs/plugin-protocol.md` but is never written back into `session.call_log`/`recent_calls`, which is built once at `pre_call` time and never touched by `post_call`). Plumbing that through is a real, separable piece of work with its own failure modes (a `post_call` plugin now needs write access to session state it never had before). **This plan ships outcome-agnostic loop detection only** (Tasks 1–4: same tool, same argument-fingerprint, called K times in a window — catches thrashing regardless of success/failure) and documents the failure-aware extension as an explicit out-of-scope follow-on (see "What does *not* change" below), the same way the taint-provenance plan split `call_chain` plumbing from the alerting work that consumed it.

**Architecture:** `LoopGuard` is a new `pre_call` policy plugin, same shape as `BaselineGuard` (`lib/phoenix_elxir_beam/mcp/plugins/baseline_guard.ex`) — stateless itself, reading a bounded window the pipeline already threads in. It needs two pieces of session history `BaselineGuard` doesn't: the **tool name** per logged call (already present in `PolicyEngine`'s in-process `call_log`, just not yet exposed to plugins as part of `recentCalls`) and an **argument fingerprint** per logged call (does not exist yet — new). `PolicyEngine.record_call/6` gains an argument-fingerprint computation (pure function, new module `PhoenixElxirBeam.MCP.CallFingerprint`) and writes `tool_name` + the fingerprint into each `call_log` entry; `CallContext`'s `recentCalls` shape grows two fields. `LoopGuard` then counts, within its own configured window, how many recent entries share the current call's `{tool_name, fingerprint}` pair (strict loop signal) versus just `tool_name` (looser thrash signal, separate threshold) and denies when either threshold is exceeded.

**Tech Stack:** Elixir 1.18, ExUnit — no new dependencies, no migration (nothing here is persisted; `call_log` is in-process `GenServer` state, same as today).

## Global Constraints

- **No new database migration.** `call_log`/`recent_calls` is `PolicyEngine`'s in-memory per-session state (`state.sessions[session_id].call_log`), never persisted to Postgres. This plan only changes what shape its entries carry in memory and over the plugin-context boundary.
- **Argument fingerprint, never raw arguments, in `call_log`/`recentCalls`.** Arguments can contain secrets (the same reason `TaintedArgGuard`/`SecretLeak` exist). The fingerprint is a salted/keyed digest (reuse the pattern `ToolHash` already established for canonical-JSON + SHA-256 hashing — see Task 1), not reversible, and never includes the raw argument values in any log, plugin context, or wire payload. This is a one-way equality check ("are these two calls' arguments the same"), not an audit trail of what the arguments were.
- **`fail_mode: :fail_open`**, same as `BaselineGuard` — this is a heuristic operational guard, not a hard security boundary; a bug here must never be able to wedge all traffic.
- **Two independent thresholds, not one.** "Same tool, same args, K times" (tight — a genuine stuck retry loop) and "same tool, any args, K times" (looser — thrashing on a flaky but varying call) are different signals with different false-positive profiles and must be independently configurable and independently reportable in the deny reason, the same way `BaselineGuard` reports exactly which tag/count tripped.
- **Outcome/failure awareness is explicitly out of scope for this plan** — see the Scope split note above. Do not attempt to thread `response.isError` back into `call_log` as part of this plan; that is a separate, future plan once this ships and the two-threshold heuristic's real-world false-positive rate is known.
- **Wire protocol (`docs/plugin-protocol.md`) update is additive only.** `recentCalls` entries gain `toolName` and `argFingerprint` fields; existing sidecar plugins that only read `tags`/`at` must keep working unchanged (same tolerance the `call_chain` field's addition already established — a consumer that doesn't look for a field it doesn't know about is unaffected).

## Review Focus

- **Argument-order sensitivity in the fingerprint.** Two calls with the same arguments but keys serialized in a different order (e.g. a client library that doesn't guarantee map key order) must fingerprint identically — reuse `ToolHash`'s canonicalization (recursively sorted keys) rather than hashing `Jason.encode!/1` directly on the raw map, or two semantically-identical calls will never match and the tight threshold becomes dead code.
- **A single long-lived session with high legitimate volume of the *same* tool with *varying* arguments** (e.g. an agent paginating through search results, same tool, same shape, different page tokens each time) must not trip the tight (tool+args) threshold — each call's fingerprint differs — but could legitimately trip the loose (tool-only) threshold if the operator sets it too low. The plan's default loose threshold must be high enough that normal pagination doesn't trip it; document this trade-off explicitly in the config moduledoc, same as `BaselineGuard` documents its own window/threshold trade-off.
- **A call with no arguments at all (empty map / nil).** Must still fingerprint deterministically (not crash, not treat every argument-less call as automatically "different" or automatically "identical" in a way that defeats the point) — canonicalize `%{}`/`nil` to the same stable value every time.
- **`recent_calls`/`call_log` entries written before this plugin existed** (a session that started before a deploy of this feature, or any other plugin reading the window that only ever set `tags`/`at`). `LoopGuard` must treat a missing `tool_name`/`arg_fingerprint` key as "doesn't match anything" rather than crashing `Map.fetch!`-style — same defensive pattern `BaselineGuard.tagged?/2` already uses for a malformed entry.
- **Interaction with `BaselineGuard` on the same call.** Both plugins read the same `recent_calls` window and can both independently deny the same call for different reasons; the pipeline's existing first-deny-wins ordering already handles this correctly (no new coordination needed) — this is a note for the reviewer to confirm, not a code change.
- **Config value validation mirrors `BaselineGuard`'s `int/2` helper exactly** (accepts non-negative integer or a numeric string, falls back to default on anything else) — don't invent a second, subtly different parsing helper for the same shape of config value.

---

## Task 1: `CallFingerprint` — pure argument-fingerprinting module

**Files:**
- Create: `lib/phoenix_elxir_beam/mcp/call_fingerprint.ex`
- Test: `test/phoenix_elxir_beam/mcp/call_fingerprint_test.exs`

**Interfaces:**
- Produces: `CallFingerprint.compute(arguments :: map() | nil) :: String.t()` — a stable `"sha256:" <> hex` digest of the canonicalized arguments. Reuses `ToolHash`'s canonicalization approach (recursively sorted map keys) rather than duplicating a slightly different one.

- [ ] **Step 1: Write the test first**

```elixir
defmodule PhoenixElxirBeam.MCP.CallFingerprintTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.CallFingerprint

  describe "compute/1" do
    test "same arguments produce the same fingerprint regardless of key order" do
      a = CallFingerprint.compute(%{"path" => "/tmp/x", "mode" => "write"})
      b = CallFingerprint.compute(%{"mode" => "write", "path" => "/tmp/x"})
      assert a == b
    end

    test "different arguments produce different fingerprints" do
      a = CallFingerprint.compute(%{"path" => "/tmp/x"})
      b = CallFingerprint.compute(%{"path" => "/tmp/y"})
      refute a == b
    end

    test "nested maps are canonicalized recursively" do
      a = CallFingerprint.compute(%{"opts" => %{"b" => 1, "a" => 2}})
      b = CallFingerprint.compute(%{"opts" => %{"a" => 2, "b" => 1}})
      assert a == b
    end

    test "nil and empty map both fingerprint deterministically, and to the same value as each other" do
      assert CallFingerprint.compute(nil) == CallFingerprint.compute(%{})
      assert CallFingerprint.compute(nil) == CallFingerprint.compute(nil)
    end

    test "returns a sha256: prefixed hex digest" do
      assert "sha256:" <> hex = CallFingerprint.compute(%{"a" => 1})
      assert String.length(hex) == 64
      assert hex =~ ~r/^[0-9a-f]+$/
    end

    test "raw argument values never appear in the output" do
      fp = CallFingerprint.compute(%{"secret" => "AKIAVERYSECRETVALUE"})
      refute fp =~ "AKIAVERYSECRETVALUE"
    end
  end
end
```

- [ ] **Step 2: Implement**

```elixir
defmodule PhoenixElxirBeam.MCP.CallFingerprint do
  @moduledoc """
  A one-way, order-independent fingerprint of a tool call's arguments —
  "are these two calls' arguments the same," never a way to recover what
  they were. Used by `Plugins.LoopGuard` to detect an agent retrying the
  identical call; never logged or surfaced alongside the raw arguments
  themselves (see that plugin's moduledoc and
  `docs/superpowers/plans/2026-10-05-loop-guard.md`'s global constraints).

  Canonicalization mirrors `PhoenixElxirBeam.MCP.ToolHash`: object keys are
  sorted recursively before hashing, so argument maps that are
  semantically identical but serialized with differently-ordered keys
  fingerprint identically.
  """

  @doc """
  Returns `"sha256:" <> hex` for a call's arguments. `nil` and `%{}` are
  treated as the same, deterministic "no arguments" value.
  """
  @spec compute(map() | nil) :: String.t()
  def compute(arguments) do
    canonical = canonicalize(arguments || %{})
    digest = :crypto.hash(:sha256, Jason.encode!(canonical))
    "sha256:" <> Base.encode16(digest, case: :lower)
  end

  defp canonicalize(map) when is_map(map) do
    map
    |> Enum.map(fn {k, v} -> {to_string(k), canonicalize(v)} end)
    |> Enum.sort_by(fn {k, _v} -> k end)
  end

  defp canonicalize(list) when is_list(list), do: Enum.map(list, &canonicalize/1)
  defp canonicalize(other), do: other
end
```

- [ ] **Step 3: Run `mix test test/phoenix_elxir_beam/mcp/call_fingerprint_test.exs`, confirm green**

---

## Task 2: Thread `tool_name` + argument fingerprint into `call_log` / `recentCalls`

**Files:**
- Modify: `lib/phoenix_elxir_beam/mcp/policy_engine.ex` (the `call_log` entry built in `handle_call({:record_call, ...})`, ~line 377-382)
- Modify: `lib/phoenix_elxir_beam/mcp/call_context.ex` (moduledoc only — correct the stale "tags, at" description)
- Modify: `lib/phoenix_elxir_beam/mcp/plugin/wire.ex` (`maybe_put_session_recent_calls/2`, ~line 163) if it narrows the entry shape before sending over the wire to sidecars
- Modify: `docs/plugin-protocol.md` (`recentCalls` entry shape, ~line 533)
- Test: extend `test/phoenix_elxir_beam/mcp/policy_engine_test.exs` (or add `policy_engine_loop_guard_test.exs` if the existing file is organized by feature — check first)

**Interfaces:**
- `call_log` / `recent_calls` entries gain two keys: `tool_name :: String.t()` (already exists in the entry as of the taint-provenance plan — confirm, don't re-add) and `arg_fingerprint :: String.t()` (new, via `CallFingerprint.compute/1`).

- [ ] **Step 1: Confirm current entry shape with a focused read**

Read `lib/phoenix_elxir_beam/mcp/policy_engine.ex` around the `call_log =` assignment in `handle_call({:record_call, ...})`. As of the taint-provenance plan (`docs/superpowers/plans/2026-10-04-...`, already shipped), the entry is `%{call_id: call_id, tool_name: tool_name, tags: tags, at: now}` — `tool_name` is already present. This task only needs to add `arg_fingerprint`.

- [ ] **Step 2: Write the test first**

Extend the existing `record_call` test coverage with a case proving the fingerprint round-trips into a later call's `CallContext`:

```elixir
test "a call's recent_calls entry carries an arg_fingerprint derived from its own arguments" do
  # ensure_session, then record_call twice with different arguments for the
  # SAME tool_name, then record_call a third time and inspect the
  # CallContext built for it (via a stub/capturing plugin, same pattern
  # existing recent_calls tests already use) — assert the first two
  # recent_calls entries have different arg_fingerprint values, and that
  # the fingerprint matches PhoenixElxirBeam.MCP.CallFingerprint.compute/1
  # applied independently to the same arguments.
end
```

- [ ] **Step 3: Implement** — in the `call_log =` build, change the entry to:

```elixir
call_log =
  prune_call_log(
    [
      %{
        call_id: call_id,
        tool_name: tool_name,
        tags: tags,
        arg_fingerprint: CallFingerprint.compute(arguments),
        at: now
      }
      | prior_calls
    ],
    now
  )
```

Add `alias PhoenixElxirBeam.MCP.CallFingerprint` near the module's existing aliases.

- [ ] **Step 4: Check `Plugin.Wire`'s `maybe_put_session_recent_calls/2`**

If it maps the entry to a narrower wire shape (likely, since the wire protocol doc currently only documents `tags`/`at`), add `toolName`/`argFingerprint` to that mapping, camelCased per the wire-protocol's existing convention (`seenTags`, `callsSoFar`, etc.).

- [ ] **Step 5: Update `docs/plugin-protocol.md`'s `recentCalls` entry shape**

```
recentCalls: Array<{                 // gated by dataNeeds ("session.recentCalls")
  toolName: string;
  tags: string[];
  argFingerprint: string;            // one-way SHA-256 of canonicalized arguments; never the raw arguments
  at: string;                       // RFC 3339
}>;                                  // bounded recent window, for behavioural baselining and loop detection
```

- [ ] **Step 6: Correct `CallContext`'s moduledoc** — it currently says `recent_calls` is "`%{tags, at}`, for behavioural baselining"; update to reflect the full shape and that it now also backs loop detection.

- [ ] **Step 7: Run the full `mcp` test subtree, confirm green, confirm no existing test asserted the old narrower entry shape in a way that now needs updating**

---

## Task 3: `LoopGuard` plugin

**Files:**
- Create: `lib/phoenix_elxir_beam/mcp/plugins/loop_guard.ex`
- Test: `test/phoenix_elxir_beam/mcp/plugins/loop_guard_test.exs`

**Interfaces:**
- A standard `Plugin.Policy` implementation: `manifest/0`, `evaluate(:pre_call, ctx)`.

- [ ] **Step 1: Write the test first**, modeled directly on `test/phoenix_elxir_beam/mcp/plugins/baseline_guard_test.exs`'s structure:

```elixir
defmodule PhoenixElxirBeam.MCP.Plugins.LoopGuardTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.{CallContext, Decision}
  alias PhoenixElxirBeam.MCP.Plugins.LoopGuard
  alias PhoenixElxirBeam.MCP.CallFingerprint

  defp entry(tool_name, fingerprint, at) do
    %{tool_name: tool_name, arg_fingerprint: fingerprint, tags: [], at: at}
  end

  defp ctx(tool_name, fingerprint, recent, cfg \\ %{}) do
    now = DateTime.utc_now()

    CallContext.new(%{
      phase: :pre_call,
      call: %{tool_name: tool_name, arguments: %{}, tags: []},
      session: %{recent_calls: recent ++ [entry(tool_name, fingerprint, now)]},
      plugin_config: cfg
    })
  end

  describe "evaluate/2 — tight threshold (same tool + same arguments)" do
    test "allows when the identical call hasn't repeated past the threshold" do
      fp = CallFingerprint.compute(%{"path" => "/x"})
      now = DateTime.utc_now()
      recent = for _ <- 1..2, do: entry("write_file", fp, now)

      assert %Decision{verdict: :allow} =
               LoopGuard.evaluate(:pre_call, ctx("write_file", fp, recent, %{"max_identical_calls" => 3}))
    end

    test "denies once the identical tool+arguments pair repeats past the threshold" do
      fp = CallFingerprint.compute(%{"path" => "/x"})
      now = DateTime.utc_now()
      recent = for _ <- 1..3, do: entry("write_file", fp, now)

      assert %Decision{verdict: :deny, reason: reason} =
               LoopGuard.evaluate(:pre_call, ctx("write_file", fp, recent, %{"max_identical_calls" => 3}))

      assert reason =~ "write_file"
      assert reason =~ "identical"
    end

    test "different arguments to the same tool do not count toward the tight threshold" do
      fp_a = CallFingerprint.compute(%{"path" => "/x"})
      fp_b = CallFingerprint.compute(%{"path" => "/y"})
      now = DateTime.utc_now()
      recent = for _ <- 1..3, do: entry("write_file", fp_a, now)

      assert %Decision{verdict: :allow} =
               LoopGuard.evaluate(:pre_call, ctx("write_file", fp_b, recent, %{"max_identical_calls" => 3}))
    end
  end

  describe "evaluate/2 — loose threshold (same tool, any arguments)" do
    test "denies once the same tool repeats past the looser threshold even with varying arguments" do
      now = DateTime.utc_now()
      recent =
        for i <- 1..5, do: entry("search", CallFingerprint.compute(%{"page" => i}), now)

      ctx =
        ctx("search", CallFingerprint.compute(%{"page" => 6}), recent, %{
          "max_identical_calls" => 100,
          "max_same_tool_calls" => 5
        })

      assert %Decision{verdict: :deny, reason: reason} = LoopGuard.evaluate(:pre_call, ctx)
      assert reason =~ "search"
    end
  end

  describe "evaluate/2 — defensive handling" do
    test "treats entries missing tool_name/arg_fingerprint as non-matching, not a crash" do
      now = DateTime.utc_now()
      stale_entry = %{tags: [], at: now}
      fp = CallFingerprint.compute(%{})

      assert %Decision{verdict: :allow} =
               LoopGuard.evaluate(:pre_call, ctx("write_file", fp, [stale_entry]))
    end

    test "only counts entries within the configured window" do
      fp = CallFingerprint.compute(%{})
      old = DateTime.add(DateTime.utc_now(), -60, :second)
      recent = for _ <- 1..3, do: entry("write_file", fp, old)

      assert %Decision{verdict: :allow} =
               LoopGuard.evaluate(
                 :pre_call,
                 ctx("write_file", fp, recent, %{"window_ms" => 5_000, "max_identical_calls" => 3})
               )
    end
  end

  test "manifest declares pre_call, fail_open, and session.recentCalls data need" do
    manifest = LoopGuard.manifest()
    assert manifest.capabilities.policy.phases == [:pre_call]
    assert manifest.capabilities.policy.fail_mode == :fail_open
    assert "session.recentCalls" in manifest.capabilities.policy.data_needs
  end
end
```

- [ ] **Step 2: Implement**

```elixir
defmodule PhoenixElxirBeam.MCP.Plugins.LoopGuard do
  @moduledoc """
  Runaway-agent-loop detection: a `pre_call` policy that denies a call once
  the session shows signs of a stuck agent thrashing on the same tool —
  independent of whether the calls look malicious or whether they've been
  succeeding or failing (outcome-awareness is a documented future
  extension, not this plugin — see
  `docs/superpowers/plans/2026-10-05-loop-guard.md`).

  Two independent thresholds, both counted over the same `window_ms`
  look-back into `session.recent_calls`:

    * **`max_identical_calls`** — the same tool called with the *same*
      arguments (via `PhoenixElxirBeam.MCP.CallFingerprint`, a one-way
      fingerprint — raw arguments are never compared or logged here)
      more than this many times. The tight signal: a genuine stuck retry
      loop (e.g. the same failing `write_file` call repeated).
    * **`max_same_tool_calls`** — the same tool called with *any*
      arguments more than this many times. The loose signal: thrashing on
      a tool with varying inputs (e.g. hammering a search endpoint).
      Set well above normal legitimate-use patterns like pagination —
      see the plan's Review Focus for the false-positive trade-off.

      config: %{
        "window_ms"            => 10_000,
        "max_identical_calls"  => 3,
        "max_same_tool_calls"  => 15
      }

  Heuristic by nature, so `fail_mode` is `:fail_open`, same as
  `BaselineGuard`, which this plugin otherwise mirrors in shape —
  `BaselineGuard` keys off *tag* volume; this keys off *tool identity*
  (and, for the tight threshold, argument identity) instead.
  """

  @behaviour PhoenixElxirBeam.MCP.Plugin.Policy

  alias PhoenixElxirBeam.MCP.{CallContext, CallFingerprint, Decision}
  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @default_window_ms 10_000
  @default_max_identical_calls 3
  @default_max_same_tool_calls 15

  @impl true
  def manifest do
    Manifest.normalize(%{
      plugin: %{
        name: "loop-guard",
        version: "0.1.0",
        description:
          "Denies a call once the session shows a runaway loop on one tool — same arguments " <>
            "repeated, or the same tool thrashed regardless of arguments."
      },
      capabilities: %{
        policy: %{
          phases: [:pre_call],
          tool_tags: [],
          data_needs: ["session.recentCalls"],
          timeout_ms: 50,
          fail_mode: :fail_open
        }
      }
    })
  end

  @impl true
  def evaluate(:pre_call, %CallContext{} = ctx) do
    cfg = ctx.plugin_config || %{}
    window_ms = int(cfg["window_ms"], @default_window_ms)
    max_identical = int(cfg["max_identical_calls"], @default_max_identical_calls)
    max_same_tool = int(cfg["max_same_tool_calls"], @default_max_same_tool_calls)

    tool_name = Map.get(ctx.call, :tool_name)
    fingerprint = CallFingerprint.compute(Map.get(ctx.call, :arguments))

    recent = Map.get(ctx.session, :recent_calls, [])
    now = latest_at(recent)

    {identical_count, same_tool_count} =
      Enum.reduce(recent, {0, 0}, fn entry, {id_acc, tool_acc} ->
        if within?(entry, now, window_ms) and same_tool?(entry, tool_name) do
          tool_acc = tool_acc + 1
          id_acc = if same_fingerprint?(entry, fingerprint), do: id_acc + 1, else: id_acc
          {id_acc, tool_acc}
        else
          {id_acc, tool_acc}
        end
      end)

    cond do
      identical_count > max_identical ->
        Decision.deny(
          :high,
          "runaway loop: #{tool_name} called with identical arguments #{identical_count} " <>
            "times in the last #{Float.round(window_ms / 1000, 1)}s (limit #{max_identical})"
        )

      same_tool_count > max_same_tool ->
        Decision.deny(
          :medium,
          "runaway loop: #{tool_name} called #{same_tool_count} times in the last " <>
            "#{Float.round(window_ms / 1000, 1)}s (limit #{max_same_tool})"
        )

      true ->
        Decision.allow()
    end
  end

  defp within?(%{at: %DateTime{} = at}, %DateTime{} = now, window_ms),
    do: DateTime.diff(now, at, :millisecond) <= window_ms

  defp within?(_entry, _now, _window_ms), do: true

  defp same_tool?(%{tool_name: name}, tool_name) when is_binary(name), do: name == tool_name
  defp same_tool?(_entry, _tool_name), do: false

  defp same_fingerprint?(%{arg_fingerprint: fp}, fingerprint) when is_binary(fp),
    do: fp == fingerprint

  defp same_fingerprint?(_entry, _fingerprint), do: false

  defp latest_at(recent) do
    recent
    |> Enum.map(&Map.get(&1, :at))
    |> Enum.filter(&match?(%DateTime{}, &1))
    |> Enum.max(DateTime, fn -> DateTime.utc_now() end)
  end

  defp int(n, _default) when is_integer(n) and n >= 0, do: n

  defp int(s, default) when is_binary(s) do
    case Integer.parse(s) do
      {n, ""} when n >= 0 -> n
      _ -> default
    end
  end

  defp int(_n, default), do: default
end
```

- [ ] **Step 3: Run `mix test test/phoenix_elxir_beam/mcp/plugins/loop_guard_test.exs`, confirm green**

---

## Task 4: Wire into config, dashboard, docs

**Files:**
- Modify: `config/dev.exs`, `config/test.exs`, `config/prod.exs` (register the plugin, same pattern as `BaselineGuard`'s three entries)
- Modify: `docs/product-guide.md` (plugin table — add a row, same section `BaselineGuard`/`ChainExfil`/`TaintGuard` are documented in)
- Modify: `docs/threat-model.md` (note this is an operational/availability guard, not a security-detection control — same distinction already drawn for `ResponseSizeGuard`, if applicable — check that doc's existing framing)
- Test: a LiveView test asserting the plugin shows up in the dashboard's plugin list (likely already covered generically by an existing "all registered plugins render" test — check before adding a new one)

- [ ] **Step 1: Register in `config/test.exs`** (place near `BaselineGuard`, same file, since they're conceptually adjacent):

```elixir
{PhoenixElxirBeam.MCP.Plugins.LoopGuard,
 config: %{
   "window_ms" => 10_000,
   "max_identical_calls" => 3,
   "max_same_tool_calls" => 15
 }},
```

- [ ] **Step 2: Register in `config/dev.exs`**, same shape.

- [ ] **Step 3: Register in `config/prod.exs`**, same shape. (Confirmed: `prod.exs`'s existing `BaselineGuard` entry uses the identical window/threshold values as `dev.exs` — no dev/prod divergence convention exists for this plugin family, so reuse the same numbers rather than inventing a split.)

- [ ] **Step 4: Run `mix test`, confirm the full suite is still green** with the new plugin active in the test environment (a new always-on `pre_call` plugin can surface interaction bugs in unrelated pipeline tests that assume a fixed plugin roster — check for any test that asserts an exact plugin count or exact decision chain length).

- [ ] **Step 5: `docs/product-guide.md`** — add a row for `loop-guard` in the plugin reference table, describing it in operator language: what it catches, the two thresholds, and that it's a safety net (cost/availability), not a security control, same distinction the doc already draws elsewhere (e.g. `dry-run mode`'s doc explicitly separates "rollout tool" from "weaker security mode").

- [ ] **Step 6: `docs/threat-model.md`** — add a short note alongside the existing `BaselineGuard` entry (if one exists) or in the "what this does not solve" style already used by other plugin docs there, making clear `LoopGuard` does not detect failure loops yet (outcome-awareness is future work) and does not replace `RateLimiter`'s DoS protection.

---

## Out of scope / explicit follow-on (do not implement here)

**Failure-aware constraint learning** (the `mcp-guardian`-inspired "block retries of a call that just failed" behavior): requires `response.isError` from `post_call` to be written back into the session's `call_log`, which today is only ever built and read at `pre_call` time. This needs its own plan: a `post_call` hook (or a new `PolicyEngine` message) that appends an outcome marker to the most recent matching `call_log` entry after the upstream response is known, plus a decision on retention/ordering if multiple pre_call entries could match the same post_call result in a concurrent-call session. Do not attempt this as part of the current plan — ship outcome-agnostic loop detection first, observe its real false-positive rate in dry-run mode (the proxy already has a dry-run mode for exactly this kind of staged rollout — pin `loop-guard` to `dry_run` on first deploy per `docs/dry-run-mode-plan.md`), and revisit.

## What does *not* change

- `BaselineGuard`, `RateLimiter`, and every other existing plugin are untouched — `LoopGuard` is additive, not a replacement for either.
- The wire protocol change (`recentCalls` gaining `toolName`/`argFingerprint`) is additive; no existing sidecar plugin's `data_needs` declaration or parsing needs to change.
- No new Postgres table or migration — everything here lives in `PolicyEngine`'s existing in-process session state.
