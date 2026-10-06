defmodule PhoenixElxirBeam.MCP.Plugins.LoopGuard do
  @moduledoc """
  Runaway-agent-loop detection: a `pre_call` policy that denies a call once
  the session shows signs of a stuck agent thrashing on the same tool —
  independent of whether the calls look malicious or whether they've been
  succeeding or failing (outcome-awareness is a documented future
  extension, not this plugin — see
  `docs/superpowers/plans/2026-10-05-loop-guard.md`).

  Two independent thresholds, both counted over the same `window_ms`
  look-back into `session.recent_calls` — the call under evaluation is
  already in that window when this runs (same convention as
  `BaselineGuard`), so the `max_*+1`-th matching call is the one that
  trips, not the `max_*`-th:

    * **`max_identical_calls`** — the same tool called with the *same*
      arguments (via `PhoenixElxirBeam.MCP.CallFingerprint`, a one-way,
      per-session fingerprint — raw arguments are never compared or
      logged here) more than this many times. The tight signal: a
      genuine stuck retry loop (e.g. the same failing `write_file` call
      repeated).
    * **`max_same_tool_calls`** — the same tool called with *any*
      arguments more than this many times. The loose signal: thrashing on
      a tool with varying inputs (e.g. hammering a search endpoint).
      **Must be set above legitimate high-volume same-tool patterns**
      (e.g. an agent paginating through search results — same tool, same
      shape, different page tokens each call) or this threshold will
      false-positive on normal use; the tight threshold doesn't have this
      problem since it requires identical arguments.

  ```
  config: %{
    "window_ms"            => 10_000,
    "max_identical_calls"  => 3,
    "max_same_tool_calls"  => 15
  }
  ```

  Both bounds are further capped by `PolicyEngine`'s own
  `@call_log_window_ms` / `@call_log_max` (60s / 50 calls) — a
  `window_ms` above 60s is silently clamped, and a `max_same_tool_calls`
  at or above 50 can never trip.

  **Outcome-agnostic by design**: this plugin does not know whether a
  logged call succeeded or failed — only its rate and repetition.
  Failure-aware detection (e.g. only counting calls that errored) is a
  documented future extension requiring new plumbing from `post_call`
  back into session history; see
  `docs/superpowers/plans/2026-10-05-loop-guard.md`'s scope-split note.

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
    session_id = Map.get(ctx.call, :session_id)
    fingerprint = CallFingerprint.compute(session_id, Map.get(ctx.call, :arguments))

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
