defmodule PhoenixElxirBeam.MCP.Plugins.BaselineGuard do
  @moduledoc """
  Behavioural baselining: a `pre_call` policy that denies a call once the
  session has made too many calls of a watched kind inside a short window —
  "this agent just read secrets six times in ten seconds".

  Where the other guards key off *what* a single call is (its tags, its
  arguments, the session's taint), `BaselineGuard` keys off the *rate* of a
  sequence of calls. It reads `session.recent_calls` — the bounded window of
  `%{tool_name, tags, arg_fingerprint, at}` the proxy threads into every
  `pre_call` `CallContext` (this plugin only looks at `tags`/`at`; see
  `Plugins.LoopGuard` for the sibling that keys off `tool_name` /
  `arg_fingerprint` instead) — and applies its own, shorter window and
  threshold from operator config:

      config: %{
        "window_ms"  => 10_000,          # look-back window
        "max_calls"  => 5,               # allowed within the window …
        "watch_tags" => ["sensitive_read"]  # … for calls carrying any of these
      }

  The current call is already in `recent_calls` when this runs, so the
  `max_calls + 1`-th matching call in the window is the one that trips.
  Heuristic by nature, so `fail_mode` is `:fail_open`.
  """

  @behaviour PhoenixElxirBeam.MCP.Plugin.Policy

  alias PhoenixElxirBeam.MCP.{CallContext, Decision}
  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @default_window_ms 10_000
  @default_max_calls 5
  @default_watch_tags ["sensitive_read"]

  @impl true
  def manifest do
    Manifest.normalize(%{
      plugin: %{
        name: "baseline-guard",
        version: "0.1.0",
        description: "Denies a call once the session's rate of watched calls exceeds a baseline."
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
    max_calls = int(cfg["max_calls"], @default_max_calls)
    watch = watch_tags(cfg["watch_tags"])

    recent = Map.get(ctx.session, :recent_calls, [])
    now = latest_at(recent)

    matching =
      Enum.count(recent, fn entry ->
        within?(entry, now, window_ms) and tagged?(entry, watch)
      end)

    if matching > max_calls do
      Decision.deny(
        :high,
        "behavioural baseline exceeded: #{matching} #{describe(watch)} calls in the last " <>
          "#{Float.round(window_ms / 1000, 1)}s (limit #{max_calls})"
      )
    else
      Decision.allow()
    end
  end

  defp within?(%{at: %DateTime{} = at}, %DateTime{} = now, window_ms),
    do: DateTime.diff(now, at, :millisecond) <= window_ms

  defp within?(_entry, _now, _window_ms), do: true

  defp tagged?(%{tags: tags}, watch) when is_list(tags) do
    Enum.any?(tags, &(to_string(&1) in watch))
  end

  defp tagged?(_entry, _watch), do: false

  defp latest_at(recent) do
    recent
    |> Enum.map(&Map.get(&1, :at))
    |> Enum.filter(&match?(%DateTime{}, &1))
    |> Enum.max(DateTime, fn -> DateTime.utc_now() end)
  end

  defp watch_tags(nil), do: @default_watch_tags
  defp watch_tags([]), do: @default_watch_tags
  defp watch_tags(list) when is_list(list), do: Enum.map(list, &to_string/1)
  defp watch_tags(other), do: [to_string(other)]

  defp describe([tag]), do: tag
  defp describe(tags), do: Enum.join(tags, "/")

  defp int(n, _default) when is_integer(n) and n >= 0, do: n

  defp int(s, default) when is_binary(s) do
    case Integer.parse(s) do
      {n, ""} when n >= 0 -> n
      _ -> default
    end
  end

  defp int(_n, default), do: default
end
