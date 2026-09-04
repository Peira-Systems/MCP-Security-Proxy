defmodule PhoenixElxirBeam.MCP.PolicyChange do
  @moduledoc """
  Records operator changes to runtime policy (M3.4c) onto the same
  tamper-evident hash chain as policy verdicts — who, when, what changed,
  old value → new value.

  Every mutating dashboard action (plugin enable/disable/reorder, tool-tag
  assignment, quarantine clear) calls `record/1` before or after applying the
  change. The write is routed through `PhoenixElxirBeam.MCP.PolicyEngine` so it
  lands serially on the chain (`EventLog`), and a `{:policy_change, entry}`
  message is broadcast on `"mcp:policy"` for the dashboard's change log.

  `before` / `after` must be JSON-safe (boolean, string, list of strings, or a
  JSON-safe map — e.g. a plugin's `config`) so a change can be replayed /
  reverted from the stored row alone.
  """

  alias PhoenixElxirBeam.MCP.{EventLog, PolicyEngine}

  @pubsub PhoenixElxirBeam.PubSub
  @topic "mcp:policy"

  @type kind :: :plugin_enabled | :plugin_order | :plugin_config | :tool_tags | :tool_quarantine

  def topic, do: @topic

  @doc """
  Records a change. `attrs`: `:kind`, `:target`, `:actor` (operator email),
  `:before`, `:after`, optional `:summary` and `:server_id`.
  """
  @spec record(map()) :: {:ok, String.t()} | {:error, term()}
  def record(%{kind: kind, target: target, actor: actor} = attrs) do
    before_val = Map.get(attrs, :before)
    after_val = Map.get(attrs, :after)
    summary = attrs[:summary] || summarize(kind, target, actor, before_val, after_val)

    change = %{
      kind: kind,
      target: to_string(target),
      actor: to_string(actor),
      before: before_val,
      after: after_val,
      summary: summary,
      server_id: attrs[:server_id]
    }

    case PolicyEngine.record_policy_change(change) do
      {:ok, event_id} ->
        Phoenix.PubSub.broadcast(
          @pubsub,
          @topic,
          {:policy_change, Map.put(change, :event_id, event_id)}
        )

        {:ok, event_id}

      other ->
        other
    end
  end

  @doc "The most recent policy changes, newest first, as display maps."
  @spec recent(pos_integer()) :: [map()]
  def recent(limit \\ 50) do
    %{entries: entries} = EventLog.list(%{status: "policy_change", page_size: limit, page: 1})

    Enum.map(entries, fn e ->
      d = List.first(e.decisions) || %{}

      %{
        event_id: e.event_id,
        at: e.occurred_at,
        actor: d["plugin"],
        kind: d["kind"],
        target: d["target"],
        before: d["before"],
        after: d["after"],
        summary: e.reason
      }
    end)
  end

  defp summarize(:plugin_enabled, target, actor, _before, after_val) do
    "#{actor} #{if after_val, do: "enabled", else: "disabled"} plugin #{target}"
  end

  defp summarize(:plugin_order, _target, actor, _b, after_val) when is_list(after_val) do
    "#{actor} reordered the plugin pipeline: #{Enum.join(after_val, " → ")}"
  end

  defp summarize(:plugin_config, target, actor, _before, _after) do
    "#{actor} changed config for plugin #{target}"
  end

  defp summarize(:tool_tags, target, actor, before_val, after_val) do
    "#{actor} set tags on #{target}: #{fmt(before_val)} → #{fmt(after_val)}"
  end

  defp summarize(:tool_quarantine, target, actor, _b, _a) do
    "#{actor} cleared the quarantine on #{target}"
  end

  defp summarize(kind, target, actor, before_val, after_val) do
    "#{actor} changed #{kind} #{target}: #{fmt(before_val)} → #{fmt(after_val)}"
  end

  defp fmt(v) when is_list(v), do: "[" <> Enum.join(v, ", ") <> "]"
  defp fmt(v), do: to_string(v)
end
