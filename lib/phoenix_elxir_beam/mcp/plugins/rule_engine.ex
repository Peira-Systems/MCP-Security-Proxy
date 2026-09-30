defmodule PhoenixElxirBeam.MCP.Plugins.RuleEngine do
  @moduledoc """
  A `policy` plugin whose verdicts come from **operator-written rules**, not
  code. Rules live in the plugin's registration `config:` block
  (`docs/plugin-protocol.md` §15.1):

      {PhoenixElxirBeam.MCP.Plugins.RuleEngine,
       config: %{
         "rules" => [
           %{"match" => %{"agent" => "agent://ci-runner", "tool_tags_any" => ["network_egress"]},
             "action" => "deny", "severity" => "high",
             "reason" => "policy: agent ci-runner may not perform network egress"}
         ]
       }}

  Rules are evaluated in order; the **first** one whose `match` is satisfied
  decides. A rule with no predicates matches every call (a catch-all). No
  matching rule → `allow`.

  Match predicates (all must hold — AND):

    * `"agent"` / `"agent_prefix"` — exact / prefix match on the call's agent id
    * `"tool"` / `"server"` — exact match on the tool name / server id
    * `"tool_tags_any"` — any of these tags is on the call
    * `"after_sensitive_read"` — a `:sensitive_read` happened earlier this session
    * `"if_tainted"` — a secret has flowed through this session (see `TaintGuard`)

  Actions: `"deny"`, `"allow"` (an explicit exception that short-circuits
  later rules), `"hold"` (`"timeout_ms"` optional, default 120 s).
  """

  @behaviour PhoenixElxirBeam.MCP.Plugin.Policy

  alias PhoenixElxirBeam.MCP.{CallContext, Decision}
  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @default_hold_ms 120_000

  @impl true
  def manifest do
    Manifest.normalize(%{
      plugin: %{
        name: "rule-engine",
        version: "0.1.0",
        description: "Config-driven allow / deny / hold rules, first match wins."
      },
      capabilities: %{
        policy: %{
          phases: [:pre_call],
          data_needs: ["session.seenTags", "session.taint"],
          timeout_ms: 50,
          fail_mode: :fail_closed
        }
      }
    })
  end

  @impl true
  def evaluate(:pre_call, %CallContext{} = ctx) do
    ctx.plugin_config
    |> Map.get("rules", [])
    |> first_match(ctx)
    |> to_decision()
  end

  @doc """
  Returns the first rule in `rules` whose `match` predicates all hold against
  `ctx` (first-match-wins, same semantics as `evaluate/2`), or `nil` if none
  match. Exposed so callers outside the plugin pipeline — the rule coverage
  checker (`PhoenixElxirBeam.MCP.RuleCoverage`) — can ask "what would this
  engine actually do" without re-implementing predicate matching.
  """
  @spec first_match([map()], CallContext.t()) :: map() | nil
  def first_match(rules, %CallContext{} = ctx) when is_list(rules) do
    Enum.find(rules, &matches?(&1, ctx))
  end

  defp to_decision(nil), do: Decision.allow()

  defp to_decision(rule) do
    reason = rule["reason"] || "blocked by rule-engine"

    case rule["action"] do
      "deny" -> Decision.deny(severity(rule["severity"]), reason)
      "hold" -> Decision.hold(reason, hold_spec(rule, reason))
      _ -> Decision.allow()
    end
  end

  defp hold_spec(rule, reason) do
    %{
      prompt: rule["prompt"] || reason,
      timeout_ms: rule["timeout_ms"] || @default_hold_ms,
      on_timeout: :deny
    }
  end

  defp severity("critical"), do: :critical
  defp severity("medium"), do: :medium
  defp severity("low"), do: :low
  defp severity(_), do: :high

  defp matches?(%{"match" => match}, ctx) when is_map(match) do
    Enum.all?(match, fn {key, value} -> predicate(key, value, ctx) end)
  end

  defp matches?(_rule_without_match, _ctx), do: true

  defp predicate("agent", value, ctx), do: agent(ctx) == value

  defp predicate("agent_prefix", value, ctx),
    do: is_binary(agent(ctx)) and String.starts_with?(agent(ctx), value)

  defp predicate("tool", value, ctx), do: ctx.call[:tool_name] == value
  defp predicate("server", value, ctx), do: ctx.call[:server_id] == value

  defp predicate("tool_tags_any", values, ctx) when is_list(values) do
    call_tags = ctx |> CallContext.call_tags() |> Enum.map(&to_string/1) |> MapSet.new()
    Enum.any?(values, &MapSet.member?(call_tags, to_string(&1)))
  end

  defp predicate("after_sensitive_read", true, ctx),
    do: :sensitive_read in (ctx.session[:seen_tags] || [])

  defp predicate("if_tainted", true, ctx),
    do: get_in(ctx.session, [:taint, :sources]) not in [nil, []]

  # An unknown predicate never matches — fail closed on operator typos.
  defp predicate(_unknown, _value, _ctx), do: false

  defp agent(ctx), do: ctx.call[:agent_id]
end
