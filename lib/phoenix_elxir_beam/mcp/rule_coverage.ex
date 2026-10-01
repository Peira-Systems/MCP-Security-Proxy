defmodule PhoenixElxirBeam.MCP.RuleCoverage do
  @moduledoc """
  Build-time audit of whether a tool's sensitive tags are actually enforced
  by the compiled `RuleEngine` config, independent of any specific agent.
  Pure: takes a tool's tags and the rule list, returns the gaps. Callers
  (`Mix.Tasks.Mcp.Rules.Check`) own fetching those inputs from Postgres /
  app config and reporting the output.

  Two gap types (`docs/superpowers/specs/2026-09-30-rule-coverage-gate-design.md`):

    * `:uncovered_tag` — the tool is tagged with a sensitive tag, but no
      agent-agnostic rule resolves to `deny`/`hold` as the first match for
      an arbitrary agent calling it.
    * `:unreviewed` — the tool has a suggested tag but empty operator tags;
      nobody has looked at it, so it's invisible to the rule engine
      regardless of what rules exist.
  """

  alias PhoenixElxirBeam.MCP.{CallContext, Plugins.RuleEngine}

  @sensitive_tags [:sensitive_read, :network_egress]

  defmodule Gap do
    @moduledoc "One coverage gap for one tool."
    defstruct [:type, :tool_name, :tag, :shadowing_rule, :unclassified_guard_mode]

    @type t :: %__MODULE__{
            type: :uncovered_tag | :unreviewed,
            tool_name: String.t(),
            tag: atom() | nil,
            shadowing_rule: map() | nil,
            unclassified_guard_mode: String.t() | nil
          }
  end

  @doc "The complete, fixed set of tags this checker cares about."
  @spec sensitive_tags() :: [atom()]
  def sensitive_tags, do: @sensitive_tags

  @doc """
  Gaps for a single tool. `tool` is `%{name:, tags:, suggested_tags:}`
  (atoms in the tag lists, matching `ServerRegistry`'s in-memory shape).
  `server_id` is the registration's own id (`ServerRegistration.id` /
  `ServerRegistry`'s `server_id` — the same value a real call's
  `ctx.call[:server_id]` carries), threaded into the synthetic call so a
  `"server"`-scoped rule can match it, exactly as it would for a real call
  to this tool. `rules` is the `RuleEngine` plugin's raw `config["rules"]`
  list. `unclassified_guard_mode` is whatever `UnclassifiedGuard`'s plugin
  config currently has for `"mode"` (`"off"` | `"deny"` | `"hold"`),
  threaded through only to annotate `:unreviewed` gaps — it doesn't change
  whether a gap is reported, only what the caller prints about it.
  """
  @spec check_tool(map(), String.t(), [map()], String.t()) :: [Gap.t()]
  def check_tool(tool, server_id, rules, unclassified_guard_mode) do
    uncovered_tag_gaps(tool, server_id, rules) ++ unreviewed_gap(tool, unclassified_guard_mode)
  end

  defp uncovered_tag_gaps(tool, server_id, rules) do
    tool.tags
    |> Enum.filter(&(&1 in @sensitive_tags))
    |> Enum.flat_map(fn tag ->
      ctx = synthetic_context(tool.name, server_id, [tag])

      case RuleEngine.first_match(rules, ctx) do
        %{"action" => action} = rule when action in ["deny", "hold"] ->
          if agent_agnostic?(rule), do: [], else: [uncovered(tool, tag, rule)]

        rule ->
          [uncovered(tool, tag, rule)]
      end
    end)
  end

  defp uncovered(tool, tag, rule) do
    %Gap{type: :uncovered_tag, tool_name: tool.name, tag: tag, shadowing_rule: rule}
  end

  defp agent_agnostic?(rule) do
    match = Map.get(rule, "match", %{})
    not Map.has_key?(match, "agent") and not Map.has_key?(match, "agent_prefix")
  end

  defp unreviewed_gap(%{tags: [], suggested_tags: suggested} = tool, mode) when suggested != [] do
    [%Gap{type: :unreviewed, tool_name: tool.name, unclassified_guard_mode: mode}]
  end

  defp unreviewed_gap(_tool, _mode), do: []

  defp synthetic_context(tool_name, server_id, tags) do
    CallContext.new(%{
      phase: :pre_call,
      call: %{tool_name: tool_name, server_id: server_id, tags: tags},
      session: %{seen_tags: [], taint: %{sources: []}},
      plugin_config: %{}
    })
  end
end
