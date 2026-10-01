defmodule PhoenixElxirBeam.MCP.Plugins.RuleEngineTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.CallContext
  alias PhoenixElxirBeam.MCP.Plugins.{RuleEngine, RuleEngineCorpus}

  defp ctx(name) do
    %{call: call_overrides, session: session_overrides, rules: rules} =
      RuleEngineCorpus.fetch!(name)

    call =
      Map.merge(
        %{
          session_id: "s",
          agent_id: "agent://demo",
          server_id: "net",
          tool_name: "post_webhook",
          tags: [:network_egress]
        },
        call_overrides
      )

    CallContext.new(%{
      phase: :pre_call,
      call: call,
      session: Map.merge(%{seen_tags: [], taint: %{sources: []}}, session_overrides),
      plugin_config: %{"rules" => rules}
    })
  end

  test "no rules → allow" do
    assert %{verdict: :allow} = RuleEngine.evaluate(:pre_call, ctx("no rules"))
  end

  test "denies when agent + tag both match" do
    assert %{verdict: :deny, reason: "no egress for ci-runner", severity: :high} =
             RuleEngine.evaluate(:pre_call, ctx("agent and tag both match"))
  end

  test "a partial match does not fire (predicates are AND)" do
    # right agent, wrong tool
    assert %{verdict: :allow} =
             RuleEngine.evaluate(:pre_call, ctx("a partial match does not fire"))
  end

  test "first matching rule wins; an explicit allow can shield a later deny" do
    assert %{verdict: :allow} =
             RuleEngine.evaluate(:pre_call, ctx("first match wins - trusted agent is shielded"))

    assert %{verdict: :deny} =
             RuleEngine.evaluate(:pre_call, ctx("first match wins - a later agent is denied"))
  end

  test "after_sensitive_read and if_tainted predicates" do
    assert %{verdict: :allow} =
             RuleEngine.evaluate(:pre_call, ctx("after_sensitive_read - not yet in this session"))

    assert %{verdict: :deny} =
             RuleEngine.evaluate(:pre_call, ctx("after_sensitive_read - fires"))

    assert %{verdict: :deny} = RuleEngine.evaluate(:pre_call, ctx("if_tainted - fires"))
  end

  test "a hold action produces a hold decision with a prompt" do
    assert %{verdict: :hold, hold: %{timeout_ms: 5_000, on_timeout: :deny}} =
             RuleEngine.evaluate(:pre_call, ctx("a hold action"))
  end

  test "an unknown predicate never matches (fail closed on operator typos)" do
    assert %{verdict: :allow} =
             RuleEngine.evaluate(:pre_call, ctx("an unknown predicate never matches"))
  end

  test "manifest: pre_call policy, fail_closed, no tool_tags filter" do
    manifest = RuleEngine.manifest()
    assert manifest.plugin.name == "rule-engine"
    assert %{policy: policy} = manifest.capabilities
    assert policy.phases == [:pre_call]
    assert policy.tool_tags == []
    assert policy.fail_mode == :fail_closed
  end

  describe "first_match/2" do
    test "returns the matching rule map, not a Decision" do
      %{call: call_overrides, session: session_overrides, rules: rules} =
        RuleEngineCorpus.fetch!("agent and tag both match")

      call =
        Map.merge(
          %{
            session_id: "s",
            agent_id: "agent://demo",
            server_id: "net",
            tool_name: "post_webhook",
            tags: [:network_egress]
          },
          call_overrides
        )

      context =
        CallContext.new(%{
          phase: :pre_call,
          call: call,
          session: Map.merge(%{seen_tags: [], taint: %{sources: []}}, session_overrides),
          plugin_config: %{"rules" => rules}
        })

      assert %{"action" => "deny", "reason" => "no egress for ci-runner"} =
               RuleEngine.first_match(rules, context)
    end

    test "returns nil when nothing matches" do
      %{call: call_overrides, session: session_overrides, rules: rules} =
        RuleEngineCorpus.fetch!("no rules")

      call = Map.merge(%{agent_id: "agent://demo", tool_name: "x", tags: []}, call_overrides)

      context =
        CallContext.new(%{
          phase: :pre_call,
          call: call,
          session: Map.merge(%{seen_tags: [], taint: %{sources: []}}, session_overrides),
          plugin_config: %{"rules" => rules}
        })

      assert RuleEngine.first_match(rules, context) == nil
    end
  end
end
