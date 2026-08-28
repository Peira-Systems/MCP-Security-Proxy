defmodule PhoenixElxirBeam.MCP.Plugins.RuleEngineTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.CallContext
  alias PhoenixElxirBeam.MCP.Plugins.RuleEngine

  defp ctx(call_overrides, session_overrides, rules) do
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
    assert %{verdict: :allow} = RuleEngine.evaluate(:pre_call, ctx(%{}, %{}, []))
  end

  test "denies when agent + tag both match" do
    rules = [
      %{
        "match" => %{"agent" => "agent://ci-runner", "tool_tags_any" => ["network_egress"]},
        "action" => "deny",
        "reason" => "no egress for ci-runner"
      }
    ]

    assert %{verdict: :deny, reason: "no egress for ci-runner", severity: :high} =
             RuleEngine.evaluate(:pre_call, ctx(%{agent_id: "agent://ci-runner"}, %{}, rules))
  end

  test "a partial match does not fire (predicates are AND)" do
    rules = [
      %{
        "match" => %{"agent" => "agent://ci-runner", "tool" => "read_secrets"},
        "action" => "deny",
        "reason" => "x"
      }
    ]

    # right agent, wrong tool
    assert %{verdict: :allow} =
             RuleEngine.evaluate(:pre_call, ctx(%{agent_id: "agent://ci-runner"}, %{}, rules))
  end

  test "first matching rule wins; an explicit allow can shield a later deny" do
    rules = [
      %{"match" => %{"agent" => "agent://trusted"}, "action" => "allow"},
      %{
        "match" => %{"tool_tags_any" => ["network_egress"]},
        "action" => "deny",
        "reason" => "no egress"
      }
    ]

    assert %{verdict: :allow} =
             RuleEngine.evaluate(:pre_call, ctx(%{agent_id: "agent://trusted"}, %{}, rules))

    assert %{verdict: :deny} =
             RuleEngine.evaluate(:pre_call, ctx(%{agent_id: "agent://other"}, %{}, rules))
  end

  test "after_sensitive_read and if_tainted predicates" do
    sr = [%{"match" => %{"after_sensitive_read" => true}, "action" => "deny", "reason" => "sr"}]
    tainted = [%{"match" => %{"if_tainted" => true}, "action" => "deny", "reason" => "t"}]

    assert %{verdict: :allow} = RuleEngine.evaluate(:pre_call, ctx(%{}, %{}, sr))

    assert %{verdict: :deny} =
             RuleEngine.evaluate(:pre_call, ctx(%{}, %{seen_tags: [:sensitive_read]}, sr))

    assert %{verdict: :deny} =
             RuleEngine.evaluate(
               :pre_call,
               ctx(%{}, %{taint: %{sources: [%{origin_tool: "x"}]}}, tainted)
             )
  end

  test "a hold action produces a hold decision with a prompt" do
    rules = [
      %{
        "match" => %{"tool" => "post_webhook"},
        "action" => "hold",
        "reason" => "needs sign-off",
        "timeout_ms" => 5_000
      }
    ]

    assert %{verdict: :hold, hold: %{timeout_ms: 5_000, on_timeout: :deny}} =
             RuleEngine.evaluate(:pre_call, ctx(%{}, %{}, rules))
  end

  test "an unknown predicate never matches (fail closed on operator typos)" do
    rules = [%{"match" => %{"whoops" => "x"}, "action" => "deny", "reason" => "r"}]
    assert %{verdict: :allow} = RuleEngine.evaluate(:pre_call, ctx(%{}, %{}, rules))
  end

  test "manifest: pre_call policy, fail_closed, no tool_tags filter" do
    manifest = RuleEngine.manifest()
    assert manifest.plugin.name == "rule-engine"
    assert %{policy: policy} = manifest.capabilities
    assert policy.phases == [:pre_call]
    assert policy.tool_tags == []
    assert policy.fail_mode == :fail_closed
  end
end
