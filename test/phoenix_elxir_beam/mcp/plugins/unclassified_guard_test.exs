defmodule PhoenixElxirBeam.MCP.Plugins.UnclassifiedGuardTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.CallContext
  alias PhoenixElxirBeam.MCP.Plugins.UnclassifiedGuard

  defp ctx(tags, mode) do
    CallContext.new(%{
      phase: :pre_call,
      call: %{tool_name: "mystery_tool", tags: tags},
      session: %{seen_tags: []},
      plugin_config: %{"mode" => mode}
    })
  end

  test "off: always allows" do
    assert %{verdict: :allow} = UnclassifiedGuard.evaluate(:pre_call, ctx([], "off"))
  end

  test "deny: refuses an untagged tool, allows a tagged one" do
    assert %{verdict: :deny, severity: :high, reason: reason} =
             UnclassifiedGuard.evaluate(:pre_call, ctx([], "deny"))

    assert reason =~ "no operator classification"

    assert %{verdict: :allow} =
             UnclassifiedGuard.evaluate(:pre_call, ctx([:network_egress], "deny"))
  end

  test "hold: parks an untagged tool for sign-off" do
    assert %{verdict: :hold, hold: hold} = UnclassifiedGuard.evaluate(:pre_call, ctx([], "hold"))
    assert hold.on_timeout == :deny
    assert hold.prompt =~ "Classify"
  end

  test "manifest: pre_call, all tools, fail_closed" do
    m = UnclassifiedGuard.manifest()
    assert m.plugin.name == "unclassified-guard"
    assert m.capabilities.policy.phases == [:pre_call]
    assert m.capabilities.policy.tool_tags == []
    assert m.capabilities.policy.fail_mode == :fail_closed
  end
end
