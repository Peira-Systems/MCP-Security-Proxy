defmodule PhoenixElxirBeam.MCP.Plugins.ApprovalGateTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.{CallContext, Decision}
  alias PhoenixElxirBeam.MCP.Plugins.ApprovalGate

  defp ctx(seen_tags, plugin_config \\ %{}) do
    CallContext.new(%{
      phase: :pre_call,
      call: %{session_id: "demo-1", tool_name: "post_webhook", tags: [:network_egress]},
      session: %{seen_tags: seen_tags},
      plugin_config: plugin_config
    })
  end

  test "holds egress once the session has seen a sensitive read" do
    assert %Decision{verdict: :hold, severity: :high, reason: reason, hold: hold} =
             ApprovalGate.evaluate(:pre_call, ctx([:sensitive_read]))

    assert reason =~ "operator sign-off"
    assert hold.prompt =~ "post_webhook"
    assert hold.prompt =~ "demo-1"
    assert hold.on_timeout == :deny
    assert hold.timeout_ms == 120_000
  end

  test "allows egress when no sensitive read has happened" do
    assert %Decision{verdict: :allow} = ApprovalGate.evaluate(:pre_call, ctx([]))
  end

  test "honours a timeout_ms from plugin config" do
    assert %Decision{hold: %{timeout_ms: 5_000}} =
             ApprovalGate.evaluate(:pre_call, ctx([:sensitive_read], %{"timeout_ms" => 5_000}))
  end

  test "manifest declares a fail_closed pre_call policy scoped to :network_egress" do
    m = ApprovalGate.manifest()
    assert m.plugin.name == "approval-gate"
    assert %{policy: p} = m.capabilities
    assert p.tool_tags == [:network_egress]
    assert p.fail_mode == :fail_closed
  end
end
