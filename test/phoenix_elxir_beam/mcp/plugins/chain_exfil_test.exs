defmodule PhoenixElxirBeam.MCP.Plugins.ChainExfilTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.{CallContext, Decision}
  alias PhoenixElxirBeam.MCP.Plugins.ChainExfil

  defp ctx(seen_tags) do
    CallContext.new(%{
      phase: :pre_call,
      call: %{
        session_id: "s",
        server_id: "net",
        tool_name: "post_webhook",
        tags: [:network_egress]
      },
      session: %{seen_tags: seen_tags}
    })
  end

  test "denies egress once the session has seen a sensitive read" do
    assert %Decision{verdict: :deny, severity: :high, reason: reason} =
             ChainExfil.evaluate(:pre_call, ctx([:sensitive_read]))

    assert reason == ChainExfil.block_reason()
  end

  test "allows egress when no sensitive read has happened" do
    assert %Decision{verdict: :allow} = ChainExfil.evaluate(:pre_call, ctx([]))
  end

  test "manifest declares a fail_closed pre_call policy scoped to :network_egress" do
    manifest = ChainExfil.manifest()

    assert manifest.plugin.name == "chain-exfil"
    assert %{policy: policy} = manifest.capabilities
    assert policy.phases == [:pre_call]
    assert policy.tool_tags == [:network_egress]
    assert policy.fail_mode == :fail_closed
  end
end
