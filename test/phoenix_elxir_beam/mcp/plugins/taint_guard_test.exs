defmodule PhoenixElxirBeam.MCP.Plugins.TaintGuardTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.CallContext
  alias PhoenixElxirBeam.MCP.Plugins.TaintGuard

  defp ctx(sources) do
    CallContext.new(%{
      phase: :pre_call,
      call: %{
        session_id: "s",
        server_id: "net",
        tool_name: "post_webhook",
        tags: [:network_egress]
      },
      session: %{seen_tags: [], taint: %{sources: sources}}
    })
  end

  test "allows egress when the session carries no taint" do
    assert %{verdict: :allow} = TaintGuard.evaluate(:pre_call, ctx([]))
  end

  test "denies egress once a secret has flowed through the session" do
    source = %{origin_tool: "read_config", finding_type: "secret_leak", at: DateTime.utc_now()}

    assert %{verdict: :deny, severity: :high, reason: reason} =
             TaintGuard.evaluate(:pre_call, ctx([source]))

    assert reason =~ "read_config"
    assert reason =~ "secret"
  end

  test "tolerates string-keyed taint sources (sidecar wire form)" do
    source = %{"origin_tool" => "fetch", "finding_type" => "secret_leak"}
    assert %{verdict: :deny, reason: reason} = TaintGuard.evaluate(:pre_call, ctx([source]))
    assert reason =~ "fetch"
  end

  test "denies egress with untrusted-content wording when the taint source is provenance-based" do
    source = %{
      origin_tool: "scrape_page",
      finding_type: "untrusted_provenance",
      at: DateTime.utc_now()
    }

    assert %{verdict: :deny, severity: :high, reason: reason} =
             TaintGuard.evaluate(:pre_call, ctx([source]))

    assert reason =~ "scrape_page"
    assert reason =~ "untrusted content"
    refute reason =~ "secret"
  end

  test "manifest: pre_call policy scoped to network_egress, fail_closed" do
    manifest = TaintGuard.manifest()

    assert manifest.plugin.name == "taint-guard"
    assert %{policy: policy} = manifest.capabilities
    assert policy.phases == [:pre_call]
    assert policy.tool_tags == [:network_egress]
    assert policy.fail_mode == :fail_closed
    assert "session.taint" in policy.data_needs
  end
end
