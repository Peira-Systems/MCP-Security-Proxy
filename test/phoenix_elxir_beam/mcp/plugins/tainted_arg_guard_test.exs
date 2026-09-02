defmodule PhoenixElxirBeam.MCP.Plugins.TaintedArgGuardTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.{CallContext, TaintMarker}
  alias PhoenixElxirBeam.MCP.Plugins.TaintedArgGuard

  @sid "s"

  defp ctx(arguments, sources) do
    CallContext.new(%{
      phase: :pre_call,
      call: %{
        session_id: @sid,
        server_id: "net",
        tool_name: "post_webhook",
        tags: [:network_egress],
        arguments: arguments
      },
      session: %{seen_tags: [], taint: %{sources: sources}}
    })
  end

  defp source(secret) do
    %{
      origin_tool: "read_secrets",
      finding_type: "secret_leak",
      markers: TaintMarker.markers_for_secret(@sid, secret),
      hint: "sk-d…"
    }
  end

  test "allows when the session has no tracked secrets" do
    assert %{verdict: :allow} = TaintedArgGuard.evaluate(:pre_call, ctx(%{"body" => "x"}, []))
  end

  test "allows when no argument contains a tracked secret" do
    ctx = ctx(%{"body" => "nothing sensitive"}, [source("API_KEY=sk-demo-FAKE1234")])
    assert %{verdict: :allow} = TaintedArgGuard.evaluate(:pre_call, ctx)
  end

  test "denies when an argument carries the exact secret bytes" do
    ctx = ctx(%{"body" => "here: API_KEY=sk-demo-FAKE1234"}, [source("API_KEY=sk-demo-FAKE1234")])

    assert %{verdict: :deny, severity: :critical, reason: reason, findings: [finding]} =
             TaintedArgGuard.evaluate(:pre_call, ctx)

    assert reason =~ "read_secrets"
    assert finding.type == "tainted_argument"
    assert finding.severity == :critical
  end

  test "matches a secret nested anywhere in the arguments map" do
    ctx = ctx(%{"meta" => %{"note" => "AKIAIOSFODNN7EXAMPLE"}}, [source("AKIAIOSFODNN7EXAMPLE")])
    assert %{verdict: :deny} = TaintedArgGuard.evaluate(:pre_call, ctx)
  end

  test "catches a base64-encoded copy of the secret (M4.1 marker evasion)" do
    secret = "API_KEY=sk-demo-FAKE1234"
    b64 = Base.encode64(secret)
    ctx = ctx(%{"body" => "payload=#{b64}"}, [source(secret)])
    assert %{verdict: :deny} = TaintedArgGuard.evaluate(:pre_call, ctx)
  end

  test "catches a hex-encoded copy of the secret" do
    secret = "AKIAIOSFODNN7EXAMPLE"
    hex = Base.encode16(secret, case: :lower)
    ctx = ctx(%{"q" => hex}, [source(secret)])
    assert %{verdict: :deny} = TaintedArgGuard.evaluate(:pre_call, ctx)
  end

  test "works against string-keyed markers (a restart-recovered session)" do
    secret = "AKIAIOSFODNN7EXAMPLE"
    string_keyed = %{"origin_tool" => "read_secrets", "markers" => source(secret).markers}
    ctx = ctx(%{"body" => secret}, [string_keyed])
    assert %{verdict: :deny} = TaintedArgGuard.evaluate(:pre_call, ctx)
  end

  test "manifest: pre_call policy, fail_closed, needs call.arguments" do
    manifest = TaintedArgGuard.manifest()
    assert manifest.plugin.name == "tainted-arg-guard"
    assert %{policy: policy} = manifest.capabilities
    assert policy.phases == [:pre_call]
    assert policy.fail_mode == :fail_closed
    assert "call.arguments" in policy.data_needs
  end
end
