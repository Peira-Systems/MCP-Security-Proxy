defmodule PhoenixElxirBeam.MCP.Plugins.ResponseSizeGuardTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.CallContext
  alias PhoenixElxirBeam.MCP.Plugins.ResponseSizeGuard

  defp ctx(text, config \\ %{}) do
    CallContext.new(%{
      phase: :post_call,
      call: %{session_id: "s", server_id: "files", tool_name: "export_all"},
      response: %{is_error: false, content: [%{"type" => "text", "text" => text}]},
      plugin_config: config
    })
  end

  test "allows a response within the byte budget" do
    assert %{verdict: :allow} = ResponseSizeGuard.evaluate(:post_call, ctx("small enough"))
  end

  test "withholds a response over the default budget" do
    big = String.duplicate("x", 5_000)

    assert %{verdict: :deny, severity: :high, reason: reason} =
             ResponseSizeGuard.evaluate(:post_call, ctx(big))

    assert reason =~ "5000 bytes"
    assert reason =~ "bulk exfiltration"
  end

  test "respects a configured max_bytes" do
    assert %{verdict: :deny} =
             ResponseSizeGuard.evaluate(:post_call, ctx("0123456789ab", %{"max_bytes" => 10}))

    assert %{verdict: :allow} =
             ResponseSizeGuard.evaluate(:post_call, ctx("0123456789ab", %{"max_bytes" => 100}))
  end

  test "sums across multiple content parts" do
    ctx =
      CallContext.new(%{
        phase: :post_call,
        call: %{session_id: "s", server_id: "files", tool_name: "export_all"},
        response: %{
          content: [
            %{"type" => "text", "text" => String.duplicate("a", 30)},
            %{"type" => "text", "text" => String.duplicate("b", 30)}
          ]
        },
        plugin_config: %{"max_bytes" => 50}
      })

    assert %{verdict: :deny} = ResponseSizeGuard.evaluate(:post_call, ctx)
  end

  test "manifest: post_call policy, fail_open" do
    manifest = ResponseSizeGuard.manifest()
    assert manifest.plugin.name == "response-size-guard"
    assert %{policy: policy} = manifest.capabilities
    assert policy.phases == [:post_call]
    assert policy.fail_mode == :fail_open
  end
end
