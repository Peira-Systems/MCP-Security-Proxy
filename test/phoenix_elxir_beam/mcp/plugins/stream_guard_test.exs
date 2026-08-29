defmodule PhoenixElxirBeam.MCP.Plugins.StreamGuardTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.CallContext
  alias PhoenixElxirBeam.MCP.Plugins.StreamGuard

  defp part(n), do: %{"type" => "text", "text" => String.duplicate("x", n)}

  defp ctx(delivered, chunk, config) do
    CallContext.new(%{
      phase: :chunk,
      call: %{session_id: "s", server_id: "files", tool_name: "stream_export"},
      response: %{
        stream: true,
        chunk: chunk,
        chunk_index: length(delivered),
        delivered: delivered
      },
      plugin_config: config
    })
  end

  @cfg %{"max_bytes" => 100}

  test "allows while the running byte count is within budget" do
    assert %{verdict: :allow} = StreamGuard.evaluate(:chunk, ctx([part(40)], part(40), @cfg))
  end

  test "denies once delivered + current chunk exceeds the budget" do
    assert %{verdict: :deny, severity: :high, reason: reason} =
             StreamGuard.evaluate(:chunk, ctx([part(60), part(30)], part(30), @cfg))

    assert reason =~ "exceeds the 100-byte budget"
    assert reason =~ "120"
  end

  test "falls back to the default budget with no config" do
    big = List.duplicate(part(500), 5)
    assert %{verdict: :deny} = StreamGuard.evaluate(:chunk, ctx(big, part(1), %{}))
    assert %{verdict: :allow} = StreamGuard.evaluate(:chunk, ctx([part(100)], part(100), %{}))
  end

  test "tolerates a string-keyed max_bytes" do
    assert %{verdict: :deny} =
             StreamGuard.evaluate(:chunk, ctx([part(80)], part(80), %{"max_bytes" => "100"}))
  end

  test "manifest: chunk-phase policy, fail_open" do
    manifest = StreamGuard.manifest()

    assert manifest.plugin.name == "stream-guard"
    assert %{policy: policy} = manifest.capabilities
    assert policy.phases == [:chunk]
    assert policy.fail_mode == :fail_open
  end
end
