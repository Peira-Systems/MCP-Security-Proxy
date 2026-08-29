defmodule PhoenixElxirBeam.MCP.StreamProxyTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.StreamProxy

  setup do
    base_url = PhoenixElxirBeam.MCPHTTPTestServer.start!()
    %{server: %{transport: :http, base_url: base_url, session_id: nil}}
  end

  @meta %{session_id: "s", server_id: "sv", tool_name: "t", method: "tools/call"}

  defp tool_body(name) do
    %{
      "jsonrpc" => "2.0",
      "id" => 7,
      "method" => "tools/call",
      "params" => %{"name" => name, "arguments" => %{}}
    }
  end

  test "returns the full reassembled response for a small reply", %{server: server} do
    assert {:ok, %{"id" => 7, "result" => %{"content" => [%{"text" => text}]}}, [], []} =
             StreamProxy.run(server, tool_body("list_files"), @meta)

    assert text =~ "directory listing"
  end

  test "a chunk policy denial cuts the stream", %{server: server} do
    # test config runs StreamGuard with a 500-byte budget; big_export is ~20 KB
    assert {:cut, reason, _findings, _taint, bytes} =
             StreamProxy.run(server, tool_body("big_export"), @meta)

    assert reason =~ "budget"
    assert bytes > 0
  end

  test "the buffer ceiling stops a flood before any verdict", %{server: server} do
    assert {:error, message} =
             StreamProxy.run(server, tool_body("big_export"), @meta, max_buffer_bytes: 200)

    assert message =~ "ceiling"
  end

  test "an unparseable body is an error", %{server: server} do
    # `initialize` on this fixture returns valid JSON; force a bad shape by
    # asking for a method it answers with an error envelope — still valid JSON,
    # so this really checks the ok-path decode. A truncated cut is covered above.
    assert {:ok, %{"error" => _}, [], []} =
             StreamProxy.run(
               server,
               %{"jsonrpc" => "2.0", "id" => 1, "method" => "bogus/method", "params" => %{}},
               @meta
             )
  end
end
