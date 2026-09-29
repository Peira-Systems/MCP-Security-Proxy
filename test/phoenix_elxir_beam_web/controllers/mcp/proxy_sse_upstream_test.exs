defmodule PhoenixElxirBeamWeb.MCP.ProxySSEUpstreamTest do
  @moduledoc """
  Drives the proxy's `:forward` disposition (`tools/list`) against an
  upstream that answers over `text/event-stream` rather than plain
  `application/json` — the shape the MCP SDK's `StreamableHTTPServerTransport`
  uses by default, and so a growing share of real servers. Exercises
  `ProxyController.forward_to_upstream/2`'s use of
  `HttpTransport.decode_body/1` end to end, through a real HTTP request.
  """
  # async: false — the request process needs the shared sandbox connection.
  use PhoenixElxirBeamWeb.ConnCase, async: false

  import PhoenixElxirBeam.MCPProxyHelpers

  alias PhoenixElxirBeam.MCP.ServerRegistry

  setup do
    base_url = PhoenixElxirBeam.MCPHTTPTestServer.start_sse!()

    {:ok, server} =
      ServerRegistry.register_server(
        "sse-catalog-#{System.unique_integer([:positive])}",
        base_url
      )

    on_exit(fn -> ServerRegistry.remove_server(server.id) end)

    {_key, token} = issue_key(granted_server_ids: [server.id])
    %{sid: server.id, token: token}
  end

  test "tools/list against an event-stream upstream is forwarded and decoded", %{
    sid: sid,
    token: token
  } do
    session_id = handshake(token, sid)
    conn = method_call(token, session_id, sid, "tools/list", %{})

    assert %{"result" => %{"tools" => tools}} = json_response(conn, 200)
    assert Enum.map(tools, & &1["name"]) == PhoenixElxirBeam.MCPHTTPTestServer.tool_names()
  end
end
