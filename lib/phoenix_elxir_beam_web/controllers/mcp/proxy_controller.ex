defmodule PhoenixElxirBeamWeb.MCP.ProxyController do
  @moduledoc """
  Policy-enforcing proxy sitting between the (simulated) MCP client and
  either a mock MCP server or a real one registered via
  `PhoenixElxirBeam.MCP.ServerRegistry`. Every `tools/call` is checked
  against `PhoenixElxirBeam.MCP.PolicyEngine` before being forwarded; a
  blocked call never reaches the target server. `initialize` and
  `tools/list` are forwarded untouched and never consulted against the
  policy engine.
  """

  use PhoenixElxirBeamWeb, :controller

  alias PhoenixElxirBeam.MCP.{PolicyEngine, ServerRegistry, ToolCatalog}

  @chain_blocked_code -32001

  def handle(conn, %{"server_id" => server_id} = params) do
    id = params["id"]
    method = params["method"]
    jsonrpc_version = params["jsonrpc"] || "2.0"
    rpc_params = params["params"] || %{}
    session_id = conn |> get_req_header("mcp-session-id") |> List.first()

    case method do
      "tools/call" ->
        route_tool_call(conn, server_id, session_id, id, jsonrpc_version, rpc_params)

      _ ->
        forward(conn, server_id, envelope(jsonrpc_version, id, method, rpc_params), id)
    end
  end

  defp route_tool_call(conn, server_id, session_id, id, jsonrpc_version, rpc_params) do
    tool_name = rpc_params["name"]
    tags = tool_tags(server_id, tool_name)

    case PolicyEngine.record_call(session_id, server_id, tool_name, tags) do
      {:allow, _event} ->
        forward(conn, server_id, envelope(jsonrpc_version, id, "tools/call", rpc_params), id)

      {:block, event} ->
        json(conn, %{
          "jsonrpc" => jsonrpc_version,
          "id" => id,
          "error" => %{"code" => @chain_blocked_code, "message" => event.reason}
        })
    end
  end

  defp envelope(jsonrpc_version, id, method, rpc_params) do
    %{"jsonrpc" => jsonrpc_version, "id" => id, "method" => method, "params" => rpc_params}
  end

  defp tool_tags(server_id, tool_name) do
    case ToolCatalog.tool(server_id, tool_name) do
      %{tags: tags} -> tags
      nil -> real_tool_tags(ServerRegistry.get_server(server_id), tool_name)
    end
  end

  defp real_tool_tags(nil, _tool_name), do: []

  defp real_tool_tags(server, tool_name) do
    case Enum.find(server.tools, &(&1.name == tool_name)) do
      nil -> []
      tool -> tool.tags
    end
  end

  defp forward(conn, server_id, body, id) do
    case ServerRegistry.get_server(server_id) do
      nil -> forward_to_mock(conn, server_id, body, id)
      server -> forward_to_real(conn, server, body, id)
    end
  end

  defp forward_to_mock(conn, server_id, body, id) do
    port = PhoenixElxirBeamWeb.Endpoint.config(:http)[:port]

    case Req.post("http://127.0.0.1:#{port}/mcp/servers/#{server_id}", json: body) do
      {:ok, %{status: 200, body: resp_body}} ->
        json(conn, resp_body)

      _ ->
        upstream_error(conn, id, "upstream mock server error")
    end
  end

  defp forward_to_real(conn, server, body, id) do
    headers = if server.session_id, do: [{"mcp-session-id", server.session_id}], else: []

    case Req.post(server.base_url, json: body, headers: headers, receive_timeout: 15_000) do
      {:ok, %{status: status, body: resp_body}} when status in 200..299 ->
        json(conn, resp_body)

      _ ->
        upstream_error(conn, id, "upstream real server error")
    end
  end

  defp upstream_error(conn, id, message) do
    json(conn, %{
      "jsonrpc" => "2.0",
      "id" => id,
      "error" => %{"code" => -32000, "message" => message}
    })
  end
end
