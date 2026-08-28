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

  alias PhoenixElxirBeam.MCP.{
    HoldRegistry,
    HttpTransport,
    PolicyEngine,
    ServerRegistry,
    StdioServer,
    ToolCatalog
  }

  @chain_blocked_code -32001
  @quarantined_code -32003

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

    case quarantine_reason(server_id, tool_name) do
      {:quarantined, reason} ->
        # A discovery scanner (e.g. rug-pull) has held this tool. Refuse
        # before the policy pipeline, but still receipt the attempt.
        PolicyEngine.record_blocked(session_id, server_id, tool_name, reason)

        json(conn, %{
          "jsonrpc" => jsonrpc_version,
          "id" => id,
          "error" => %{"code" => @quarantined_code, "message" => reason}
        })

      :ok ->
        tags = tool_tags(server_id, tool_name)

        # Ensures session state exists before the policy decision runs, so a
        # lookup miss inside `record_call/5` is an anomaly PolicyEngine can
        # fail closed on rather than the normal shape of a new session.
        :ok = PolicyEngine.ensure_session(session_id)

        case PolicyEngine.record_call(session_id, server_id, tool_name, tags) do
          {:allow, _event} ->
            forward(conn, server_id, envelope(jsonrpc_version, id, "tools/call", rpc_params), id)

          {:block, event} ->
            json(conn, %{
              "jsonrpc" => jsonrpc_version,
              "id" => id,
              "error" => %{"code" => @chain_blocked_code, "message" => event.reason}
            })

          {:hold, hold_id, timeout_ms, _event} ->
            # Park the request until an operator approves/denies on the
            # dashboard (or the hold's own timeout fires).
            resolve_hold(conn, hold_id, timeout_ms, %{
              server_id: server_id,
              session_id: session_id,
              tool_name: tool_name,
              tags: tags,
              id: id,
              jsonrpc: jsonrpc_version,
              rpc_params: rpc_params
            })
        end
    end
  end

  defp resolve_hold(conn, hold_id, timeout_ms, c) do
    case HoldRegistry.await(hold_id, timeout_ms + 5_000) do
      {:ok, :approved} ->
        {:allow, _event} =
          PolicyEngine.finalize_hold(c.session_id, c.server_id, c.tool_name, c.tags, :approved)

        forward(conn, c.server_id, envelope(c.jsonrpc, c.id, "tools/call", c.rpc_params), c.id)

      {:ok, :denied} ->
        {:block, event} =
          PolicyEngine.finalize_hold(c.session_id, c.server_id, c.tool_name, c.tags, :denied)

        json(conn, %{
          "jsonrpc" => c.jsonrpc,
          "id" => c.id,
          "error" => %{"code" => @chain_blocked_code, "message" => event.reason}
        })
    end
  end

  defp quarantine_reason(server_id, tool_name) do
    with %{tools: tools} <- ServerRegistry.get_server(server_id),
         %{quarantined: true} = tool <- Enum.find(tools, &(&1.name == tool_name)) do
      {:quarantined, tool.quarantine_reason || "tool quarantined by a discovery scan"}
    else
      _ -> :ok
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

  defp forward_to_real(conn, %{transport: :stdio, pid: pid}, body, id) do
    case StdioServer.request(pid, body) do
      {:ok, resp_body} -> json(conn, resp_body)
      {:error, _reason} -> upstream_error(conn, id, "upstream real server error")
    end
  end

  defp forward_to_real(conn, %{transport: :http} = server, body, id) do
    session_headers = if server.session_id, do: [{"mcp-session-id", server.session_id}], else: []
    {url, transport_headers} = HttpTransport.prepare(server.base_url)
    headers = transport_headers ++ session_headers

    case Req.post(url, json: body, headers: headers, receive_timeout: 15_000) do
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
