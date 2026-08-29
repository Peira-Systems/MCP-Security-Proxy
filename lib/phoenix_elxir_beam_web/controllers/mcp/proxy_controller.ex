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
    CallContext,
    HoldRegistry,
    HttpTransport,
    Pipeline,
    PolicyEngine,
    Redaction,
    ServerRegistry,
    StdioServer,
    ToolCatalog
  }

  alias PhoenixElxirBeam.MCP.Plugin.Registry, as: PluginRegistry

  @chain_blocked_code -32001
  @response_withheld_code -32002
  @quarantined_code -32003

  def handle(conn, %{"server_id" => server_id} = params) do
    id = params["id"]
    method = params["method"]
    jsonrpc_version = params["jsonrpc"] || "2.0"
    rpc_params = params["params"] || %{}
    session_id = conn |> get_req_header("mcp-session-id") |> List.first()
    agent_id = conn |> get_req_header("mcp-agent-id") |> List.first()

    case method do
      "tools/call" ->
        route_tool_call(conn, server_id, session_id, agent_id, id, jsonrpc_version, rpc_params)

      _ ->
        forward(conn, server_id, envelope(jsonrpc_version, id, method, rpc_params), id)
    end
  end

  defp route_tool_call(conn, server_id, session_id, agent_id, id, jsonrpc_version, rpc_params) do
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
        # fail closed on rather than the normal shape of a new session. Also
        # the point where a session's agent identity is first recorded.
        :ok = PolicyEngine.ensure_session(session_id, agent_id)

        args = rpc_params["arguments"] || %{}

        case PolicyEngine.record_call(session_id, server_id, tool_name, tags, PolicyEngine, args) do
          {:allow, _event} ->
            call_and_scan(conn, server_id, session_id, tool_name, id, jsonrpc_version, rpc_params)

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

        call_and_scan(conn, c.server_id, c.session_id, c.tool_name, c.id, c.jsonrpc, c.rpc_params)

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

  # Non-`tools/call` methods (initialize / tools/list): forward verbatim, no scan.
  defp forward(conn, server_id, body, id) do
    case fetch(server_id, body) do
      {:ok, resp_body} -> json(conn, resp_body)
      {:error, message} -> upstream_error(conn, id, message)
    end
  end

  # `tools/call`: forward, then run the `post_call` pipeline over the response
  # and apply any redactions (or withhold the whole response) before replying.
  defp call_and_scan(conn, server_id, session_id, tool_name, id, jsonrpc, rpc_params) do
    case fetch(server_id, envelope(jsonrpc, id, "tools/call", rpc_params)) do
      {:error, message} ->
        upstream_error(conn, id, message)

      {:ok, %{"result" => %{"content" => content}} = resp_body} when is_list(content) ->
        ctx =
          CallContext.new(%{
            phase: :post_call,
            call: %{
              session_id: session_id,
              server_id: server_id,
              tool_name: tool_name,
              method: "tools/call"
            },
            response: %{is_error: false, content: content}
          })

        {verdict, findings, redactions, taint_sources, reason} =
          Pipeline.run_post_call(ctx, PluginRegistry.active_post_call())

        case verdict do
          :deny ->
            PolicyEngine.record_response_scan(
              session_id,
              server_id,
              tool_name,
              findings,
              reason || "response withheld by policy",
              taint_sources
            )

            json(conn, %{
              "jsonrpc" => jsonrpc,
              "id" => id,
              "error" => %{"code" => @response_withheld_code, "message" => reason}
            })

          :allow ->
            PolicyEngine.record_response_scan(
              session_id,
              server_id,
              tool_name,
              findings,
              nil,
              taint_sources
            )

            content = Redaction.apply(content, redactions)
            json(conn, put_in(resp_body, ["result", "content"], content))
        end

      {:ok, resp_body} ->
        # Error result or an unexpected shape — nothing to scan.
        json(conn, resp_body)
    end
  end

  defp fetch(server_id, body) do
    case ServerRegistry.get_server(server_id) do
      nil -> fetch_from_mock(server_id, body)
      server -> fetch_from_real(server, body)
    end
  end

  defp fetch_from_mock(server_id, body) do
    port = PhoenixElxirBeamWeb.Endpoint.config(:http)[:port]

    case Req.post("http://127.0.0.1:#{port}/mcp/servers/#{server_id}", json: body) do
      {:ok, %{status: 200, body: resp_body}} -> {:ok, resp_body}
      _ -> {:error, "upstream mock server error"}
    end
  end

  defp fetch_from_real(%{transport: :stdio, pid: pid}, body) do
    case StdioServer.request(pid, body) do
      {:ok, resp_body} -> {:ok, resp_body}
      {:error, _reason} -> {:error, "upstream real server error"}
    end
  end

  defp fetch_from_real(%{transport: :http} = server, body) do
    session_headers = if server.session_id, do: [{"mcp-session-id", server.session_id}], else: []
    {url, transport_headers} = HttpTransport.prepare(server.base_url)
    headers = transport_headers ++ session_headers

    case Req.post(url, json: body, headers: headers, receive_timeout: 15_000) do
      {:ok, %{status: status, body: resp_body}} when status in 200..299 -> {:ok, resp_body}
      _ -> {:error, "upstream real server error"}
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
