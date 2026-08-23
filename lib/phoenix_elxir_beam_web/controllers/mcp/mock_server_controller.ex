defmodule PhoenixElxirBeamWeb.MCP.MockServerController do
  @moduledoc """
  A single mock MCP server, keyed by `:server_id`, delegating tool
  definitions and canned responses to `PhoenixElxirBeam.MCP.ToolCatalog`.
  Handles the three JSON-RPC methods the demo needs: `initialize`,
  `tools/list`, and `tools/call`. Nothing here performs a real file read
  or network call — every tool response is a hardcoded string.
  """

  use PhoenixElxirBeamWeb, :controller

  alias PhoenixElxirBeam.MCP.ToolCatalog

  def handle(conn, %{"server_id" => server_id} = req_params) do
    id = req_params["id"]
    method = req_params["method"]
    params = req_params["params"] || %{}

    case handle_method(method, server_id, params) do
      {:ok, result} -> json(conn, %{"jsonrpc" => "2.0", "id" => id, "result" => result})
      :error -> json(conn, %{"jsonrpc" => "2.0", "id" => id, "error" => method_not_found()})
    end
  end

  defp handle_method("initialize", server_id, _params) do
    {:ok,
     %{
       "protocolVersion" => "2024-11-05",
       "capabilities" => %{"tools" => %{}},
       "serverInfo" => %{"name" => "mcp-mock-#{server_id}", "version" => "0.1.0"}
     }}
  end

  defp handle_method("tools/list", server_id, _params) do
    {:ok, %{"tools" => ToolCatalog.list_tools_json(server_id)}}
  end

  defp handle_method("tools/call", server_id, %{"name" => tool_name}) do
    case ToolCatalog.tool(server_id, tool_name) do
      nil ->
        :error

      tool ->
        {:ok, %{"content" => [%{"type" => "text", "text" => tool.response}], "isError" => false}}
    end
  end

  defp handle_method(_method, _server_id, _params), do: :error

  defp method_not_found, do: %{"code" => -32601, "message" => "method not found"}
end
