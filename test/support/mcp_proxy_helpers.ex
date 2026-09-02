defmodule PhoenixElxirBeam.MCPProxyHelpers do
  @moduledoc """
  Shared helpers for driving the authenticated proxy endpoint from tests:
  issue an API key, complete the MCP handshake, make calls.
  """

  import Phoenix.ConnTest
  import Plug.Conn

  alias PhoenixElxirBeam.MCP.{ApiKey, SessionStore}

  @endpoint PhoenixElxirBeamWeb.Endpoint

  @doc """
  Issues an API key for the test and schedules its revocation. `opts`:
  `:principal`, `:agent_id`, `:all_servers` (default true),
  `:granted_server_ids`. Returns `{key, token}`.
  """
  def issue_key(opts \\ []) do
    {:ok, key, token} =
      ApiKey.issue(%{
        principal: opts[:principal] || "test",
        agent_id: opts[:agent_id] || "agent://test",
        all_servers: Keyword.get(opts, :all_servers, true),
        granted_server_ids: opts[:granted_server_ids] || []
      })

    ExUnit.Callbacks.on_exit(fn -> ApiKey.revoke(key.key_id) end)
    {key, token}
  end

  @doc "A `build_conn` carrying the bearer token."
  def authed(token), do: put_req_header(build_conn(), "authorization", "Bearer #{token}")

  def rpc(method, params),
    do: %{"jsonrpc" => "2.0", "id" => 1, "method" => method, "params" => params}

  def proxy_post(conn, server_id, body),
    do: dispatch(conn, @endpoint, :post, "/mcp/proxy/#{server_id}", body)

  def proxy_delete(conn, server_id),
    do: dispatch(conn, @endpoint, :delete, "/mcp/proxy/#{server_id}", nil)

  @doc "Completes initialize + initialized for `token` against `server_id`; returns the session id."
  def handshake(token, server_id) do
    init =
      authed(token)
      |> proxy_post(
        server_id,
        rpc("initialize", %{
          "protocolVersion" => "2025-06-18",
          "clientInfo" => %{"name" => "test", "version" => "1"}
        })
      )

    [session_id] = get_resp_header(init, "mcp-session-id")

    authed(token)
    |> put_req_header("mcp-session-id", session_id)
    |> proxy_post(server_id, %{"jsonrpc" => "2.0", "method" => "notifications/initialized"})

    ExUnit.Callbacks.on_exit(fn -> SessionStore.close(session_id) end)
    session_id
  end

  @doc "POSTs a `tools/call` on an established session."
  def tool_call(token, session_id, server_id, name, args \\ %{}) do
    authed(token)
    |> put_req_header("mcp-session-id", session_id)
    |> proxy_post(server_id, rpc("tools/call", %{"name" => name, "arguments" => args}))
  end

  @doc "POSTs an arbitrary method on an established session."
  def method_call(token, session_id, server_id, method, params) do
    authed(token)
    |> put_req_header("mcp-session-id", session_id)
    |> proxy_post(server_id, rpc(method, params))
  end
end
