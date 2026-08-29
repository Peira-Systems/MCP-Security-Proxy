defmodule PhoenixElxirBeamWeb.Plugs.ApiKeyAuth do
  @moduledoc """
  Authenticates the downstream MCP client on the proxy endpoint. Requires
  `Authorization: Bearer mcpk_<id>.<secret>`; on success assigns the
  `PhoenixElxirBeam.MCP.ApiKey` to `conn.assigns.api_key`. On failure the
  request is halted with a `401` and a JSON-RPC-shaped error body — there is
  no unauthenticated path to the proxy.
  """

  import Plug.Conn

  alias PhoenixElxirBeam.MCP.ApiKey

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    with {:ok, token} <- bearer_token(conn),
         {:ok, key} <- ApiKey.authenticate(token) do
      assign(conn, :api_key, key)
    else
      _ -> deny(conn)
    end
  end

  defp bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] when byte_size(token) > 0 -> {:ok, String.trim(token)}
      _ -> :error
    end
  end

  defp deny(conn) do
    body =
      Jason.encode!(%{
        "jsonrpc" => "2.0",
        "id" => nil,
        "error" => %{"code" => -32001, "message" => "authentication required"}
      })

    conn
    |> put_resp_header("www-authenticate", "Bearer")
    |> put_resp_content_type("application/json")
    |> send_resp(401, body)
    |> halt()
  end
end
