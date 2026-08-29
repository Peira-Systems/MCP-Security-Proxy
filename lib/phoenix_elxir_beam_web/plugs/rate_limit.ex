defmodule PhoenixElxirBeamWeb.Plugs.RateLimit do
  @moduledoc """
  Per-principal rate limiting on the proxy endpoint. Runs after
  `PhoenixElxirBeamWeb.Plugs.ApiKeyAuth`, so it keys on
  `conn.assigns.api_key.key_id`. Over budget → `429` with a `Retry-After`
  header and a JSON-RPC-shaped error body.
  """

  import Plug.Conn

  alias PhoenixElxirBeam.MCP.RateLimiter

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(%{assigns: %{api_key: %{key_id: key_id}}} = conn, _opts) do
    case RateLimiter.check(key_id) do
      :ok ->
        conn

      {:error, retry_after} ->
        body =
          Jason.encode!(%{
            "jsonrpc" => "2.0",
            "id" => nil,
            "error" => %{"code" => -32001, "message" => "rate limit exceeded"}
          })

        conn
        |> put_resp_header("retry-after", Integer.to_string(retry_after))
        |> put_resp_content_type("application/json")
        |> send_resp(429, body)
        |> halt()
    end
  end

  # No authenticated key (ApiKeyAuth would already have halted) — nothing to key on.
  def call(conn, _opts), do: conn
end
