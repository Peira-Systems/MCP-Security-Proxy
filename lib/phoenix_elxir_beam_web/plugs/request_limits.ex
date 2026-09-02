defmodule PhoenixElxirBeamWeb.Plugs.RequestLimits do
  @moduledoc """
  Rejects an oversized request on the proxy endpoint before it is buffered
  or parsed. MCP JSON-RPC requests are small; a large body is either a bug
  or an attempt to exhaust memory on the decision path. `413` on a
  `content-length` over the limit (`config :phoenix_elxir_beam,
  #{inspect(__MODULE__)}, max_body_bytes: …`, default 1 MiB).

  Header count / size limits are enforced by Bandit via the endpoint's
  `http` options.
  """

  import Plug.Conn

  @behaviour Plug

  @default_max_body_bytes 1_048_576

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    max = max_body_bytes()

    case get_req_header(conn, "content-length") do
      [len] ->
        case Integer.parse(len) do
          {n, _} when n > max -> reject(conn, max)
          _ -> conn
        end

      _ ->
        conn
    end
  end

  defp reject(conn, max) do
    body =
      Jason.encode!(%{
        "jsonrpc" => "2.0",
        "id" => nil,
        "error" => %{"code" => -32001, "message" => "request body exceeds #{max} bytes"}
      })

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(413, body)
    |> halt()
  end

  defp max_body_bytes do
    :phoenix_elxir_beam
    |> Application.get_env(__MODULE__, [])
    |> Keyword.get(:max_body_bytes, @default_max_body_bytes)
  end
end
