defmodule PhoenixElxirBeamWeb.Plugs.AgentCredentialAuth do
  @moduledoc """
  Reads an optional `X-Agent-Credential: <agent_id>.<secret>` header and, on
  a valid match, assigns `conn.assigns.verified_agent_id` -- letting an
  agent assert its own identity independent of which API key authenticated
  the connection (`PhoenixElxirBeamWeb.Plugs.ApiKeyAuth` runs first in the
  pipeline and already rejected the request if the bearer token itself was
  invalid).

  Absent header: no-op, `verified_agent_id` stays unset, callers fall back
  to the API key's own `agent_id` exactly as before this plug existed.
  Present but invalid header: the request is rejected the same way a bad
  API key is -- silently falling back to the key's default `agent_id`
  instead would let an attacker probe for valid `agent_id` strings for
  free, since a wrong guess would otherwise just quietly succeed at the
  lower trust level.
  """

  import Plug.Conn

  alias PhoenixElxirBeam.MCP.AgentCredential

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    case get_req_header(conn, "x-agent-credential") do
      [] ->
        conn

      [token] ->
        case AgentCredential.authenticate(token) do
          {:ok, cred} -> assign(conn, :verified_agent_id, cred.agent_id)
          {:error, _reason} -> deny(conn)
        end

      _ ->
        deny(conn)
    end
  end

  defp deny(conn) do
    body =
      Jason.encode!(%{
        "jsonrpc" => "2.0",
        "id" => nil,
        "error" => %{"code" => -32001, "message" => "invalid agent credential"}
      })

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(401, body)
    |> halt()
  end
end
