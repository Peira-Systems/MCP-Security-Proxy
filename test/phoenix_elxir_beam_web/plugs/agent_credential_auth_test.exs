defmodule PhoenixElxirBeamWeb.Plugs.AgentCredentialAuthTest do
  use PhoenixElxirBeamWeb.ConnCase, async: true

  alias PhoenixElxirBeam.MCP.AgentCredential
  alias PhoenixElxirBeamWeb.Plugs.AgentCredentialAuth

  defp issue(attrs \\ %{}) do
    {:ok, cred, token} =
      AgentCredential.issue(Map.merge(%{agent_id: "agent://specific-bot"}, attrs))

    {cred, token}
  end

  test "no header is a no-op", %{conn: conn} do
    conn = AgentCredentialAuth.call(conn, [])
    refute Map.has_key?(conn.assigns, :verified_agent_id)
    refute conn.halted
  end

  test "a valid header assigns verified_agent_id", %{conn: conn} do
    {_cred, token} = issue()

    conn =
      conn
      |> Plug.Conn.put_req_header("x-agent-credential", token)
      |> AgentCredentialAuth.call([])

    assert conn.assigns.verified_agent_id == "agent://specific-bot"
    refute conn.halted
  end

  test "an unknown agent_id in the header halts with 401", %{conn: conn} do
    conn =
      conn
      |> Plug.Conn.put_req_header("x-agent-credential", "agent://nope.whatever")
      |> AgentCredentialAuth.call([])

    assert conn.halted
    assert conn.status == 401
  end

  test "a wrong secret halts with 401, does not fall back silently", %{conn: conn} do
    {cred, _token} = issue()

    conn =
      conn
      |> Plug.Conn.put_req_header("x-agent-credential", cred.agent_id <> ".wrong")
      |> AgentCredentialAuth.call([])

    assert conn.halted
    assert conn.status == 401
    refute Map.has_key?(conn.assigns, :verified_agent_id)
  end

  test "a duplicated header fails closed with 401, not a 500 crash", %{conn: conn} do
    {_cred, token} = issue()

    # `Plug.Conn.put_req_header/3` uses `List.keystore/4` under the hood, so
    # calling it twice with the same key *replaces* the value rather than
    # appending -- it can never produce a genuine 2-element header list.
    # Build `req_headers` directly instead, as Cowboy would if a client (or
    # a misbehaving intermediary) sent the same header twice.
    conn =
      conn
      |> Map.update!(:req_headers, fn headers ->
        headers ++ [{"x-agent-credential", token}, {"x-agent-credential", token}]
      end)
      |> AgentCredentialAuth.call([])

    assert conn.halted
    assert conn.status == 401
    assert conn.resp_body =~ "invalid agent credential"
    refute Map.has_key?(conn.assigns, :verified_agent_id)
  end

  test "a disabled credential halts with 401", %{conn: conn} do
    {cred, token} = issue()
    :ok = AgentCredential.revoke(cred.agent_id)

    conn =
      conn
      |> Plug.Conn.put_req_header("x-agent-credential", token)
      |> AgentCredentialAuth.call([])

    assert conn.halted
    assert conn.status == 401
  end
end
