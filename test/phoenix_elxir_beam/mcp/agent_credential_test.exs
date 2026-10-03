defmodule PhoenixElxirBeam.MCP.AgentCredentialTest do
  use PhoenixElxirBeam.DataCase, async: true

  alias PhoenixElxirBeam.MCP.AgentCredential

  defp issue(attrs \\ %{}) do
    {:ok, cred, token} =
      AgentCredential.issue(Map.merge(%{agent_id: "agent://specific-bot"}, attrs))

    {cred, token}
  end

  test "issue returns a token once and stores only a hash" do
    {cred, token} = issue()

    assert String.starts_with?(token, cred.agent_id <> ".")
    assert cred.token_hash != nil
    refute token =~ Base.encode16(cred.token_hash, case: :lower)
  end

  test "authenticate accepts the real token, rejects tampered ones" do
    {cred, token} = issue()

    assert {:ok, authed} = AgentCredential.authenticate(token)
    assert authed.id == cred.id

    assert {:error, :bad_secret} = AgentCredential.authenticate(cred.agent_id <> ".wrong")
    assert {:error, :unknown_agent} = AgentCredential.authenticate("agent://nope.whatever")
    assert {:error, :malformed} = AgentCredential.authenticate("no-dot")
    assert {:error, :malformed} = AgentCredential.authenticate(nil)
  end

  test "a disabled credential is rejected even with the correct secret" do
    {cred, token} = issue()
    :ok = AgentCredential.revoke(cred.agent_id)

    assert {:error, :disabled} = AgentCredential.authenticate(token)
  end

  test "revoke is idempotent and reports :not_found for an unknown agent_id" do
    {cred, _token} = issue()
    assert :ok = AgentCredential.revoke(cred.agent_id)
    assert :ok = AgentCredential.revoke(cred.agent_id)
    assert {:error, :not_found} = AgentCredential.revoke("agent://never-existed")
  end
end
