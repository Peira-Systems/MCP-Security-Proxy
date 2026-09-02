defmodule PhoenixElxirBeam.MCP.ApiKeyTest do
  use PhoenixElxirBeam.DataCase, async: true

  alias PhoenixElxirBeam.MCP.{ApiKey, ApiKeyCache}

  defp issue(attrs \\ %{}) do
    {:ok, key, token} =
      ApiKey.issue(Map.merge(%{principal: "acme", agent_id: "agent://acme"}, attrs))

    {key, token}
  end

  test "issue returns a token once and stores only a hash" do
    {key, token} = issue()

    assert String.starts_with?(token, key.key_id <> ".")
    assert key.token_hash != nil
    refute token =~ Base.encode16(key.token_hash, case: :lower)
  end

  test "authenticate accepts the real token, rejects tampered ones" do
    {key, token} = issue()

    assert {:ok, authed} = ApiKey.authenticate(token)
    assert authed.id == key.id

    assert {:error, :bad_secret} = ApiKey.authenticate(key.key_id <> ".wrong")
    assert {:error, :unknown_key} = ApiKey.authenticate("mcpk_nope.whatever")
    assert {:error, :malformed} = ApiKey.authenticate("no-dot")
    assert {:error, :malformed} = ApiKey.authenticate(nil)
  end

  test "last_used_at only updates on a successful authentication, not a failed one" do
    {key, token} = issue()
    assert Repo.get(ApiKey, key.id).last_used_at == nil

    assert {:error, :bad_secret} = ApiKey.authenticate(key.key_id <> ".wrong")
    assert Repo.get(ApiKey, key.id).last_used_at == nil

    # touch_last_used only ever runs on the DB (cache-miss) path -- a real
    # cache hit here would legitimately also skip the write (see the
    # ApiKey moduledoc), which would make this assert nil regardless of the
    # fix under test. Force the next call back through the DB path so this
    # actually isolates "does a *successful* DB-path auth still touch it".
    :ok = ApiKeyCache.invalidate(key.key_id)

    assert {:ok, _} = ApiKey.authenticate(token)
    assert Repo.get(ApiKey, key.id).last_used_at != nil
  end

  test "a revoked key no longer authenticates" do
    {key, token} = issue()
    assert :ok = ApiKey.revoke(key.key_id)

    assert {:error, :disabled} = ApiKey.authenticate(token)
  end

  test "revoking an already-cached key takes effect on the next request" do
    {key, token} = issue()

    # populates the cache (docs/latency-budget.md — auth cache follow-up)
    assert {:ok, _} = ApiKey.authenticate(token)

    assert :ok = ApiKey.revoke(key.key_id)
    assert {:error, :disabled} = ApiKey.authenticate(token)
  end

  test "grant changes to an already-cached key take effect on the next request" do
    {key, token} = issue(%{all_servers: false, granted_server_ids: ["real-a"]})

    assert {:ok, cached} = ApiKey.authenticate(token)
    assert ApiKey.authorize?(cached, "real-a")
    refute ApiKey.authorize?(cached, "real-b")

    {:ok, _} = ApiKey.set_grants(key.key_id, server_ids: ["real-b"])

    assert {:ok, refreshed} = ApiKey.authenticate(token)
    refute ApiKey.authorize?(refreshed, "real-a")
    assert ApiKey.authorize?(refreshed, "real-b")
  end

  test "authorize? honours all_servers and the grant list" do
    {all, _} = issue(%{all_servers: true})
    {scoped, _} = issue(%{all_servers: false, granted_server_ids: ["real-a"]})

    assert ApiKey.authorize?(all, "real-anything")
    assert ApiKey.authorize?(scoped, "real-a")
    refute ApiKey.authorize?(scoped, "real-b")
  end

  test "set_grants replaces the grants" do
    {key, _} = issue(%{all_servers: false, granted_server_ids: ["real-a"]})

    {:ok, updated} = ApiKey.set_grants(key.key_id, server_ids: ["real-b", "real-c"])
    assert updated.granted_server_ids == ["real-b", "real-c"]
    refute ApiKey.authorize?(updated, "real-a")

    {:ok, all} = ApiKey.set_grants(key.key_id, all_servers: true)
    assert ApiKey.authorize?(all, "real-a")
  end

  test "ensure_dashboard_key is idempotent and yields a usable token" do
    assert :ok = ApiKey.ensure_dashboard_key()
    token = ApiKey.dashboard_token()
    assert {:ok, key} = ApiKey.authenticate(token)
    assert key.principal == "dashboard"
    assert key.all_servers

    assert :ok = ApiKey.ensure_dashboard_key()
  end
end
