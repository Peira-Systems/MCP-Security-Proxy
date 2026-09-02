defmodule PhoenixElxirBeam.MCP.ApiKeyCacheTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.ApiKeyCache

  defp key_id, do: "mcpk_test_#{System.unique_integer([:positive])}"

  test "a put entry is returned by get within the ttl" do
    id = key_id()
    assert :miss = ApiKeyCache.get(id, ttl_ms: 10_000)

    :ok = ApiKeyCache.put(id, %{marker: :one})
    assert {:ok, %{marker: :one}} = ApiKeyCache.get(id, ttl_ms: 10_000)
  end

  test "an entry older than ttl_ms reads as a miss" do
    id = key_id()
    :ok = ApiKeyCache.put(id, %{marker: :stale})

    Process.sleep(3)
    assert :miss = ApiKeyCache.get(id, ttl_ms: 1)
  end

  test "invalidate evicts regardless of ttl" do
    id = key_id()
    :ok = ApiKeyCache.put(id, %{marker: :evict_me})
    assert {:ok, _} = ApiKeyCache.get(id, ttl_ms: 60_000)

    :ok = ApiKeyCache.invalidate(id)
    assert :miss = ApiKeyCache.get(id, ttl_ms: 60_000)
  end

  test "invalidate on a never-cached key_id is a no-op" do
    assert :ok = ApiKeyCache.invalidate(key_id())
  end

  test "a fresh put overwrites a previous entry for the same key_id" do
    id = key_id()
    :ok = ApiKeyCache.put(id, %{marker: :first})
    :ok = ApiKeyCache.put(id, %{marker: :second})

    assert {:ok, %{marker: :second}} = ApiKeyCache.get(id, ttl_ms: 10_000)
  end

  test "invalidate's delayed second eviction closes a stale write that lands after the immediate one" do
    id = key_id()

    # Simulates the race this exists to close: a concurrent authenticate/1
    # call that already read the row from Postgres calls put/2 with a
    # now-stale value *after* the immediate delete below has already run
    # (docs -- ApiKeyCache moduledoc).
    :ok = ApiKeyCache.invalidate(id, delay_ms: 15)
    :ok = ApiKeyCache.put(id, %{marker: :stale_write_after_invalidate})
    assert {:ok, _} = ApiKeyCache.get(id, ttl_ms: 60_000)

    Process.sleep(30)
    assert :miss = ApiKeyCache.get(id, ttl_ms: 60_000)
  end
end
