defmodule PhoenixElxirBeam.MCP.SessionStoreTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.{Session, SessionStore}

  defp start_store(opts \\ []) do
    name = :"session_store_#{System.unique_integer([:positive])}"
    opts = Keyword.merge([name: name, gc_interval_ms: 60_000], opts)
    start_supervised!({SessionStore, opts})
    name
  end

  defp open(store, server_id \\ "real-x", opts \\ []) do
    {:ok, session} = SessionStore.open(server_id, opts, store)
    session
  end

  test "open mints an :initializing session bound to the server" do
    store = start_store()
    s = open(store, "real-abc", protocol_version: "2025-06-18", agent_id: "agent://a")

    assert %Session{state: :initializing, server_id: "real-abc", agent_id: "agent://a"} = s
    assert String.starts_with?(s.id, "mcps-")
    assert {:ok, %Session{id: id}} = SessionStore.fetch(s.id, store)
    assert id == s.id
  end

  test "mark_ready promotes the session" do
    store = start_store()
    s = open(store)

    assert :ok = SessionStore.mark_ready(s.id, store)
    assert {:ok, %Session{state: :ready}} = SessionStore.fetch(s.id, store)
  end

  test "mark_ready on an unknown id is an error" do
    store = start_store()
    assert {:error, :not_found} = SessionStore.mark_ready("mcps-nope", store)
  end

  test "fetch is :error for nil and unknown ids" do
    store = start_store()
    assert :error = SessionStore.fetch(nil, store)
    assert :error = SessionStore.fetch("mcps-nope", store)
  end

  test "close removes the session" do
    store = start_store()
    s = open(store)

    assert :ok = SessionStore.close(s.id, store)
    assert :error = SessionStore.fetch(s.id, store)
  end

  test "the periodic GC drops idle sessions" do
    store = start_store(idle_ttl_ms: 0)
    s = open(store)

    send(store, :gc)
    _ = :sys.get_state(store)

    assert :error = SessionStore.fetch(s.id, store)
  end

  test "opening past the cap evicts the least-recently-seen session" do
    store = start_store(max_sessions: 2)

    a = open(store)
    b = open(store)
    # touch `a` so `b` is now the least-recently-seen
    {:ok, _} = SessionStore.fetch(a.id, store)
    c = open(store)

    assert :error = SessionStore.fetch(b.id, store)
    assert {:ok, _} = SessionStore.fetch(a.id, store)
    assert {:ok, _} = SessionStore.fetch(c.id, store)
  end

  test "list returns live sessions most-recently-active first" do
    store = start_store()
    a = open(store)
    _b = open(store)
    {:ok, _} = SessionStore.fetch(a.id, store)

    assert [first | _] = SessionStore.list(store)
    assert first.id == a.id
  end
end
