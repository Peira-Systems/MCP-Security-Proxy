defmodule PhoenixElxirBeam.MCP.HoldStoreTest do
  @moduledoc "M2.2 follow-up: durable pending-hold rows for reap_orphans/0."
  use PhoenixElxirBeam.DataCase, async: true

  alias PhoenixElxirBeam.MCP.{HoldStore, PendingHold}

  defp hold(overrides \\ %{}) do
    Map.merge(
      %{
        id: "hold-#{System.unique_integer([:positive])}",
        prompt: "Approve?",
        reason: "egress after read",
        session_id: "s-1",
        server_id: "net",
        tool_name: "post_webhook",
        tags: [:network_egress],
        timeout_ms: 5_000,
        on_timeout: :deny
      },
      overrides
    )
  end

  test "persist inserts a row readable back by hold_id" do
    h = hold()
    :ok = HoldStore.persist(h)

    row = Repo.get(PendingHold, h.id)
    assert row.session_id == "s-1"
    assert row.server_id == "net"
    assert row.tool_name == "post_webhook"
    assert row.tags == ["network_egress"]
    assert row.timeout_ms == 5_000
    assert row.on_timeout == "deny"
  end

  test "persist is idempotent for the same hold_id" do
    h = hold()
    assert :ok = HoldStore.persist(h)
    assert :ok = HoldStore.persist(h)
    assert Repo.get(PendingHold, h.id)
  end

  test "resolve deletes the row" do
    h = hold()
    :ok = HoldStore.persist(h)
    assert :ok = HoldStore.resolve(h.id)
    refute Repo.get(PendingHold, h.id)
  end

  test "resolve on an unknown hold_id is a no-op" do
    assert :ok = HoldStore.resolve("hold-does-not-exist")
  end

  test "all/0 lists every currently-pending row" do
    a = hold()
    b = hold()
    :ok = HoldStore.persist(a)
    :ok = HoldStore.persist(b)

    ids = HoldStore.all() |> Enum.map(& &1.hold_id)
    assert a.id in ids
    assert b.id in ids
  end

  test "a hold with no tags persists as an empty list" do
    h = hold(%{tags: nil})
    :ok = HoldStore.persist(h)
    assert Repo.get(PendingHold, h.id).tags == []
  end
end
