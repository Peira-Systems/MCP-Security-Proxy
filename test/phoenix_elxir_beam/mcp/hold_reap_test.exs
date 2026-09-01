defmodule PhoenixElxirBeam.MCP.HoldReapTest do
  @moduledoc """
  M2.2 follow-up: a hold left over from a previous process lifetime (a
  restart, deploy, or crash interrupted it before it resolved) gets a
  terminal audit event instead of being silently orphaned forever.
  """
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.{EventLog, HoldRegistry, HoldStore, PendingHold, PolicyEngine}
  alias PhoenixElxirBeam.Repo

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)

    engine = :"hold_reap_engine_#{System.unique_integer([:positive])}"
    {:ok, pid} = start_supervised({PolicyEngine, name: engine}, id: engine)
    Ecto.Adapters.SQL.Sandbox.allow(Repo, self(), pid)

    %{engine: engine}
  end

  defp leftover_hold(overrides \\ %{}) do
    Map.merge(
      %{
        id: "hold-#{System.unique_integer([:positive])}",
        prompt: "Approve?",
        reason: "egress after read",
        session_id: "s-#{System.unique_integer([:positive])}",
        server_id: "net",
        tool_name: "post_webhook",
        tags: [:network_egress],
        timeout_ms: 5_000,
        on_timeout: :deny
      },
      overrides
    )
  end

  test "reap_orphans finalizes a leftover row as blocked and deletes it", %{engine: engine} do
    h = leftover_hold()
    :ok = HoldStore.persist(h)

    assert :ok = HoldRegistry.reap_orphans(engine)

    refute Repo.get(PendingHold, h.id)

    %{entries: [event | _]} = EventLog.list(%{status: "blocked"})
    assert event.session_id == h.session_id
    assert event.server_id == "net"
    assert event.tool_name == "post_webhook"
    assert event.reason =~ "orphaned by a proxy restart"
  end

  test "reap_orphans handles several leftover rows independently" do
    engine = :"hold_reap_engine_multi_#{System.unique_integer([:positive])}"
    {:ok, pid} = start_supervised({PolicyEngine, name: engine}, id: engine)
    Ecto.Adapters.SQL.Sandbox.allow(Repo, self(), pid)

    a = leftover_hold()
    b = leftover_hold()
    :ok = HoldStore.persist(a)
    :ok = HoldStore.persist(b)

    assert :ok = HoldRegistry.reap_orphans(engine)

    refute Repo.get(PendingHold, a.id)
    refute Repo.get(PendingHold, b.id)
  end

  test "reap_orphans is a no-op when nothing is pending", %{engine: engine} do
    assert HoldStore.all() == []
    assert :ok = HoldRegistry.reap_orphans(engine)
  end
end
