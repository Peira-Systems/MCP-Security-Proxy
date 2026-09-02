defmodule PhoenixElxirBeam.MCP.HoldRegistryTest do
  # park/finalize now write through to HoldStore (Postgres) from the
  # registry's own GenServer process — checkout + allow so that write is
  # visible (and rolled back) within this test rather than erroring.
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.{HoldRegistry, PendingHold}
  alias PhoenixElxirBeam.Repo

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)

    name = :"hold_registry_#{System.unique_integer([:positive])}"
    {:ok, pid} = start_supervised({HoldRegistry, name: name}, id: name)
    Ecto.Adapters.SQL.Sandbox.allow(Repo, self(), pid)

    Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, "mcp:holds")
    %{reg: name}
  end

  defp spec(overrides \\ %{}) do
    Map.merge(
      %{
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

  test "park lists the hold and broadcasts it", %{reg: reg} do
    id = HoldRegistry.park(spec(), reg)

    assert_receive {:hold_pending, %{id: ^id, prompt: "Approve?"}}
    assert [%{id: ^id}] = HoldRegistry.pending(reg)
  end

  test "park write-throughs to HoldStore; resolving deletes the row", %{reg: reg} do
    id = HoldRegistry.park(spec(), reg)
    assert %PendingHold{tool_name: "post_webhook"} = Repo.get(PendingHold, id)

    task = Task.async(fn -> HoldRegistry.await(id, 5_000, reg) end)
    Process.sleep(20)
    :ok = HoldRegistry.resolve(id, :approve, reg)
    Task.await(task)

    refute Repo.get(PendingHold, id)
  end

  test "await blocks until resolve(:approve)", %{reg: reg} do
    id = HoldRegistry.park(spec(), reg)
    task = Task.async(fn -> HoldRegistry.await(id, 5_000, reg) end)
    Process.sleep(20)

    :ok = HoldRegistry.resolve(id, :approve, reg)

    assert Task.await(task) == {:ok, :approved}
    assert_receive {:hold_resolved, ^id, :approved}
    assert [] = HoldRegistry.pending(reg)
  end

  test "resolve(:deny) yields :denied", %{reg: reg} do
    id = HoldRegistry.park(spec(), reg)
    task = Task.async(fn -> HoldRegistry.await(id, 5_000, reg) end)
    Process.sleep(20)
    :ok = HoldRegistry.resolve(id, :deny, reg)
    assert Task.await(task) == {:ok, :denied}
  end

  test "the timeout fires with on_timeout", %{reg: reg} do
    id = HoldRegistry.park(spec(%{timeout_ms: 40, on_timeout: :deny}), reg)
    assert HoldRegistry.await(id, 2_000, reg) == {:ok, :denied}
    assert_receive {:hold_resolved, ^id, :denied}
  end

  test "await on an already-resolved or unknown hold returns immediately", %{reg: reg} do
    assert HoldRegistry.await("hold-nope", 2_000, reg) == {:ok, :denied}
  end
end
