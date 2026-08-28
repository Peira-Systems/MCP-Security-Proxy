defmodule PhoenixElxirBeam.MCP.HoldRegistryTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.HoldRegistry

  setup do
    name = :"hold_registry_#{System.unique_integer([:positive])}"
    start_supervised!({HoldRegistry, name: name}, id: name)
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
