defmodule PhoenixElxirBeam.MCP.PolicyEngineHoldTest do
  @moduledoc "PolicyEngine ↔ HoldRegistry: a :hold verdict parks the call; finalize_hold resolves it."
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.{HoldRegistry, PolicyEngine}
  alias PhoenixElxirBeam.MCP.Plugin.Registry
  alias PhoenixElxirBeam.MCP.Plugins.ApprovalGate
  alias PhoenixElxirBeam.Repo

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)

    suffix = System.unique_integer([:positive])
    reg = :"peh_registry_#{suffix}"
    holds = :"peh_holds_#{suffix}"
    engine = :"peh_engine_#{suffix}"

    {:ok, _} = start_supervised({Registry, name: reg, plugins: [{ApprovalGate, []}]}, id: reg)
    {:ok, _} = start_supervised({HoldRegistry, name: holds}, id: holds)

    {:ok, pid} =
      start_supervised(
        {PolicyEngine, name: engine, registry: reg, hold_registry: holds},
        id: engine
      )

    Ecto.Adapters.SQL.Sandbox.allow(Repo, self(), pid)

    %{engine: engine, holds: holds}
  end

  defp egress_after_read(engine) do
    session = "s-#{System.unique_integer([:positive])}"
    :ok = PolicyEngine.start_session(session, :attack, nil, engine)

    {:allow, _} =
      PolicyEngine.record_call(session, "files", "read_secrets", [:sensitive_read], engine)

    {session, PolicyEngine.record_call(session, "net", "post_webhook", [:network_egress], engine)}
  end

  test "egress after a sensitive read is held and parked", %{engine: engine, holds: holds} do
    {_session, result} = egress_after_read(engine)

    assert {:hold, hold_id, timeout_ms, event} = result
    assert event.status == :held
    assert is_integer(timeout_ms)
    assert [%{id: ^hold_id}] = HoldRegistry.pending(holds)
  end

  test "finalize_hold(:approved) allows and accumulates the tags", %{engine: engine} do
    {session, {:hold, _id, _t, _e}} = egress_after_read(engine)

    assert {:allow, event} =
             PolicyEngine.finalize_hold(
               session,
               "net",
               "post_webhook",
               [:network_egress],
               :approved,
               engine
             )

    assert event.status == :ok
  end

  test "finalize_hold(:denied) blocks", %{engine: engine} do
    {session, {:hold, _id, _t, _e}} = egress_after_read(engine)

    assert {:block, event} =
             PolicyEngine.finalize_hold(
               session,
               "net",
               "post_webhook",
               [:network_egress],
               :denied,
               engine
             )

    assert event.status == :blocked
    assert event.reason =~ "denied by operator"
  end

  test "egress without a prior sensitive read is allowed, no hold", %{
    engine: engine,
    holds: holds
  } do
    session = "s-#{System.unique_integer([:positive])}"
    :ok = PolicyEngine.start_session(session, :benign, nil, engine)

    assert {:allow, _} =
             PolicyEngine.record_call(session, "net", "post_webhook", [:network_egress], engine)

    assert [] = HoldRegistry.pending(holds)
  end
end
