defmodule PhoenixElxirBeam.MCP.PolicyEnginePipelineTest do
  @moduledoc """
  Proves the verdict travels through the plugin pipeline rather than a
  hardcoded check: with `chain-exfil` registered, egress-after-read is
  blocked; with the registry empty, the identical sequence is allowed.
  """
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.PolicyEngine
  alias PhoenixElxirBeam.MCP.Plugin.Registry
  alias PhoenixElxirBeam.MCP.Plugins.ChainExfil
  alias PhoenixElxirBeam.Repo

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
  end

  defp start_stack(plugins) do
    suffix = System.unique_integer([:positive])
    registry = :"pe_pipeline_registry_#{suffix}"
    engine = :"pe_pipeline_engine_#{suffix}"

    {:ok, _} = start_supervised({Registry, name: registry, plugins: plugins}, id: registry)
    {:ok, pid} = start_supervised({PolicyEngine, name: engine, registry: registry}, id: engine)
    Ecto.Adapters.SQL.Sandbox.allow(Repo, self(), pid)

    engine
  end

  defp egress_after_read(engine) do
    session = "s-#{System.unique_integer([:positive])}"
    :ok = PolicyEngine.start_session(session, :attack, engine)

    {:allow, _} =
      PolicyEngine.record_call(session, "files", "read_secrets", [:sensitive_read], engine)

    PolicyEngine.record_call(session, "net", "post_webhook", [:network_egress], engine)
  end

  test "chain-exfil registered: egress after a sensitive read is blocked" do
    engine = start_stack([{ChainExfil, []}])
    assert {:block, event} = egress_after_read(engine)
    assert event.reason == ChainExfil.block_reason()
  end

  test "empty registry: the same sequence is allowed (no plugin, no block)" do
    engine = start_stack([])
    assert {:allow, event} = egress_after_read(engine)
    assert event.status == :ok
  end

  test "chain-exfil disabled at runtime: the block goes away" do
    suffix = System.unique_integer([:positive])
    registry = :"pe_pipeline_registry_#{suffix}"
    engine = :"pe_pipeline_engine_#{suffix}"

    {:ok, _} =
      start_supervised({Registry, name: registry, plugins: [{ChainExfil, []}]}, id: registry)

    {:ok, pid} = start_supervised({PolicyEngine, name: engine, registry: registry}, id: engine)
    Ecto.Adapters.SQL.Sandbox.allow(Repo, self(), pid)

    assert {:block, _} = egress_after_read(engine)

    :ok = Registry.disable("chain-exfil", registry)
    assert {:allow, _} = egress_after_read(engine)
  end
end
