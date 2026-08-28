defmodule PhoenixElxirBeam.MCP.Plugin.RegistryTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.Decision
  alias PhoenixElxirBeam.MCP.Plugin.{Manifest, Registry}
  alias PhoenixElxirBeam.MCP.Plugins.{ChainExfil, EventLogSink, RugPull}

  defmodule AuditPolicy do
    @behaviour PhoenixElxirBeam.MCP.Plugin.Policy

    @impl true
    def manifest do
      Manifest.normalize(%{
        plugin: %{name: "audit-policy", version: "0.0.1"},
        capabilities: %{policy: %{phases: [:pre_call, :post_call]}}
      })
    end

    @impl true
    def evaluate(_phase, _ctx), do: Decision.allow()
  end

  defp start_registry(plugins) do
    suffix = System.unique_integer([:positive])
    name = :"plugin_registry_#{suffix}"
    sup = :"sidecar_sup_#{suffix}"

    start_supervised!({DynamicSupervisor, name: sup, strategy: :one_for_one}, id: sup)

    {:ok, _pid} =
      start_supervised(
        {Registry, name: name, plugins: plugins, sidecar_supervisor: sup},
        id: name
      )

    Registry.await(name)
    name
  end

  test "seeds an in-process policy plugin from config, enabled" do
    reg = start_registry([{ChainExfil, []}])

    assert [entry] = Registry.list(reg)
    assert entry.name == "chain-exfil"
    assert entry.kind == :policy
    assert entry.enabled
    assert entry.tool_tags == [:network_egress]
    assert entry.fail_mode == :fail_closed
  end

  test "active_policies/2 filters by phase" do
    reg = start_registry([{ChainExfil, []}])

    assert [%{name: "chain-exfil"}] = Registry.active_policies(:pre_call, reg)
    assert [] = Registry.active_policies(:post_call, reg)
  end

  test "active_policies/2 preserves configured order and reorder/2 changes it" do
    reg = start_registry([{AuditPolicy, []}, {ChainExfil, []}])

    assert ["audit-policy", "chain-exfil"] =
             Enum.map(Registry.active_policies(:pre_call, reg), & &1.name)

    :ok = Registry.reorder(["chain-exfil", "audit-policy"], reg)

    assert ["chain-exfil", "audit-policy"] =
             Enum.map(Registry.active_policies(:pre_call, reg), & &1.name)
  end

  test "disable/2 drops an entry from active_policies but keeps it listed" do
    reg = start_registry([{ChainExfil, []}])

    :ok = Registry.disable("chain-exfil", reg)

    assert [] = Registry.active_policies(:pre_call, reg)
    assert [%{name: "chain-exfil", enabled: false}] = Registry.list(reg)

    :ok = Registry.enable("chain-exfil", reg)
    assert [%{name: "chain-exfil"}] = Registry.active_policies(:pre_call, reg)
  end

  test "disable/2 on an unknown plugin returns an error" do
    reg = start_registry([{ChainExfil, []}])
    assert {:error, :not_found} = Registry.disable("nope", reg)
  end

  @sidecar_fixture Path.expand("../../../support/fixtures/sidecar_scanner.js", __DIR__)

  test "a sidecar spec spawns a runner and registers its capability from the manifest" do
    node = System.find_executable("node") || raise "node not found on PATH"
    sc_name = "sc-#{System.unique_integer([:positive])}"

    reg =
      start_registry([
        {ChainExfil, []},
        {:sidecar, name: sc_name, transport: :stdio, cmd: node, args: [@sidecar_fixture]}
      ])

    entry = Enum.find(Registry.list(reg), &(&1.name == "test-sidecar-scanner"))
    assert entry.kind == :scanner
    assert entry.enabled
    assert match?({:sidecar, _}, entry.impl)
    assert [%{name: "test-sidecar-scanner"}] = Registry.active_scanners(:discovery, reg)
  end

  test "a sidecar with a bad command is skipped; other plugins still register" do
    reg =
      start_registry([
        {ChainExfil, []},
        {:sidecar, name: "broken", transport: :stdio, cmd: "/no/such/binary"}
      ])

    names = Enum.map(Registry.list(reg), & &1.name)
    assert "chain-exfil" in names
    refute Enum.any?(names, &(&1 == "broken"))
  end

  test "seeds a scanner plugin enabled and exposes it via active_scanners/2" do
    reg = start_registry([{RugPull, []}])

    assert [%{name: "rug-pull", kind: :scanner, enabled: true, can_block: true}] =
             Registry.list(reg)

    assert [%{name: "rug-pull"}] = Registry.active_scanners(:discovery, reg)
    assert [] = Registry.active_scanners(:pre_call, reg)
    assert [] = Registry.active_policies(:pre_call, reg)
  end

  test "seeds an audit_sink plugin enabled and exposes it via active_sinks/1" do
    reg = start_registry([{EventLogSink, []}])

    assert [%{name: "event-log", kind: :audit_sink, enabled: true}] = Registry.list(reg)
    assert [%{name: "event-log"}] = Registry.active_sinks(reg)

    :ok = Registry.disable("event-log", reg)
    assert [] = Registry.active_sinks(reg)
  end
end
