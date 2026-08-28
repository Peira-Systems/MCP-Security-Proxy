defmodule PhoenixElxirBeam.MCP.Plugin.RegistryTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.Decision
  alias PhoenixElxirBeam.MCP.Plugin.{Manifest, Registry}
  alias PhoenixElxirBeam.MCP.Plugins.ChainExfil

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
    name = :"plugin_registry_#{System.unique_integer([:positive])}"
    {:ok, _pid} = start_supervised({Registry, name: name, plugins: plugins}, id: name)
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

  test "a sidecar spec is parsed but stored disabled and not active" do
    reg = start_registry([{:sidecar, name: "py-scan", transport: :stdio, cmd: "python"}])

    assert [entry] = Registry.list(reg)
    assert entry.name == "py-scan"
    assert entry.kind == :sidecar
    refute entry.enabled
    assert entry.note == :not_implemented
    assert [] = Registry.active_policies(:pre_call, reg)
  end
end
