defmodule PhoenixElxirBeam.MCP.Plugin.RegistryDryRunDurabilityTest do
  @moduledoc "D1: per-plugin mode and the global proxy mode survive a registry restart via Postgres."
  use PhoenixElxirBeam.DataCase, async: false

  alias PhoenixElxirBeam.MCP.Plugin.Registry
  alias PhoenixElxirBeam.MCP.Plugins.ChainExfil

  @name :registry_dry_run_durability

  defp start_reg do
    start_supervised!(
      {Registry, name: @name, plugins: [{ChainExfil, []}], persist: true},
      id: @name
    )

    Registry.await(@name)
  end

  defp restart_reg do
    stop_supervised!(@name)
    start_reg()
    Registry.await(@name)
  end

  setup do
    start_reg()
    :ok
  end

  test "a pinned plugin mode survives a restart" do
    :ok = Registry.set_mode("chain-exfil", :dry_run, @name)
    restart_reg()

    assert [%{name: "chain-exfil", mode: :dry_run}] = Registry.list(@name)
  end

  test "the global proxy mode survives a restart" do
    :ok = Registry.set_proxy_mode(:dry_run, @name)
    restart_reg()

    assert Registry.proxy_mode(@name) == :dry_run
  end
end
