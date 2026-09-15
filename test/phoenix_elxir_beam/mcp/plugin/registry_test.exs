defmodule PhoenixElxirBeam.MCP.Plugin.RegistryTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.Decision
  alias PhoenixElxirBeam.MCP.Plugin.{Manifest, Registry}
  alias PhoenixElxirBeam.MCP.Plugins.{ChainExfil, EventLogSink, RugPull, SecretLeak, StreamGuard}

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
    sidecar_sup = :"sidecar_sup_#{suffix}"
    wasm_sup = :"wasm_sup_#{suffix}"

    start_supervised!({DynamicSupervisor, name: sidecar_sup, strategy: :one_for_one},
      id: sidecar_sup
    )

    start_supervised!({DynamicSupervisor, name: wasm_sup, strategy: :one_for_one}, id: wasm_sup)

    {:ok, _pid} =
      start_supervised(
        {Registry,
         name: name, plugins: plugins, sidecar_supervisor: sidecar_sup, wasm_supervisor: wasm_sup},
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

  test "an :enabled opt in the spec starts a plugin disabled" do
    reg = start_registry([{ChainExfil, enabled: false}])
    assert [%{name: "chain-exfil", enabled: false}] = Registry.list(reg)
    assert [] = Registry.active_policies(:pre_call, reg)
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

  test "update_config/2 replaces a plugin's config, visible immediately via list/1" do
    reg = start_registry([{StreamGuard, config: %{"max_bytes" => 1_200}}])

    assert [%{config: %{"max_bytes" => 1_200}}] = Registry.list(reg)

    :ok = Registry.update_config("stream-guard", %{"max_bytes" => 500}, reg)

    assert [%{config: %{"max_bytes" => 500}}] = Registry.list(reg)
  end

  test "update_config/2 on an unknown plugin returns an error" do
    reg = start_registry([{ChainExfil, []}])
    assert {:error, :not_found} = Registry.update_config("nope", %{"a" => 1}, reg)
  end

  test "default_config holds the registered config and is unaffected by update_config/2" do
    reg = start_registry([{StreamGuard, config: %{"max_bytes" => 1_200}}])

    :ok = Registry.update_config("stream-guard", %{"max_bytes" => 500}, reg)

    assert [%{config: %{"max_bytes" => 500}, default_config: %{"max_bytes" => 1_200}}] =
             Registry.list(reg)
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

  test "a sidecar declaring :post_call is exposed via active_post_call/1" do
    node = System.find_executable("node") || raise "node not found on PATH"
    sc_name = "sc-#{System.unique_integer([:positive])}"

    reg =
      start_registry([
        {:sidecar, name: sc_name, transport: :stdio, cmd: node, args: [@sidecar_fixture]}
      ])

    assert [%{name: "test-sidecar-scanner", kind: :scanner, impl: {:sidecar, _}}] =
             Registry.active_post_call(reg)

    assert "response.content" in hd(Registry.active_post_call(reg)).data_needs
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

  test "active_post_call/1 lists a :post_call scanner and excludes a pre_call-only policy" do
    reg = start_registry([{ChainExfil, []}, {SecretLeak, []}])

    assert [%{name: "secret-leak", kind: :scanner}] = Registry.active_post_call(reg)

    :ok = Registry.disable("secret-leak", reg)
    assert [] = Registry.active_post_call(reg)
  end

  test "active_chunk/1 lists a :chunk policy and excludes others" do
    reg = start_registry([{ChainExfil, []}, {StreamGuard, config: %{"max_bytes" => 100}}])

    assert [%{name: "stream-guard", kind: :policy}] = Registry.active_chunk(reg)
    assert [] = Registry.active_post_call(reg)

    :ok = Registry.disable("stream-guard", reg)
    assert [] = Registry.active_chunk(reg)
  end

  @wasm_fixture Path.expand("../../../support/fixtures/wasm_echo_scanner.wat", __DIR__)

  test "a wasm spec spawns a runner and registers its capability from the manifest" do
    wasm_name = "wasm-#{System.unique_integer([:positive])}"

    reg =
      start_registry([
        {ChainExfil, []},
        {:wasm, name: wasm_name, path: @wasm_fixture}
      ])

    entry = Enum.find(Registry.list(reg), &(&1.name == "wasm-echo-scanner"))
    assert entry.kind == :scanner
    assert entry.enabled
    assert entry.transport == :wasm
    assert match?({:wasm, _}, entry.impl)
    assert [%{name: "wasm-echo-scanner"}] = Registry.active_scanners(:discovery, reg)
  end

  test "a wasm scanner declaring :post_call is exposed via active_post_call/1" do
    wasm_name = "wasm-#{System.unique_integer([:positive])}"

    reg = start_registry([{:wasm, name: wasm_name, path: @wasm_fixture}])

    assert [%{name: "wasm-echo-scanner", kind: :scanner, impl: {:wasm, _}}] =
             Registry.active_post_call(reg)
  end

  test "a wasm scanner's canBlock is capped by grants: %{block: false}" do
    wasm_name = "wasm-#{System.unique_integer([:positive])}"

    reg = start_registry([{:wasm, name: wasm_name, path: @wasm_fixture, grants: %{block: false}}])

    assert [%{can_block: false}] = Registry.list(reg)
  end

  test "a wasm spec with a missing file is skipped; other plugins still register" do
    reg =
      start_registry([
        {ChainExfil, []},
        {:wasm, name: "broken", path: "/no/such/file.wasm"}
      ])

    names = Enum.map(Registry.list(reg), & &1.name)
    assert "chain-exfil" in names
    refute "broken" in names
  end

  test "seeds an audit_sink plugin enabled and exposes it via active_sinks/1" do
    reg = start_registry([{EventLogSink, []}])

    assert [%{name: "event-log", kind: :audit_sink, enabled: true}] = Registry.list(reg)
    assert [%{name: "event-log"}] = Registry.active_sinks(reg)

    :ok = Registry.disable("event-log", reg)
    assert [] = Registry.active_sinks(reg)
  end
end
