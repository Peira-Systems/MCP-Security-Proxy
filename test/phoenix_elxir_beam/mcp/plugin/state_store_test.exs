defmodule PhoenixElxirBeam.MCP.Plugin.StateStoreTest do
  use PhoenixElxirBeam.DataCase, async: true

  alias PhoenixElxirBeam.MCP.Plugin.StateStore

  test "put_mode/2 persists a plugin's dry-run override, visible via all/0" do
    :ok = StateStore.put_mode("chain-exfil", "dry_run")

    assert %{"chain-exfil" => %{mode: "dry_run"}} = StateStore.all()
  end

  test "a plugin with no mode override has mode: nil in all/0" do
    :ok = StateStore.put_enabled("chain-exfil", false)

    assert %{"chain-exfil" => %{mode: nil}} = StateStore.all()
  end

  test "put_mode/2 can be cleared back to nil (inherit)" do
    :ok = StateStore.put_mode("chain-exfil", "dry_run")
    :ok = StateStore.put_mode("chain-exfil", nil)

    assert %{"chain-exfil" => %{mode: nil}} = StateStore.all()
  end

  test "proxy_mode/0 defaults to :enforcing when no row exists yet" do
    assert StateStore.proxy_mode() == :enforcing
  end

  test "put_proxy_mode/1 persists the global mode, read back by proxy_mode/0" do
    :ok = StateStore.put_proxy_mode(:dry_run)

    assert StateStore.proxy_mode() == :dry_run
  end

  test "put_proxy_mode/1 is idempotent across repeated writes" do
    :ok = StateStore.put_proxy_mode(:dry_run)
    :ok = StateStore.put_proxy_mode(:enforcing)

    assert StateStore.proxy_mode() == :enforcing
  end
end
