defmodule PhoenixElxirBeam.MCP.PluginStatePersistenceTest do
  # async: false — drives the singleton Plugin.Registry (persist? = true) and
  # needs the shared sandbox connection.
  use PhoenixElxirBeam.DataCase, async: false

  alias PhoenixElxirBeam.MCP.Plugin.{Registry, StateStore}

  setup do
    Ecto.Adapters.SQL.Sandbox.mode(PhoenixElxirBeam.Repo, {:shared, self()})

    original = Enum.map(Registry.list(), &{&1.name, &1.enabled})

    on_exit(fn ->
      # Sandbox rolls back the rows; also restore the live ETS registry so the
      # rest of the suite sees the config defaults.
      for {name, enabled} <- original do
        if enabled, do: Registry.enable(name), else: Registry.disable(name)
      end

      Registry.reorder(Enum.map(original, &elem(&1, 0)))
    end)

    %{original_names: Enum.map(original, &elem(&1, 0))}
  end

  test "disable is written through to Postgres", %{original_names: [name | _]} do
    :ok = Registry.disable(name)

    assert %{^name => %{enabled: false}} = StateStore.all()
    refute Enum.find(Registry.list(), &(&1.name == name)).enabled
  end

  test "reorder is written through to Postgres", %{original_names: names} do
    reordered = tl(names) ++ [hd(names)]
    :ok = Registry.reorder(reordered)

    stored = StateStore.all()
    assert stored[hd(reordered)].position == 0
    assert Enum.map(Registry.list(), & &1.name) == reordered
  end

  test "a named (test) registry does not touch the store" do
    reg = :"reg_#{System.unique_integer([:positive])}"

    start_supervised!(
      {Registry, name: reg, plugins: [{PhoenixElxirBeam.MCP.Plugins.ChainExfil, []}]},
      id: reg
    )

    before = StateStore.all()
    :ok = Registry.disable("chain-exfil", reg)
    assert StateStore.all() == before
  end
end
