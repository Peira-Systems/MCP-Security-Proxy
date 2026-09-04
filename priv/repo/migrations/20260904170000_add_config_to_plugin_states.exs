defmodule PhoenixElxirBeam.Repo.Migrations.AddConfigToPluginStates do
  use Ecto.Migration

  def change do
    alter table(:plugin_states) do
      # Operator-edited config override from the dashboard (nil = no
      # override, use the compile-time default from config/*.exs) — see
      # PhoenixElxirBeam.MCP.Plugin.StateStore.
      add :config, :map
    end
  end
end
