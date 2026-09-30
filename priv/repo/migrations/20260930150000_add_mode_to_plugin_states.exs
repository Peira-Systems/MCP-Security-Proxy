defmodule PhoenixElxirBeam.Repo.Migrations.AddModeToPluginStates do
  use Ecto.Migration

  def change do
    alter table(:plugin_states) do
      # Per-plugin dry-run override: nil = inherit the global proxy mode,
      # "enforcing" | "dry_run" = pinned regardless of the global switch.
      # See PhoenixElxirBeam.MCP.Plugin.StateStore.
      add :mode, :string
    end
  end
end
