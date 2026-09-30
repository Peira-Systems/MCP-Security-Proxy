defmodule PhoenixElxirBeam.Repo.Migrations.CreateProxySettings do
  use Ecto.Migration

  def change do
    # A single row (key "global") holding proxy-wide, dashboard-editable
    # settings — currently just the dry-run mode switch. See
    # PhoenixElxirBeam.MCP.Plugin.StateStore.
    create table(:proxy_settings, primary_key: false) do
      add :key, :string, primary_key: true
      add :mode, :string, null: false, default: "enforcing"

      timestamps(type: :utc_datetime_usec)
    end
  end
end
