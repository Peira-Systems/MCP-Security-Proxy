defmodule PhoenixElxirBeam.Repo.Migrations.CreatePluginStates do
  use Ecto.Migration

  def change do
    create table(:plugin_states, primary_key: false) do
      # Plugin `name` from the manifest — the stable identity across restarts.
      add :name, :string, primary_key: true
      add :enabled, :boolean, null: false, default: true
      # Position in the pipeline; nil = keep the config-declared slot.
      add :position, :integer

      timestamps(type: :utc_datetime_usec)
    end
  end
end
