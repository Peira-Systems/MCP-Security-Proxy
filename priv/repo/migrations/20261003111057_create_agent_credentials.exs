defmodule PhoenixElxirBeam.Repo.Migrations.CreateAgentCredentials do
  use Ecto.Migration

  def change do
    create table(:agent_credentials) do
      add :agent_id, :string, null: false
      add :token_hash, :binary, null: false
      add :description, :string
      add :disabled_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:agent_credentials, [:agent_id])
  end
end
