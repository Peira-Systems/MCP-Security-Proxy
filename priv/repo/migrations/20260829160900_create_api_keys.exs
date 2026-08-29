defmodule PhoenixElxirBeam.Repo.Migrations.CreateApiKeys do
  use Ecto.Migration

  def change do
    create table(:api_keys) do
      # `key_id` is the public half of the token (`mcpk_<hex>`); `token_hash`
      # is sha256 of the secret half. The secret is shown once at issuance
      # and never stored.
      add :key_id, :string, null: false
      add :token_hash, :binary, null: false

      # who this key authenticates as
      add :principal, :string, null: false
      add :agent_id, :string, null: false
      add :description, :string

      # which registered servers this key may reach
      add :all_servers, :boolean, null: false, default: false
      add :granted_server_ids, {:array, :string}, null: false, default: []

      add :disabled_at, :utc_datetime_usec
      add :last_used_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:api_keys, [:key_id])
  end
end
