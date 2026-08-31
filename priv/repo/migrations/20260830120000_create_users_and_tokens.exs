defmodule PhoenixElxirBeam.Repo.Migrations.CreateUsersAndTokens do
  use Ecto.Migration

  def change do
    create table(:users) do
      # Stored lower-cased; a functional unique index enforces case-insensitive
      # uniqueness without requiring the citext extension.
      add :email, :string, null: false
      add :hashed_password, :string, null: false
      # viewer < operator < admin — see PhoenixElxirBeam.MCP.Accounts.
      add :role, :string, null: false, default: "viewer"
      add :disabled_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:users, ["lower(email)"], name: :users_email_index)

    create table(:user_tokens) do
      add :user_id, references(:users, on_delete: :delete_all), null: false
      add :token, :binary, null: false
      add :context, :string, null: false
      add :inserted_at, :utc_datetime_usec, null: false
    end

    create index(:user_tokens, [:user_id])
    create unique_index(:user_tokens, [:context, :token])
  end
end
