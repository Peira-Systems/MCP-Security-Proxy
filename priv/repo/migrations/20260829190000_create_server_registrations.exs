defmodule PhoenixElxirBeam.Repo.Migrations.CreateServerRegistrations do
  use Ecto.Migration

  def change do
    create table(:server_registrations, primary_key: false) do
      add :id, :string, primary_key: true
      add :name, :string, null: false
      add :transport, :string, null: false

      # :http
      add :base_url, :string

      # :stdio
      add :command, :string
      add :args, {:array, :string}, null: false, default: []
      add :command_label, :string

      # Operator + scanner overlay carried across a re-handshake / restart,
      # keyed by tool name: %{"tool" => %{"tags", "quarantined",
      # "quarantine_reason", "hash"}}. Fresh tool descriptions / schemas come
      # from the live handshake on boot; only this overlay is persisted.
      add :tool_state, :map, null: false, default: %{}

      timestamps(type: :utc_datetime_usec)
    end
  end
end
