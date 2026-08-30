defmodule PhoenixElxirBeam.Repo.Migrations.CreatePolicySessions do
  use Ecto.Migration

  def change do
    create table(:policy_sessions, primary_key: false) do
      # The proxy `mcp-session-id`. PolicyEngine keeps an in-memory cache;
      # this row is the source of truth so a `tools/call` decision still
      # sees the session's accumulated tags + taint after a restart.
      add :session_id, :string, primary_key: true
      add :agent_id, :string
      add :tags, {:array, :string}, null: false, default: []
      # Taint provenance — the raw `secret` field is stripped before it is
      # written here (it stays in the process's memory only).
      add :taint, {:array, :map}, null: false, default: []
      add :call_count, :integer, null: false, default: 0

      timestamps(type: :utc_datetime_usec)
    end

    # The periodic sweep deletes rows whose session has been idle too long.
    create index(:policy_sessions, [:updated_at])
  end
end
