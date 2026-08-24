defmodule PhoenixElxirBeam.Repo.Migrations.CreatePolicyEvents do
  use Ecto.Migration

  def change do
    create table(:policy_events) do
      add :event_id, :string, null: false
      add :session_id, :string
      add :scenario, :string
      add :server_id, :string
      add :tool_name, :string
      add :tags, {:array, :string}, null: false, default: []
      add :status, :string, null: false
      add :reason, :text
      add :occurred_at, :utc_datetime_usec, null: false

      timestamps(updated_at: false, type: :utc_datetime_usec)
    end

    # Append-only log: reads filter by time range, status, and server, so
    # each gets its own index rather than one wide composite — status and
    # server_id are low-cardinality and get combined with the time range
    # via index intersection, which SQLite's query planner handles fine at
    # this scale.
    create index(:policy_events, [:occurred_at])
    create index(:policy_events, [:status])
    create index(:policy_events, [:server_id])
    create unique_index(:policy_events, [:event_id])
  end
end
