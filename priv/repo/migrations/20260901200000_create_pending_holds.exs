defmodule PhoenixElxirBeam.Repo.Migrations.CreatePendingHolds do
  use Ecto.Migration

  def change do
    create table(:pending_holds, primary_key: false) do
      # HoldRegistry's generated id ("hold-<hex>"). A row here means the
      # hold has not yet reached a terminal outcome -- resolve/1 deletes it
      # once one has, so this table only ever holds currently-open holds
      # (bounded by concurrent held calls, not total historical volume).
      # Anything still here at boot is a leftover from a previous process
      # lifetime that never resolved (see HoldRegistry.reap_orphans/0).
      add :hold_id, :string, primary_key: true
      add :session_id, :string
      add :server_id, :string
      add :tool_name, :string
      add :tags, {:array, :string}, null: false, default: []
      add :prompt, :text
      add :reason, :text
      add :timeout_ms, :integer, null: false
      add :on_timeout, :string, null: false

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end
  end
end
