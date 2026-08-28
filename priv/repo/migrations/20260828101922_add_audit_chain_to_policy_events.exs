defmodule PhoenixElxirBeam.Repo.Migrations.AddAuditChainToPolicyEvents do
  use Ecto.Migration

  def change do
    alter table(:policy_events) do
      # Tamper-evident hash chain: hash = sha256(prev_hash <> canonical(row)).
      add :prev_hash, :string
      add :hash, :string

      # Pipeline provenance carried from PhoenixElxirBeam.MCP.AuditEvent:
      # which plugin returned which verdict, and any scanner findings.
      add :decisions, {:array, :map}, null: false, default: []
      add :findings, {:array, :map}, null: false, default: []
    end

    create index(:policy_events, [:hash])
  end
end
