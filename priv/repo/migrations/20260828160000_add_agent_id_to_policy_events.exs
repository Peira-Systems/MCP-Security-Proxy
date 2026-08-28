defmodule PhoenixElxirBeam.Repo.Migrations.AddAgentIdToPolicyEvents do
  use Ecto.Migration

  def change do
    alter table(:policy_events) do
      add :agent_id, :string
    end
  end
end
