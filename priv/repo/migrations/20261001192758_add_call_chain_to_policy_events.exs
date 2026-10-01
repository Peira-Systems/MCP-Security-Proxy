defmodule PhoenixElxirBeam.Repo.Migrations.AddCallChainToPolicyEvents do
  use Ecto.Migration

  def change do
    alter table(:policy_events) do
      add :call_chain, {:array, :map}, default: []
    end
  end
end
