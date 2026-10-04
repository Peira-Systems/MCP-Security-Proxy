defmodule PhoenixElxirBeam.Repo.Migrations.AddAuthSourceToUsers do
  use Ecto.Migration

  def change do
    alter table(:users) do
      add :auth_source, :string, null: false, default: "local"
    end
  end
end
