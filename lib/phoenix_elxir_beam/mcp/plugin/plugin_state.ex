defmodule PhoenixElxirBeam.MCP.Plugin.PluginState do
  @moduledoc "Persisted runtime state for one plugin (M3.4b). See `Plugin.StateStore`."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:name, :string, autogenerate: false}
  schema "plugin_states" do
    field :enabled, :boolean, default: true
    field :position, :integer
    field :config, :map
    field :mode, :string

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(state, attrs) do
    state
    |> cast(attrs, [:name, :enabled, :position, :config, :mode])
    |> validate_required([:name])
  end
end
