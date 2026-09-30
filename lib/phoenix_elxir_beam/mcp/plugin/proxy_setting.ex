defmodule PhoenixElxirBeam.MCP.Plugin.ProxySetting do
  @moduledoc "Persisted proxy-wide dashboard settings (single row). See `Plugin.StateStore`."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:key, :string, autogenerate: false}
  schema "proxy_settings" do
    field :mode, :string, default: "enforcing"

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(setting, attrs) do
    setting
    |> cast(attrs, [:key, :mode])
    |> validate_required([:key, :mode])
  end
end
