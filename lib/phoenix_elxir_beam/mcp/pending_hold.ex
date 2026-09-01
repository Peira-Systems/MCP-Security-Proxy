defmodule PhoenixElxirBeam.MCP.PendingHold do
  @moduledoc """
  Ecto schema for a not-yet-resolved `PhoenixElxirBeam.MCP.HoldRegistry`
  hold — see `PhoenixElxirBeam.MCP.HoldStore`.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @primary_key {:hold_id, :string, autogenerate: false}

  schema "pending_holds" do
    field :session_id, :string
    field :server_id, :string
    field :tool_name, :string
    field :tags, {:array, :string}, default: []
    field :prompt, :string
    field :reason, :string
    field :timeout_ms, :integer
    field :on_timeout, :string

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  @type t :: %__MODULE__{}

  @fields ~w(hold_id session_id server_id tool_name tags prompt reason timeout_ms on_timeout)a

  def changeset(hold, attrs) do
    hold
    |> cast(attrs, @fields)
    |> validate_required([:hold_id, :timeout_ms, :on_timeout])
  end
end
