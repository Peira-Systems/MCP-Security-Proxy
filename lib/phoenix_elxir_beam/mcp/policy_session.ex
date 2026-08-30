defmodule PhoenixElxirBeam.MCP.PolicySession do
  @moduledoc """
  Ecto schema for the durable half of a `PhoenixElxirBeam.MCP.PolicyEngine`
  session — see `PhoenixElxirBeam.MCP.PolicyStore`.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @primary_key {:session_id, :string, autogenerate: false}

  schema "policy_sessions" do
    field :agent_id, :string
    field :tags, {:array, :string}, default: []
    field :taint, {:array, :map}, default: []
    field :call_count, :integer, default: 0

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  def changeset(session, attrs) do
    session
    |> cast(attrs, [:session_id, :agent_id, :tags, :taint, :call_count])
    |> validate_required([:session_id])
  end
end
