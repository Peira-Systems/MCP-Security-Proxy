defmodule PhoenixElxirBeam.MCP.PolicyEvent do
  @moduledoc """
  Durable, append-only record of a `PhoenixElxirBeam.MCP.Event` — every
  session lifecycle marker and policy verdict PolicyEngine has ever
  produced, persisted so it survives a restart and can be paged through
  and filtered after the fact. Rows are never updated, only inserted.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @statuses ~w(session_start ok blocked session_complete)

  schema "policy_events" do
    field(:event_id, :string)
    field(:session_id, :string)
    field(:scenario, :string)
    field(:server_id, :string)
    field(:tool_name, :string)
    field(:tags, {:array, :string}, default: [])
    field(:status, :string)
    field(:reason, :string)
    field(:occurred_at, :utc_datetime_usec)

    timestamps(updated_at: false, type: :utc_datetime_usec)
  end

  @fields ~w(event_id session_id scenario server_id tool_name tags status reason occurred_at)a

  @doc "Builds an insert changeset from a `PhoenixElxirBeam.MCP.Event` struct."
  def changeset(%__MODULE__{} = event_log, attrs) do
    event_log
    |> cast(attrs, @fields)
    |> validate_required([:event_id, :status, :occurred_at])
    |> validate_inclusion(:status, @statuses)
    |> unique_constraint(:event_id)
  end
end
