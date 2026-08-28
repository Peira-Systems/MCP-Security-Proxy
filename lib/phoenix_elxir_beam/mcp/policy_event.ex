defmodule PhoenixElxirBeam.MCP.PolicyEvent do
  @moduledoc """
  Durable, append-only record of a `PhoenixElxirBeam.MCP.AuditEvent` — every
  session lifecycle marker and policy verdict PolicyEngine has ever
  produced, persisted so it survives a restart and can be paged through
  and filtered after the fact.

  Rows are never updated, only inserted, and they form a **hash chain**:
  each row's `hash` is `sha256(prev_hash <> canonical(row))`, so deleting or
  altering any row breaks every row after it (`EventLog.verify_chain/0`).
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
    field(:prev_hash, :string)
    field(:hash, :string)
    field(:decisions, {:array, :map}, default: [])
    field(:findings, {:array, :map}, default: [])

    timestamps(updated_at: false, type: :utc_datetime_usec)
  end

  @fields ~w(event_id session_id scenario server_id tool_name tags status reason
             occurred_at prev_hash hash decisions findings)a

  @doc "Builds an insert changeset from a `PhoenixElxirBeam.MCP.AuditEvent` (via `EventLog`)."
  def changeset(%__MODULE__{} = event_log, attrs) do
    event_log
    |> cast(attrs, @fields)
    |> validate_required([:event_id, :status, :occurred_at, :hash])
    |> validate_inclusion(:status, @statuses)
    |> unique_constraint(:event_id)
  end
end
