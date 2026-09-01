defmodule PhoenixElxirBeam.MCP.ServerRegistration do
  @moduledoc """
  Ecto schema for a persisted `PhoenixElxirBeam.MCP.ServerRegistry` entry —
  see `PhoenixElxirBeam.MCP.ServerStore`.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @primary_key {:id, :string, autogenerate: false}

  schema "server_registrations" do
    field :name, :string
    field :transport, :string
    field :base_url, :string
    field :command, :string
    field :args, {:array, :string}, default: []
    field :command_label, :string
    field :tool_state, :map, default: %{}
    # Per-server overrides of the global receive-timeout / TLS-verify
    # defaults (M1.5 follow-up). nil = inherit the proxy-wide default; only
    # meaningful for :http (:stdio makes no HTTP calls).
    field :timeout_ms, :integer
    field :tls_verify, :boolean

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  def changeset(reg, attrs) do
    reg
    |> cast(attrs, [
      :id,
      :name,
      :transport,
      :base_url,
      :command,
      :args,
      :command_label,
      :tool_state,
      :timeout_ms,
      :tls_verify
    ])
    |> validate_required([:id, :name, :transport])
    |> validate_inclusion(:transport, ["http", "stdio"])
    |> validate_number(:timeout_ms, greater_than: 0)
  end
end
