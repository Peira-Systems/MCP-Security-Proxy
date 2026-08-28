defmodule PhoenixElxirBeam.MCP.Event do
  @moduledoc """
  A single point-in-time occurrence in an MCP demo session, broadcast by
  `PhoenixElxirBeam.MCP.PolicyEngine` over the `"mcp:events"` PubSub topic.
  """

  @enforce_keys [:id, :session_id, :scenario, :status, :timestamp]
  defstruct [
    :id,
    :session_id,
    :agent_id,
    :scenario,
    :server_id,
    :tool_name,
    :reason,
    :timestamp,
    tags: [],
    status: :ok,
    findings: []
  ]

  @type status :: :session_start | :ok | :blocked | :held | :session_complete

  @type t :: %__MODULE__{
          id: String.t(),
          session_id: String.t(),
          agent_id: String.t() | nil,
          scenario: atom(),
          server_id: String.t() | nil,
          tool_name: String.t() | nil,
          tags: [atom()],
          status: status(),
          reason: String.t() | nil,
          timestamp: DateTime.t(),
          findings: [map()]
        }
end
