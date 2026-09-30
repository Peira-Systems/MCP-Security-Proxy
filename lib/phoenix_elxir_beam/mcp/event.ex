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

  @type status ::
          :session_start
          | :ok
          | :blocked
          | :held
          # `:shadow_blocked` / `:shadow_held` — the plugin pipeline computed a
          # real `:deny` / `:hold`, but its effective mode was `:dry_run`, so
          # the call proceeded like an allow. `reason` carries what it would
          # have been. See `PhoenixElxirBeam.MCP.Decision.shadow_verdict`.
          | :shadow_blocked
          | :shadow_held
          | :session_complete
          | :policy_change

  @type t :: %__MODULE__{
          id: String.t(),
          session_id: String.t() | nil,
          agent_id: String.t() | nil,
          scenario: atom() | nil,
          server_id: String.t() | nil,
          tool_name: String.t() | nil,
          tags: [atom()],
          status: status(),
          reason: String.t() | nil,
          timestamp: DateTime.t(),
          findings: [map()]
        }
end
