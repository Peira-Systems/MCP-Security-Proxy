defmodule PhoenixElxirBeam.MCP.Session do
  @moduledoc """
  A proxy-owned MCP session: the binding between one downstream client's
  `initialize` handshake and the registered upstream server it is talking to.

  The `id` is minted by the proxy (`PhoenixElxirBeam.MCP.SessionStore`) and
  handed back to the client in the `mcp-session-id` response header on the
  `initialize` reply. The client echoes it on every subsequent request; the
  proxy never trusts a client-supplied session id it did not mint.

  `state` is `:initializing` between the `initialize` reply and the client's
  `notifications/initialized`, then `:ready`. Non-handshake methods
  (`tools/call`, …) are refused until `:ready`.
  """

  @enforce_keys [:id, :server_id, :state, :protocol_version, :created_at, :last_seen_at]
  defstruct [
    :id,
    :server_id,
    :agent_id,
    :client_info,
    :protocol_version,
    :state,
    :created_at,
    :last_seen_at,
    # Monotonic access counter maintained by the store; used for
    # least-recently-seen eviction without depending on wall-clock resolution.
    seq: 0
  ]

  @type state :: :initializing | :ready

  @type t :: %__MODULE__{
          id: String.t(),
          server_id: String.t(),
          agent_id: String.t() | nil,
          client_info: map() | nil,
          protocol_version: String.t(),
          state: state(),
          created_at: DateTime.t(),
          last_seen_at: DateTime.t(),
          seq: non_neg_integer()
        }
end
