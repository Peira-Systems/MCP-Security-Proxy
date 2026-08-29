defmodule PhoenixElxirBeam.MCP.MethodPolicy do
  @moduledoc """
  The single place every non-handshake MCP method's disposition is decided.
  `PhoenixElxirBeamWeb.MCP.ProxyController` consults `disposition/1` rather
  than falling methods through a `case` — an unlisted method is refused, not
  silently forwarded (default-deny for the protocol surface).

  Dispositions:

    * `:police` — run the full `pre_call` policy pipeline, then forward and
      scan the response (`tools/call`).
    * `:scan_response` — forward untouched, then run the `post_call` content
      scan over the reply and apply redactions / accumulate taint. For
      methods whose result carries model- or user-facing text that is an
      injection surface and a taint source (`resources/read`, `prompts/get`).
    * `:forward` — pass through untouched. Metadata-only reads and controls
      with no content payload to police (`tools/list`, `resources/list`,
      `completion/complete`, `logging/setLevel`, …).
    * `:refuse` — reject with JSON-RPC `-32601`. Server→client methods the
      proxy does not mediate yet (`sampling/createMessage`, `roots/list`,
      `elicitation/create`) and every unknown method.
    * `:ack` — accept with `202` and do not forward. Client notifications
      (`notifications/*`); per-notification routing is a later milestone.

  `initialize`, `notifications/initialized`, and `ping` are handled directly
  by the controller before this table is consulted.
  """

  @dispositions %{
    "tools/call" => :police,
    "tools/list" => :forward,
    "resources/list" => :forward,
    "resources/templates/list" => :forward,
    "resources/read" => :scan_response,
    "resources/subscribe" => :forward,
    "resources/unsubscribe" => :forward,
    "prompts/list" => :forward,
    "prompts/get" => :scan_response,
    "completion/complete" => :forward,
    "logging/setLevel" => :forward,
    # Server→client requests. Reaching the proxy as an inbound method means a
    # server is relaying one (or a client is misbehaving); the proxy does not
    # mediate these yet, so refuse rather than blindly pass an
    # inference / filesystem-root request through.
    "sampling/createMessage" => :refuse,
    "elicitation/create" => :refuse,
    "roots/list" => :refuse
  }

  @type disposition :: :police | :scan_response | :forward | :refuse | :ack

  @doc "The disposition for `method`. Unknown methods are refused."
  @spec disposition(String.t() | nil) :: disposition()
  def disposition(method) when is_map_key(@dispositions, method), do: @dispositions[method]

  def disposition("notifications/" <> _), do: :ack

  def disposition(_method), do: :refuse

  @doc "Every method with an explicit table entry (for enumeration in tests)."
  @spec known_methods() :: [String.t()]
  def known_methods, do: Map.keys(@dispositions)
end
