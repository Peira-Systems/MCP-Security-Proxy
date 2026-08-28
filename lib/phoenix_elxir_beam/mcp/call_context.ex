defmodule PhoenixElxirBeam.MCP.CallContext do
  @moduledoc """
  The serialized snapshot of a `tools/call` (or a discovery pass) the proxy
  hands to a plugin — the in-process representation of the protocol
  `CallContext` (`docs/plugin-protocol.md` §7.1).

  The proxy owns canonical session state; a `CallContext` is a read-only view
  of it at one instant. Fields the current caller has no data for are left
  `nil`. Today `PhoenixElxirBeam.MCP.PolicyEngine` populates `phase`, `call`,
  and `session.seen_tags`; `call.arguments`, `tool`, and `response` are
  threaded in by later roadmap steps (scanners, post_call).
  """

  @enforce_keys [:phase, :call]
  defstruct phase: nil,
            call: %{},
            tool: nil,
            session: %{seen_tags: [], taint: %{sources: []}, calls_so_far: 0, findings_so_far: []},
            response: nil,
            plugin_config: %{}

  @type phase :: :discovery | :pre_call | :post_call

  @type t :: %__MODULE__{
          phase: phase(),
          call: map(),
          tool: map() | nil,
          session: map(),
          response: map() | nil,
          plugin_config: map()
        }

  @default_session %{seen_tags: [], taint: %{sources: []}, calls_so_far: 0, findings_so_far: []}

  @doc """
  Builds a context from a map. `:phase` and `:call` are required; `:session`
  is merged onto sane defaults so plugins can read `ctx.session.seen_tags`
  unconditionally.
  """
  @spec new(map()) :: t()
  def new(%{phase: phase, call: call} = attrs) do
    %__MODULE__{
      phase: phase,
      call: call,
      tool: Map.get(attrs, :tool),
      session: Map.merge(@default_session, Map.get(attrs, :session, %{})),
      response: Map.get(attrs, :response),
      plugin_config: Map.get(attrs, :plugin_config, %{})
    }
  end

  @doc """
  Returns the context with `tags` unioned into `session.seen_tags` — how the
  pipeline applies a granted `add_tags` mutation so later plugins in the chain
  observe it.
  """
  @spec put_session_tags(t(), [atom()]) :: t()
  def put_session_tags(%__MODULE__{session: session} = ctx, tags) when is_list(tags) do
    merged = Enum.uniq(Map.get(session, :seen_tags, []) ++ tags)
    %{ctx | session: %{session | seen_tags: merged}}
  end

  @doc "The tags carried by the call currently under evaluation."
  @spec call_tags(t()) :: [atom()]
  def call_tags(%__MODULE__{call: call}), do: Map.get(call, :tags, [])
end
