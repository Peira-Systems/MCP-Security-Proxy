defmodule PhoenixElxirBeam.MCP.Plugin.Policy do
  @moduledoc """
  Behaviour for a `policy` plugin: decides whether a `tools/call` may
  proceed. Invoked by `PhoenixElxirBeam.MCP.Pipeline` in the `pre_call`
  (and, later, `post_call`) phase, in the operator-configured order, with
  short-circuit on the first `:deny`.

  This is the only capability that can block a call by default. See
  `docs/plugin-protocol.md` §4.1 and §13.
  """

  alias PhoenixElxirBeam.MCP.{CallContext, Decision}
  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @doc "Static self-description. Must be pure — called at registration."
  @callback manifest() :: Manifest.t()

  @doc """
  Returns a `Decision` for the call snapshotted in `ctx`. Must be
  side-effect free and must respect the manifest's `timeout_ms`; the
  pipeline enforces the deadline regardless.
  """
  @callback evaluate(phase :: :pre_call | :post_call, ctx :: CallContext.t()) :: Decision.t()
end
