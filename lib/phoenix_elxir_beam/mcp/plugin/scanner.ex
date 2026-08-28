defmodule PhoenixElxirBeam.MCP.Plugin.Scanner do
  @moduledoc """
  Behaviour for a `scanner` plugin: inspects text — tool descriptions
  (`discovery`), call arguments (`pre_call`), tool responses (`post_call`) —
  and returns `PhoenixElxirBeam.MCP.Finding`s. Advisory by default; a scanner
  opts into blocking with `can_block: true` in its manifest, which the
  operator must still enable.

  Defined now for the contract's completeness (`docs/plugin-protocol.md`
  §4.2 / §13). The first implementation is the rug-pull / tool-drift scanner
  (roadmap step 3); `PhoenixElxirBeam.MCP.Pipeline` does not invoke scanners
  yet.
  """

  alias PhoenixElxirBeam.MCP.{CallContext, Decision, Finding}
  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @callback manifest() :: Manifest.t()

  @callback scan(phase :: :discovery | :pre_call | :post_call, ctx :: CallContext.t()) ::
              {:ok, [Finding.t()]} | {:ok, [Finding.t()], Decision.t()}
end
