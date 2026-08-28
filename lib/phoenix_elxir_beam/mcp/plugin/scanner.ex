defmodule PhoenixElxirBeam.MCP.Plugin.Scanner do
  @moduledoc """
  Behaviour for a `scanner` plugin: inspects text — tool descriptions
  (`discovery`), call arguments (`pre_call`), tool responses (`post_call`) —
  and returns `PhoenixElxirBeam.MCP.Finding`s. Advisory by default; a scanner
  opts into blocking with `can_block: true` in its manifest, which the
  operator must still enable.

  `docs/plugin-protocol.md` §4.2 / §9.1 / §13. `PhoenixElxirBeam.MCP.Pipeline`
  runs `:discovery` scanners (`run_discovery/2`); `:pre_call` / `:post_call`
  scanner invocation lands in a later roadmap step.
  """

  alias PhoenixElxirBeam.MCP.{CallContext, Decision, Finding}
  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @typedoc """
  A per-tool action a `:discovery` scanner proposes. `quarantine: true` holds
  the tool until an operator clears it; `add_tags` is unioned onto the tool's
  operator-assigned tags.
  """
  @type tool_update :: %{
          required(:name) => String.t(),
          optional(:quarantine) => boolean(),
          optional(:add_tags) => [atom()],
          optional(:reason) => String.t()
        }

  @callback manifest() :: Manifest.t()

  @callback scan(:discovery, ctx :: CallContext.t()) :: {:ok, [Finding.t()], [tool_update()]}

  @callback scan(:pre_call | :post_call, ctx :: CallContext.t()) ::
              {:ok, [Finding.t()]} | {:ok, [Finding.t()], Decision.t()}
end
