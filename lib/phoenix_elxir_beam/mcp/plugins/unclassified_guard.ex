defmodule PhoenixElxirBeam.MCP.Plugins.UnclassifiedGuard do
  @moduledoc """
  Default-deny for unclassified tools (M4.2).

  A freshly discovered tool starts with **no operator tags**, so every
  tag-scoped policy (`ChainExfil`, `TaintGuard`, `ApprovalGate`, …) is inert on
  it. Without this plugin an operator who hasn't curated tags has, in effect,
  an allow-all proxy.

  When enabled, a `tools/call` to a tool the operator has not tagged is:

    * `"deny"` — refused with a `-32001` error, or
    * `"hold"` — parked for operator sign-off (they can classify then approve).

  Config (`plugin_config`):

      {PhoenixElxirBeam.MCP.Plugins.UnclassifiedGuard, config: %{"mode" => "hold"}}

  `mode` ∈ `"off"` (default) | `"deny"` | `"hold"`. `off` makes the plugin a
  no-op so it can ship enabled-but-inert and be flipped on from config / a
  future runtime toggle.
  """

  @behaviour PhoenixElxirBeam.MCP.Plugin.Policy

  alias PhoenixElxirBeam.MCP.{CallContext, Decision, Finding}
  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @version "0.1.0"

  @impl true
  def manifest do
    Manifest.normalize(%{
      plugin: %{
        name: "unclassified-guard",
        version: @version,
        description: "Denies or holds a call to a tool the operator has not tagged."
      },
      capabilities: %{
        policy: %{
          # Runs on every call (tool_tags: []) — the point is the *absence* of tags.
          phases: [:pre_call],
          tool_tags: [],
          data_needs: ["call.tags"],
          timeout_ms: 50,
          fail_mode: :fail_closed
        }
      }
    })
  end

  @impl true
  def evaluate(:pre_call, %CallContext{} = ctx) do
    mode = (ctx.plugin_config || %{})["mode"] || "off"

    if mode != "off" and CallContext.call_tags(ctx) == [] do
      act(mode, ctx)
    else
      Decision.allow()
    end
  end

  defp act("deny", ctx) do
    %{
      Decision.deny(:high, reason(ctx))
      | findings: [finding(ctx)]
    }
  end

  defp act("hold", ctx) do
    %{
      Decision.hold(reason(ctx), %{
        prompt: "Classify #{tool(ctx)} then approve, or deny.",
        timeout_ms: 5 * 60_000,
        on_timeout: :deny
      })
      | findings: [finding(ctx)]
    }
  end

  defp act(_unknown, _ctx), do: Decision.allow()

  defp reason(ctx) do
    "default-deny: #{tool(ctx)} has no operator classification"
  end

  defp finding(ctx) do
    Finding.new(%{
      type: "unclassified_tool",
      severity: :medium,
      title: "call to unclassified tool #{tool(ctx)}",
      plugin: %{name: "unclassified-guard", version: @version}
    })
  end

  defp tool(%CallContext{call: call}), do: call[:tool_name] || call["toolName"] || "a tool"
end
