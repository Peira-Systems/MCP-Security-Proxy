defmodule PhoenixElxirBeam.MCP.Plugins.ChainExfil do
  @moduledoc """
  The demo's original tool-chaining rule, now a `policy` plugin: a call
  tagged `:network_egress` is denied iff a `:sensitive_read` occurred
  earlier in the same session. Order matters — an egress before any
  sensitive read is allowed.

  The manifest's `tool_tags: [:network_egress]` means the pipeline only
  consults this plugin for egress-tagged calls, so `evaluate/2` just has to
  check whether the session is already tainted.
  """

  @behaviour PhoenixElxirBeam.MCP.Plugin.Policy

  alias PhoenixElxirBeam.MCP.{CallContext, Decision}
  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @block_reason "network egress blocked: a sensitive read occurred earlier in this session"

  @doc "The reason string surfaced on a block — kept public for the dashboard narrative."
  def block_reason, do: @block_reason

  @impl true
  def manifest do
    Manifest.normalize(%{
      plugin: %{
        name: "chain-exfil",
        version: "0.1.0",
        description: "Blocks network egress after a sensitive read in the same session."
      },
      capabilities: %{
        policy: %{
          phases: [:pre_call],
          tool_tags: [:network_egress],
          data_needs: ["session.seenTags"],
          timeout_ms: 50,
          fail_mode: :fail_closed
        }
      }
    })
  end

  @impl true
  def evaluate(:pre_call, %CallContext{} = ctx) do
    if :sensitive_read in ctx.session.seen_tags do
      Decision.deny(:high, @block_reason)
    else
      Decision.allow()
    end
  end
end
