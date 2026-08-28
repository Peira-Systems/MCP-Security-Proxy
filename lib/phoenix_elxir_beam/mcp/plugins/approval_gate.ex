defmodule PhoenixElxirBeam.MCP.Plugins.ApprovalGate do
  @moduledoc """
  The human-in-the-loop counterpart to `ChainExfil`: instead of hard-blocking
  network egress after a sensitive read, it returns `verdict: :hold` — the
  proxy parks the call and the dashboard shows an Approve / Deny card.

  No operator action within `timeout_ms` applies `on_timeout` (`:deny`).
  The timeout is `plugin_config["timeout_ms"]` (from the registration
  `config:` block) or 120 s.
  """

  @behaviour PhoenixElxirBeam.MCP.Plugin.Policy

  alias PhoenixElxirBeam.MCP.{CallContext, Decision}
  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @default_timeout_ms 120_000
  @reason "network egress after a sensitive read — needs operator sign-off"

  @impl true
  def manifest do
    Manifest.normalize(%{
      plugin: %{
        name: "approval-gate",
        version: "0.1.0",
        description: "Holds network egress after a sensitive read for operator approval."
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
      Decision.hold(@reason, %{
        prompt: prompt(ctx),
        timeout_ms: Map.get(ctx.plugin_config, "timeout_ms", @default_timeout_ms),
        on_timeout: :deny
      })
    else
      Decision.allow()
    end
  end

  defp prompt(%CallContext{call: call}) do
    tool = call[:tool_name] || "this tool"
    session = call[:session_id] || "?"

    "Approve #{tool} (network egress) for session #{session}? A sensitive read happened earlier in this session."
  end
end
