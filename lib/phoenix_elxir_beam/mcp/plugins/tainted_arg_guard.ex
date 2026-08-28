defmodule PhoenixElxirBeam.MCP.Plugins.TaintedArgGuard do
  @moduledoc """
  Byte-level taint: blocks a `tools/call` whose **arguments** contain a
  secret that a `post_call` scanner saw earlier in the same session
  (`PhoenixElxirBeam.MCP.Plugins.SecretLeak` records the raw match in the
  session's `taint.sources`, in memory only).

  Where `PhoenixElxirBeam.MCP.Plugins.TaintGuard` is coarse — *any* egress
  once *any* secret has flowed — this is exact: it only fires when the
  specific secret bytes reappear in an outbound call. It is scoped to no
  tags, so it inspects every call's arguments, not just egress-tagged ones.
  """

  @behaviour PhoenixElxirBeam.MCP.Plugin.Policy

  alias PhoenixElxirBeam.MCP.{CallContext, Decision, Finding}
  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @version "0.1.0"

  @impl true
  def manifest do
    Manifest.normalize(%{
      plugin: %{
        name: "tainted-arg-guard",
        version: @version,
        description: "Blocks a call whose arguments carry a secret read earlier this session."
      },
      capabilities: %{
        policy: %{
          phases: [:pre_call],
          data_needs: ["call.arguments", "session.taint"],
          timeout_ms: 50,
          fail_mode: :fail_closed
        }
      }
    })
  end

  @impl true
  def evaluate(:pre_call, %CallContext{} = ctx) do
    haystack = stringify(ctx.call[:arguments])

    ctx
    |> tracked_secrets()
    |> Enum.find(fn %{secret: s} -> s != "" and String.contains?(haystack, s) end)
    |> case do
      nil -> Decision.allow()
      source -> deny(source)
    end
  end

  defp tracked_secrets(%CallContext{session: session}) do
    session
    |> get_in([:taint, :sources])
    |> List.wrap()
    |> Enum.filter(&is_binary(&1[:secret]))
  end

  defp deny(%{origin_tool: origin} = source) do
    reason =
      "call blocked: an argument contains a secret this session read earlier via #{origin || "another tool"}"

    finding =
      Finding.new(%{
        type: "tainted_argument",
        severity: :critical,
        title: "outbound argument carries a tracked secret (#{source[:hint] || "‹secret›"})",
        plugin: %{name: "tainted-arg-guard", version: @version}
      })

    %{Decision.deny(:critical, reason) | findings: [finding]}
  end

  defp stringify(nil), do: ""
  defp stringify(bin) when is_binary(bin), do: bin

  defp stringify(term) do
    case Jason.encode(term) do
      {:ok, json} -> json
      _ -> inspect(term)
    end
  end
end
