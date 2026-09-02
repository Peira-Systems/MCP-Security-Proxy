defmodule PhoenixElxirBeam.MCP.Plugins.TaintedArgGuard do
  @moduledoc """
  Marker-level taint: blocks a `tools/call` whose **arguments** carry a
  secret that a `post_call` scanner saw earlier in the same session.
  `PhoenixElxirBeam.MCP.Plugins.SecretLeak` records HMAC **taint markers**
  (`PhoenixElxirBeam.MCP.TaintMarker`) for the secret and its common
  encodings; this plugin tokenises the outbound arguments, marks each token
  and its plausible decodings, and denies on any collision — so a base64- or
  hex-encoded copy of the secret is caught, not just the raw bytes.

  Where `PhoenixElxirBeam.MCP.Plugins.TaintGuard` is coarse — *any* egress
  once *any* secret has flowed — this is targeted, and scoped to no tags so
  it inspects every call's arguments, not just egress-tagged ones.
  """

  @behaviour PhoenixElxirBeam.MCP.Plugin.Policy

  alias PhoenixElxirBeam.MCP.{CallContext, Decision, Finding, TaintMarker}
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
    session_id = ctx.call[:session_id] || ctx.call["sessionId"]
    candidates = TaintMarker.candidate_markers(session_id, ctx.call[:arguments])

    ctx
    |> tracked_sources()
    |> Enum.find(fn src ->
      src |> markers_of() |> Enum.any?(&MapSet.member?(candidates, &1))
    end)
    |> case do
      nil -> Decision.allow()
      source -> deny(source)
    end
  end

  defp tracked_sources(%CallContext{session: session}) do
    session |> get_in([:taint, :sources]) |> List.wrap()
  end

  defp markers_of(source) do
    (source[:markers] || source["markers"] || []) |> List.wrap()
  end

  defp deny(source) do
    origin = source[:origin_tool] || source["origin_tool"] || "another tool"
    hint = source[:hint] || source["hint"] || "‹secret›"

    reason =
      "call blocked: an argument carries a secret this session read earlier via #{origin}"

    finding =
      Finding.new(%{
        type: "tainted_argument",
        severity: :critical,
        title: "outbound argument carries a tracked secret (#{hint})",
        plugin: %{name: "tainted-arg-guard", version: @version}
      })

    %{Decision.deny(:critical, reason) | findings: [finding]}
  end
end
