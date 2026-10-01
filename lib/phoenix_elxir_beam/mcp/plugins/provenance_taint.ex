defmodule PhoenixElxirBeam.MCP.Plugins.ProvenanceTaint do
  @moduledoc """
  `post_call` scanner: taints the session when a tool tagged `:untrusted_source`
  returns a response, independent of what that response contains.

  `PhoenixElxirBeam.MCP.Plugins.SecretLeak` only taints when its regexes find
  something credential-shaped — real coverage for a secret coming back
  verbatim or lightly encoded, but structurally blind to content the agent
  paraphrases, reformats, or that was never a "secret" to begin with (a
  prompt-injection payload in a scraped page, an unvetted tool's own
  description). This scanner closes that gap by tagging the *source*: an
  operator marks a tool (or a whole upstream server) `:untrusted_source`, and
  every response from it taints the session regardless of content.

  Produces the same `add_taint_sources` mutation shape `SecretLeak` does, so
  `PhoenixElxirBeam.MCP.Plugins.TaintGuard` gates egress on it the same way —
  except the source carries no markers (there is no specific value to
  fingerprint), so `PhoenixElxirBeam.MCP.Plugins.TaintedArgGuard` correctly
  never matches against it.
  """

  @behaviour PhoenixElxirBeam.MCP.Plugin.Scanner

  alias PhoenixElxirBeam.MCP.{CallContext, Decision}
  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @version "0.1.0"

  @impl true
  def manifest do
    Manifest.normalize(%{
      plugin: %{
        name: "provenance-taint",
        version: @version,
        description: "Taints the session when an untrusted-tagged tool's response is returned."
      },
      capabilities: %{
        scanner: %{
          phases: [:post_call],
          data_needs: ["call.tags"],
          timeout_ms: 50,
          fail_mode: :fail_open,
          can_block: false
        }
      }
    })
  end

  @impl true
  def scan(:post_call, %CallContext{call: call} = ctx) do
    if :untrusted_source in (call[:tags] || []) do
      {:ok, [], %Decision{verdict: :annotate, mutations: %{add_taint_sources: [source(ctx)]}}}
    else
      {:ok, [], %Decision{verdict: :annotate, mutations: %{}}}
    end
  end

  defp source(%CallContext{call: call}) do
    %{
      origin_tool: call[:tool_name],
      finding_type: "untrusted_provenance",
      at: DateTime.utc_now(),
      markers: [],
      hint: "untrusted response"
    }
  end
end
