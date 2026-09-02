defmodule PhoenixElxirBeam.MCP.Plugins.SecretLeak do
  @moduledoc """
  `post_call` scanner: finds credentials in a tool's response and proposes
  `redact_response` mutations so the secret never reaches the agent
  (`docs/plugin-protocol.md` §16.4).

  Advisory — it redacts, it does not block. The proxy applies the redactions
  (`PhoenixElxirBeam.MCP.Redaction`) to the response `content` before returning it.

  When it finds anything it also proposes `add_taint_sources` mutations — one
  per distinct secret — carrying HMAC **taint markers**
  (`PhoenixElxirBeam.MCP.TaintMarker`, M4.1) for the secret and its common
  encodings, plus a redacted `hint`. The raw secret is never stored, broadcast,
  or persisted. `PhoenixElxirBeam.MCP.Plugins.TaintGuard` uses the session
  provenance to block later egress coarsely; `PhoenixElxirBeam.MCP.Plugins.TaintedArgGuard`
  matches the markers against a later call's arguments (defeating
  base64 / hex / URL-encoding evasion).
  """

  @behaviour PhoenixElxirBeam.MCP.Plugin.Scanner

  alias PhoenixElxirBeam.MCP.{CallContext, Decision, Finding, TaintMarker}
  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @version "0.1.0"
  @replacement "‹redacted by secret-leak›"

  # {label, compiled regex}. Ordered most-specific first.
  @patterns [
    {"AWS access key id", ~r/AKIA[0-9A-Z]{16}/},
    {"AWS secret access key", ~r/aws_secret_access_key["\s]*[=:]["\s]*[^\s"']{16,}/i},
    {"private key block", ~r/-----BEGIN [A-Z ]*PRIVATE KEY-----/},
    {"credential assignment",
     ~r/(?i)\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)\b\s*[=:]\s*[^\s"']{8,}/}
  ]

  @impl true
  def manifest do
    Manifest.normalize(%{
      plugin: %{
        name: "secret-leak",
        version: @version,
        description: "Redacts credentials found in tool responses."
      },
      capabilities: %{
        scanner: %{
          phases: [:post_call],
          data_needs: ["response.content"],
          timeout_ms: 200,
          fail_mode: :fail_open,
          can_block: false
        }
      }
    })
  end

  @impl true
  def scan(:post_call, %CallContext{response: response} = ctx) do
    parts = (response && response[:content]) || (response && response["content"]) || []

    {findings, redactions} =
      parts
      |> Enum.with_index()
      |> Enum.flat_map(fn {part, i} -> scan_part(text_of(part), i) end)
      |> Enum.unzip()

    mutations =
      %{redact_response: redactions}
      |> Map.merge(taint_mutation(redactions, ctx))

    {:ok, findings, %Decision{verdict: :annotate, mutations: mutations}}
  end

  # One taint source per distinct secret found — each carries HMAC markers
  # (never the raw secret) and a redacted hint.
  defp taint_mutation([], _ctx), do: %{}

  defp taint_mutation(redactions, %CallContext{call: call}) do
    origin = call[:tool_name] || call["toolName"] || "unknown"
    session_id = call[:session_id] || call["sessionId"]
    now = DateTime.utc_now()

    sources =
      redactions
      |> Enum.map(& &1.match)
      |> Enum.uniq()
      |> Enum.map(fn secret ->
        %{
          origin_tool: origin,
          finding_type: "secret_leak",
          at: now,
          markers: TaintMarker.markers_for_secret(session_id, secret),
          hint: hint(secret)
        }
      end)
      |> Enum.reject(&(&1.markers == []))

    if sources == [], do: %{}, else: %{add_taint_sources: sources}
  end

  defp hint(s) when byte_size(s) > 12 do
    String.slice(s, 0, 6) <> "…" <> String.slice(s, -2, 2)
  end

  defp hint(_s), do: "‹secret›"

  defp text_of(%{"text" => t}), do: t
  defp text_of(%{text: t}), do: t
  defp text_of(_), do: nil

  defp scan_part(nil, _i), do: []

  defp scan_part(text, i) do
    for {label, re} <- @patterns,
        match <- Regex.scan(re, text) |> Enum.map(&hd/1) |> Enum.uniq() do
      {finding(label, match, i), redaction(match, i)}
    end
  end

  defp finding(label, match, i) do
    Finding.new(%{
      type: "secret_leak",
      severity: :high,
      confidence: 0.9,
      title: "#{label} in tool response",
      locator: %{path: "content[#{i}].text"},
      evidence: match,
      plugin: %{name: "secret-leak", version: @version}
    })
  end

  defp redaction(match, i) do
    %{path: "content[#{i}].text", match: match, replacement: @replacement}
  end
end
