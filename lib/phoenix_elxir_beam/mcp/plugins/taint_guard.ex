defmodule PhoenixElxirBeam.MCP.Plugins.TaintGuard do
  @moduledoc """
  The provenance counterpart to `ChainExfil`: a call tagged `:network_egress`
  is denied when the session's **taint** list is non-empty — i.e. a
  `post_call` scanner (today `PhoenixElxirBeam.MCP.Plugins.SecretLeak`) has
  already seen a secret flow through a response in this session.

  Where `ChainExfil` keys off the operator's `:sensitive_read` tag on the
  tool definition, `TaintGuard` keys off what actually came back over the
  wire — so it catches exfil even when the leaking tool was never tagged.
  """

  @behaviour PhoenixElxirBeam.MCP.Plugin.Policy

  alias PhoenixElxirBeam.MCP.{CallContext, Decision}
  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @impl true
  def manifest do
    Manifest.normalize(%{
      plugin: %{
        name: "taint-guard",
        version: "0.1.0",
        description: "Blocks network egress once a secret has flowed through the session."
      },
      capabilities: %{
        policy: %{
          phases: [:pre_call],
          tool_tags: [:network_egress],
          data_needs: ["session.taint"],
          timeout_ms: 50,
          fail_mode: :fail_closed
        }
      }
    })
  end

  @impl true
  def evaluate(:pre_call, %CallContext{} = ctx) do
    case sources(ctx) do
      [] -> Decision.allow()
      [source | _] = all -> Decision.deny(:high, reason(source, length(all)))
    end
  end

  defp sources(%CallContext{session: session}) do
    session |> Map.get(:taint, %{}) |> Map.get(:sources, [])
  end

  defp reason(source, count) do
    origin = get(source, :origin_tool) || "an earlier tool"
    tail = if count > 1, do: " (+#{count - 1} more)", else: ""
    what = what(source)

    "network egress blocked: this session handled #{what} via #{origin}#{age(source)}#{tail}"
  end

  defp what(source) do
    case get(source, :finding_type) do
      "untrusted_provenance" -> "untrusted content"
      _ -> "a secret"
    end
  end

  defp age(source) do
    case get(source, :at) do
      %DateTime{} = at -> " #{max(DateTime.diff(DateTime.utc_now(), at), 0)}s ago"
      _ -> ""
    end
  end

  # Taint sources are atom-keyed in-process, string-keyed off the sidecar wire.
  defp get(map, key) when is_map(map), do: Map.get(map, key) || Map.get(map, to_string(key))
end
