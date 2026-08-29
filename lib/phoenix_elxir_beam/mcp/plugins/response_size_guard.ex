defmodule PhoenixElxirBeam.MCP.Plugins.ResponseSizeGuard do
  @moduledoc """
  A `post_call` `policy` that **withholds** a tool response whose text
  content exceeds a byte budget — a blunt bulk-exfiltration guard: a tool
  asked to dump a whole table / directory / file returns far more than a
  normal call, and the proxy refuses to relay it (JSON-RPC `-32002`).

  The budget is `plugin_config["max_bytes"]` (default #{4_000}). This is the
  first shipped plugin that exercises the `post_call` deny → `-32002` path
  (`docs/plugin-protocol.md` §9.4).
  """

  @behaviour PhoenixElxirBeam.MCP.Plugin.Policy

  alias PhoenixElxirBeam.MCP.{CallContext, Decision}
  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @default_max_bytes 4_000

  @impl true
  def manifest do
    Manifest.normalize(%{
      plugin: %{
        name: "response-size-guard",
        version: "0.1.0",
        description: "Withholds a tool response larger than a byte budget (bulk-exfil guard)."
      },
      capabilities: %{
        policy: %{
          phases: [:post_call],
          data_needs: ["response.content"],
          timeout_ms: 50,
          fail_mode: :fail_open
        }
      }
    })
  end

  @impl true
  def evaluate(:post_call, %CallContext{response: response} = ctx) do
    max = Map.get(ctx.plugin_config, "max_bytes", @default_max_bytes)
    size = response_bytes(response)

    if size > max do
      Decision.deny(
        :high,
        "response withheld: #{size} bytes exceeds the #{max}-byte budget for a single tool response (possible bulk exfiltration)"
      )
    else
      Decision.allow()
    end
  end

  defp response_bytes(response) do
    parts = (response && (response[:content] || response["content"])) || []

    Enum.reduce(parts, 0, fn part, acc ->
      text = (is_map(part) && (part[:text] || part["text"])) || ""
      acc + byte_size(to_string(text))
    end)
  end
end
