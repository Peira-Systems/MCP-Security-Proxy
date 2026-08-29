defmodule PhoenixElxirBeam.MCP.Plugins.StreamGuard do
  @moduledoc """
  The streaming counterpart to `ResponseSizeGuard`: a `chunk`-phase `policy`
  that watches the running byte count of a streamed tool response and denies
  once it passes a budget — telling the proxy to **cut the stream**.

  `ResponseSizeGuard` can only act once the whole response has been buffered;
  `StreamGuard` acts mid-flight, so an oversized export is stopped after a
  couple of kilobytes instead of after all of it has crossed the proxy. The
  chunks already delivered stay delivered — this is containment, not
  prevention.

      config: %{"max_bytes" => 2_000}   # running total across delivered + current chunk
  """

  @behaviour PhoenixElxirBeam.MCP.Plugin.Policy

  alias PhoenixElxirBeam.MCP.{CallContext, Decision}
  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @default_max_bytes 2_000

  @impl true
  def manifest do
    Manifest.normalize(%{
      plugin: %{
        name: "stream-guard",
        version: "0.1.0",
        description: "Cuts a streamed tool response once its running byte count exceeds a budget."
      },
      capabilities: %{
        policy: %{
          phases: [:chunk],
          tool_tags: [],
          data_needs: ["response.content"],
          timeout_ms: 50,
          fail_mode: :fail_open
        }
      }
    })
  end

  @impl true
  def evaluate(:chunk, %CallContext{} = ctx) do
    max = int(get_in(ctx.plugin_config, ["max_bytes"]), @default_max_bytes)
    response = ctx.response || %{}
    delivered = Map.get(response, :delivered, [])
    chunk = Map.get(response, :chunk)

    total = text_bytes(delivered) + text_bytes(List.wrap(chunk))

    if total > max do
      Decision.deny(
        :high,
        "stream terminated: #{total} bytes streamed exceeds the #{max}-byte budget " <>
          "(chunks already delivered are kept)"
      )
    else
      Decision.allow()
    end
  end

  defp text_bytes(parts) when is_list(parts) do
    Enum.reduce(parts, 0, fn part, acc -> acc + byte_size(part_text(part)) end)
  end

  defp part_text(%{"text" => t}) when is_binary(t), do: t
  defp part_text(%{text: t}) when is_binary(t), do: t
  defp part_text(_), do: ""

  defp int(n, _default) when is_integer(n) and n >= 0, do: n

  defp int(s, default) when is_binary(s) do
    case Integer.parse(s) do
      {n, ""} when n >= 0 -> n
      _ -> default
    end
  end

  defp int(_n, default), do: default
end
