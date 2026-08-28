defmodule PhoenixElxirBeam.MCP.Redaction do
  @moduledoc """
  Applies `redactResponse` mutations (`docs/plugin-protocol.md` §7.2) to a
  tool response's `content` list before it is returned to the agent.

  A redaction is `%{"path" => "content[i].text", "match" => …, "replacement" => …}`
  (string keys — it round-trips through JSON / the sidecar wire). `match` is a
  literal substring, or a regex when wrapped in slashes (`"/AKIA[0-9A-Z]+/"`).
  Redactions are applied in order and are idempotent — a `match` that is no
  longer present is a no-op.
  """

  @doc "Returns `content` with every redaction applied."
  @spec apply(list(), [map()]) :: list()
  def apply(content, redactions) when is_list(content) do
    Enum.reduce(redactions, content, &apply_one/2)
  end

  def apply(content, _redactions), do: content

  defp apply_one(redaction, content) do
    r = normalize(redaction)

    with {:ok, index} <- text_index(r["path"]),
         %{} = part <- Enum.at(content, index),
         text when is_binary(text) <- Map.get(part, "text") do
      redacted = replace(text, r["match"], r["replacement"] || "‹redacted›")
      List.replace_at(content, index, Map.put(part, "text", redacted))
    else
      _ -> content
    end
  end

  # Accept atom- or string-keyed redactions (in-process plugins vs the wire).
  defp normalize(r) when is_map(r), do: Map.new(r, fn {k, v} -> {to_string(k), v} end)

  defp text_index("content[" <> rest) do
    case Integer.parse(rest) do
      {n, "].text"} when n >= 0 -> {:ok, n}
      _ -> :error
    end
  end

  defp text_index(_), do: :error

  defp replace(text, "/" <> _ = slashed, replacement) do
    case Regex.compile(String.slice(slashed, 1..-2//1)) do
      {:ok, re} -> Regex.replace(re, text, replacement)
      _ -> text
    end
  end

  defp replace(text, match, replacement) when is_binary(match) do
    String.replace(text, match, replacement)
  end

  defp replace(text, _match, _replacement), do: text
end
