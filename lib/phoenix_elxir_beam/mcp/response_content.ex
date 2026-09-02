defmodule PhoenixElxirBeam.MCP.ResponseContent do
  @moduledoc """
  Normalizes the text payload of an MCP `result` into the flat
  `[%{"type" => "text", "text" => …}]` list the `post_call` scanners and
  `PhoenixElxirBeam.MCP.Redaction` expect, and reinjects the (possibly
  redacted) text back into the original result shape.

  Handles the three result shapes whose content the proxy scans:

    * `tools/call`   — `result["content"]`
    * `resources/read` — `result["contents"]` (each a `text`/`blob` resource)
    * `prompts/get`  — `result["messages"]` (each `message.content` a
      `text`/`image`/`resource` block)

  Non-text parts (blob, image, embedded resource) are passed through as
  opaque placeholders so list indices stay aligned with the redaction paths.
  """

  @doc """
  Returns `{content, reinject}` for a result whose text can be scanned, or
  `:skip` when there is nothing to scan. `reinject.(content)` returns the
  updated result with any changed `text` written back.
  """
  @spec extract(String.t(), map()) :: {[map()], (list() -> map())} | :skip
  def extract("tools/call", %{"content" => content} = result) when is_list(content) do
    {content, fn new -> Map.put(result, "content", new) end}
  end

  def extract("resources/read", %{"contents" => contents} = result) when is_list(contents) do
    parts = Enum.map(contents, &to_part/1)

    reinject = fn new ->
      merged =
        contents
        |> Enum.zip(new)
        |> Enum.map(fn {orig, part} -> merge_text(orig, part) end)

      Map.put(result, "contents", merged)
    end

    {parts, reinject}
  end

  def extract("prompts/get", %{"messages" => messages} = result) when is_list(messages) do
    parts = Enum.map(messages, fn m -> to_part(m["content"] || %{}) end)

    reinject = fn new ->
      merged =
        messages
        |> Enum.zip(new)
        |> Enum.map(fn {msg, part} ->
          Map.put(msg, "content", merge_text(msg["content"] || %{}, part))
        end)

      Map.put(result, "messages", merged)
    end

    {parts, reinject}
  end

  def extract(_method, _result), do: :skip

  # A resource / content block -> a scannable part.
  defp to_part(%{"text" => text}) when is_binary(text), do: %{"type" => "text", "text" => text}

  defp to_part(%{"type" => "text", "text" => text}) when is_binary(text),
    do: %{"type" => "text", "text" => text}

  defp to_part(_opaque), do: %{"type" => "opaque"}

  # Writes a possibly-redacted `text` back onto the original block, leaving
  # every other field (uri, mimeType, …) untouched. Opaque blocks are
  # returned unchanged.
  defp merge_text(orig, %{"text" => text}) when is_binary(text), do: Map.put(orig, "text", text)
  defp merge_text(orig, _part), do: orig
end
