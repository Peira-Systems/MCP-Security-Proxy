defmodule PhoenixElxirBeam.MCP.ToolHash do
  @moduledoc """
  Content hash of an MCP tool definition — the `descriptionHash` the
  rug-pull / tool-drift scanner pins at registration and re-checks on every
  handshake (`docs/plugin-protocol.md` §7.1).

  The hash covers `{name, description, inputSchema}` over a **canonical**
  JSON encoding: object keys are sorted recursively, so a server that
  re-serializes the same schema with its keys in a different order does not
  read as drift. A genuine change to any of the three fields does.
  """

  @doc """
  Returns `"sha256:" <> hex` for a tool map. Accepts either the internal
  shape (`:name` / `:description` / `:input_schema`) or the wire shape
  (`"name"` / `"description"` / `"inputSchema"`).
  """
  @spec hash(map()) :: String.t()
  def hash(tool) when is_map(tool) do
    canonical =
      canonicalize(%{
        "name" => field(tool, :name, "name"),
        "description" => field(tool, :description, "description"),
        "inputSchema" => field(tool, :input_schema, "inputSchema")
      })

    digest = :crypto.hash(:sha256, Jason.encode!(canonical))
    "sha256:" <> Base.encode16(digest, case: :lower)
  end

  defp field(map, atom_key, string_key) do
    case Map.fetch(map, atom_key) do
      {:ok, value} -> value
      :error -> Map.get(map, string_key)
    end
  end

  # Maps become key-sorted ordered objects so the JSON encoding is
  # deterministic. Lists keep their order (array order is significant).
  defp canonicalize(map) when is_map(map) do
    map
    |> Enum.map(fn {k, v} -> {to_string(k), canonicalize(v)} end)
    |> Enum.sort_by(&elem(&1, 0))
    |> Jason.OrderedObject.new()
  end

  defp canonicalize(list) when is_list(list), do: Enum.map(list, &canonicalize/1)
  defp canonicalize(other), do: other
end
