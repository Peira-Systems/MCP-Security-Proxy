defmodule PhoenixElxirBeam.MCP.CallFingerprint do
  @moduledoc """
  A one-way, order-independent fingerprint of a tool call's arguments —
  "are these two calls' arguments the same," never a way to recover what
  they were. Used by `Plugins.LoopGuard` to detect an agent retrying the
  identical call; never logged or surfaced alongside the raw arguments
  themselves (see that plugin's moduledoc and
  `docs/superpowers/plans/2026-10-05-loop-guard.md`'s global constraints).

  Canonicalization mirrors `PhoenixElxirBeam.MCP.ToolHash`: object keys are
  sorted recursively before hashing, so argument maps that are
  semantically identical but serialized with differently-ordered keys
  fingerprint identically.
  """

  @doc """
  Returns `"sha256:" <> hex` for a call's arguments. `nil` and `%{}` are
  treated as the same, deterministic "no arguments" value.
  """
  @spec compute(map() | nil) :: String.t()
  def compute(arguments) do
    canonical = canonicalize(arguments || %{})
    digest = :crypto.hash(:sha256, Jason.encode!(canonical))
    "sha256:" <> Base.encode16(digest, case: :lower)
  end

  defp canonicalize(map) when is_map(map) do
    map
    |> Enum.map(fn {k, v} -> {to_string(k), canonicalize(v)} end)
    |> Enum.sort_by(fn {k, _v} -> k end)
    |> Jason.OrderedObject.new()
  end

  defp canonicalize(list) when is_list(list), do: Enum.map(list, &canonicalize/1)
  defp canonicalize(other), do: other
end
