defmodule PhoenixElxirBeam.MCP.CallFingerprint do
  @moduledoc """
  A one-way, order-independent, **session-scoped** fingerprint of a tool
  call's arguments — "are these two calls' arguments the same, within this
  session," never a way to recover what they were or to correlate values
  across sessions. Used by `Plugins.LoopGuard` to detect an agent retrying
  the identical call; the fingerprint (never the raw arguments) can end up
  in the durable audit log (`PolicyEngine`'s `call_chain`) and in sidecar
  payloads that declare `session.recentCalls`, so it must carry the same
  guarantee `PhoenixElxirBeam.MCP.TaintMarker` already established for
  exactly this reason: an HMAC keyed per-session, not a bare hash. A bare
  `SHA-256(arguments)` would let anyone who can read the persisted
  fingerprint brute-force a guessed low-entropy argument offline, and
  would let the same argument value be linked across different sessions —
  both defeated by keying per session the same way `TaintMarker` does.

  Canonicalization mirrors `PhoenixElxirBeam.MCP.ToolHash`: object keys are
  sorted recursively before hashing, so argument maps that are
  semantically identical but serialized with differently-keyed or
  differently-ordered representations fingerprint identically.
  """

  @doc """
  Returns `"sha256:" <> hex` for a call's arguments, HMAC-keyed to
  `session_id` (same `server_key` + per-session derivation pattern as
  `PhoenixElxirBeam.MCP.TaintMarker`, under a distinct label so the two
  never collide). `nil` and `%{}` are treated as the same, deterministic
  "no arguments" value within a given session.

  Arguments are attacker/agent-controlled input reaching
  `PhoenixElxirBeam.MCP.PolicyEngine`'s single GenServer on its hot path —
  this function is total and never raises, even if `arguments` contains a
  value with no `Jason.Encoder` impl (an `Enumerable.impl_for!` failure here
  would crash the GenServer and wipe every in-memory session). On any
  encoding failure it falls back to fingerprinting `inspect(arguments)`
  instead — still deterministic, still one-way, just not canonicalized
  (acceptable: well-formed JSON-decoded arguments, the expected shape, never
  hit this path).
  """
  @spec compute(String.t() | nil, map() | nil) :: String.t()
  def compute(session_id, arguments) do
    key = session_key(session_id)

    payload =
      try do
        Jason.encode!(canonicalize(arguments || %{}))
      rescue
        _ -> inspect(arguments)
      end

    digest = :crypto.mac(:hmac, :sha256, key, payload)
    "sha256:" <> Base.encode16(digest, case: :lower)
  end

  defp session_key(session_id) do
    :crypto.mac(:hmac, :sha256, server_key(), "loopfp|" <> to_string(session_id || ""))
  end

  defp server_key do
    case Application.get_env(:phoenix_elxir_beam, :taint_marker_key) do
      key when is_binary(key) and byte_size(key) >= 16 -> key
      _ -> "insecure-default-taint-marker-key-change-me"
    end
  end

  # Only a *plain* map is treated as a JSON object to canonicalize — a
  # struct (DateTime, Date, a Reference wrapped in a map, anything with
  # __struct__) is not a JSON object shape and must not be torn apart by
  # `Enum.map/2` as if it were one. Arguments are expected to already be
  # plain JSON-decoded data (maps/lists/scalars); a struct showing up here
  # is a degenerate input, not the common case — treated as an opaque leaf.
  defp canonicalize(%_struct{} = value), do: value

  defp canonicalize(map) when is_map(map) do
    map
    |> Enum.map(fn {k, v} -> {to_string(k), canonicalize(v)} end)
    |> Enum.sort_by(fn {k, _v} -> k end)
    |> Jason.OrderedObject.new()
  end

  defp canonicalize(list) when is_list(list), do: Enum.map(list, &canonicalize/1)
  defp canonicalize(other), do: other
end
