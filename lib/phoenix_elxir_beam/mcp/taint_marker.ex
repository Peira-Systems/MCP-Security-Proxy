defmodule PhoenixElxirBeam.MCP.TaintMarker do
  @moduledoc """
  HMAC taint markers (M4.1 / plugin-protocol §18).

  When a `post_call` scanner sees a credential in a tool response
  (`PhoenixElxirBeam.MCP.Plugins.SecretLeak`), the proxy must remember it so a
  later `tools/call` that tries to exfiltrate it can be blocked
  (`PhoenixElxirBeam.MCP.Plugins.TaintedArgGuard`). Keeping the **raw secret**
  in session state to substring-match against is fragile (base64 / hex /
  URL-encoding evasion) and means the secret lives in memory — and cannot be
  persisted (M2.2a had to drop it, degrading the check across a restart).

  Instead we store **markers**: `HMAC-SHA256(session_key, representation)` where
  `session_key = HMAC-SHA256(server_key, "taint|" <> session_id)`. For each
  leaked secret we mark it *and its common encodings*; on an outbound call we
  tokenise the arguments, mark each token *and its common decodings*, and block
  on any marker collision. Markers are opaque, safe to persist, and scoped to
  the session (the same secret in two sessions has different markers).

  The `server_key` comes from `config :phoenix_elxir_beam, :taint_marker_key`
  (prod: `TAINT_MARKER_KEY` secret, or derived from `SECRET_KEY_BASE`).

  Not defeated: splitting a secret across several arguments/calls, or a
  transform we don't enumerate (e.g. gzip). Documented in the threat model.
  """

  @min_len 8
  @prefix "tm:"

  @type marker :: String.t()

  @doc "Every marker to STORE for a credential `secret` seen this session."
  @spec markers_for_secret(String.t() | nil, binary()) :: [marker()]
  def markers_for_secret(session_id, secret) when is_binary(secret) do
    if byte_size(secret) >= @min_len do
      k = session_key(session_id)
      secret |> representations() |> Enum.map(&hmac(k, &1)) |> Enum.uniq()
    else
      []
    end
  end

  def markers_for_secret(_session_id, _secret), do: []

  @doc """
  Every marker to CHECK for the outbound `arguments` (a string, map, or any
  term). Tokenises, then marks each token and its plausible decodings.
  """
  @spec candidate_markers(String.t() | nil, term()) :: MapSet.t(marker())
  def candidate_markers(session_id, arguments) do
    k = session_key(session_id)

    arguments
    |> stringify()
    |> tokenize()
    |> Enum.flat_map(&[&1 | decodings(&1)])
    |> Enum.filter(&(is_binary(&1) and byte_size(&1) >= @min_len))
    |> Enum.map(&hmac(k, &1))
    |> MapSet.new()
  end

  @doc "True if any candidate marker for `arguments` is in `marker_set`."
  @spec tainted?(String.t() | nil, term(), Enumerable.t()) :: boolean()
  def tainted?(session_id, arguments, marker_set) do
    set = MapSet.new(marker_set)

    not MapSet.disjoint?(set, candidate_markers(session_id, arguments))
  end

  # -- internals -----------------------------------------------------------

  defp session_key(session_id) do
    :crypto.mac(:hmac, :sha256, server_key(), "taint|" <> to_string(session_id || ""))
  end

  defp hmac(key, value) when is_binary(value) do
    @prefix <> (:crypto.mac(:hmac, :sha256, key, value) |> Base.encode16(case: :lower))
  end

  defp representations(s) do
    [
      s,
      Base.encode64(s),
      Base.encode64(s, padding: false),
      Base.encode16(s, case: :lower),
      Base.encode16(s, case: :upper),
      URI.encode(s, &URI.char_unreserved?/1)
    ]
    |> Enum.uniq()
  end

  defp decodings(token) do
    [safe_b64(token), safe_hex(token)]
    |> Enum.reject(&is_nil/1)
  end

  defp safe_b64(t) do
    case Base.decode64(t, padding: false) do
      {:ok, bin} -> if printable_enough?(bin), do: bin
      :error -> nil
    end
  end

  defp safe_hex(t) do
    case Base.decode16(t, case: :mixed) do
      {:ok, bin} -> if printable_enough?(bin), do: bin
      :error -> nil
    end
  end

  defp printable_enough?(bin) do
    byte_size(bin) >= @min_len and String.printable?(bin, 64)
  end

  # Tokenise two ways and union the results:
  #   1. keeping `=` / `+` / `/` so `KEY=value` and base64 survive whole;
  #   2. also splitting on `= : & ?` so a `param=<base64-secret>` yields the
  #      bare base64 too.
  defp tokenize(str) do
    coarse = String.split(str, ~r/[^A-Za-z0-9+\/=_.\-]+/, trim: true)
    fine = Enum.flat_map(coarse, &String.split(&1, ~r/[=:&?]+/, trim: true))

    (coarse ++ fine) |> Enum.uniq()
  end

  defp stringify(bin) when is_binary(bin), do: bin

  defp stringify(term) do
    case Jason.encode(term) do
      {:ok, json} -> json
      _ -> inspect(term)
    end
  end

  defp server_key do
    case Application.get_env(:phoenix_elxir_beam, :taint_marker_key) do
      key when is_binary(key) and byte_size(key) >= 16 -> key
      _ -> "insecure-default-taint-marker-key-change-me"
    end
  end
end
