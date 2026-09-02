defmodule PhoenixElxirBeam.MCP.Plugin.Provenance do
  @moduledoc """
  Sidecar plugin provenance verification (M3.5 / plugin-protocol §18).

  A sidecar is an out-of-process program the proxy trusts to return security
  verdicts. This module lets an operator **pin** what that program is, so a
  swapped binary or a tampered script is caught at startup rather than silently
  trusted.

  Two digests are computed at every sidecar start:

    * **code digest** — `sha256` over the command string plus the bytes of each
      argument that resolves to a real file (the plugin's own script/binary,
      not the interpreter). Independent of where on disk it lives.
    * **manifest digest** — `sha256` over the canonical JSON of the manifest the
      sidecar reports at handshake (its declared capability, grants, phases).

  The config spec may carry `pin: [code: "sha256:…", manifest: "sha256:…"]`:

    * both match      → sidecar comes online;
    * either mismatch → `verify/2` returns `{:error, detail}`; the runner
      refuses to start and a `:sidecar_provenance` alert is raised;
    * `pin` absent    → `verify/2` returns `{:ok, digests}` and the computed
      digests are logged so an operator can paste them into config to pin.
  """

  require Logger

  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @type digests :: %{code: String.t(), manifest: String.t()}

  @doc """
  Verifies the running sidecar against its `pin` (a keyword list or map with
  `:code` / `:manifest`, or `nil`).

  `cmd` is the command string as configured, `resolved_args` the fully-resolved
  argument list (`{:priv, _}` already expanded), `manifest` the handshake
  `Manifest`.
  """
  @spec verify(map(), Manifest.t()) :: {:ok, digests()} | {:error, String.t()}
  def verify(%{cmd: cmd, resolved_args: args, pin: pin, name: name}, %Manifest{} = manifest) do
    digests = %{code: code_digest(cmd, args), manifest: manifest_digest(manifest)}

    case normalize_pin(pin) do
      nil ->
        Logger.warning(
          "Plugin.Provenance: sidecar #{name} is unpinned — its code is trusted without " <>
            "verification. To pin, add to its config:\n" <>
            "  pin: [code: \"#{digests.code}\", manifest: \"#{digests.manifest}\"]"
        )

        {:ok, digests}

      %{code: want_code, manifest: want_manifest} ->
        cond do
          is_binary(want_code) and want_code != digests.code ->
            {:error, "code digest mismatch for #{name}: pinned #{want_code}, got #{digests.code}"}

          is_binary(want_manifest) and want_manifest != digests.manifest ->
            {:error,
             "manifest digest mismatch for #{name}: pinned #{want_manifest}, got #{digests.manifest}"}

          true ->
            {:ok, digests}
        end
    end
  end

  @doc "The `sha256:` code digest for a command + resolved args (no verification)."
  @spec code_digest(String.t(), [String.t()]) :: String.t()
  def code_digest(cmd, resolved_args) do
    files = Enum.filter(resolved_args, &safe_regular_file?/1)

    files =
      cond do
        files != [] -> files
        safe_regular_file?(cmd) -> [cmd]
        true -> []
      end

    parts =
      Enum.map(files, fn f ->
        Path.basename(f) <> ":" <> sha256_hex(File.read!(f))
      end)

    sha256("code|#{cmd}|" <> Enum.join(parts, "|"))
  end

  @doc "The `sha256:` manifest digest (no verification)."
  @spec manifest_digest(Manifest.t()) :: String.t()
  def manifest_digest(%Manifest{} = manifest) do
    manifest
    |> Map.from_struct()
    |> canonicalize()
    |> Jason.encode!()
    |> sha256()
  end

  # -- internals -------------------------------------------------------------

  defp normalize_pin(nil), do: nil
  defp normalize_pin([]), do: nil

  defp normalize_pin(pin) when is_list(pin) do
    %{code: pin[:code], manifest: pin[:manifest]}
  end

  defp normalize_pin(pin) when is_map(pin) do
    %{code: pin[:code] || pin["code"], manifest: pin[:manifest] || pin["manifest"]}
  end

  defp safe_regular_file?(path) when is_binary(path) do
    File.regular?(path)
  rescue
    _ -> false
  end

  defp safe_regular_file?(_), do: false

  defp sha256(bin), do: "sha256:" <> sha256_hex(bin)
  defp sha256_hex(bin), do: :crypto.hash(:sha256, bin) |> Base.encode16(case: :lower)

  defp canonicalize(%{__struct__: _} = struct), do: struct |> Map.from_struct() |> canonicalize()

  # Mirrors PhoenixElxirBeam.MCP.EventLog: sorted pairs into a small Erlang map
  # (which iterates in key order) so Jason.encode! is deterministic.
  defp canonicalize(map) when is_map(map) do
    map
    |> Enum.map(fn {k, v} -> {to_string(k), canonicalize(v)} end)
    |> Enum.sort()
    |> Map.new()
  end

  defp canonicalize(list) when is_list(list), do: Enum.map(list, &canonicalize/1)

  defp canonicalize(atom) when is_atom(atom) and not is_nil(atom) and not is_boolean(atom),
    do: to_string(atom)

  defp canonicalize(other), do: other
end
