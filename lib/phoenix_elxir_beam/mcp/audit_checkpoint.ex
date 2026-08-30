defmodule PhoenixElxirBeam.MCP.AuditCheckpoint do
  @moduledoc """
  Off-database anchoring of the `PhoenixElxirBeam.MCP.EventLog` hash chain
  (`docs/productionization-plan.md` M2.3).

  `EventLog.verify_chain/0` proves the rows *present* form an unbroken chain
  — but a shortened chain (someone deleted the last N rows and recomputed
  nothing, since each row already carries its own hash) still verifies. A
  periodic signed checkpoint written **outside Postgres** closes that gap:
  it records `{event_id, hash, count}` for the chain head plus an HMAC over
  those fields. A later check compares the live head against the newest
  checkpoint — a drop in `count`, or a checkpointed `hash` that no longer
  exists as a row, is tamper evidence a DB-only attacker cannot hide (they
  do not have the HMAC key).

  Append-only file, one JSON object per line, at
  `config :phoenix_elxir_beam, #{inspect(__MODULE__)}, path: …`
  (`AUDIT_CHECKPOINT_PATH` in prod — put it on a volume separate from the DB).
  """

  require Logger

  @default_path "priv/audit_checkpoints.log"

  @type entry :: %{
          event_id: String.t(),
          hash: String.t(),
          count: non_neg_integer(),
          verified_at: String.t(),
          sig: String.t()
        }

  @doc "Appends a signed checkpoint for `head` (`%{event_id, hash, count}`). Returns the entry."
  @spec append(map()) :: {:ok, entry()} | {:error, term()}
  def append(head) do
    entry =
      %{
        "event_id" => head.event_id,
        "hash" => head.hash,
        "count" => head.count,
        "verified_at" => DateTime.utc_now() |> DateTime.to_iso8601()
      }
      |> then(&Map.put(&1, "sig", sign(&1)))

    path = path()
    File.mkdir_p!(Path.dirname(path))

    case File.open(path, [:append, :utf8], &IO.puts(&1, Jason.encode!(entry))) do
      {:ok, :ok} -> {:ok, atomize(entry)}
      other -> {:error, other}
    end
  end

  @doc "The newest checkpoint whose signature verifies, or `nil`."
  @spec latest() :: entry() | nil
  def latest do
    case File.read(path()) do
      {:ok, contents} ->
        contents
        |> String.split("\n", trim: true)
        |> Enum.reverse()
        |> Enum.find_value(nil, fn line ->
          with {:ok, obj} <- Jason.decode(line),
               true <- valid?(obj) do
            atomize(obj)
          else
            _ -> nil
          end
        end)

      {:error, :enoent} ->
        nil

      {:error, reason} ->
        Logger.warning("AuditCheckpoint: cannot read #{path()}: #{inspect(reason)}")
        nil
    end
  end

  @doc "Whether a checkpoint object's signature is intact."
  @spec valid?(map()) :: boolean()
  def valid?(%{"sig" => sig} = obj) when is_binary(sig) do
    Plug.Crypto.secure_compare(sig, sign(Map.delete(obj, "sig")))
  end

  def valid?(_), do: false

  defp sign(obj) do
    payload =
      obj
      |> Enum.sort_by(&elem(&1, 0))
      |> Jason.OrderedObject.new()
      |> Jason.encode!()

    :crypto.mac(:hmac, :sha256, key(), payload) |> Base.encode16(case: :lower)
  end

  # Keys come from a checkpoint file this module wrote — a fixed 5-key set.
  defp atomize(obj) do
    Map.new(obj, fn
      {"event_id", v} -> {:event_id, v}
      {"hash", v} -> {:hash, v}
      {"count", v} -> {:count, v}
      {"verified_at", v} -> {:verified_at, v}
      {"sig", v} -> {:sig, v}
      {k, v} -> {k, v}
    end)
  end

  defp path do
    config()[:path] || @default_path
  end

  defp key do
    config()[:key] ||
      raise "AuditCheckpoint key is not configured (config :phoenix_elxir_beam, #{inspect(__MODULE__)}, key: …)"
  end

  defp config, do: Application.get_env(:phoenix_elxir_beam, __MODULE__, [])
end
