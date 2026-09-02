defmodule PhoenixElxirBeam.MCP.PolicyStore do
  @moduledoc """
  Postgres persistence for `PhoenixElxirBeam.MCP.PolicyEngine`'s per-session
  state (`docs/productionization-plan.md` M2.2). The engine keeps a
  write-through in-memory cache; this table is the source of truth so a
  decision still sees a session's accumulated **tags** and **taint** after a
  restart.

  Not persisted: the 60-second behavioural-baseline `call_log` (ephemeral by
  design — `BaselineGuard` is `fail_open` and re-warms). Taint sources persist
  in full now that they carry HMAC **markers** rather than the raw secret
  (M4.1 / `PhoenixElxirBeam.MCP.TaintMarker`), so `TaintedArgGuard` keeps its
  full precision across a restart. `sanitize_source/1` still drops a stray
  `secret` key for defence in depth.
  """

  import Ecto.Query

  alias PhoenixElxirBeam.MCP.PolicySession
  alias PhoenixElxirBeam.Repo

  @type state :: %{
          tags: MapSet.t(),
          taint: [map()],
          agent_id: String.t() | nil,
          call_count: non_neg_integer()
        }

  @doc "Loads a session's persisted state, or `nil` if there is no row."
  @spec load(String.t()) :: state() | nil
  def load(session_id) do
    case Repo.get(PolicySession, session_id) do
      nil ->
        nil

      row ->
        %{
          tags: MapSet.new(row.tags, &to_tag/1),
          taint: row.taint,
          agent_id: row.agent_id,
          call_count: row.call_count
        }
    end
  end

  @doc "Upserts a session's state. `session` is an in-memory PolicyEngine session map."
  @spec persist(String.t(), map()) :: {:ok, PolicySession.t()} | {:error, Ecto.Changeset.t()}
  def persist(session_id, session) do
    attrs = %{
      session_id: session_id,
      agent_id: session[:agent_id],
      tags: session.tags |> MapSet.to_list() |> Enum.map(&to_string/1) |> Enum.sort(),
      taint: Enum.map(session.taint, &sanitize_source/1),
      call_count: session[:call_count] || 0
    }

    %PolicySession{}
    |> PolicySession.changeset(attrs)
    |> Repo.insert(
      on_conflict: {:replace, [:agent_id, :tags, :taint, :call_count, :updated_at]},
      conflict_target: :session_id
    )
  end

  @doc "Deletes a session's row (called on teardown)."
  @spec delete(String.t()) :: non_neg_integer()
  def delete(session_id) do
    {n, _} = Repo.delete_all(from(s in PolicySession, where: s.session_id == ^session_id))
    n
  end

  @doc "Deletes rows not touched in the last `older_than_seconds`. Returns the count."
  @spec sweep(pos_integer()) :: non_neg_integer()
  def sweep(older_than_seconds) do
    cutoff = DateTime.add(DateTime.utc_now(), -older_than_seconds, :second)
    {n, _} = Repo.delete_all(from(s in PolicySession, where: s.updated_at < ^cutoff))
    n
  end

  # -- helpers --------------------------------------------------------

  # Drop the raw secret; render everything JSON-safe and string-keyed (jsonb
  # round-trips as string keys anyway).
  defp sanitize_source(source) when is_map(source) do
    source
    |> Map.drop([:secret, "secret"])
    |> Map.new(fn {k, v} -> {to_string(k), jsonable(v)} end)
  end

  defp jsonable(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp jsonable(v) when is_atom(v) and not is_boolean(v) and not is_nil(v), do: Atom.to_string(v)
  defp jsonable(v), do: v

  @doc "Converts a persisted string tag back to its atom, if that atom already exists (else back verbatim)."
  @spec to_tag(String.t()) :: atom() | String.t()
  def to_tag(tag) when is_binary(tag) do
    String.to_existing_atom(tag)
  rescue
    ArgumentError -> tag
  end
end
