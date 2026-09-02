defmodule PhoenixElxirBeam.MCP.HoldStore do
  @moduledoc """
  Postgres persistence for *pending* `PhoenixElxirBeam.MCP.HoldRegistry`
  holds (`docs/productionization-plan.md` M2.2 follow-up — "SessionStore /
  HoldRegistry -> Postgres").

  This is not a general-purpose durable HoldRegistry: the thing a hold is
  actually waiting on — the blocked HTTP request process inside
  `PhoenixElxirBeamWeb.MCP.ProxyController` — cannot survive a restart no
  matter what gets persisted, so there is nothing to resume. What *is*
  worth persisting is closing the audit gap a restart would otherwise
  leave: without it, a hold interrupted mid-flight leaves a permanent
  `:held` audit row with no closing `:ok`/`:blocked` event, and the
  dashboard would show it as still pending forever.

  A row exists for exactly as long as its hold is open: `persist/1` inserts
  it at `park/2` time; `resolve/1` deletes it once a terminal outcome has
  been reached (approved, denied, or timed out). `HoldRegistry.reap_orphans/0`
  runs once at boot, before any new hold can be parked — so anything still
  in this table at that point is definitionally a leftover from a previous
  process lifetime that never resolved (a restart, deploy, or crash), and
  gets finalized as `:orphaned`.

  All operations are fail-soft (logged, never raised) — a persistence hiccup
  here must not block a hold from being parked, resolved, or awaited.
  """

  import Ecto.Query
  require Logger

  alias PhoenixElxirBeam.MCP.PendingHold
  alias PhoenixElxirBeam.Repo

  @doc "Inserts a pending-hold row for `hold` (a `HoldRegistry` hold map)."
  @spec persist(map()) :: :ok
  def persist(hold) do
    attrs = %{
      hold_id: hold.id,
      session_id: hold.session_id,
      server_id: hold.server_id,
      tool_name: hold.tool_name,
      tags: Enum.map(hold[:tags] || [], &to_string/1),
      prompt: hold.prompt,
      reason: hold.reason,
      timeout_ms: hold.timeout_ms,
      on_timeout: to_string(hold.on_timeout)
    }

    %PendingHold{}
    |> PendingHold.changeset(attrs)
    |> Repo.insert(on_conflict: :nothing, conflict_target: :hold_id)

    :ok
  rescue
    error -> log_and_ok(:persist, hold[:id], error)
  end

  @doc "Deletes a hold's row once it has reached a terminal outcome."
  @spec resolve(String.t()) :: :ok
  def resolve(hold_id) do
    Repo.delete_all(from h in PendingHold, where: h.hold_id == ^hold_id)
    :ok
  rescue
    error -> log_and_ok(:resolve, hold_id, error)
  end

  @doc "Every row currently in the table — at boot, all of them are orphans."
  @spec all() :: [PendingHold.t()]
  def all do
    Repo.all(PendingHold)
  rescue
    error ->
      log_and_ok(:all, nil, error)
      []
  end

  defp log_and_ok(op, id, error) do
    Logger.warning("HoldStore: #{op} for #{inspect(id)} failed: #{Exception.message(error)}")
    :ok
  end
end
