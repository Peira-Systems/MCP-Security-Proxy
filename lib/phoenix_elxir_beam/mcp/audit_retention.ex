defmodule PhoenixElxirBeam.MCP.AuditRetention do
  @moduledoc """
  Opt-in pruning of old `policy_events` rows
  (`docs/productionization-plan.md` M2.3 follow-up — "audit retention").
  Off by default (`retention_days: nil`/unset, `AUDIT_RETENTION_DAYS` in
  prod): the log grows unbounded, as documented in
  `docs/deployment.md#retention--backups`.

  `prune/1` takes the `hash` of a row `PhoenixElxirBeam.MCP.AuditIntegrity`
  just re-confirmed is still present via a signed
  `PhoenixElxirBeam.MCP.AuditCheckpoint` this cycle, looks up that row's id,
  and only ever deletes rows strictly before it. That row and everything
  after it is never touched, so the next check still has what it needs —
  `PhoenixElxirBeam.MCP.EventLog.verify_chain/0` trusts the oldest surviving
  row's own stored `prev_hash` as its starting point precisely so a table
  pruned this way keeps verifying correctly.

  This is deletion, not archival — it does not write anything out first.
  Durability of anything pruned relies on your Postgres backups and/or
  `PhoenixElxirBeam.MCP.Plugins.EventLogSink`'s sibling `StructuredLogSink`
  shipping rows to a SIEM in real time, both already documented in
  `docs/deployment.md`. Do not enable `AUDIT_RETENTION_DAYS` until one of
  those is actually in place.
  """

  import Ecto.Query
  require Logger

  alias PhoenixElxirBeam.MCP.{ModuleConfig, PolicyEvent}
  alias PhoenixElxirBeam.Repo

  @doc """
  Deletes rows with `id` before the row whose `hash` is `anchor_hash`, and
  `occurred_at` older than the configured `retention_days`. A no-op
  (returns `0`) when `retention_days` is unset, `nil`, `<= 0`, or the
  anchor row can't be found. Returns the number of rows deleted.
  """
  @spec prune(String.t()) :: non_neg_integer()
  def prune(anchor_hash) do
    with days when is_integer(days) and days > 0 <- retention_days(),
         anchor_id when not is_nil(anchor_id) <- anchor_row_id(anchor_hash) do
      cutoff = DateTime.add(DateTime.utc_now(), -days * 86_400, :second)

      {count, _} =
        Repo.delete_all(
          from e in PolicyEvent,
            where: e.id < ^anchor_id and e.occurred_at < ^cutoff
        )

      if count > 0 do
        Logger.info(
          "mcp.audit.retention pruned #{count} row(s) before id #{anchor_id}, " <>
            "older than #{days}d"
        )
      end

      count
    else
      _ -> 0
    end
  end

  defp anchor_row_id(hash) do
    PolicyEvent |> where([e], e.hash == ^hash) |> select([e], e.id) |> Repo.one()
  end

  defp retention_days, do: ModuleConfig.get(__MODULE__, :retention_days)
end
