defmodule PhoenixElxirBeam.MCP.AuditRetentionTest do
  @moduledoc "M2.3 follow-up: opt-in, anchor-safe pruning of policy_events."
  use PhoenixElxirBeam.DataCase, async: false

  import Ecto.Query

  alias PhoenixElxirBeam.MCP.{AuditEvent, AuditRetention, EventLog, PolicyEvent}

  setup do
    on_exit(fn -> Application.delete_env(:phoenix_elxir_beam, AuditRetention) end)
    :ok
  end

  defp log_event(occurred_at) do
    {:ok, row} =
      EventLog.record(%AuditEvent{
        event_id: Ecto.UUID.generate(),
        session_id: "s-#{System.unique_integer([:positive])}",
        status: "ok",
        occurred_at: occurred_at
      })

    row
  end

  defp days_ago(n), do: DateTime.add(DateTime.utc_now(), -n * 86_400, :second)

  defp remaining_event_ids do
    PolicyEvent |> order_by(asc: :id) |> select([e], e.event_id) |> Repo.all()
  end

  test "a no-op when retention_days is unset" do
    old = log_event(days_ago(200))
    _anchor = log_event(days_ago(1))

    assert AuditRetention.prune(EventLog.last_hash()) == 0
    assert old.event_id in remaining_event_ids()
  end

  test "prunes rows older than retention_days that are before the anchor" do
    Application.put_env(:phoenix_elxir_beam, AuditRetention, retention_days: 30)

    old = log_event(days_ago(90))
    recent = log_event(days_ago(5))
    anchor = log_event(days_ago(1))
    after_anchor = log_event(DateTime.utc_now())

    assert AuditRetention.prune(anchor.hash) == 1

    ids = remaining_event_ids()
    refute old.event_id in ids
    assert recent.event_id in ids
    assert anchor.event_id in ids
    assert after_anchor.event_id in ids
  end

  test "never deletes the anchor row or anything at/after it, regardless of age" do
    Application.put_env(:phoenix_elxir_beam, AuditRetention, retention_days: 1)

    anchor = log_event(days_ago(400))
    after_anchor = log_event(days_ago(400))

    AuditRetention.prune(anchor.hash)

    ids = remaining_event_ids()
    assert anchor.event_id in ids
    assert after_anchor.event_id in ids
  end

  test "leaves rows within the retention window untouched even if before the anchor" do
    Application.put_env(:phoenix_elxir_beam, AuditRetention, retention_days: 30)

    recent = log_event(days_ago(2))
    anchor = log_event(days_ago(1))

    assert AuditRetention.prune(anchor.hash) == 0
    assert recent.event_id in remaining_event_ids()
  end

  test "a pruned table still verifies via verify_chain/0" do
    Application.put_env(:phoenix_elxir_beam, AuditRetention, retention_days: 30)

    _old = log_event(days_ago(90))
    _recent = log_event(days_ago(5))
    anchor = log_event(days_ago(1))
    _after = log_event(DateTime.utc_now())

    AuditRetention.prune(anchor.hash)

    assert EventLog.verify_chain() == :ok
  end

  test "an unknown anchor hash is a no-op" do
    Application.put_env(:phoenix_elxir_beam, AuditRetention, retention_days: 1)
    _old = log_event(days_ago(400))

    assert AuditRetention.prune("sha256:doesnotexist") == 0
  end
end
