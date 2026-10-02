defmodule PhoenixElxirBeam.MCP.EventLogTest do
  use PhoenixElxirBeam.DataCase, async: true

  import Ecto.Query

  alias PhoenixElxirBeam.MCP.{AuditEvent, EventLog, PolicyEvent}

  defp event(attrs) do
    defaults = %{
      event_id: "evt-#{System.unique_integer([:positive, :monotonic])}",
      session_id: "session-1",
      scenario: :attack,
      server_id: "files",
      tool_name: "read_secrets",
      tags: [:sensitive_read],
      status: :ok,
      reason: nil,
      occurred_at: DateTime.utc_now(),
      decisions: [],
      findings: []
    }

    struct(AuditEvent, Map.merge(defaults, attrs))
  end

  test "record/1 persists an event and list/1 returns it, most recent first" do
    {:ok, _} = EventLog.record(event(%{event_id: "evt-a", occurred_at: hours_ago(2)}))
    {:ok, _} = EventLog.record(event(%{event_id: "evt-b", occurred_at: hours_ago(1)}))

    %{entries: entries, total_count: total_count} = EventLog.list()

    assert total_count == 2
    assert Enum.map(entries, & &1.event_id) == ["evt-b", "evt-a"]
  end

  test "list/1 filters by status" do
    {:ok, _} = EventLog.record(event(%{event_id: "evt-allowed", status: :ok}))

    {:ok, _} =
      EventLog.record(event(%{event_id: "evt-blocked", status: :blocked, reason: "nope"}))

    %{entries: blocked} = EventLog.list(%{status: "blocked"})
    assert Enum.map(blocked, & &1.event_id) == ["evt-blocked"]

    %{entries: allowed} = EventLog.list(%{status: "ok"})
    assert Enum.map(allowed, & &1.event_id) == ["evt-allowed"]
  end

  test "list/1 filters by server_id" do
    {:ok, _} = EventLog.record(event(%{event_id: "evt-files", server_id: "files"}))
    {:ok, _} = EventLog.record(event(%{event_id: "evt-net", server_id: "net"}))

    %{entries: entries} = EventLog.list(%{server_id: "net"})
    assert Enum.map(entries, & &1.event_id) == ["evt-net"]
  end

  test "list/1 filters by an inclusive date range" do
    {:ok, _} = EventLog.record(event(%{event_id: "evt-old", occurred_at: hours_ago(10)}))
    {:ok, _} = EventLog.record(event(%{event_id: "evt-recent", occurred_at: hours_ago(1)}))

    %{entries: entries} = EventLog.list(%{from: hours_ago(3), to: hours_ago(0)})
    assert Enum.map(entries, & &1.event_id) == ["evt-recent"]
  end

  test "list/1 pages results" do
    for i <- 1..5 do
      {:ok, _} = EventLog.record(event(%{event_id: "evt-#{i}", occurred_at: hours_ago(5 - i)}))
    end

    %{entries: page1, total_pages: total_pages, total_count: total_count} =
      EventLog.list(%{page: 1, page_size: 2})

    assert total_count == 5
    assert total_pages == 3
    assert Enum.map(page1, & &1.event_id) == ["evt-5", "evt-4"]

    %{entries: page2} = EventLog.list(%{page: 2, page_size: 2})
    assert Enum.map(page2, & &1.event_id) == ["evt-3", "evt-2"]
  end

  test "distinct_server_ids/0 lists servers seen in the log, excluding nils" do
    {:ok, _} = EventLog.record(event(%{event_id: "evt-1", server_id: "files"}))
    {:ok, _} = EventLog.record(event(%{event_id: "evt-2", server_id: "net"}))

    {:ok, _} =
      EventLog.record(event(%{event_id: "evt-3", server_id: nil, status: :session_start}))

    assert EventLog.distinct_server_ids() == ["files", "net"]
  end

  test "record/1 chains rows: first prev_hash is nil, each row links to the previous" do
    {:ok, a} = EventLog.record(event(%{event_id: "evt-a"}))
    {:ok, b} = EventLog.record(event(%{event_id: "evt-b"}))

    assert a.prev_hash == nil
    assert is_binary(a.hash)
    assert b.prev_hash == a.hash
    assert b.hash != a.hash
  end

  test "persists decisions and reads them back as maps" do
    {:ok, _} =
      EventLog.record(
        event(%{
          event_id: "evt-d",
          status: :blocked,
          reason: "nope",
          decisions: [%{plugin: "chain-exfil", verdict: :deny, reason: "nope"}]
        })
      )

    %{entries: [row]} = EventLog.list(%{status: "blocked"})
    assert [%{"plugin" => "chain-exfil", "verdict" => "deny"}] = row.decisions
  end

  test "persists call_chain and reads it back, and it does not affect the chain hash" do
    chain = [
      %{call_id: "c-1", tool_name: "read_secrets", tags: [:sensitive_read], at: hours_ago(1)}
    ]

    {:ok, _} =
      EventLog.record(
        event(%{
          event_id: "evt-e",
          status: :blocked,
          reason: "nope",
          call_chain: chain
        })
      )

    {:ok, _} =
      EventLog.record(event(%{event_id: "evt-f", status: :blocked, reason: "nope"}))

    %{entries: [without_chain, with_chain]} = EventLog.list(%{status: "blocked"})

    assert [%{"tool_name" => "read_secrets"}] = with_chain.call_chain
    assert without_chain.call_chain == []
    assert EventLog.verify_chain() == :ok
  end

  test "verify_chain/0 returns :ok for an untouched log" do
    for i <- 1..4, do: {:ok, _} = EventLog.record(event(%{event_id: "evt-#{i}"}))
    assert EventLog.verify_chain() == :ok
  end

  test "verify_chain/0 flags the first row whose stored content was altered" do
    {:ok, _} = EventLog.record(event(%{event_id: "evt-1"}))
    {:ok, _} = EventLog.record(event(%{event_id: "evt-2", status: :blocked, reason: "orig"}))
    {:ok, _} = EventLog.record(event(%{event_id: "evt-3"}))

    # Tamper directly, bypassing record/1 (which would recompute the hash).
    {1, _} =
      Repo.update_all(
        from(e in PolicyEvent, where: e.event_id == "evt-2"),
        set: [reason: "tampered"]
      )

    assert {:error, %{event_id: "evt-2"}} = EventLog.verify_chain()
  end

  defp hours_ago(n), do: DateTime.add(DateTime.utc_now(), -n * 3600, :second)
end
