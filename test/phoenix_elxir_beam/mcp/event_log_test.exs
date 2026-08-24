defmodule PhoenixElxirBeam.MCP.EventLogTest do
  use PhoenixElxirBeam.DataCase, async: true

  alias PhoenixElxirBeam.MCP.{Event, EventLog}

  defp event(attrs) do
    defaults = %{
      id: "evt-#{System.unique_integer([:positive, :monotonic])}",
      session_id: "session-1",
      scenario: :attack,
      server_id: "files",
      tool_name: "read_secrets",
      tags: [:sensitive_read],
      status: :ok,
      reason: nil,
      timestamp: DateTime.utc_now()
    }

    struct(Event, Map.merge(defaults, attrs))
  end

  test "record/1 persists an event and list/1 returns it, most recent first" do
    {:ok, _} = EventLog.record(event(%{id: "evt-a", timestamp: hours_ago(2)}))
    {:ok, _} = EventLog.record(event(%{id: "evt-b", timestamp: hours_ago(1)}))

    %{entries: entries, total_count: total_count} = EventLog.list()

    assert total_count == 2
    assert Enum.map(entries, & &1.event_id) == ["evt-b", "evt-a"]
  end

  test "list/1 filters by status" do
    {:ok, _} = EventLog.record(event(%{id: "evt-allowed", status: :ok}))
    {:ok, _} = EventLog.record(event(%{id: "evt-blocked", status: :blocked, reason: "nope"}))

    %{entries: blocked} = EventLog.list(%{status: "blocked"})
    assert Enum.map(blocked, & &1.event_id) == ["evt-blocked"]

    %{entries: allowed} = EventLog.list(%{status: "ok"})
    assert Enum.map(allowed, & &1.event_id) == ["evt-allowed"]
  end

  test "list/1 filters by server_id" do
    {:ok, _} = EventLog.record(event(%{id: "evt-files", server_id: "files"}))
    {:ok, _} = EventLog.record(event(%{id: "evt-net", server_id: "net"}))

    %{entries: entries} = EventLog.list(%{server_id: "net"})
    assert Enum.map(entries, & &1.event_id) == ["evt-net"]
  end

  test "list/1 filters by an inclusive date range" do
    {:ok, _} = EventLog.record(event(%{id: "evt-old", timestamp: hours_ago(10)}))
    {:ok, _} = EventLog.record(event(%{id: "evt-recent", timestamp: hours_ago(1)}))

    %{entries: entries} = EventLog.list(%{from: hours_ago(3), to: hours_ago(0)})
    assert Enum.map(entries, & &1.event_id) == ["evt-recent"]
  end

  test "list/1 pages results" do
    for i <- 1..5 do
      {:ok, _} = EventLog.record(event(%{id: "evt-#{i}", timestamp: hours_ago(5 - i)}))
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
    {:ok, _} = EventLog.record(event(%{id: "evt-1", server_id: "files"}))
    {:ok, _} = EventLog.record(event(%{id: "evt-2", server_id: "net"}))
    {:ok, _} = EventLog.record(event(%{id: "evt-3", server_id: nil, status: :session_start}))

    assert EventLog.distinct_server_ids() == ["files", "net"]
  end

  defp hours_ago(n), do: DateTime.add(DateTime.utc_now(), -n * 3600, :second)
end
