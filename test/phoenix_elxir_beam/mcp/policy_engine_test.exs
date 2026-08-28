defmodule PhoenixElxirBeam.MCP.PolicyEngineTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.{EventLog, PolicyEngine}
  alias PhoenixElxirBeam.Repo

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)

    name = :"policy_engine_#{System.unique_integer([:positive])}"
    {:ok, pid} = start_supervised({PolicyEngine, name: name})
    # PolicyEngine persists every verdict from its own GenServer process —
    # let it borrow this test's sandboxed connection so that write is
    # visible (and rolled back) within this test rather than erroring.
    Ecto.Adapters.SQL.Sandbox.allow(Repo, self(), pid)

    %{name: name}
  end

  test "benign two-call sequence is entirely allowed", %{name: name} do
    session_id = "session-benign"
    :ok = PolicyEngine.start_session(session_id, :benign, name)

    assert {:allow, event1} =
             PolicyEngine.record_call(session_id, "files", "list_files", [], name)

    assert event1.status == :ok

    assert {:allow, event2} =
             PolicyEngine.record_call(session_id, "net", "check_status", [], name)

    assert event2.status == :ok
  end

  test "network egress after a sensitive read in the same session is blocked", %{name: name} do
    session_id = "session-attack"
    :ok = PolicyEngine.start_session(session_id, :attack, name)

    assert {:allow, _event} =
             PolicyEngine.record_call(
               session_id,
               "files",
               "read_secrets",
               [:sensitive_read],
               name
             )

    assert {:block, event} =
             PolicyEngine.record_call(session_id, "net", "post_webhook", [:network_egress], name)

    assert event.status == :blocked
    assert is_binary(event.reason)
  end

  test "same tools split across two different session ids do not leak across sessions", %{
    name: name
  } do
    session_a = "session-a"
    session_b = "session-b"
    :ok = PolicyEngine.start_session(session_a, :attack, name)
    :ok = PolicyEngine.start_session(session_b, :attack, name)

    assert {:allow, _event} =
             PolicyEngine.record_call(session_a, "files", "read_secrets", [:sensitive_read], name)

    assert {:allow, event} =
             PolicyEngine.record_call(session_b, "net", "post_webhook", [:network_egress], name)

    assert event.status == :ok
  end

  test "a call for a session with no state on record fails closed", %{name: name} do
    assert {:block, event} =
             PolicyEngine.record_call("never-started", "files", "list_files", [], name)

    assert event.status == :blocked
    assert event.reason =~ "no session state on record"
  end

  test "a call with no session id fails closed", %{name: name} do
    assert {:block, event} = PolicyEngine.record_call(nil, "files", "list_files", [], name)

    assert event.status == :blocked
    assert event.reason =~ "no session id"
  end

  test "ensure_session is idempotent and never resets tags already accumulated", %{name: name} do
    session_id = "session-ensure"
    :ok = PolicyEngine.ensure_session(session_id, name)

    assert {:allow, _event} =
             PolicyEngine.record_call(
               session_id,
               "files",
               "read_secrets",
               [:sensitive_read],
               name
             )

    :ok = PolicyEngine.ensure_session(session_id, name)

    assert {:block, event} =
             PolicyEngine.record_call(session_id, "net", "post_webhook", [:network_egress], name)

    assert event.status == :blocked
  end

  test "record_blocked/5 receipts a blocked event without needing session state", %{name: name} do
    assert {:block, event} =
             PolicyEngine.record_blocked(
               "no-session",
               "real-abc",
               "note",
               "tool definition changed since registration",
               name
             )

    assert event.status == :blocked
    assert event.reason =~ "changed since registration"

    %{entries: entries} = EventLog.list(%{page_size: 100})
    assert Enum.any?(entries, &(&1.event_id == event.id and &1.status == "blocked"))
  end

  test "verdicts are durably persisted for allows as well as blocks", %{name: name} do
    session_id = "session-receipts"
    :ok = PolicyEngine.start_session(session_id, :benign, name)

    assert {:allow, allow_event} =
             PolicyEngine.record_call(session_id, "files", "list_files", [], name)

    assert {:block, block_event} =
             PolicyEngine.record_call("never-started", "net", "post_webhook", [], name)

    %{entries: entries} = EventLog.list(%{page_size: 100})
    entry_ids = Enum.map(entries, & &1.event_id)

    assert allow_event.id in entry_ids
    assert block_event.id in entry_ids

    assert Enum.find(entries, &(&1.event_id == allow_event.id)).status == "ok"
  end
end
