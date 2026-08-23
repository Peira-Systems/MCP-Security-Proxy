defmodule PhoenixElxirBeam.MCP.PolicyEngineTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.PolicyEngine

  setup do
    name = :"policy_engine_#{System.unique_integer([:positive])}"
    start_supervised!({PolicyEngine, name: name})
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
end
