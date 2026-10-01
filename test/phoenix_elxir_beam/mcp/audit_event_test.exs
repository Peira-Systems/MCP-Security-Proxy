defmodule PhoenixElxirBeam.MCP.AuditEventTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.{AuditEvent, Event}

  defp event(attrs \\ %{}) do
    struct(
      Event,
      Map.merge(
        %{
          id: "evt-1",
          session_id: "s-1",
          scenario: :attack,
          server_id: "net",
          tool_name: "post_webhook",
          tags: [:network_egress],
          status: :blocked,
          reason: "nope",
          timestamp: ~U[2026-08-28 10:00:00.000000Z]
        },
        attrs
      )
    )
  end

  test "from_event/2 maps Event fields and defaults decisions/findings/call_chain to []" do
    audit = AuditEvent.from_event(event())

    assert audit.event_id == "evt-1"
    assert audit.occurred_at == ~U[2026-08-28 10:00:00.000000Z]
    assert audit.status == :blocked
    assert audit.tags == [:network_egress]
    assert audit.decisions == []
    assert audit.findings == []
    assert audit.call_id == nil
    assert audit.call_chain == []
  end

  test "from_event/2 carries call_chain from opts" do
    chain = [
      %{
        call_id: "c-1",
        tool_name: "read_secrets",
        tags: [:sensitive_read],
        at: ~U[2026-08-28 09:59:00.000000Z]
      }
    ]

    audit = AuditEvent.from_event(event(), call_chain: chain)

    assert audit.call_chain == chain
  end

  test "from_event/2 carries decisions, findings, call_id, agent_id from opts" do
    audit =
      AuditEvent.from_event(event(),
        decisions: [%{plugin: "chain-exfil", verdict: :deny, reason: "nope"}],
        findings: [%{type: "rug_pull"}],
        call_id: "c-9",
        agent_id: "agent://ci"
      )

    assert [%{plugin: "chain-exfil"}] = audit.decisions
    assert [%{type: "rug_pull"}] = audit.findings
    assert audit.call_id == "c-9"
    assert audit.agent_id == "agent://ci"
  end
end
