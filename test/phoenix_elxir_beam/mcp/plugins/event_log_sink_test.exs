defmodule PhoenixElxirBeam.MCP.Plugins.EventLogSinkTest do
  use PhoenixElxirBeam.DataCase, async: true

  alias PhoenixElxirBeam.MCP.{AuditEvent, EventLog}
  alias PhoenixElxirBeam.MCP.Plugins.EventLogSink

  defp audit(attrs) do
    struct(
      AuditEvent,
      Map.merge(
        %{
          event_id: "evt-#{System.unique_integer([:positive])}",
          session_id: "s-1",
          scenario: :attack,
          server_id: "net",
          tool_name: "post_webhook",
          tags: [:network_egress],
          status: :blocked,
          reason: "nope",
          occurred_at: DateTime.utc_now(),
          decisions: [%{plugin: "chain-exfil", verdict: :deny, reason: "nope"}],
          findings: []
        },
        attrs
      )
    )
  end

  test "record/1 persists each audit event to the log" do
    :ok = EventLogSink.record([audit(%{event_id: "sink-a"}), audit(%{event_id: "sink-b"})])

    %{entries: entries} = EventLog.list()
    assert "sink-a" in Enum.map(entries, & &1.event_id)
    assert "sink-b" in Enum.map(entries, & &1.event_id)
  end

  test "manifest declares an enabled-by-default audit_sink" do
    manifest = EventLogSink.manifest()

    assert manifest.plugin.name == "event-log"
    assert %{audit_sink: sink} = manifest.capabilities
    assert sink.batch == false
  end
end
