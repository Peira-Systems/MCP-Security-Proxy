defmodule PhoenixElxirBeam.MCP.Plugins.StructuredLogSinkTest do
  # Not async: the assertions depend on the global Logger level.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias PhoenixElxirBeam.MCP.{AuditEvent, Finding}
  alias PhoenixElxirBeam.MCP.Plugins.StructuredLogSink

  setup do
    prev = Logger.level()
    Logger.configure(level: :info)
    on_exit(fn -> Logger.configure(level: prev) end)
    :ok
  end

  defp event(overrides) do
    struct(
      %AuditEvent{
        event_id: "e-1",
        session_id: "s-1",
        status: :blocked,
        occurred_at: ~U[2026-08-28 12:00:00.000000Z]
      },
      overrides
    )
  end

  test "emits one parseable JSON line per event, prefixed mcp.audit" do
    ev =
      event(%{
        agent_id: "agent://ci-runner",
        scenario: :restricted_agent,
        server_id: "net",
        tool_name: "post_webhook",
        tags: [:network_egress],
        reason: "policy: agent ci-runner may not perform network egress",
        decisions: [%{plugin: "rule-engine", verdict: :deny, reason: nil}],
        findings: [Finding.new(%{type: "tainted_argument", severity: :critical, title: "x"})]
      })

    log = capture_log(fn -> assert :ok = StructuredLogSink.record([ev]) end)

    line = log |> String.split("\n") |> Enum.find(&String.contains?(&1, "mcp.audit "))
    json = line |> String.split("mcp.audit ", parts: 2) |> List.last() |> String.trim()

    assert {:ok, decoded} = Jason.decode(json)
    assert decoded["event_id"] == "e-1"
    assert decoded["agent_id"] == "agent://ci-runner"
    assert decoded["status"] == "blocked"
    assert decoded["tool"] == "post_webhook"
    assert decoded["tags"] == ["network_egress"]
    assert [%{"plugin" => "rule-engine", "verdict" => "deny"}] = decoded["decisions"]
    assert [%{"type" => "tainted_argument", "severity" => "critical"}] = decoded["findings"]
  end

  test "manifest declares an audit_sink" do
    manifest = StructuredLogSink.manifest()
    assert manifest.plugin.name == "structured-log"
    assert %{audit_sink: _} = manifest.capabilities
  end
end
