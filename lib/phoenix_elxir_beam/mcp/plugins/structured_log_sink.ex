defmodule PhoenixElxirBeam.MCP.Plugins.StructuredLogSink do
  @moduledoc """
  A second `auditSink`, alongside `PhoenixElxirBeam.MCP.Plugins.EventLogSink`:
  emits every `AuditEvent` as a single-line JSON object on the `Logger` at
  `:info`, prefixed `mcp.audit`. A log shipper (Vector, Fluent Bit, the OTel
  Collector's filelog receiver, a Splunk forwarder) tails stdout and forwards
  these to a SIEM — no core changes, just another plugin (`docs/plugin-protocol.md`
  §4.3).

  The line carries verdict metadata only — never raw finding evidence or the
  tracked secret. Finding `hint`s that reach the `title` are already redacted.
  """

  @behaviour PhoenixElxirBeam.MCP.Plugin.AuditSink

  require Logger

  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @impl true
  def manifest do
    Manifest.normalize(%{
      plugin: %{
        name: "structured-log",
        version: "0.1.0",
        description: "Emits each audit event as one JSON log line for SIEM / OTel ingestion."
      },
      capabilities: %{audit_sink: %{batch: false}}
    })
  end

  @impl true
  def record(events) do
    Enum.each(events, fn event ->
      Logger.info("mcp.audit " <> Jason.encode!(payload(event)))
    end)

    :ok
  end

  defp payload(e) do
    %{
      "event_id" => e.event_id,
      "ts" => iso(e.occurred_at),
      "session_id" => e.session_id,
      "agent_id" => e.agent_id,
      "scenario" => e.scenario && to_string(e.scenario),
      "server" => e.server_id,
      "tool" => e.tool_name,
      "tags" => Enum.map(e.tags, &to_string/1),
      "status" => to_string(e.status),
      "reason" => e.reason,
      "decisions" =>
        Enum.map(e.decisions, fn d ->
          %{"plugin" => d.plugin, "verdict" => to_string(d.verdict)}
        end),
      "findings" =>
        Enum.map(e.findings, fn f ->
          %{
            "type" => finding_field(f, :type),
            "severity" => to_string(finding_field(f, :severity))
          }
        end)
    }
  end

  defp iso(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp iso(other), do: other

  defp finding_field(%{__struct__: _} = f, key), do: Map.get(f, key)
  defp finding_field(f, key) when is_map(f), do: Map.get(f, key) || Map.get(f, to_string(key))
end
