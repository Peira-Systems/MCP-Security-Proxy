defmodule PhoenixElxirBeam.MCP.Plugins.EventLogSink do
  @moduledoc """
  The built-in `auditSink`: persists every `AuditEvent` to the local,
  hash-chained `policy_events` table via `PhoenixElxirBeam.MCP.EventLog`.

  It runs alongside `PhoenixElxirBeam.MCP.Plugins.StructuredLogSink` (JSON log
  lines for SIEM / OTel ingestion) — two sinks, no core changes, just two
  entries in the `plugins:` list; see `docs/plugin-protocol.md` §4.3.
  """

  @behaviour PhoenixElxirBeam.MCP.Plugin.AuditSink

  require Logger

  alias PhoenixElxirBeam.MCP.EventLog
  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @impl true
  def manifest do
    Manifest.normalize(%{
      plugin: %{
        name: "event-log",
        version: "0.1.0",
        description: "Durable, hash-chained local audit log (policy_events table)."
      },
      capabilities: %{audit_sink: %{batch: false}}
    })
  end

  @impl true
  def record(events) do
    Enum.each(events, fn event ->
      case EventLog.record(event) do
        {:ok, _row} ->
          :ok

        {:error, changeset} ->
          Logger.error(
            "EventLogSink: failed to persist audit event #{event.event_id}: #{inspect(changeset.errors)}"
          )
      end
    end)

    :ok
  end
end
