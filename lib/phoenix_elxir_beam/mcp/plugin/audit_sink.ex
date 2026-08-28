defmodule PhoenixElxirBeam.MCP.Plugin.AuditSink do
  @moduledoc """
  Behaviour for an `auditSink` plugin: receives the finalized
  `PhoenixElxirBeam.MCP.AuditEvent` stream for durable storage or export
  (SIEM, OpenTelemetry, object storage). Invoked off the request path.

  `PhoenixElxirBeam.MCP.PolicyEngine` fans out to every enabled sink
  (`Plugin.Registry.active_sinks/1`) synchronously after a verdict is final,
  one event per call. Batching (`Manifest.AuditSink` `batch` / `max_batch` /
  `flush_interval_ms`) is declared but not honoured yet — `record/1` should
  tolerate a one-element list. See `docs/plugin-protocol.md` §4.3.
  """

  alias PhoenixElxirBeam.MCP.AuditEvent
  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @callback manifest() :: Manifest.t()

  @callback record(events :: [AuditEvent.t()]) :: :ok
end
