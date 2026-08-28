defmodule PhoenixElxirBeam.MCP.Plugin.AuditSink do
  @moduledoc """
  Behaviour for an `auditSink` plugin: receives the finalized event +
  finding stream for durable storage or export (SIEM, OpenTelemetry, object
  storage). Invoked off the request path.

  Defined now for the contract's completeness (`docs/plugin-protocol.md`
  §4.3 / §13). Roadmap step 4 moves `PhoenixElxirBeam.MCP.EventLog` behind
  this behaviour and introduces the `AuditEvent` struct with `prev_hash`
  chaining; until then `events` is a list of `PhoenixElxirBeam.MCP.Event`.
  """

  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @callback manifest() :: Manifest.t()

  @callback record(events :: [struct()]) :: :ok
end
