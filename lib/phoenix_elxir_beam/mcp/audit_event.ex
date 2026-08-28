defmodule PhoenixElxirBeam.MCP.AuditEvent do
  @moduledoc """
  The finalized record handed to every `auditSink` — a superset of
  `PhoenixElxirBeam.MCP.Event` (`docs/plugin-protocol.md` §7.4). Where
  `Event` is the lean shape broadcast to live dashboards, `AuditEvent`
  carries what durable storage / export cares about: the `decisions` the
  pipeline made (which plugin returned which verdict) and the `findings`
  scanners produced.

  Built by `PhoenixElxirBeam.MCP.PolicyEngine` after a verdict is final.
  """

  alias PhoenixElxirBeam.MCP.{Event, Finding}

  @enforce_keys [:event_id, :session_id, :status, :occurred_at]
  defstruct [
    :event_id,
    :call_id,
    :session_id,
    :agent_id,
    :scenario,
    :server_id,
    :tool_name,
    :reason,
    :occurred_at,
    tags: [],
    status: :ok,
    decisions: [],
    findings: []
  ]

  @type decision :: %{plugin: String.t() | nil, verdict: atom(), reason: String.t() | nil}

  @type t :: %__MODULE__{
          event_id: String.t(),
          call_id: String.t() | nil,
          session_id: String.t() | nil,
          agent_id: String.t() | nil,
          scenario: atom() | nil,
          server_id: String.t() | nil,
          tool_name: String.t() | nil,
          reason: String.t() | nil,
          occurred_at: DateTime.t(),
          tags: [atom()],
          status: Event.status(),
          decisions: [decision()],
          findings: [Finding.t()]
        }

  @doc """
  Lifts an `Event` into an `AuditEvent`. `opts` supplies the fields `Event`
  does not carry: `:decisions`, `:findings`, `:call_id`, `:agent_id`.
  """
  @spec from_event(Event.t(), keyword()) :: t()
  def from_event(%Event{} = event, opts \\ []) do
    %__MODULE__{
      event_id: event.id,
      call_id: Keyword.get(opts, :call_id),
      session_id: event.session_id,
      agent_id: Keyword.get(opts, :agent_id),
      scenario: event.scenario,
      server_id: event.server_id,
      tool_name: event.tool_name,
      reason: event.reason,
      occurred_at: event.timestamp,
      tags: event.tags,
      status: event.status,
      decisions: Keyword.get(opts, :decisions, []),
      findings: Keyword.get(opts, :findings, [])
    }
  end
end
