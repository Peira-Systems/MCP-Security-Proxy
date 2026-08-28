defmodule PhoenixElxirBeam.MCP.PolicyEngine do
  @moduledoc """
  Owns canonical per-session state (the `MapSet` of tags seen per
  `session_id`), runs the plugin pipeline for every `tools/call`, and is the
  sole broadcaster of `PhoenixElxirBeam.MCP.Event` structs on the
  `"mcp:events"` PubSub topic.

  The actual allow/deny logic lives in `policy` plugins consulted through
  `PhoenixElxirBeam.MCP.Pipeline` (today just
  `PhoenixElxirBeam.MCP.Plugins.ChainExfil`: a `:network_egress` call is
  denied iff `:sensitive_read` is already in that session's seen-set —
  order matters, so an egress call before any sensitive read is allowed).
  This module builds a `PhoenixElxirBeam.MCP.CallContext` from its session
  state, maps the pipeline's `Decision` back to `{:allow | :block, Event}`,
  accumulates tags on an allow, and receipts the result.

  Three properties this engine is deliberately built around, since it sits
  as a policy decision point in a live request path:

    * Session lookups fail closed. `record_call/5` never treats a
      session_id it has no record of as a fresh, clean session — that
      would let lost state (a restart) or a caller that bypassed
      `ensure_session/2` silently re-open a session an earlier call had
      already tainted. A lookup miss is a block, not a skip.
    * Every verdict is receipted, allows included, not just blocks —
      otherwise "no record" and "recorded allow" are indistinguishable.
      Receipts fan out to every registered `auditSink`
      (`PhoenixElxirBeam.MCP.Plugin.Registry.active_sinks/1`; today just the
      hash-chained `PhoenixElxirBeam.MCP.Plugins.EventLogSink`), not just a
      PubSub broadcast to whichever dashboard happens to be subscribed.
    * Evidence recording (the durable receipt, the PubSub broadcast)
      happens strictly after the verdict is final and can never feed
      back into it.
  """

  use GenServer
  require Logger

  alias PhoenixElxirBeam.MCP.{AuditEvent, CallContext, Event, Pipeline}
  alias PhoenixElxirBeam.MCP.Plugin.Registry, as: PluginRegistry

  @pubsub PhoenixElxirBeam.PubSub
  @topic "mcp:events"

  @unknown_session_reason "blocked: no session state on record for this session id"
  @missing_session_reason "blocked: no session id presented"

  # Client API

  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    registry = Keyword.get(opts, :registry, PluginRegistry)
    GenServer.start_link(__MODULE__, %{registry: registry}, name: name)
  end

  @doc "Registers a new session and broadcasts `:session_start`."
  def start_session(session_id, scenario, name \\ __MODULE__) do
    GenServer.call(name, {:start_session, session_id, scenario})
  end

  @doc """
  Idempotently ensures `session_id` has session state on record, without
  disturbing any tags already accumulated for it. The proxy calls this on
  every request so that a later lookup miss in `record_call/5` is a real
  anomaly rather than the normal shape of a new session.
  """
  def ensure_session(session_id, name \\ __MODULE__) do
    GenServer.call(name, {:ensure_session, session_id})
  end

  @doc """
  Records a `tools/call` invocation, returns `{:allow, event}` or
  `{:block, event}`, and receipts the resulting event either way.
  """
  def record_call(session_id, server_id, tool_name, tags, name \\ __MODULE__) do
    GenServer.call(name, {:record_call, session_id, server_id, tool_name, tags})
  end

  @doc "Marks a session as finished and broadcasts `:session_complete`."
  def complete_session(session_id, name \\ __MODULE__) do
    GenServer.call(name, {:complete_session, session_id})
  end

  @doc """
  Receipts a `:blocked` event for a call the proxy refused before the
  pipeline — e.g. a `tools/call` to a tool a discovery scanner has
  quarantined. No session state is required or consulted.
  """
  def record_blocked(session_id, server_id, tool_name, reason, name \\ __MODULE__) do
    GenServer.call(name, {:record_blocked, session_id, server_id, tool_name, reason})
  end

  # Server callbacks

  @impl true
  def init(%{registry: registry}), do: {:ok, %{sessions: %{}, registry: registry}}

  @impl true
  def handle_call({:start_session, session_id, scenario}, _from, state) do
    state = put_in(state.sessions[session_id], %{scenario: scenario, tags: MapSet.new()})

    event = %Event{
      id: generate_id(),
      session_id: session_id,
      scenario: scenario,
      status: :session_start,
      timestamp: DateTime.utc_now()
    }

    receipt(event, state)
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:ensure_session, nil}, _from, state) do
    # No identity to key state on. Left unrecorded on purpose so a nil
    # session_id can never be silently pooled with other callers that
    # also have no session id — `record_call` fails closed on it instead.
    {:reply, :ok, state}
  end

  def handle_call({:ensure_session, session_id}, _from, state) do
    state =
      if Map.has_key?(state.sessions, session_id) do
        state
      else
        put_in(state.sessions[session_id], %{scenario: nil, tags: MapSet.new()})
      end

    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:record_blocked, session_id, server_id, tool_name, reason}, _from, state) do
    event = blocked_event(session_id, nil, server_id, tool_name, [], reason)
    receipt(event, state)
    {:reply, {:block, event}, state}
  end

  def handle_call({:record_call, nil, server_id, tool_name, tags}, _from, state) do
    event = blocked_event(nil, nil, server_id, tool_name, tags, @missing_session_reason)
    receipt(event, state)
    {:reply, {:block, event}, state}
  end

  def handle_call({:record_call, session_id, server_id, tool_name, tags}, _from, state) do
    case Map.get(state.sessions, session_id) do
      nil ->
        event =
          blocked_event(session_id, nil, server_id, tool_name, tags, @unknown_session_reason)

        receipt(event, state)
        {:reply, {:block, event}, state}

      session ->
        ctx =
          CallContext.new(%{
            phase: :pre_call,
            call: %{
              id: generate_id(),
              session_id: session_id,
              server_id: server_id,
              tool_name: tool_name,
              tags: tags,
              method: "tools/call"
            },
            session: %{seen_tags: MapSet.to_list(session.tags)}
          })

        {pipeline_verdict, decision, findings} =
          Pipeline.run(:pre_call, ctx, PluginRegistry.active_policies(:pre_call, state.registry))

        blocked? = pipeline_verdict == :deny
        {status, reason} = if blocked?, do: {:blocked, decision.reason}, else: {:ok, nil}

        state =
          if blocked? do
            state
          else
            update_in(state.sessions[session_id], fn existing ->
              %{existing | tags: MapSet.union(existing.tags, MapSet.new(tags))}
            end)
          end

        event = %Event{
          id: generate_id(),
          session_id: session_id,
          scenario: session.scenario,
          server_id: server_id,
          tool_name: tool_name,
          tags: tags,
          status: status,
          reason: reason,
          timestamp: DateTime.utc_now()
        }

        verdict = if blocked?, do: :block, else: :allow
        receipt(event, state, decisions: decisions_from(decision), findings: findings)
        {:reply, {verdict, event}, state}
    end
  end

  @impl true
  def handle_call({:complete_session, session_id}, _from, state) do
    scenario = get_in(state.sessions, [session_id, :scenario])

    event = %Event{
      id: generate_id(),
      session_id: session_id,
      scenario: scenario,
      status: :session_complete,
      timestamp: DateTime.utc_now()
    }

    receipt(event, state)
    {:reply, :ok, state}
  end

  defp blocked_event(session_id, scenario, server_id, tool_name, tags, reason) do
    %Event{
      id: generate_id(),
      session_id: session_id,
      scenario: scenario,
      server_id: server_id,
      tool_name: tool_name,
      tags: tags,
      status: :blocked,
      reason: reason,
      timestamp: DateTime.utc_now()
    }
  end

  defp decisions_from(%{deciding_plugin: nil}), do: []

  defp decisions_from(%{deciding_plugin: plugin, verdict: verdict, reason: reason}) do
    [%{plugin: plugin, verdict: verdict, reason: reason}]
  end

  # `event` already carries its final verdict by the time this runs. This
  # only broadcasts it and fans it out to the audit sinks — a failure in any
  # of those is swallowed rather than crashing the GenServer or the caller.
  # A crash here would wipe every in-flight session's state, which is a worse
  # fail-open than the write failure it would be reacting to.
  defp receipt(event, state, opts \\ []) do
    audit_event = AuditEvent.from_event(event, opts)

    try do
      broadcast(event)
    rescue
      error ->
        Logger.error(
          "PolicyEngine: failed to broadcast event #{event.id}: #{Exception.format(:error, error, __STACKTRACE__)}"
        )
    end

    for sink <- PluginRegistry.active_sinks(state.registry) do
      try do
        sink.module.record([audit_event])
      rescue
        # A test process that never checked out a sandboxed connection is
        # not a persistence failure worth alarming on.
        _error in [DBConnection.OwnershipError] ->
          Logger.debug(
            "PolicyEngine: audit sink #{sink.name}: no DB connection owned for event #{event.id}"
          )

        error ->
          Logger.error(
            "PolicyEngine: audit sink #{sink.name} failed for event #{event.id}: #{Exception.format(:error, error, __STACKTRACE__)}"
          )
      end
    end

    :ok
  end

  defp broadcast(event) do
    Phoenix.PubSub.broadcast(@pubsub, @topic, {:mcp_event, event})
  end

  # A per-boot counter isn't good enough now that events are durably
  # persisted across restarts — it resets to 1 each boot and collides
  # with ids already on record from an earlier run. Needs to be globally
  # unique instead.
  defp generate_id do
    Ecto.UUID.generate()
  end
end
