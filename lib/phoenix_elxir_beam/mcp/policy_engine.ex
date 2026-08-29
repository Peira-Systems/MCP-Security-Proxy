defmodule PhoenixElxirBeam.MCP.PolicyEngine do
  @moduledoc """
  Owns canonical per-session state (the `MapSet` of tags seen per
  `session_id`), runs the plugin pipeline for every `tools/call`, and is the
  sole broadcaster of `PhoenixElxirBeam.MCP.Event` structs on the
  `"mcp:events"` PubSub topic.

  The actual verdict logic lives in `policy` plugins consulted through
  `PhoenixElxirBeam.MCP.Pipeline`. This module builds a
  `PhoenixElxirBeam.MCP.CallContext` from its session state, maps the
  pipeline's `Decision` back to `{:allow | :block | :hold, …}`, accumulates
  tags on an allow, and receipts the result. On `:hold` it parks the call in
  `PhoenixElxirBeam.MCP.HoldRegistry` and replies `{:hold, hold_id, …}`; the
  controller later drives `finalize_hold/6` from the operator's decision.

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

  alias PhoenixElxirBeam.MCP.{AuditEvent, CallContext, Event, HoldRegistry, Pipeline}
  alias PhoenixElxirBeam.MCP.Plugin.Registry, as: PluginRegistry

  @pubsub PhoenixElxirBeam.PubSub
  @topic "mcp:events"

  @unknown_session_reason "blocked: no session state on record for this session id"
  @missing_session_reason "blocked: no session id presented"

  # Client API

  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)

    init_arg = %{
      registry: Keyword.get(opts, :registry, PluginRegistry),
      hold_registry: Keyword.get(opts, :hold_registry, HoldRegistry)
    }

    GenServer.start_link(__MODULE__, init_arg, name: name)
  end

  @doc "Registers a new session and broadcasts `:session_start`."
  def start_session(session_id, scenario, agent_id \\ nil, name \\ __MODULE__) do
    GenServer.call(name, {:start_session, session_id, scenario, agent_id})
  end

  @doc """
  Idempotently ensures `session_id` has session state on record, without
  disturbing any tags already accumulated for it. The proxy calls this on
  every request so that a later lookup miss in `record_call/5` is a real
  anomaly rather than the normal shape of a new session.

  `agent_id` is recorded the first time it is seen for a session and is
  never overwritten or downgraded to `nil` afterwards — a session's agent
  identity is fixed once established.
  """
  def ensure_session(session_id, agent_id \\ nil, name \\ __MODULE__) do
    GenServer.call(name, {:ensure_session, session_id, agent_id})
  end

  @doc """
  Records a `tools/call` invocation, returns `{:allow, event}` or
  `{:block, event}`, and receipts the resulting event either way.

  `arguments` (the tool call's `params.arguments`) is threaded into the
  `pre_call` `CallContext` so argument-inspecting policies — e.g.
  `PhoenixElxirBeam.MCP.Plugins.TaintedArgGuard` — can see it. It trails
  `name` so the many `arity/5` callers keep working unchanged.
  """
  def record_call(session_id, server_id, tool_name, tags, name \\ __MODULE__, arguments \\ %{}) do
    GenServer.call(name, {:record_call, session_id, server_id, tool_name, tags, arguments})
  end

  @doc "Marks a session as finished and broadcasts `:session_complete`."
  def complete_session(session_id, name \\ __MODULE__) do
    GenServer.call(name, {:complete_session, session_id})
  end

  @doc """
  Resolves a previously `:hold`-ed call once the operator (or the timeout)
  has decided. `:approved` accumulates the call's tags and receipts an `:ok`
  event; `:denied` receipts a `:blocked` event.
  """
  def finalize_hold(session_id, server_id, tool_name, tags, outcome, name \\ __MODULE__)
      when outcome in [:approved, :denied] do
    GenServer.call(name, {:finalize_hold, session_id, server_id, tool_name, tags, outcome})
  end

  @doc """
  Receipts a `:blocked` event for a call the proxy refused before the
  pipeline — e.g. a `tools/call` to a tool a discovery scanner has
  quarantined. No session state is required or consulted.
  """
  def record_blocked(session_id, server_id, tool_name, reason, name \\ __MODULE__) do
    GenServer.call(name, {:record_blocked, session_id, server_id, tool_name, reason})
  end

  @doc """
  Receipts the result of a `post_call` response scan and folds any
  `taint_sources` the scan produced into the session's taint provenance.
  Skipped entirely when the scan was clean (no findings, no taint, not
  withheld). `withheld` is `nil` for a delivered response, or the reason
  string when the whole response was discarded → a `:blocked` event.
  """
  def record_response_scan(
        session_id,
        server_id,
        tool_name,
        findings,
        withheld,
        taint_sources \\ [],
        name \\ __MODULE__
      )

  def record_response_scan(_s, _sv, _t, [], nil, [], _name), do: :ok

  def record_response_scan(
        session_id,
        server_id,
        tool_name,
        findings,
        withheld,
        taint_sources,
        name
      ) do
    GenServer.call(
      name,
      {:record_response_scan, session_id, server_id, tool_name, findings, withheld, taint_sources}
    )
  end

  # Server callbacks

  @impl true
  def init(%{registry: registry, hold_registry: hold_registry}) do
    {:ok, %{sessions: %{}, registry: registry, hold_registry: hold_registry}}
  end

  @impl true
  def handle_call({:start_session, session_id, scenario, agent_id}, _from, state) do
    state =
      put_in(state.sessions[session_id], %{
        scenario: scenario,
        tags: MapSet.new(),
        taint: [],
        agent_id: agent_id
      })

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
  def handle_call({:ensure_session, nil, _agent_id}, _from, state) do
    # No identity to key state on. Left unrecorded on purpose so a nil
    # session_id can never be silently pooled with other callers that
    # also have no session id — `record_call` fails closed on it instead.
    {:reply, :ok, state}
  end

  def handle_call({:ensure_session, session_id, agent_id}, _from, state) do
    state =
      case Map.get(state.sessions, session_id) do
        nil ->
          put_in(state.sessions[session_id], %{
            scenario: nil,
            tags: MapSet.new(),
            taint: [],
            agent_id: agent_id
          })

        %{agent_id: nil} = existing when not is_nil(agent_id) ->
          put_in(state.sessions[session_id], %{existing | agent_id: agent_id})

        _existing ->
          state
      end

    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:record_blocked, session_id, server_id, tool_name, reason}, _from, state) do
    event = blocked_event(session_id, nil, server_id, tool_name, [], reason)
    receipt(event, state)
    {:reply, {:block, event}, state}
  end

  def handle_call(
        {:record_response_scan, session_id, server_id, tool_name, findings, withheld,
         taint_sources},
        _from,
        state
      ) do
    scenario = get_in(state.sessions, [session_id, :scenario])
    state = accumulate_taint(state, session_id, taint_sources)

    {status, reason} =
      if withheld, do: {:blocked, withheld}, else: {:ok, nil}

    event = %Event{
      id: generate_id(),
      session_id: session_id,
      scenario: scenario,
      server_id: server_id,
      tool_name: tool_name,
      status: status,
      reason: reason,
      findings: findings,
      timestamp: DateTime.utc_now()
    }

    receipt(event, state, findings: findings)
    {:reply, :ok, state}
  end

  def handle_call({:record_call, nil, server_id, tool_name, tags, _arguments}, _from, state) do
    event = blocked_event(nil, nil, server_id, tool_name, tags, @missing_session_reason)
    receipt(event, state)
    {:reply, {:block, event}, state}
  end

  def handle_call({:record_call, session_id, server_id, tool_name, tags, arguments}, _from, state) do
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
              agent_id: session.agent_id,
              server_id: server_id,
              tool_name: tool_name,
              tags: tags,
              arguments: arguments,
              method: "tools/call"
            },
            session: %{
              seen_tags: MapSet.to_list(session.tags),
              taint: %{sources: session.taint}
            }
          })

        {pipeline_verdict, decision, findings} =
          Pipeline.run(:pre_call, ctx, PluginRegistry.active_policies(:pre_call, state.registry))

        opts = [decisions: decisions_from(decision), findings: findings]
        meta = {session, session_id, server_id, tool_name, tags}

        case pipeline_verdict do
          :hold -> reply_hold(meta, decision, opts, state)
          :deny -> reply_verdict(meta, :blocked, decision.reason, opts, state)
          :allow -> reply_verdict(meta, :ok, nil, opts, accumulate_tags(state, session_id, tags))
        end
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

  @impl true
  def handle_call({:finalize_hold, session_id, server_id, tool_name, tags, outcome}, _from, state) do
    scenario = get_in(state.sessions, [session_id, :scenario])

    {reply_verdict, status, reason, state} =
      case outcome do
        :approved ->
          state =
            if Map.has_key?(state.sessions, session_id),
              do: accumulate_tags(state, session_id, tags),
              else: state

          {:allow, :ok, nil, state}

        :denied ->
          {:block, :blocked, "network egress denied by operator", state}
      end

    event = %Event{
      id: generate_id(),
      session_id: session_id,
      scenario: scenario,
      server_id: server_id,
      tool_name: tool_name,
      tags: tags,
      status: status,
      reason: reason,
      timestamp: DateTime.utc_now()
    }

    receipt(event, state)
    {:reply, {reply_verdict, event}, state}
  end

  defp accumulate_tags(state, session_id, tags) do
    update_in(state.sessions[session_id], fn existing ->
      %{existing | tags: MapSet.union(existing.tags, MapSet.new(tags))}
    end)
  end

  # Appends taint sources to the session's provenance, deduped on the tracked
  # secret (or, absent one, {origin_tool, finding_type}). A no-op for an
  # unknown / nil session id — a scan without recorded session state can't
  # taint anything.
  defp accumulate_taint(state, _session_id, []), do: state

  defp accumulate_taint(state, session_id, sources) do
    if Map.has_key?(state.sessions, session_id) do
      update_in(state.sessions[session_id], fn existing ->
        seen = MapSet.new(existing.taint, &taint_key/1)
        fresh = Enum.reject(sources, &MapSet.member?(seen, taint_key(&1)))
        %{existing | taint: existing.taint ++ fresh}
      end)
    else
      state
    end
  end

  defp taint_key(%{secret: secret}) when is_binary(secret), do: {:secret, secret}
  defp taint_key(source), do: {source[:origin_tool], source[:finding_type]}

  defp reply_verdict(
         {session, session_id, server_id, tool_name, tags},
         status,
         reason,
         opts,
         state
       ) do
    event = %Event{
      id: generate_id(),
      session_id: session_id,
      scenario: session.scenario,
      server_id: server_id,
      tool_name: tool_name,
      tags: tags,
      status: status,
      reason: reason,
      findings: Keyword.get(opts, :findings, []),
      timestamp: DateTime.utc_now()
    }

    receipt(event, state, opts)
    {:reply, {if(status == :ok, do: :allow, else: :block), event}, state}
  end

  defp reply_hold({session, session_id, server_id, tool_name, tags}, decision, opts, state) do
    hold = decision.hold || %{prompt: decision.reason, timeout_ms: 120_000, on_timeout: :deny}

    hold_id =
      HoldRegistry.park(
        %{
          prompt: hold.prompt,
          reason: decision.reason,
          session_id: session_id,
          server_id: server_id,
          tool_name: tool_name,
          tags: tags,
          timeout_ms: hold.timeout_ms,
          on_timeout: hold.on_timeout
        },
        state.hold_registry
      )

    event = %Event{
      id: generate_id(),
      session_id: session_id,
      scenario: session.scenario,
      server_id: server_id,
      tool_name: tool_name,
      tags: tags,
      status: :held,
      reason: decision.reason,
      timestamp: DateTime.utc_now()
    }

    receipt(event, state, opts)
    {:reply, {:hold, hold_id, hold.timeout_ms, event}, state}
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
    # A session's agent identity lives in session state, not on every Event
    # construction site — stamp it here, on the way out.
    agent_id = event.agent_id || get_in(state.sessions, [event.session_id, :agent_id])
    event = %{event | agent_id: agent_id}
    audit_event = AuditEvent.from_event(event, Keyword.put_new(opts, :agent_id, agent_id))

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
