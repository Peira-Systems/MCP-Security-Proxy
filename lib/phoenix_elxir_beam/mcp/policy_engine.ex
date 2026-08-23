defmodule PhoenixElxirBeam.MCP.PolicyEngine do
  @moduledoc """
  Enforces the demo's tool-chaining policy and is the sole broadcaster of
  `PhoenixElxirBeam.MCP.Event` structs on the `"mcp:events"` PubSub topic.

  Keeps a `MapSet` of tags seen per `session_id`. A call tagged
  `:network_egress` is blocked iff `:sensitive_read` is already in that
  session's seen-set at the time of the call — order matters, so an egress
  call before any sensitive read is allowed.
  """

  use GenServer

  alias PhoenixElxirBeam.MCP.Event

  @pubsub PhoenixElxirBeam.PubSub
  @topic "mcp:events"

  @block_reason "network egress blocked: a sensitive read occurred earlier in this session"

  # Client API

  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, %{}, name: name)
  end

  @doc "Registers a new session and broadcasts `:session_start`."
  def start_session(session_id, scenario, name \\ __MODULE__) do
    GenServer.call(name, {:start_session, session_id, scenario})
  end

  @doc """
  Records a `tools/call` invocation, returns `{:allow, event}` or
  `{:block, event}`, and broadcasts the resulting event either way.
  """
  def record_call(session_id, server_id, tool_name, tags, name \\ __MODULE__) do
    GenServer.call(name, {:record_call, session_id, server_id, tool_name, tags})
  end

  @doc "Marks a session as finished and broadcasts `:session_complete`."
  def complete_session(session_id, name \\ __MODULE__) do
    GenServer.call(name, {:complete_session, session_id})
  end

  # Server callbacks

  @impl true
  def init(_), do: {:ok, %{sessions: %{}}}

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

    broadcast(event)
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:record_call, session_id, server_id, tool_name, tags}, _from, state) do
    session = Map.get(state.sessions, session_id, %{scenario: nil, tags: MapSet.new()})
    blocked? = MapSet.member?(session.tags, :sensitive_read) and :network_egress in tags

    {status, reason} = if blocked?, do: {:blocked, @block_reason}, else: {:ok, nil}

    state =
      if blocked? do
        state
      else
        update_in(state.sessions[session_id], fn
          nil -> %{scenario: session.scenario, tags: MapSet.new(tags)}
          existing -> %{existing | tags: MapSet.union(existing.tags, MapSet.new(tags))}
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

    broadcast(event)
    verdict = if blocked?, do: :block, else: :allow
    {:reply, {verdict, event}, state}
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

    broadcast(event)
    {:reply, :ok, state}
  end

  defp broadcast(event) do
    Phoenix.PubSub.broadcast(@pubsub, @topic, {:mcp_event, event})
  end

  defp generate_id do
    System.unique_integer([:positive, :monotonic]) |> Integer.to_string()
  end
end
