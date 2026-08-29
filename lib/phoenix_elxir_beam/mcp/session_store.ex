defmodule PhoenixElxirBeam.MCP.SessionStore do
  @moduledoc """
  Owns the table of live proxy MCP sessions (`PhoenixElxirBeam.MCP.Session`).

  In-memory for now; `docs/productionization-plan.md` M2.2 moves this to
  Postgres so sessions survive a restart. The API here is written to make
  that swap mechanical — every mutation goes through this module.

  Bounds enforced:

    * **Idle TTL** — a session not seen for `idle_ttl_ms` is dropped by the
      periodic GC.
    * **Hard cap** — at `max_sessions`, opening a new session first evicts
      the least-recently-seen one.

  Both a drop and an eviction call `PolicyEngine.complete_session/1` +
  `PolicyEngine.drop_session/1` so the per-session policy state (tags, taint,
  call log) does not outlive the session, and an audit `:session_complete`
  event is receipted.
  """

  use GenServer
  require Logger

  alias PhoenixElxirBeam.MCP.Session
  alias PhoenixElxirBeam.MCP.PolicyEngine

  @default_idle_ttl_ms 30 * 60_000
  @default_max_sessions 10_000
  @default_gc_interval_ms 60_000

  # Client API

  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Mints a session bound to `server_id`. `opts`: `:client_info`,
  `:protocol_version` (already negotiated), `:agent_id`.
  """
  @spec open(String.t(), keyword(), GenServer.server()) :: {:ok, Session.t()}
  def open(server_id, opts \\ [], store \\ __MODULE__) do
    GenServer.call(store, {:open, server_id, opts})
  end

  @doc "Promotes a session to `:ready` on the client's `notifications/initialized`."
  @spec mark_ready(String.t(), GenServer.server()) :: :ok | {:error, :not_found}
  def mark_ready(id, store \\ __MODULE__) do
    GenServer.call(store, {:mark_ready, id})
  end

  @doc "Looks up a session and bumps its `last_seen_at`. `:error` if unknown."
  @spec fetch(String.t() | nil, GenServer.server()) :: {:ok, Session.t()} | :error
  def fetch(id, store \\ __MODULE__)
  def fetch(nil, _store), do: :error
  def fetch(id, store), do: GenServer.call(store, {:fetch, id})

  @doc "Explicit teardown (client HTTP DELETE, or transport close)."
  @spec close(String.t(), GenServer.server()) :: :ok
  def close(id, store \\ __MODULE__) do
    GenServer.call(store, {:close, id})
  end

  @doc "Every live session, most-recently-active first (dashboard)."
  @spec list(GenServer.server()) :: [Session.t()]
  def list(store \\ __MODULE__) do
    GenServer.call(store, :list)
  end

  # Server callbacks

  @impl true
  def init(opts) do
    config = Application.get_env(:phoenix_elxir_beam, __MODULE__, [])

    state = %{
      sessions: %{},
      seq: 0,
      idle_ttl_ms: opts[:idle_ttl_ms] || config[:idle_ttl_ms] || @default_idle_ttl_ms,
      max_sessions: opts[:max_sessions] || config[:max_sessions] || @default_max_sessions,
      gc_interval_ms: opts[:gc_interval_ms] || config[:gc_interval_ms] || @default_gc_interval_ms,
      policy_engine: opts[:policy_engine] || PolicyEngine
    }

    schedule_gc(state)
    {:ok, state}
  end

  @impl true
  def handle_call({:open, server_id, opts}, _from, state) do
    now = DateTime.utc_now()
    state = maybe_evict_for_capacity(state)
    {seq, state} = next_seq(state)

    session = %Session{
      id: generate_id(),
      server_id: server_id,
      agent_id: opts[:agent_id],
      client_info: opts[:client_info],
      protocol_version: opts[:protocol_version],
      state: :initializing,
      created_at: now,
      last_seen_at: now,
      seq: seq
    }

    {:reply, {:ok, session}, put_in(state.sessions[session.id], session)}
  end

  @impl true
  def handle_call({:mark_ready, id}, _from, state) do
    case Map.get(state.sessions, id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      session ->
        {seq, state} = next_seq(state)
        session = %{session | state: :ready, last_seen_at: DateTime.utc_now(), seq: seq}
        {:reply, :ok, put_in(state.sessions[id], session)}
    end
  end

  @impl true
  def handle_call({:fetch, id}, _from, state) do
    case Map.get(state.sessions, id) do
      nil ->
        {:reply, :error, state}

      session ->
        {seq, state} = next_seq(state)
        session = %{session | last_seen_at: DateTime.utc_now(), seq: seq}
        {:reply, {:ok, session}, put_in(state.sessions[id], session)}
    end
  end

  @impl true
  def handle_call({:close, id}, _from, state) do
    {:reply, :ok, drop(state, id, :closed)}
  end

  @impl true
  def handle_call(:list, _from, state) do
    sessions =
      state.sessions
      |> Map.values()
      |> Enum.sort_by(& &1.seq, :desc)

    {:reply, sessions, state}
  end

  @impl true
  def handle_info(:gc, state) do
    cutoff = DateTime.add(DateTime.utc_now(), -state.idle_ttl_ms, :millisecond)

    idle_ids =
      for {id, %{last_seen_at: seen}} <- state.sessions,
          DateTime.compare(seen, cutoff) != :gt,
          do: id

    state = Enum.reduce(idle_ids, state, &drop(&2, &1, :idle_timeout))
    schedule_gc(state)
    {:noreply, state}
  end

  defp next_seq(state), do: {state.seq + 1, %{state | seq: state.seq + 1}}

  # Evicts the least-recently-seen session when the table is full, so a new
  # `open/2` always has room.
  defp maybe_evict_for_capacity(state) do
    if map_size(state.sessions) >= state.max_sessions do
      {oldest_id, _} = Enum.min_by(state.sessions, fn {_id, s} -> s.seq end)
      drop(state, oldest_id, :capacity_evicted)
    else
      state
    end
  end

  defp drop(state, id, reason) do
    case Map.pop(state.sessions, id) do
      {nil, sessions} ->
        %{state | sessions: sessions}

      {session, sessions} ->
        teardown_policy_state(session, reason, state.policy_engine)

        Logger.info("mcp.session ended id=#{id} server=#{session.server_id} reason=#{reason}")

        %{state | sessions: sessions}
    end
  end

  defp teardown_policy_state(%Session{id: id}, _reason, policy_engine) do
    PolicyEngine.complete_session(id, policy_engine)
    PolicyEngine.drop_session(id, policy_engine)
  rescue
    error ->
      Logger.warning("SessionStore: policy-state teardown for #{id} failed: #{inspect(error)}")
  catch
    :exit, _ -> :ok
  end

  defp schedule_gc(state), do: Process.send_after(self(), :gc, state.gc_interval_ms)

  defp generate_id do
    "mcps-" <> (:crypto.strong_rand_bytes(18) |> Base.url_encode64(padding: false))
  end
end
