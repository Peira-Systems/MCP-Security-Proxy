defmodule PhoenixElxirBeam.MCP.HoldRegistry do
  @moduledoc """
  Parks `tools/call`s that a `policy` plugin returned `:hold` for, until an
  operator approves or denies them (`docs/plugin-protocol.md` §9.4).

    * `park/2` — from `PolicyEngine`: registers the hold, starts the
      `timeout_ms` timer, broadcasts `{:hold_pending, hold}` on `"mcp:holds"`,
      and write-through persists it via `PhoenixElxirBeam.MCP.HoldStore`.
      Returns the `hold_id` immediately (does not block).
    * `await/3` — from the `ProxyController` request process: blocks until the
      hold resolves, then returns `{:ok, :approved | :denied}`. Returns
      immediately if the hold already resolved (or is unknown).
    * `resolve/3` — from the dashboard LiveView: `:approve` / `:deny`.
    * the timer firing resolves with the spec's `on_timeout`.

  The registry itself is in-memory and pure: it never calls `PolicyEngine`
  directly for a live hold. The controller drives `PolicyEngine.finalize_hold/6`
  off the `await/3` result. `reap_orphans/0` is the exception — it runs once
  at boot to finalize holds a previous process lifetime never resolved; see
  its doc and `HoldStore` for why persisting a *pending* hold is worthwhile
  even though nothing about resuming the wait itself is (M2.2 follow-up).
  """

  use GenServer
  require Logger

  alias PhoenixElxirBeam.MCP.{HoldStore, PolicyEngine, PolicyStore}

  @pubsub PhoenixElxirBeam.PubSub
  @topic "mcp:holds"

  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, %{}, name: name)
  end

  @doc "Registers a hold. `spec` needs `:prompt`, `:reason`, `:timeout_ms`, `:on_timeout` and call metadata."
  @spec park(map(), GenServer.server()) :: String.t()
  def park(spec, server \\ __MODULE__), do: GenServer.call(server, {:park, spec})

  @doc "Blocks until the hold resolves. `timeout` should exceed the hold's own `timeout_ms`."
  @spec await(String.t(), pos_integer(), GenServer.server()) :: {:ok, :approved | :denied}
  def await(hold_id, timeout, server \\ __MODULE__) do
    GenServer.call(server, {:await, hold_id}, timeout)
  catch
    :exit, _ -> {:ok, :denied}
  end

  @spec resolve(String.t(), :approve | :deny, GenServer.server()) :: :ok | {:error, :not_found}
  def resolve(hold_id, decision, server \\ __MODULE__) when decision in [:approve, :deny] do
    GenServer.call(server, {:resolve, hold_id, decision})
  end

  @doc "Every currently-parked hold, newest first (for the dashboard mount)."
  @spec pending(GenServer.server()) :: [map()]
  def pending(server \\ __MODULE__), do: GenServer.call(server, :pending)

  @doc """
  Finalizes, as `:orphaned`, every hold `HoldStore` still has a row for.
  Meant to run exactly once, early at boot (before the endpoint is serving
  and so before any new hold can be parked) — every row found is therefore
  a leftover from a previous process lifetime that never resolved. Requires
  `policy_engine` to already be running. Best-effort per row; one bad row
  does not stop the rest from being reaped.
  """
  @spec reap_orphans(GenServer.server()) :: :ok
  def reap_orphans(policy_engine \\ PolicyEngine) do
    HoldStore.all() |> Enum.each(&reap_one(&1, policy_engine))
    :ok
  end

  defp reap_one(row, policy_engine) do
    tags = Enum.map(row.tags, &PolicyStore.to_tag/1)

    {:block, _event} =
      PolicyEngine.finalize_hold(
        row.session_id,
        row.server_id,
        row.tool_name,
        tags,
        :orphaned,
        policy_engine
      )

    HoldStore.resolve(row.hold_id)

    Logger.info(
      "mcp.hold orphaned id=#{row.hold_id} session=#{row.session_id} " <>
        "server=#{row.server_id} tool=#{row.tool_name} (interrupted by a restart)"
    )
  rescue
    error ->
      Logger.warning("HoldRegistry: reap of #{row.hold_id} failed: #{Exception.message(error)}")
  catch
    # finalize_hold/6 is a bare GenServer.call — a timeout under boot-time DB
    # pressure (exactly when there's most likely to be something to reap)
    # exits rather than raises, and `rescue` alone would let it escape.
    :exit, reason ->
      Logger.warning("HoldRegistry: reap of #{row.hold_id} timed out: #{inspect(reason)}")
  end

  # -- server --------------------------------------------------------------

  @impl true
  def init(_), do: {:ok, %{holds: %{}}}

  @impl true
  def handle_call({:park, spec}, _from, state) do
    id = "hold-" <> (:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower))
    timeout_ms = spec.timeout_ms
    timer = Process.send_after(self(), {:timeout, id}, timeout_ms)

    hold = %{
      id: id,
      prompt: spec.prompt,
      reason: spec.reason,
      session_id: spec[:session_id],
      server_id: spec[:server_id],
      tool_name: spec[:tool_name],
      tags: spec[:tags] || [],
      timeout_ms: timeout_ms,
      created_at: DateTime.utc_now(),
      on_timeout: spec.on_timeout,
      timer: timer,
      waiter: nil,
      resolution: nil
    }

    HoldStore.persist(hold)
    broadcast({:hold_pending, public(hold)})
    {:reply, id, put_in(state.holds[id], hold)}
  end

  @impl true
  def handle_call({:await, hold_id}, from, state) do
    case Map.get(state.holds, hold_id) do
      nil -> {:reply, {:ok, :denied}, state}
      %{resolution: r} when r != nil -> {:reply, {:ok, r}, state}
      hold -> {:noreply, put_in(state.holds[hold_id], %{hold | waiter: from})}
    end
  end

  @impl true
  def handle_call({:resolve, hold_id, decision}, _from, state) do
    case Map.get(state.holds, hold_id) do
      nil -> {:reply, {:error, :not_found}, state}
      hold -> {:reply, :ok, finalize(state, hold, outcome(decision))}
    end
  end

  @impl true
  def handle_call(:pending, _from, state) do
    holds =
      state.holds
      |> Map.values()
      |> Enum.filter(&is_nil(&1.resolution))
      |> Enum.sort_by(& &1.created_at, {:desc, DateTime})
      |> Enum.map(&public/1)

    {:reply, holds, state}
  end

  @impl true
  def handle_info({:timeout, hold_id}, state) do
    case Map.get(state.holds, hold_id) do
      nil -> {:noreply, state}
      %{resolution: r} when r != nil -> {:noreply, state}
      hold -> {:noreply, finalize(state, hold, hold.on_timeout |> timeout_outcome())}
    end
  end

  defp timeout_outcome(:allow), do: :approved
  defp timeout_outcome(_), do: :denied

  defp outcome(:approve), do: :approved
  defp outcome(:deny), do: :denied

  defp finalize(state, hold, resolution) do
    if hold.timer, do: Process.cancel_timer(hold.timer)
    if hold.waiter, do: GenServer.reply(hold.waiter, {:ok, resolution})
    HoldStore.resolve(hold.id)
    broadcast({:hold_resolved, hold.id, resolution})
    %{state | holds: Map.delete(state.holds, hold.id)}
  end

  defp public(hold) do
    Map.take(hold, [
      :id,
      :prompt,
      :reason,
      :session_id,
      :server_id,
      :tool_name,
      :timeout_ms,
      :created_at
    ])
  end

  defp broadcast(msg), do: Phoenix.PubSub.broadcast(@pubsub, @topic, msg)
end
