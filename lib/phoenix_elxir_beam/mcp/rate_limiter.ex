defmodule PhoenixElxirBeam.MCP.RateLimiter do
  @moduledoc """
  Per-principal request rate limiting for the proxy endpoint — DoS protection
  for a component that sits on the decision path of every call
  (`docs/productionization-plan.md` M1.5).

  A fixed-window counter per `{key_id, window}` in a public ETS table:
  `check/1` bumps the current window's count with an atomic
  `:ets.update_counter/4` and allows the request while the count is within
  `max_per_window`. This admits up to ~2× the limit across a window boundary,
  which is an acceptable trade for a lock-free hot path. Stale windows are
  swept periodically.

  Distinct from `ResponseSizeGuard` / `BaselineGuard`, which police *tool*
  semantics — this polices raw HTTP request volume per authenticated key.
  """

  use GenServer

  @table __MODULE__
  @default_window_ms 1_000
  @default_max_per_window 20
  @sweep_every_ms 60_000

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc """
  Records one request for `key_id`. Returns `:ok` if within budget, or
  `{:error, retry_after_seconds}` if the current window is full.
  """
  @spec check(String.t(), keyword()) :: :ok | {:error, pos_integer()}
  def check(key_id, opts \\ []) do
    window_ms = opts[:window_ms] || config(:window_ms, @default_window_ms)
    max = opts[:max_per_window] || config(:max_per_window, @default_max_per_window)

    now = System.system_time(:millisecond)
    window = div(now, window_ms)
    count = :ets.update_counter(@table, {key_id, window}, {2, 1}, {{key_id, window}, 0})

    if count <= max do
      :ok
    else
      {:error, max(1, ceil((window_ms - rem(now, window_ms)) / 1000))}
    end
  end

  # Server

  @impl true
  def init(_opts) do
    :ets.new(@table, [
      :named_table,
      :public,
      :set,
      write_concurrency: true,
      read_concurrency: true
    ])

    schedule_sweep()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:sweep, state) do
    window_ms = config(:window_ms, @default_window_ms)
    keep_from = div(System.system_time(:millisecond), window_ms) - 1

    :ets.select_delete(@table, [{{{:_, :"$1"}, :_}, [{:<, :"$1", keep_from}], [true]}])
    schedule_sweep()
    {:noreply, state}
  end

  defp schedule_sweep, do: Process.send_after(self(), :sweep, @sweep_every_ms)

  defp config(key, default) do
    :phoenix_elxir_beam
    |> Application.get_env(__MODULE__, [])
    |> Keyword.get(key, default)
  end
end
