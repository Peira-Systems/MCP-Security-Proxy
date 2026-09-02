defmodule PhoenixElxirBeam.MCP.ApiKeyCache do
  @moduledoc """
  Short-TTL in-memory cache of `key_id -> %ApiKey{}`, so `ApiKeyAuth` doesn't
  pay a Postgres `SELECT` on every proxied request
  (`docs/latency-budget.md` — "API-key auth cache" tuning lever, follow-up to
  M1.5/M3.3).

  A public ETS table, same shape as `RateLimiter`: `get/2` and `put/2` are
  lock-free reads/writes off the hot path. The secret is still checked with
  `Plug.Crypto.secure_compare/2` against the cached `token_hash` on every
  request — caching removes the DB round-trip, not the authentication check.

  Freshness is enforced at read time (an aged-out entry reads as `:miss`), so
  `ttl_ms` is the only thing bounding how stale a cache hit can be. That is
  not the only invalidation path: `ApiKey.revoke/1` and `ApiKey.set_grants/2`
  call `invalidate/1` directly, so a revocation or grant change is visible on
  the very next request rather than waiting out the TTL — the TTL only bounds
  staleness for a key nobody explicitly changed (e.g. `last_used_at` drift).

  `invalidate/1` also closes a narrower race: a request that already read
  the row from Postgres — via `ApiKey.verify_from_db/2`, concurrently with a
  revoke — can still call `put/2` with that now-stale value *after* the
  immediate delete below has run, re-caching a revoked key for up to
  `ttl_ms`. A second, delayed eviction (`double_invalidate_delay_ms`,
  default 2s — comfortably longer than a realistic DB round-trip) closes
  that window without needing to serialize reads against writes.
  """

  use GenServer

  alias PhoenixElxirBeam.MCP.ModuleConfig

  @table __MODULE__
  @default_ttl_ms 5_000
  @default_double_invalidate_delay_ms 2_000
  @sweep_every_ms 60_000
  # entries older than this (well past any sane ttl_ms) are swept even if
  # never read again, so a churn of one-off keys doesn't grow the table
  # unbounded.
  @sweep_max_age_ms 300_000

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "Cached key for `key_id`, if present and within `ttl_ms`."
  @spec get(String.t(), keyword()) :: {:ok, struct()} | :miss
  def get(key_id, opts \\ []) do
    ttl_ms = opts[:ttl_ms] || ModuleConfig.get(__MODULE__, :ttl_ms, @default_ttl_ms)

    case :ets.lookup(@table, key_id) do
      [{^key_id, key, inserted_at}] ->
        if System.monotonic_time(:millisecond) - inserted_at <= ttl_ms do
          {:ok, key}
        else
          :miss
        end

      [] ->
        :miss
    end
  end

  @doc "Caches `key` (a live, non-disabled `%ApiKey{}`) under `key_id`."
  @spec put(String.t(), struct()) :: :ok
  def put(key_id, key) do
    :ets.insert(@table, {key_id, key, System.monotonic_time(:millisecond)})
    :ok
  end

  @doc """
  Evicts `key_id`, if cached, and schedules a second eviction shortly after
  (see the moduledoc — closes a write-through race with a concurrent
  `ApiKey.verify_from_db/2`). Called on revoke/grant changes. `opts[:delay_ms]`
  overrides the configured delay (tests only — real callers use the default).
  """
  @spec invalidate(String.t(), keyword()) :: :ok
  def invalidate(key_id, opts \\ []) do
    :ets.delete(@table, key_id)

    Process.send_after(
      __MODULE__,
      {:invalidate_again, key_id},
      opts[:delay_ms] ||
        ModuleConfig.get(
          __MODULE__,
          :double_invalidate_delay_ms,
          @default_double_invalidate_delay_ms
        )
    )

    :ok
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
    keep_from = System.monotonic_time(:millisecond) - @sweep_max_age_ms
    :ets.select_delete(@table, [{{:_, :_, :"$1"}, [{:<, :"$1", keep_from}], [true]}])
    schedule_sweep()
    {:noreply, state}
  end

  @impl true
  def handle_info({:invalidate_again, key_id}, state) do
    :ets.delete(@table, key_id)
    {:noreply, state}
  end

  defp schedule_sweep, do: Process.send_after(self(), :sweep, @sweep_every_ms)
end
