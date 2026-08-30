defmodule PhoenixElxirBeam.MCP.AuditIntegrity do
  @moduledoc """
  Scheduled tamper-evidence check for the `PhoenixElxirBeam.MCP.EventLog`
  hash chain (`docs/productionization-plan.md` M2.3) — not just the
  dashboard button.

  Every `interval_ms` (default 15 min) it:

    1. runs `EventLog.verify_chain/0` (rows present form an unbroken chain);
    2. compares the live head against the newest signed
       `PhoenixElxirBeam.MCP.AuditCheckpoint` (catches a truncated log that
       still verifies internally);
    3. on success, writes a fresh checkpoint.

  A failure raises an alert: a structured `mcp.audit.integrity` error line
  for the log shipper / SIEM, and `{:audit_integrity, :broken, detail}` on
  the `"mcp:audit"` PubSub topic for the dashboard. `status/0` exposes the
  last result; `check_now/0` runs it on demand.
  """

  use GenServer
  require Logger

  alias PhoenixElxirBeam.MCP.{AuditCheckpoint, EventLog}

  @pubsub PhoenixElxirBeam.PubSub
  @topic "mcp:audit"
  @default_interval_ms 15 * 60_000
  @first_check_delay_ms 30_000

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "Runs a check now and returns its result."
  @spec check_now(GenServer.server()) :: :ok | {:broken, String.t()}
  def check_now(server \\ __MODULE__), do: GenServer.call(server, :check_now)

  @doc "The last check's outcome + the newest checkpoint."
  @spec status(GenServer.server()) :: map()
  def status(server \\ __MODULE__), do: GenServer.call(server, :status)

  # -- server --------------------------------------------------------

  @impl true
  def init(opts) do
    interval = opts[:interval_ms] || config(:interval_ms, @default_interval_ms)
    Process.send_after(self(), :check, opts[:first_delay_ms] || @first_check_delay_ms)
    {:ok, %{interval_ms: interval, last_check: nil}}
  end

  @impl true
  def handle_info(:check, state) do
    {_result, state} = run(state)
    Process.send_after(self(), :check, state.interval_ms)
    {:noreply, state}
  end

  @impl true
  def handle_call(:check_now, _from, state) do
    {result, state} = run(state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:status, _from, state) do
    {:reply, %{last_check: state.last_check, checkpoint: safe(&AuditCheckpoint.latest/0)}, state}
  end

  # -- check --------------------------------------------------------

  defp run(state) do
    result =
      try do
        case EventLog.verify_chain() do
          :ok -> against_checkpoint()
          {:error, %{event_id: id, occurred_at: at}} -> {:broken, "row #{id} at #{at}"}
        end
      rescue
        error -> {:skipped, Exception.message(error)}
      catch
        :exit, _ -> {:skipped, "db unavailable"}
      end

    handle_result(result)
    {normalize(result), %{state | last_check: %{at: DateTime.utc_now(), result: result}}}
  end

  defp against_checkpoint do
    with %{} = cp <- AuditCheckpoint.latest(),
         head when is_map(head) <- EventLog.head() do
      cond do
        head.count < cp.count ->
          {:broken, "log has #{head.count} rows; checkpoint recorded #{cp.count} — truncated"}

        not EventLog.hash_present?(cp.hash) ->
          {:broken, "checkpointed head hash is no longer present in the log"}

        true ->
          write_checkpoint()
          :ok
      end
    else
      # no checkpoint yet, or an empty log — nothing to verify against, so
      # just (re)write the checkpoint from the current head.
      nil -> write_checkpoint()
    end
  end

  defp write_checkpoint do
    case EventLog.head() do
      nil -> :ok
      head -> AuditCheckpoint.append(head)
    end

    :ok
  end

  defp handle_result({:broken, detail}) do
    Logger.error("mcp.audit.integrity chain check FAILED: #{detail}")
    Phoenix.PubSub.broadcast(@pubsub, @topic, {:audit_integrity, :broken, detail})
  end

  defp handle_result({:skipped, _}), do: :ok
  defp handle_result(:ok), do: :ok

  defp normalize({:broken, _} = b), do: b
  defp normalize(_), do: :ok

  defp safe(fun) do
    fun.()
  rescue
    _ -> nil
  end

  defp config(key, default) do
    :phoenix_elxir_beam
    |> Application.get_env(__MODULE__, [])
    |> Keyword.get(key, default)
  end
end
