defmodule PhoenixElxirBeam.MCP.Alerts do
  @moduledoc """
  The proxy's operational alert bus (M3.2).

  An alert is raised with `emit/3` from anywhere an operator needs to know
  something is wrong that isn't a single request's verdict:

    * `:audit_integrity` — the audit hash chain failed verification (M2.3)
    * `:plugin_fail_open` — a `fail_open` plugin actually errored and the call
      was allowed to proceed without its check
    * `:sidecar_circuit_open` — a sidecar plugin's circuit breaker tripped
    * `:upstream_unreachable` — a registered upstream failed the readiness probe

  Every alert:

    1. writes a structured `mcp.alert` error line (for the log shipper / SIEM —
       see `MCP.Plugin.StructuredLogSink` / `docs/observability.md`);
    2. broadcasts `{:alert, alert}` on the `"mcp:alerts"` PubSub topic → the
       dashboard's red banner;
    3. emits a `[:mcp, :alert]` telemetry counter (`%{key, severity}`) → the
       `mcp_alerts_total` Prometheus series, which the alert rules watch.

  The last `history_limit` alerts are kept in memory for the dashboard mount and
  the `/health/ready` payload; they do not survive a restart (the conditions
  re-fire on their own schedule).
  """

  use GenServer
  require Logger

  @pubsub PhoenixElxirBeam.PubSub
  @topic "mcp:alerts"
  @history_limit 50

  @type severity :: :warning | :critical
  @type alert :: %{
          key: atom(),
          severity: severity(),
          detail: String.t(),
          meta: map(),
          at: DateTime.t()
        }

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "Topic dashboards subscribe to for `{:alert, alert}` messages."
  def topic, do: @topic

  @doc """
  Raises an operational alert. `severity` is `:warning` or `:critical`.
  Safe to call from any process; never raises.
  """
  @spec emit(atom(), severity(), String.t(), map()) :: :ok
  def emit(key, severity, detail, meta \\ %{})
      when is_atom(key) and severity in [:warning, :critical] do
    alert = %{
      key: key,
      severity: severity,
      detail: to_string(detail),
      meta: meta,
      at: DateTime.utc_now()
    }

    Logger.error(
      "mcp.alert #{key} (#{severity}): #{alert.detail}",
      mcp_alert: %{key: key, severity: severity, meta: meta}
    )

    :telemetry.execute([:mcp, :alert], %{count: 1}, %{key: key, severity: severity})

    _ = Phoenix.PubSub.broadcast(@pubsub, @topic, {:alert, alert})
    _ = safe_cast({:record, alert})
    :ok
  end

  @doc "The most recent alerts, newest first."
  @spec recent(GenServer.server()) :: [alert()]
  def recent(server \\ __MODULE__) do
    GenServer.call(server, :recent)
  catch
    :exit, _ -> []
  end

  # -- server --------------------------------------------------------

  @impl true
  def init(_opts), do: {:ok, %{history: []}}

  @impl true
  def handle_cast({:record, alert}, state) do
    {:noreply, %{state | history: Enum.take([alert | state.history], @history_limit)}}
  end

  @impl true
  def handle_call(:recent, _from, state), do: {:reply, state.history, state}

  defp safe_cast(msg) do
    GenServer.cast(__MODULE__, msg)
  catch
    :exit, _ -> :ok
  end
end
