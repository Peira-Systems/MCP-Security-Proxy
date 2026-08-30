defmodule PhoenixElxirBeam.MCP.Telemetry do
  @moduledoc """
  The `:telemetry` event taxonomy for the proxy request path (M3.2).

  All events live under the `[:mcp, ...]` prefix. `PhoenixElxirBeamWeb.Telemetry`
  turns them into Prometheus series (scraped at `/metrics`); the periodic gauges
  are driven by `:telemetry_poller` via `measurements/0` below.

  ## Span events (`:telemetry.span/3` — `:start` / `:stop` / `:exception`)

    * `[:mcp, :pipeline, :run, _]` — one plugin-chain phase.
      metadata `%{phase, verdict}` · measurement `%{duration}`
    * `[:mcp, :plugin, :run, _]` — one plugin invocation inside a phase.
      metadata `%{plugin, kind, phase, outcome, verdict}` · `%{duration}`
      `outcome` ∈ `:ok | :timeout | :crash | :bad_return`
    * `[:mcp, :upstream, :request, _]` — one call to an upstream MCP server.
      metadata `%{server_id, transport, outcome, status}` · `%{duration}`
      `outcome` ∈ `:ok | :error`

  ## Counter events (`:telemetry.execute/3`)

    * `[:mcp, :decision]` — `%{count: 1}` · `%{verdict, deciding_plugin, phase}`
    * `[:mcp, :alert]` — `%{count: 1}` · `%{key, severity}` (see `MCP.Alerts`)

  ## Gauge events (emitted from `measurements/0` on the poller period)

    * `[:mcp, :sessions]` — `%{count}` live downstream MCP sessions
    * `[:mcp, :holds]` — `%{pending}` parked approval holds
    * `[:mcp, :servers]` — `%{count, unreachable}` registered upstreams
      (`unreachable` = persisted records that failed to restore / re-handshake)
  """

  alias PhoenixElxirBeam.MCP.{Health, HoldRegistry, SessionStore}

  @doc """
  Wraps `fun` in a `[:mcp | prefix]` span. `fun` returns `{result, metadata}`;
  the metadata is merged onto `start_meta` for the `:stop` event.
  """
  @spec span([atom(), ...], map(), (-> {result, map()})) :: result when result: var
  def span(prefix, start_meta, fun) do
    :telemetry.span([:mcp | prefix], start_meta, fun)
  end

  @doc "Emits a `[:mcp, :decision]` counter event."
  def decision(verdict, deciding_plugin, phase) do
    :telemetry.execute(
      [:mcp, :decision],
      %{count: 1},
      %{verdict: verdict, deciding_plugin: deciding_plugin || "-", phase: phase}
    )
  end

  @doc "Emits a `[:mcp, :plugin, :run, :stop]` event for one plugin invocation."
  def plugin_run(plugin, kind, phase, outcome, verdict, duration_native) do
    :telemetry.execute(
      [:mcp, :plugin, :run, :stop],
      %{duration: duration_native},
      %{plugin: plugin, kind: kind, phase: phase, outcome: outcome, verdict: verdict}
    )
  end

  @doc false
  # Invoked by `:telemetry_poller` on its period — see PhoenixElxirBeamWeb.Telemetry.
  def measurements do
    safe(fn ->
      :telemetry.execute([:mcp, :sessions], %{count: length(SessionStore.list())}, %{})
    end)

    safe(fn ->
      :telemetry.execute([:mcp, :holds], %{pending: length(HoldRegistry.pending())}, %{})
    end)

    # Health.refresh/0 runs the readiness probe, emits [:mcp, :servers], and
    # raises the :upstream_unreachable alert on a transition. Disabled in test
    # (config :phoenix_elxir_beam, :telemetry_probe_upstreams, false) so the
    # probe's outbound HTTP doesn't perturb request-count assertions.
    if Application.get_env(:phoenix_elxir_beam, :telemetry_probe_upstreams, true) do
      safe(fn -> Health.refresh() end)
    end
  end

  defp safe(fun) do
    fun.()
  rescue
    _ -> :ok
  catch
    :exit, _ -> :ok
  end
end
