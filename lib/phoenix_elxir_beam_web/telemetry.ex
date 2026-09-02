defmodule PhoenixElxirBeamWeb.Telemetry do
  use Supervisor
  import Telemetry.Metrics

  @moduledoc """
  Telemetry supervision + metric definitions.

  Hosts the `:telemetry_poller` (periodic VM + MCP gauge measurements) and the
  `TelemetryMetricsPrometheus.Core` reporter, whose registry is scraped as
  Prometheus text by `PhoenixElxirBeamWeb.MetricsController` at `GET /metrics`
  (M3.2). See `PhoenixElxirBeam.MCP.Telemetry` for the `[:mcp, ...]` event
  taxonomy and `docs/observability.md` for the deployment wiring.
  """

  @prometheus_name :mcp_prometheus

  def start_link(arg) do
    Supervisor.start_link(__MODULE__, arg, name: __MODULE__)
  end

  @doc "The name the Prometheus.Core reporter registers under (for `scrape/1`)."
  def prometheus_name, do: @prometheus_name

  @impl true
  def init(_arg) do
    children = [
      {:telemetry_poller, measurements: periodic_measurements(), period: 10_000},
      {TelemetryMetricsPrometheus.Core, name: @prometheus_name, metrics: metrics()}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end

  def metrics do
    phoenix_metrics() ++ vm_metrics() ++ mcp_metrics()
  end

  # Prometheus.Core has no `summary`; HTTP latency is a histogram.
  @http_buckets [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]

  defp phoenix_metrics do
    [
      distribution("phoenix.endpoint.stop.duration",
        reporter_options: [buckets: @http_buckets],
        unit: {:native, :millisecond}
      ),
      distribution("phoenix.router_dispatch.stop.duration",
        reporter_options: [buckets: @http_buckets],
        tags: [:route],
        unit: {:native, :millisecond}
      ),
      distribution("phoenix.router_dispatch.exception.duration",
        reporter_options: [buckets: @http_buckets],
        tags: [:route],
        unit: {:native, :millisecond}
      )
    ]
  end

  defp vm_metrics do
    [
      last_value("vm.memory.total", unit: {:byte, :kilobyte}),
      last_value("vm.total_run_queue_lengths.total"),
      last_value("vm.total_run_queue_lengths.cpu"),
      last_value("vm.total_run_queue_lengths.io")
    ]
  end

  # -- MCP proxy request path (see PhoenixElxirBeam.MCP.Telemetry) --------
  defp mcp_metrics do
    [
      # Per-phase plugin-chain latency + throughput. The histogram carries its
      # own `_count` series, so no separate counter is needed.
      distribution("mcp.pipeline.run.stop.duration",
        reporter_options: [buckets: [0.5, 1, 2, 5, 10, 25, 50, 100, 250, 500]],
        tags: [:phase, :verdict],
        unit: {:native, :millisecond},
        description: "Plugin-chain phase latency, ms"
      ),
      # Per-plugin latency + outcome (outcome ok|timeout|crash|bad_return).
      distribution("mcp.plugin.run.stop.duration",
        reporter_options: [buckets: [0.5, 1, 2, 5, 10, 25, 50, 100, 250, 500]],
        tags: [:plugin, :phase, :outcome],
        unit: {:native, :millisecond},
        description: "Individual plugin evaluation latency, ms"
      ),
      # Upstream MCP server request latency + error rate (outcome ok|error).
      distribution("mcp.upstream.request.stop.duration",
        reporter_options: [buckets: [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]],
        tags: [:transport, :outcome],
        unit: {:native, :millisecond},
        description: "Upstream MCP server request latency, ms"
      ),
      # Policy decisions by verdict.
      counter("mcp.decision.count",
        tags: [:verdict, :phase],
        description: "Policy decisions by verdict (allow|deny|hold)"
      ),
      # Operational alerts raised (MCP.Alerts).
      counter("mcp.alert.count",
        tags: [:key, :severity],
        description: "Operational alerts raised"
      ),
      # Periodic gauges.
      last_value("mcp.sessions.count", description: "Live downstream MCP sessions"),
      last_value("mcp.holds.pending", description: "Parked approval holds"),
      last_value("mcp.servers.count", description: "Registered upstream servers (live)"),
      last_value("mcp.servers.unreachable",
        description: "Registered upstreams that failed to restore / re-handshake"
      )
    ]
  end

  defp periodic_measurements do
    [
      {PhoenixElxirBeam.MCP.Telemetry, :measurements, []}
    ]
  end
end
