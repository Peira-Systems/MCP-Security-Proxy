defmodule PhoenixElxirBeamWeb.HealthController do
  @moduledoc """
  Health endpoints (M3.2):

    * `GET /health/live` — liveness. Process-only: if this handler runs, the VM
      is up. Never touches the DB or upstreams, so an orchestrator won't kill
      the container over a transient dependency outage. The compose healthcheck
      points here.
    * `GET /health/ready` — readiness. `200` when `PhoenixElxirBeam.MCP.Health`
      reports the DB reachable and (unless `config :phoenix_elxir_beam,
      :readiness, require_upstreams: false`) every registered upstream
      reachable; `503` with the failing detail otherwise. Point a load balancer
      / external monitor here.
    * `GET /health` — kept as an alias of `/health/live` for back-compat.
  """
  use PhoenixElxirBeamWeb, :controller

  alias PhoenixElxirBeam.MCP.Health

  def show(conn, params), do: live(conn, params)

  def live(conn, _params) do
    json(conn, %{
      status: "ok",
      app: :phoenix_elxir_beam,
      version: version(),
      timestamp: DateTime.utc_now()
    })
  end

  def ready(conn, _params) do
    report = Health.check()
    code = if report.status == :ok, do: 200, else: 503

    conn
    |> put_status(code)
    |> json(%{
      status: to_string(report.status),
      db: to_string(report.db),
      upstreams:
        Enum.map(report.upstreams, fn u ->
          %{
            id: u.id,
            name: u.name,
            transport: to_string(u.transport),
            status: to_string(u.status)
          }
        end),
      unreachable: report.unreachable,
      version: version(),
      timestamp: DateTime.utc_now()
    })
  end

  defp version, do: Application.spec(:phoenix_elxir_beam, :vsn) |> to_string()
end
