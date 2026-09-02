defmodule PhoenixElxirBeamWeb.MetricsController do
  @moduledoc """
  `GET /metrics` — the Prometheus scrape endpoint (M3.2).

  Renders the `TelemetryMetricsPrometheus.Core` registry that
  `PhoenixElxirBeamWeb.Telemetry` populates from the `[:mcp, ...]` events (see
  `PhoenixElxirBeam.MCP.Telemetry`) plus the Phoenix/VM series.

  This endpoint exposes internal operational data and has no auth of its own —
  keep it on an internal network / scrape it over the compose network, or set
  `METRICS_TOKEN` (checked as `Authorization: Bearer <token>`) and configure the
  scraper with a bearer token. See `docs/observability.md`.
  """
  use PhoenixElxirBeamWeb, :controller

  alias PhoenixElxirBeamWeb.Telemetry

  def index(conn, _params) do
    if authorized?(conn) do
      metrics = TelemetryMetricsPrometheus.Core.scrape(Telemetry.prometheus_name())

      conn
      |> put_resp_content_type("text/plain; version=0.0.4")
      |> send_resp(200, metrics)
    else
      conn
      |> put_resp_header("www-authenticate", "Bearer")
      |> send_resp(401, "unauthorized")
    end
  end

  defp authorized?(conn) do
    case Application.get_env(:phoenix_elxir_beam, :metrics_token) do
      token when is_binary(token) and token != "" ->
        Plug.Crypto.secure_compare(bearer(conn), token)

      _ ->
        true
    end
  end

  defp bearer(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> token
      _ -> ""
    end
  end
end
