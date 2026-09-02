defmodule PhoenixElxirBeamWeb.MetricsControllerTest do
  use PhoenixElxirBeamWeb.ConnCase, async: false

  test "GET /metrics renders Prometheus text with the MCP series", %{conn: conn} do
    # Force a couple of samples so the series exist.
    :telemetry.execute([:mcp, :decision], %{count: 1}, %{
      verdict: :allow,
      deciding_plugin: "-",
      phase: :pre_call
    })

    :telemetry.execute([:mcp, :sessions], %{count: 3}, %{})

    conn = get(conn, ~p"/metrics")
    body = response(conn, 200)

    assert body =~ "mcp_decision"
    assert body =~ "mcp_sessions"
    assert conn |> get_resp_header("content-type") |> hd() =~ "text/plain"
  end

  test "GET /metrics requires the bearer token when METRICS_TOKEN is set", %{conn: conn} do
    Application.put_env(:phoenix_elxir_beam, :metrics_token, "s3cret")
    on_exit(fn -> Application.delete_env(:phoenix_elxir_beam, :metrics_token) end)

    assert conn |> get(~p"/metrics") |> response(401)

    ok =
      conn
      |> put_req_header("authorization", "Bearer s3cret")
      |> get(~p"/metrics")

    assert response(ok, 200)
  end
end
