defmodule PhoenixElxirBeamWeb.HealthControllerTest do
  use PhoenixElxirBeamWeb.ConnCase, async: false

  alias PhoenixElxirBeam.MCP.ServerRegistry

  test "GET /health is a liveness alias", %{conn: conn} do
    conn = get(conn, ~p"/health")
    assert %{"status" => "ok", "app" => "phoenix_elxir_beam"} = json_response(conn, 200)
  end

  test "GET /health/live never touches the DB or upstreams", %{conn: conn} do
    conn = get(conn, ~p"/health/live")
    assert %{"status" => "ok", "version" => _} = json_response(conn, 200)
  end

  test "GET /health/ready is 200 with the DB up and no upstreams", %{conn: conn} do
    conn = get(conn, ~p"/health/ready")
    body = json_response(conn, 200)
    assert body["status"] == "ok"
    assert body["db"] == "ok"
    assert body["unreachable"] == 0
  end

  test "GET /health/ready is 503 when a registered upstream is unreachable", %{conn: conn} do
    node = System.find_executable("node") || raise "node not found on PATH"

    {:ok, server} =
      ServerRegistry.register_stdio_server("dead-#{uniq()}", node, [catalog_fixture()])

    on_exit(fn -> ServerRegistry.remove_server(server.id) end)

    # Kill the stdio subprocess out from under the registry; its stored pid
    # goes stale and the readiness probe sees the upstream as down.
    %{pid: pid} = ServerRegistry.get_server(server.id)
    ref = Process.monitor(pid)
    Process.exit(pid, :kill)
    assert_receive {:DOWN, ^ref, :process, _, _}, 1_000

    conn = get(conn, ~p"/health/ready")
    body = json_response(conn, 503)
    assert body["status"] == "degraded"
    assert body["unreachable"] >= 1
    assert Enum.any?(body["upstreams"], &(&1["id"] == server.id and &1["status"] != "ok"))
  end

  defp uniq, do: System.unique_integer([:positive])

  defp catalog_fixture,
    do: Path.expand("../../support/fixtures/catalog_mcp_server.js", __DIR__)
end
