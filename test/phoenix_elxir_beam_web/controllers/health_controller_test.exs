defmodule PhoenixElxirBeamWeb.HealthControllerTest do
  use PhoenixElxirBeamWeb.ConnCase

  test "GET /health", %{conn: conn} do
    conn = get(conn, ~p"/health")
    assert %{"status" => "ok", "app" => "phoenix_elxir_beam"} = json_response(conn, 200)
  end
end
