defmodule PhoenixElxirBeamWeb.SessionControllerTest do
  use PhoenixElxirBeamWeb.ConnCase, async: true

  describe "GET /login with SSO configured" do
    setup do
      Application.put_env(:phoenix_elxir_beam, :oidc_sso_enabled?, true)
      on_exit(fn -> Application.put_env(:phoenix_elxir_beam, :oidc_sso_enabled?, false) end)
    end

    test "shows a sign-in-with-SSO link", %{conn: conn} do
      conn = get(conn, ~p"/login")
      assert html_response(conn, 200) =~ "Sign in with SSO"
    end
  end

  describe "GET /login without SSO configured" do
    test "does not show a sign-in-with-SSO link", %{conn: conn} do
      conn = get(conn, ~p"/login")
      refute html_response(conn, 200) =~ "Sign in with SSO"
    end
  end
end
