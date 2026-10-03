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

  describe "GET /auth/:provider with SSO enabled" do
    setup do
      Application.put_env(:phoenix_elxir_beam, :oidc_sso_enabled?, true)
      on_exit(fn -> Application.put_env(:phoenix_elxir_beam, :oidc_sso_enabled?, false) end)
    end

    test "reaches the SSO request action instead of 404ing", %{conn: conn} do
      # No provider is actually configured in config/test.exs (no OIDC env
      # vars at boot), so `Ueberauth.call/2` can't match `operator_sso` to a
      # real strategy and run a redirect -- but the route itself must exist
      # and be reachable through the router (this is the point: the Critical
      # finding was that the /auth scope never compiled in at all). The
      # controller's own `maybe_respond/1` fallback turns Ueberauth's
      # unchanged-conn case into a flash + redirect rather than an
      # unhandled 500, so we assert on that observable outcome.
      conn = get(conn, "/auth/operator_sso")

      refute conn.status == 404
      assert redirected_to(conn) == ~p"/login"
    end

    test "GET /auth/:provider/callback with an unconfigured provider doesn't crash", %{
      conn: conn
    } do
      # Same situation as above but for the callback action: neither
      # :ueberauth_auth nor :ueberauth_failure gets assigned (no real
      # strategy ran), so do_callback/2's catch-all clause must handle it
      # instead of raising FunctionClauseError (a 500).
      conn = get(conn, "/auth/operator_sso/callback")

      refute conn.status == 500
      assert redirected_to(conn) == ~p"/login"
    end
  end

  describe "GET /auth/:provider with SSO disabled (default)" do
    test "does not reach SsoSessionController; redirects to /login", %{conn: conn} do
      conn = get(conn, "/auth/operator_sso")

      assert redirected_to(conn) == ~p"/login"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "SSO is not enabled"
    end
  end
end
