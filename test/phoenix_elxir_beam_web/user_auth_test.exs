defmodule PhoenixElxirBeamWeb.UserAuthTest do
  use PhoenixElxirBeamWeb.ConnCase, async: true

  import PhoenixElxirBeam.AccountsFixtures

  alias PhoenixElxirBeam.Accounts

  describe "login page" do
    test "renders and rejects bad credentials", %{conn: conn} do
      assert conn |> get(~p"/login") |> html_response(200) =~ "Operator sign in"

      conn =
        post(conn, ~p"/login", %{"user" => %{"email" => "x@example.test", "password" => "nope"}})

      assert html_response(conn, 200) =~ "Invalid email or password"
    end

    test "logs in a real user and sets a session token", %{conn: conn} do
      user = user_fixture()

      conn =
        post(conn, ~p"/login", %{
          "user" => %{"email" => user.email, "password" => valid_password()}
        })

      assert redirected_to(conn) == ~p"/"
      assert token = get_session(conn, :user_token)
      assert Accounts.get_user_by_session_token(token).id == user.id
    end
  end

  describe "the operator console" do
    test "redirects an anonymous request to /login", %{conn: conn} do
      conn = get(conn, ~p"/")
      assert redirected_to(conn) == ~p"/login"
    end

    test "an authenticated user reaches the dashboard", %{conn: conn} do
      conn = conn |> log_in_user(user_fixture()) |> get(~p"/")
      assert html_response(conn, 200) =~ "MCP Security Proxy"
    end

    test "logout clears the session token", %{conn: conn} do
      user = user_fixture()
      conn = log_in_user(conn, user)
      token = get_session(conn, :user_token)

      conn = delete(conn, ~p"/logout")
      assert redirected_to(conn) == ~p"/login"
      refute Accounts.get_user_by_session_token(token)
    end
  end

  describe "require_admin plug" do
    test "halts + redirects a non-admin", %{conn: conn} do
      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Plug.Conn.assign(:current_user, user_fixture(role: :operator))
        |> Phoenix.Controller.fetch_flash()
        |> PhoenixElxirBeamWeb.UserAuth.require_admin([])

      assert conn.halted
      assert redirected_to(conn) == ~p"/"
    end

    test "passes an admin through", %{conn: conn} do
      conn =
        conn
        |> Plug.Conn.assign(:current_user, user_fixture(role: :admin))
        |> PhoenixElxirBeamWeb.UserAuth.require_admin([])

      refute conn.halted
    end
  end
end
