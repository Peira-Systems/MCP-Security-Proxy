defmodule PhoenixElxirBeamWeb.SsoSessionControllerTest do
  use PhoenixElxirBeamWeb.ConnCase, async: true

  alias PhoenixElxirBeam.Accounts

  describe "callback/2 with a verified ueberauth_auth assign" do
    test "logs in an existing auth_source: :sso account", %{conn: conn} do
      {:ok, user} = Accounts.create_sso_user(%{email: "ops@example.com", role: :operator})

      auth = %Ueberauth.Auth{
        info: %Ueberauth.Auth.Info{email: "ops@example.com"},
        extra: %Ueberauth.Auth.Extra{
          raw_info: %UeberauthOidcc.RawInfo{claims: %{"email_verified" => true}}
        }
      }

      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Phoenix.Controller.fetch_flash()
        |> Plug.Conn.assign(:ueberauth_auth, auth)
        |> PhoenixElxirBeamWeb.SsoSessionController.callback(%{})

      assert Phoenix.Flash.get(conn.assigns.flash, :info) == "Welcome back."
      assert get_session(conn, "user_token")
      refute is_nil(user)
    end

    test "rejects login when email_verified is false", %{conn: conn} do
      {:ok, _user} = Accounts.create_sso_user(%{email: "unverified@example.com", role: :viewer})

      auth = %Ueberauth.Auth{
        info: %Ueberauth.Auth.Info{email: "unverified@example.com"},
        extra: %Ueberauth.Auth.Extra{
          raw_info: %UeberauthOidcc.RawInfo{claims: %{"email_verified" => false}}
        }
      }

      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Phoenix.Controller.fetch_flash()
        |> Plug.Conn.assign(:ueberauth_auth, auth)
        |> PhoenixElxirBeamWeb.SsoSessionController.callback(%{})

      refute get_session(conn, "user_token")
      assert redirected_to(conn) == ~p"/login"
    end

    test "rejects login when email_verified claim is missing entirely", %{conn: conn} do
      {:ok, _user} = Accounts.create_sso_user(%{email: "noclaim@example.com", role: :viewer})

      auth = %Ueberauth.Auth{
        info: %Ueberauth.Auth.Info{email: "noclaim@example.com"},
        extra: %Ueberauth.Auth.Extra{raw_info: %UeberauthOidcc.RawInfo{claims: %{}}}
      }

      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Phoenix.Controller.fetch_flash()
        |> Plug.Conn.assign(:ueberauth_auth, auth)
        |> PhoenixElxirBeamWeb.SsoSessionController.callback(%{})

      refute get_session(conn, "user_token")
      assert redirected_to(conn) == ~p"/login"
    end

    test "rejects login when no matching users row exists", %{conn: conn} do
      auth = %Ueberauth.Auth{
        info: %Ueberauth.Auth.Info{email: "nobody@example.com"},
        extra: %Ueberauth.Auth.Extra{
          raw_info: %UeberauthOidcc.RawInfo{claims: %{"email_verified" => true}}
        }
      }

      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Phoenix.Controller.fetch_flash()
        |> Plug.Conn.assign(:ueberauth_auth, auth)
        |> PhoenixElxirBeamWeb.SsoSessionController.callback(%{})

      refute get_session(conn, "user_token")
      assert redirected_to(conn) == ~p"/login"
    end

    test "rejects login when the matching account is auth_source: :local", %{conn: conn} do
      {:ok, _user} =
        Accounts.create_user(%{
          email: "local@example.com",
          password: "supersecretpw123",
          role: :viewer
        })

      auth = %Ueberauth.Auth{
        info: %Ueberauth.Auth.Info{email: "local@example.com"},
        extra: %Ueberauth.Auth.Extra{
          raw_info: %UeberauthOidcc.RawInfo{claims: %{"email_verified" => true}}
        }
      }

      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Phoenix.Controller.fetch_flash()
        |> Plug.Conn.assign(:ueberauth_auth, auth)
        |> PhoenixElxirBeamWeb.SsoSessionController.callback(%{})

      refute get_session(conn, "user_token")
      assert redirected_to(conn) == ~p"/login"
    end
  end

  describe "callback/2 with a ueberauth_failure assign" do
    test "redirects to login with an error flash", %{conn: conn} do
      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Phoenix.Controller.fetch_flash()
        |> Plug.Conn.assign(:ueberauth_failure, %Ueberauth.Failure{})
        |> PhoenixElxirBeamWeb.SsoSessionController.callback(%{})

      assert redirected_to(conn) == ~p"/login"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "SSO sign-in failed"
    end
  end
end
