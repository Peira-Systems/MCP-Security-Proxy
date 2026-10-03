defmodule PhoenixElxirBeamWeb.SsoSessionController do
  @moduledoc """
  OIDC SSO login callback (Phase 1 identity work). Authenticates an
  already-admin-provisioned `auth_source: :sso` account by verified email
  claim; never creates or authorizes an account on its own. See
  `docs/superpowers/specs/2026-10-02-operator-oidc-sso-design.md`.
  """
  use PhoenixElxirBeamWeb, :controller

  plug Ueberauth

  alias PhoenixElxirBeam.Accounts
  alias PhoenixElxirBeamWeb.UserAuth

  def request(conn, _params), do: conn

  def callback(%{assigns: %{ueberauth_failure: _failure}} = conn, _params) do
    conn
    |> put_flash(:error, "SSO sign-in failed. Try again or use your password, if you have one.")
    |> redirect(to: ~p"/login")
  end

  def callback(%{assigns: %{ueberauth_auth: auth}} = conn, _params) do
    with {:ok, email} <- verified_email(auth),
         %Accounts.User{auth_source: :sso, disabled_at: nil} = user <-
           Accounts.get_user_by_email(email) do
      conn
      |> put_flash(:info, "Welcome back.")
      |> UserAuth.log_in_user(user)
    else
      _ ->
        conn
        |> put_flash(
          :error,
          "No SSO account is provisioned for that identity. Ask an admin to create one."
        )
        |> redirect(to: ~p"/login")
    end
  end

  defp verified_email(%Ueberauth.Auth{info: %{email: email}, extra: extra})
       when is_binary(email) do
    if email_verified?(extra), do: {:ok, email}, else: :error
  end

  defp verified_email(_auth), do: :error

  # `ueberauth_oidcc` (as of 0.4.2) populates `Ueberauth.Auth.Extra.raw_info`
  # with a `%UeberauthOidcc.RawInfo{claims: string_keyed_map, ...}` struct
  # (see `Ueberauth.Strategy.Oidcc.extra/1` and `UeberauthOidcc.RawInfo`),
  # where `claims` is the raw OIDC ID token claims. `Access.key/2` reads the
  # `:claims` field off any struct (or plain map), so this works for both the
  # real struct and a plain-map test double.
  defp email_verified?(%Ueberauth.Auth.Extra{raw_info: raw_info}) do
    raw_info
    |> get_in([Access.key(:claims, %{})])
    |> Kernel.||(%{})
    |> Map.get("email_verified", false)
    |> Kernel.==(true)
  end

  defp email_verified?(_extra), do: false
end
