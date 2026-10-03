defmodule PhoenixElxirBeamWeb.SsoSessionController do
  @moduledoc """
  OIDC SSO login callback (Phase 1 identity work). Authenticates an
  already-admin-provisioned `auth_source: :sso` account by verified email
  claim; never creates or authorizes an account on its own. See
  `docs/superpowers/specs/2026-10-02-operator-oidc-sso-design.md`.
  """
  use PhoenixElxirBeamWeb, :controller

  alias PhoenixElxirBeam.Accounts
  alias PhoenixElxirBeamWeb.UserAuth

  # `plug Ueberauth` (module-level) is deliberately NOT used here: its
  # `init/1` reads `config :ueberauth, Ueberauth, :providers`, and a
  # module-level `plug` call has its `init/1` run under `plug_init_mode`,
  # which is `:compile` by default (and in every env that doesn't
  # explicitly override it, including `:prod`). This app's provider config
  # is only set at BOOT, in `config/runtime.exs` (driven by
  # `OIDC_ISSUER_URL` etc.), which runs after compilation finishes --  so a
  # compile-time `init/1` call always sees no providers configured and
  # crashes `MIX_ENV=prod mix compile`, with or without OIDC configured.
  #
  # Calling `Ueberauth.call(conn, Ueberauth.init())` directly inside each
  # action instead defers both the config read and the route-matching
  # struct build to request time, every request -- cheap (a config lookup
  # + building a small list), and exactly what the macro form does under
  # the hood (see `Ueberauth.init/1` / `Ueberauth.call/2` in
  # deps/ueberauth/lib/ueberauth.ex), just invoked manually instead of
  # auto-wired by `plug_init_mode`.
  def request(conn, _params) do
    conn
    |> Ueberauth.call(Ueberauth.init())
    |> maybe_respond()
  end

  def callback(%{assigns: %{ueberauth_auth: _}} = conn, params), do: do_callback(conn, params)

  def callback(%{assigns: %{ueberauth_failure: _}} = conn, params), do: do_callback(conn, params)

  def callback(conn, params) do
    conn
    |> Ueberauth.call(Ueberauth.init())
    |> do_callback(params)
  end

  defp do_callback(%{assigns: %{ueberauth_failure: _failure}} = conn, _params) do
    conn
    |> put_flash(:error, "SSO sign-in failed. Try again or use your password, if you have one.")
    |> redirect(to: ~p"/login")
  end

  defp do_callback(%{assigns: %{ueberauth_auth: auth}} = conn, _params) do
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

  # Neither `:ueberauth_auth` nor `:ueberauth_failure` is set -- `Ueberauth.call/2`
  # didn't recognize the `:provider` path segment (see `maybe_respond/1`).
  defp do_callback(conn, _params), do: maybe_respond(conn)

  # `Ueberauth.call/2` only produces a response itself when the request
  # path matched a configured provider's request/callback route (it then
  # redirects to the IdP, or sets `:ueberauth_auth`/`:ueberauth_failure` and
  # falls through) -- see `call/2` / `run/2` in
  # deps/ueberauth/lib/ueberauth.ex, which returns `conn` UNCHANGED when no
  # route matched (e.g. the `:provider` path segment doesn't match any
  # configured provider name). That's reachable even with SSO enabled --
  # the request-time gate (router plug) only checks `oidc_sso_enabled?`,
  # not that `:provider` names a real, configured provider -- so both
  # `request/2` and `callback/2` need a fallback once `Ueberauth.call/2`
  # leaves the conn untouched, instead of hitting an unhandled 500
  # (`request/2`'s old `do: conn` catch-all) or a `FunctionClauseError`
  # (`do_callback/2` had no clause for "neither assign set").
  defp maybe_respond(%{state: :sent} = conn), do: conn
  defp maybe_respond(%{halted: true} = conn), do: conn

  defp maybe_respond(conn) do
    conn
    |> put_flash(:error, "SSO sign-in failed. Try again or use your password, if you have one.")
    |> redirect(to: ~p"/login")
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
