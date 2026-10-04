defmodule PhoenixElxirBeamWeb.Plugs.RequireSsoEnabled do
  @moduledoc """
  Gates the `/auth/*` SSO routes at REQUEST time, not compile time.

  The `/auth` scope in the router is registered unconditionally (SSO
  enablement is a deployment choice made via `OIDC_ISSUER_URL` etc. at
  BOOT, which `config/runtime.exs` sets -- something a compile-time
  `Application.compile_env/3` check in the router can never observe,
  since compilation finishes before boot-time runtime config ever runs).
  This plug is what actually enforces "SSO must be opted in" per the
  Global Constraint in
  `docs/superpowers/specs/2026-10-02-operator-oidc-sso-design.md`: an
  unconfigured deployment gets a flash + redirect to `/login` for any
  `/auth/*` request, identical in spirit to how `UserAuth.require_authenticated_user/2`
  redirects an unauthenticated request instead of serving the page.
  """

  use PhoenixElxirBeamWeb, :verified_routes

  import Plug.Conn
  import Phoenix.Controller

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    if Application.get_env(:phoenix_elxir_beam, :oidc_sso_enabled?, false) do
      conn
    else
      conn
      |> put_flash(:error, "SSO is not enabled on this deployment.")
      |> redirect(to: ~p"/login")
      |> halt()
    end
  end
end
