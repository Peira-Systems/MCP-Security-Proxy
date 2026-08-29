defmodule PhoenixElxirBeamWeb.Router do
  use PhoenixElxirBeamWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {PhoenixElxirBeamWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  # The proxy endpoint: size-limited, authenticated, rate-limited (M1.4–M1.5).
  pipeline :mcp_api do
    plug :accepts, ["json"]
    plug PhoenixElxirBeamWeb.Plugs.RequestLimits
    plug PhoenixElxirBeamWeb.Plugs.ApiKeyAuth
    plug PhoenixElxirBeamWeb.Plugs.RateLimit
  end

  # The dashboard and dev tools sit behind HTTP Basic auth (credentials from
  # config, env-driven in prod). Full session login + RBAC is M3.4.
  pipeline :dashboard_auth do
    plug :dashboard_basic_auth
  end

  scope "/", PhoenixElxirBeamWeb do
    pipe_through [:browser, :dashboard_auth]

    live "/", MCPDashboardLive
    live "/mcp/dashboard", MCPDashboardLive
  end

  scope "/", PhoenixElxirBeamWeb do
    pipe_through :api

    get "/health", HealthController, :show
  end

  scope "/mcp", PhoenixElxirBeamWeb.MCP do
    pipe_through :mcp_api

    post "/proxy/:server_id", ProxyController, :handle
    delete "/proxy/:server_id", ProxyController, :delete
  end

  # LiveDashboard + Swoosh mailbox preview — dev only, and behind the same
  # Basic auth as the app dashboard.
  if Application.compile_env(:phoenix_elxir_beam, :dev_routes) do
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through [:browser, :dashboard_auth]

      live_dashboard "/dashboard", metrics: PhoenixElxirBeamWeb.Telemetry
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end
  end

  # Compares against `config :phoenix_elxir_beam, :dashboard_auth` — set from
  # DASHBOARD_USER / DASHBOARD_PASSWORD in `config/runtime.exs` for prod.
  defp dashboard_basic_auth(conn, _opts) do
    case Application.get_env(:phoenix_elxir_beam, :dashboard_auth) do
      [username: user, password: pass] when is_binary(user) and is_binary(pass) ->
        Plug.BasicAuth.basic_auth(conn, username: user, password: pass)

      _ ->
        conn
        |> Plug.Conn.send_resp(500, "dashboard auth is not configured")
        |> Plug.Conn.halt()
    end
  end
end
