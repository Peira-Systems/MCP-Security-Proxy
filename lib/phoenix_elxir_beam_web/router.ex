defmodule PhoenixElxirBeamWeb.Router do
  use PhoenixElxirBeamWeb, :router

  import PhoenixElxirBeamWeb.UserAuth

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {PhoenixElxirBeamWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug :fetch_current_user
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  pipeline :require_authenticated do
    plug :require_authenticated_user
  end

  pipeline :require_admin_role do
    plug :require_admin
  end

  pipeline :redirect_if_authenticated do
    plug :redirect_if_user_is_authenticated
  end

  # The proxy endpoint: size-limited, authenticated, rate-limited (M1.4–M1.5).
  pipeline :mcp_api do
    plug :accepts, ["json"]
    plug PhoenixElxirBeamWeb.Plugs.RequestLimits
    plug PhoenixElxirBeamWeb.Plugs.ApiKeyAuth
    plug PhoenixElxirBeamWeb.Plugs.AgentCredentialAuth
    plug PhoenixElxirBeamWeb.Plugs.RateLimit
  end

  ## Login (M3.4 — replaces the M1.4 HTTP Basic auth)

  scope "/", PhoenixElxirBeamWeb do
    pipe_through [:browser, :redirect_if_authenticated]

    get "/login", SessionController, :new
    post "/login", SessionController, :create
  end

  scope "/", PhoenixElxirBeamWeb do
    pipe_through :browser

    delete "/logout", SessionController, :delete
    get "/logout", SessionController, :delete
  end

  # Operator SSO (OIDC/OAuth2) login, entirely opt-in (Phase 1 identity
  # work). Route registration is a compile-time decision, same as
  # `dev_routes` below — toggling `OIDC_ISSUER_URL` requires a rebuild.
  if Application.compile_env(:phoenix_elxir_beam, :oidc_sso_enabled?, false) do
    scope "/auth", PhoenixElxirBeamWeb do
      pipe_through [:browser, :redirect_if_authenticated]

      get "/:provider", SsoSessionController, :request
      get "/:provider/callback", SsoSessionController, :callback
      post "/:provider/callback", SsoSessionController, :callback
    end
  end

  ## Operator console — requires an authenticated account

  scope "/", PhoenixElxirBeamWeb do
    pipe_through [:browser, :require_authenticated]

    live_session :authenticated,
      on_mount: [{PhoenixElxirBeamWeb.UserAuth, :ensure_authenticated}] do
      live "/", MCPDashboardLive
      live "/mcp/dashboard", MCPDashboardLive
    end
  end

  scope "/", PhoenixElxirBeamWeb do
    pipe_through :api

    get "/health", HealthController, :show
    get "/health/live", HealthController, :live
    get "/health/ready", HealthController, :ready

    # Prometheus scrape endpoint (M3.2). Optionally gated by METRICS_TOKEN —
    # otherwise unauthenticated; keep it on an internal network.
    get "/metrics", MetricsController, :index
  end

  scope "/mcp", PhoenixElxirBeamWeb.MCP do
    pipe_through :mcp_api

    post "/proxy/:server_id", ProxyController, :handle
    delete "/proxy/:server_id", ProxyController, :delete
  end

  # LiveDashboard + Swoosh mailbox preview — dev only, admin-gated.
  if Application.compile_env(:phoenix_elxir_beam, :dev_routes) do
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through [:browser, :require_authenticated, :require_admin_role]

      live_dashboard "/dashboard", metrics: PhoenixElxirBeamWeb.Telemetry
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end
  end
end
