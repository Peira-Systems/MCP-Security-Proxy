import Config

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# system starts, so it is typically used to load production configuration
# and secrets from environment variables or elsewhere. Do not define
# any compile-time configuration in here, as it won't be applied.
# The block below contains prod specific runtime configuration.

# ## Using releases
#
# If you use `mix release`, you need to explicitly enable the server
# by passing the PHX_SERVER=true when you start it:
#
#     PHX_SERVER=true bin/phoenix_elxir_beam start
#
# Alternatively, you can use `mix phx.gen.release` to generate a `bin/server`
# script that automatically sets the env var above.
if System.get_env("PHX_SERVER") do
  config :phoenix_elxir_beam, PhoenixElxirBeamWeb.Endpoint, server: true
end

config :phoenix_elxir_beam, PhoenixElxirBeamWeb.Endpoint,
  http: [port: String.to_integer(System.get_env("PORT", "4000"))]

# When the proxy runs in a container it can't reach an MCP server on the
# *host's* loopback via `127.0.0.1`. Setting this (the compose file sets it to
# `host.docker.internal`) lets a registered `localhost` / `127.0.0.1` URL be
# dialed through that alias instead. Unset outside a container — loopback URLs
# are then used as-is. See `PhoenixElxirBeam.MCP.HttpTransport`.
case System.get_env("MCP_HOST_LOOPBACK_ALIAS") do
  alias when is_binary(alias) and alias != "" ->
    config :phoenix_elxir_beam, :host_loopback_alias, alias

  _ ->
    :ok
end

if config_env() == :dev do
  # Reload browser tabs when matching files change.
  config :phoenix_elxir_beam, PhoenixElxirBeamWeb.Endpoint,
    live_reload: [
      web_console_logger: true,
      patterns: [
        # Static assets, except user uploads
        ~r"priv/static/(?!uploads/).*\.(js|css|png|jpeg|jpg|gif|svg)$",
        # Gettext translations
        ~r"priv/gettext/.*\.po$",
        # Router, Controllers, LiveViews and LiveComponents
        ~r"lib/phoenix_elxir_beam_web/router\.ex$",
        ~r"lib/phoenix_elxir_beam_web/(controllers|live|components)/.*\.(ex|heex)$"
      ]
    ]
end

if config_env() == :prod do
  # Dashboard / dev-tools Basic auth. Required in prod — no default.
  dashboard_user = System.get_env("DASHBOARD_USER") || "admin"

  dashboard_pass =
    System.get_env("DASHBOARD_PASSWORD") ||
      raise "environment variable DASHBOARD_PASSWORD is missing"

  config :phoenix_elxir_beam, :dashboard_auth,
    username: dashboard_user,
    password: dashboard_pass

  # Optional bearer token for GET /metrics (M3.2). Unset ⇒ the endpoint is
  # open — only acceptable if it's unreachable from outside the scrape network.
  case System.get_env("METRICS_TOKEN") do
    token when is_binary(token) and token != "" ->
      config :phoenix_elxir_beam, :metrics_token, token

    _ ->
      :ok
  end

  # Readiness (GET /health/ready) fails with 503 when a registered upstream is
  # unreachable. Set READINESS_REQUIRE_UPSTREAMS=false to make upstream
  # reachability advisory (DB-only readiness).
  config :phoenix_elxir_beam, :readiness,
    require_upstreams: System.get_env("READINESS_REQUIRE_UPSTREAMS", "true") != "false"

  # Off-DB audit-chain checkpoint (M2.3). Put the file on a volume separate
  # from Postgres. The key must be stable across deploys and NOT stored in
  # the database — a rotated key invalidates older checkpoints.
  config :phoenix_elxir_beam, PhoenixElxirBeam.MCP.AuditCheckpoint,
    key:
      System.get_env("AUDIT_CHECKPOINT_KEY") ||
        raise("environment variable AUDIT_CHECKPOINT_KEY is missing"),
    path: System.get_env("AUDIT_CHECKPOINT_PATH") || "/checkpoints/audit.log"

  database_url =
    System.get_env("DATABASE_URL") ||
      raise "environment variable DATABASE_URL is missing (postgres://user:pass@host/db)"

  config :phoenix_elxir_beam, PhoenixElxirBeam.Repo,
    url: database_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"),
    # Fail fast rather than pile requests up if the DB is unreachable — this
    # is on the policy decision path.
    queue_target: 200,
    queue_interval: 1_000,
    parameters: [statement_timeout: System.get_env("PG_STATEMENT_TIMEOUT_MS") || "15000"],
    socket_options: if(System.get_env("ECTO_IPV6") in ~w(true 1), do: [:inet6], else: [])

  # The secret key base is used to sign/encrypt cookies and other secrets.
  # A default value is used in config/dev.exs and config/test.exs but you
  # want to use a different value for prod and you most likely don't want
  # to check this value into version control, so we use an environment
  # variable instead.
  secret_key_base =
    case System.get_env("SECRET_KEY_BASE") do
      value when is_binary(value) and byte_size(value) >= 64 ->
        value

      _ ->
        raise """
        environment variable SECRET_KEY_BASE is missing or too short (must be
        at least 64 bytes).
        You can generate one by calling: mix phx.gen.secret
        """
    end

  host = System.get_env("PHX_HOST") || "example.com"

  dns_cluster_query =
    case System.get_env("DNS_CLUSTER_QUERY") do
      nil -> nil
      "" -> nil
      value -> value
    end

  config :phoenix_elxir_beam, :dns_cluster_query, dns_cluster_query

  config :phoenix_elxir_beam, PhoenixElxirBeamWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    http: [
      # Bind on all interfaces (IPv4 + IPv6).
      ip: {0, 0, 0, 0, 0, 0, 0, 0},
      port: String.to_integer(System.get_env("PORT", "4000")),
      # Cap concurrent connections and header size (Bandit / Thousand Island
      # defaults are already conservative; pinned here so hardening is visible
      # in one place). The proxy body cap lives in Plugs.RequestLimits.
      http_1_options: [max_header_length: 16_384],
      thousand_island_options: [max_connections: 16_384]
    ],
    secret_key_base: secret_key_base

  # TLS termination in the app container. The Docker Compose reference setup
  # puts a reverse proxy (Caddy/nginx) in front for TLS instead; set these
  # only when Bandit should terminate TLS directly.
  case {System.get_env("SSL_CERT_PATH"), System.get_env("SSL_KEY_PATH")} do
    {cert, key} when is_binary(cert) and is_binary(key) ->
      config :phoenix_elxir_beam, PhoenixElxirBeamWeb.Endpoint,
        https: [
          port: String.to_integer(System.get_env("SSL_PORT", "443")),
          cipher_suite: :strong,
          certfile: cert,
          keyfile: key
        ]

    _ ->
      :ok
  end

  # ## SSL Support
  #
  # To get SSL working, you will need to add the `https` key
  # to your endpoint configuration:
  #
  #     config :phoenix_elxir_beam, PhoenixElxirBeamWeb.Endpoint,
  #       https: [
  #         ...,
  #         port: 443,
  #         cipher_suite: :strong,
  #         keyfile: System.get_env("SOME_APP_SSL_KEY_PATH"),
  #         certfile: System.get_env("SOME_APP_SSL_CERT_PATH")
  #       ]
  #
  # The `cipher_suite` is set to `:strong` to support only the
  # latest and more secure SSL ciphers. This means old browsers
  # and clients may not be supported. You can set it to
  # `:compatible` for wider support.
  #
  # `:keyfile` and `:certfile` expect an absolute path to the key
  # and cert in disk or a relative path inside priv, for example
  # "priv/ssl/server.key". For all supported SSL configuration
  # options, see https://plug.hexdocs.pm/Plug.SSL.html#configure/1
  #
  # We also recommend setting `force_ssl` in your config/prod.exs,
  # ensuring no data is ever sent via http, always redirecting to https:
  #
  #     config :phoenix_elxir_beam, PhoenixElxirBeamWeb.Endpoint,
  #       force_ssl: [hsts: true]
  #
  # Check `Plug.SSL` for all available options in `force_ssl`.

  # ## Configuring the mailer
  #
  # In production you need to configure the mailer to use a different adapter.
  # Here is an example configuration for Mailgun:
  #
  #     config :phoenix_elxir_beam, PhoenixElxirBeam.Mailer,
  #       adapter: Swoosh.Adapters.Mailgun,
  #       api_key: System.get_env("MAILGUN_API_KEY"),
  #       domain: System.get_env("MAILGUN_DOMAIN")
  #
  # Most non-SMTP adapters require an API client. Swoosh supports Req, Hackney,
  # and Finch out-of-the-box. This configuration is typically done at
  # compile-time in your config/prod.exs:
  #
  #     config :swoosh, :api_client, Swoosh.ApiClient.Req
  #
  # See https://swoosh.hexdocs.pm/Swoosh.html#module-installation for details.
end
