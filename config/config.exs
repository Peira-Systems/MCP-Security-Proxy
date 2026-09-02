# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :phoenix_elxir_beam,
  ecto_repos: [PhoenixElxirBeam.Repo],
  generators: [timestamp_type: :utc_datetime]

# Proxy endpoint hardening (M1.5).
config :phoenix_elxir_beam, PhoenixElxirBeam.MCP.RateLimiter,
  window_ms: 1_000,
  max_per_window: 20

# HMAC key for taint markers (M4.1). Overridden in config/runtime.exs for prod
# (TAINT_MARKER_KEY secret, or derived from SECRET_KEY_BASE). Markers are
# session-scoped and opaque; a rotated key just re-bases in-flight sessions.
config :phoenix_elxir_beam, :taint_marker_key, "dev-and-test-taint-marker-key-not-a-secret"

config :phoenix_elxir_beam, PhoenixElxirBeamWeb.Plugs.RequestLimits, max_body_bytes: 1_048_576

# Verify TLS certificates when the proxy dials an upstream `:http` MCP server.
# Set false only for a dev server with a self-signed cert.
config :phoenix_elxir_beam, :upstream_tls_verify, true

# Off-DB anchoring of the audit hash chain (M2.3). In prod the key comes
# from AUDIT_CHECKPOINT_KEY and the path should be on a volume separate from
# Postgres (config/runtime.exs).
config :phoenix_elxir_beam, PhoenixElxirBeam.MCP.AuditCheckpoint,
  key: "dev-audit-checkpoint-key-not-for-production",
  path: "priv/audit_checkpoints.log"

config :phoenix_elxir_beam, PhoenixElxirBeam.MCP.AuditIntegrity, interval_ms: 900_000

# Opt-in pruning of policy_events rows older than N days, anchored so it
# never touches a row an ongoing verify_chain/0 chain check still needs
# (docs/deployment.md#retention--backups). Off (nil) by default -- the log
# grows unbounded until an operator sets AUDIT_RETENTION_DAYS.
config :phoenix_elxir_beam, PhoenixElxirBeam.MCP.AuditRetention, retention_days: nil

# The MCP proxy plugin pipeline (`docs/plugin-protocol.md` §15) is configured
# per-env in `config/{test,dev,prod}.exs` — each sets the full `plugins:` list
# once. It is NOT set here: `Config` merges the keyword-shaped list by key, so
# a base entry here could not be removed by an env override.

# Configure the endpoint
config :phoenix_elxir_beam, PhoenixElxirBeamWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: PhoenixElxirBeamWeb.ErrorHTML, json: PhoenixElxirBeamWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: PhoenixElxirBeam.PubSub,
  live_view: [signing_salt: "6bKsImGs"]

# Configure LiveView
config :phoenix_live_view,
  # the attribute set on all root tags. Used for Phoenix.LiveView.ColocatedCSS.
  root_tag_attribute: "phx-r"

# Windows without Developer Mode/admin can't symlink assets/node_modules for
# colocated JS. Harmless as long as colocated hooks don't import npm packages.
config :phoenix_live_view, :colocated_assets, disable_symlink_warning: true

# Configure the mailer
#
# By default it uses the "Local" adapter which stores the emails
# locally. You can see the emails in your browser, at "/dev/mailbox".
#
# For production it's recommended to configure a different adapter
# at the `config/runtime.exs`.
config :phoenix_elxir_beam, PhoenixElxirBeam.Mailer, adapter: Swoosh.Adapters.Local

# Configure esbuild (the version is required)
config :esbuild,
  version: "0.25.4",
  phoenix_elxir_beam: [
    args:
      ~w(js/app.js --bundle --target=es2022 --outdir=../priv/static/assets/js --external:/fonts/* --external:/images/* --alias:@=.),
    cd: Path.expand("../assets", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ]

# Configure tailwind (the version is required)
config :tailwind,
  version: "4.3.0",
  phoenix_elxir_beam: [
    args: ~w(
      --input=assets/css/app.css
      --output=priv/static/assets/css/app.css
    ),
    cd: Path.expand("..", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ]

# Configure Elixir's Logger
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
