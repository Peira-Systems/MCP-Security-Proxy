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

# Plugins consulted by the MCP proxy pipeline, in evaluation order.
# See docs/plugin-protocol.md §15 and docs/adr/0001-plugin-architecture.md.
config :phoenix_elxir_beam, PhoenixElxirBeam.MCP,
  plugins: [
    {PhoenixElxirBeam.MCP.Plugins.ChainExfil, []},
    {PhoenixElxirBeam.MCP.Plugins.RugPull, []},
    {PhoenixElxirBeam.MCP.Plugins.EventLogSink, []}
  ]

# The reference out-of-process (sidecar) plugin is added per-env in
# `config/dev.exs` / `config/prod.exs` — not here, so the test env stays
# in-process-only. (`Config` merges the `plugins:` list by key, so a plain
# override in `test.exs` would not remove an entry added here.)

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
