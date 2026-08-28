import Config

# In-process, deterministic plugin set for tests. `ChainExfil` (hard block),
# not `ApprovalGate` (hold) — the hold flow is covered by its own suites.
# Sidecar behaviour is exercised via the Node fixture + `Registry`'s `:plugins`.
config :phoenix_elxir_beam, PhoenixElxirBeam.MCP,
  plugins: [
    {PhoenixElxirBeam.MCP.Plugins.RuleEngine,
     config: %{
       "rules" => [
         %{
           "match" => %{"agent" => "agent://ci-runner", "tool_tags_any" => ["network_egress"]},
           "action" => "deny",
           "severity" => "high",
           "reason" => "policy: agent ci-runner may not perform network egress"
         }
       ]
     }},
    {PhoenixElxirBeam.MCP.Plugins.ChainExfil, []},
    {PhoenixElxirBeam.MCP.Plugins.TaintGuard, []},
    {PhoenixElxirBeam.MCP.Plugins.RugPull, []},
    {PhoenixElxirBeam.MCP.Plugins.SecretLeak, []},
    {PhoenixElxirBeam.MCP.Plugins.EventLogSink, []}
  ]

config :phoenix_elxir_beam, PhoenixElxirBeam.Repo,
  database: Path.expand("../priv/repo/test.db", __DIR__),
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: System.schedulers_online() * 2,
  # SQLite serializes writers; with async tests each on its own sandbox
  # connection, WAL + a generous busy timeout makes concurrent writes wait
  # rather than raise "Database busy".
  journal_mode: :wal,
  busy_timeout: 5_000

# The MCP proxy controller forwards calls to the mock server over a real
# loopback HTTP request (via Req), so the server must actually be running
# during tests for that hop to succeed.
config :phoenix_elxir_beam, PhoenixElxirBeamWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "zeTuYfL8VcWlAQ7T/K6kG14U6cayBKJVm9zDPnfI2OKZoFE5GTH3vaZZjHAszdEi",
  server: true

# In test we don't send emails
config :phoenix_elxir_beam, PhoenixElxirBeam.Mailer, adapter: Swoosh.Adapters.Test

# Disable swoosh api client as it is only required for production adapters
config :swoosh, :api_client, false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Enable helpful, but potentially expensive runtime checks
config :phoenix_live_view,
  enable_expensive_runtime_checks: true

# Sort query params output of verified routes for robust url comparisons
config :phoenix,
  sort_verified_routes_query_params: true
