defmodule PhoenixElxirBeam.Application do
  # See https://elixir.hexdocs.pm/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      PhoenixElxirBeamWeb.Telemetry,
      PhoenixElxirBeam.Repo,
      # Short-TTL key_id -> %ApiKey{} cache so ApiKeyAuth doesn't SELECT on
      # every proxied request (docs/latency-budget.md). Must precede
      # dashboard_key_init below, which invalidates the mcpk_dashboard entry
      # on every boot (its secret rotates each start).
      PhoenixElxirBeam.MCP.ApiKeyCache,
      # One-shot: mint the internal key the dashboard's manual tool-call flow
      # authenticates with. Transient so it doesn't restart after it exits.
      %{
        id: :dashboard_key_init,
        start: {Task, :start_link, [&ensure_dashboard_key/0]},
        restart: :transient
      },
      # One-shot: seed the first operator admin from ADMIN_EMAIL / ADMIN_PASSWORD
      # when the users table is empty (M3.4). No-op otherwise.
      %{
        id: :admin_seed,
        start: {Task, :start_link, [&PhoenixElxirBeam.Accounts.seed_admin/0]},
        restart: :transient
      },
      {DNSCluster,
       query: Application.get_env(:phoenix_elxir_beam, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: PhoenixElxirBeam.PubSub},
      # Operational alert bus (M3.2) — structured log + dashboard banner +
      # the [:mcp, :alert] telemetry counter. Fail-soft; start it early.
      PhoenixElxirBeam.MCP.Alerts,
      # PolicyEngine reads the plugin registry's ETS table and runs the
      # pipeline on TaskSupervisor-spawned tasks, so both must precede it.
      {Task.Supervisor, name: PhoenixElxirBeam.MCP.TaskSupervisor},
      PhoenixElxirBeam.MCP.RateLimiter,
      # Sidecar plugin subprocesses. Must precede the Plugin.Registry, which
      # starts one per {:sidecar, _} config entry. Generous restart limits so
      # a flaky sidecar doesn't take the supervisor (and its siblings) down.
      {DynamicSupervisor,
       name: PhoenixElxirBeam.MCP.SidecarSupervisor, max_restarts: 10, max_seconds: 60},
      PhoenixElxirBeam.MCP.Plugin.Registry,
      PhoenixElxirBeam.MCP.HoldRegistry,
      PhoenixElxirBeam.MCP.PolicyEngine,
      # One-shot: finalize (as :orphaned) any hold a previous process
      # lifetime never resolved — HoldRegistry itself boots empty every
      # time, so this is what closes the audit gap a restart would
      # otherwise leave (docs/productionization-plan.md M2.2 follow-up).
      # Must follow PolicyEngine, which it calls into, and must *finish*
      # strictly before Endpoint starts serving — unlike the Task-based
      # one-shots above, this runs synchronously in `start/2` (returning
      # `:ignore`, a valid "no child process needed" child-spec result) so
      # the supervisor's own sequential child-start blocks on it. A
      # brand-new hold parked the instant Endpoint opens must never land in
      # the same snapshot this reap already read as "leftover from before".
      %{
        id: :hold_reap,
        start: {__MODULE__, :hold_reap_child, []},
        restart: :temporary
      },
      # Scheduled audit-chain tamper-evidence check + off-DB checkpoints.
      PhoenixElxirBeam.MCP.AuditIntegrity,
      # Owns the table of live downstream MCP sessions; teardown notifies
      # PolicyEngine, so it starts after it.
      PhoenixElxirBeam.MCP.SessionStore,
      {DynamicSupervisor, name: PhoenixElxirBeam.MCP.StdioServerSupervisor},
      PhoenixElxirBeam.MCP.ServerRegistry,
      # Start a worker by calling: PhoenixElxirBeam.Worker.start_link(arg)
      # {PhoenixElxirBeam.Worker, arg},
      # Start to serve requests, typically the last entry
      PhoenixElxirBeamWeb.Endpoint
    ]

    # See https://elixir.hexdocs.pm/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: PhoenixElxirBeam.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    PhoenixElxirBeamWeb.Endpoint.config_change(changed, removed)
    :ok
  end

  defp ensure_dashboard_key do
    PhoenixElxirBeam.MCP.ApiKey.ensure_dashboard_key()
  rescue
    error ->
      require Logger
      Logger.warning("dashboard key init skipped: #{Exception.message(error)}")
      :ok
  end

  @doc false
  # Child-spec start function for :hold_reap — runs synchronously (see the
  # comment at its call site) and returns `:ignore`, since there is no
  # process to keep around once the reap has run.
  def hold_reap_child do
    PhoenixElxirBeam.MCP.HoldRegistry.reap_orphans()
    :ignore
  rescue
    error -> hold_reap_failed(Exception.message(error))
  catch
    # This runs synchronously as part of the supervisor's own child-start
    # sequence (see the comment at its call site) — an uncaught exit here
    # doesn't just skip a hold, it fails the whole boot. reap_one/2 already
    # catches a timed-out finalize_hold/6 per row; this is the outer net for
    # anything else on this path that can exit rather than raise.
    :exit, reason -> hold_reap_failed(inspect(reason))
  end

  defp hold_reap_failed(detail) do
    require Logger
    Logger.warning("hold reap skipped: #{detail}")

    PhoenixElxirBeam.MCP.Alerts.emit(
      :hold_reap_failed,
      :warning,
      "orphaned-hold reap at boot failed: #{detail} — any hold left over " <>
        "from a previous restart stays unresolved until the next boot"
    )

    :ignore
  end
end
