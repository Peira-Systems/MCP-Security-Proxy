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
      # One-shot: mint the internal key the dashboard's manual tool-call flow
      # authenticates with. Transient so it doesn't restart after it exits.
      %{
        id: :dashboard_key_init,
        start: {Task, :start_link, [&ensure_dashboard_key/0]},
        restart: :transient
      },
      {DNSCluster,
       query: Application.get_env(:phoenix_elxir_beam, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: PhoenixElxirBeam.PubSub},
      # PolicyEngine reads the plugin registry's ETS table and runs the
      # pipeline on TaskSupervisor-spawned tasks, so both must precede it.
      {Task.Supervisor, name: PhoenixElxirBeam.MCP.TaskSupervisor},
      # Sidecar plugin subprocesses. Must precede the Plugin.Registry, which
      # starts one per {:sidecar, _} config entry. Generous restart limits so
      # a flaky sidecar doesn't take the supervisor (and its siblings) down.
      {DynamicSupervisor,
       name: PhoenixElxirBeam.MCP.SidecarSupervisor, max_restarts: 10, max_seconds: 60},
      PhoenixElxirBeam.MCP.Plugin.Registry,
      PhoenixElxirBeam.MCP.HoldRegistry,
      PhoenixElxirBeam.MCP.PolicyEngine,
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
end
