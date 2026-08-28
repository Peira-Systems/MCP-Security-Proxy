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
      {DNSCluster,
       query: Application.get_env(:phoenix_elxir_beam, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: PhoenixElxirBeam.PubSub},
      # PolicyEngine reads the plugin registry's ETS table and runs the
      # pipeline on TaskSupervisor-spawned tasks, so both must precede it.
      {Task.Supervisor, name: PhoenixElxirBeam.MCP.TaskSupervisor},
      PhoenixElxirBeam.MCP.Plugin.Registry,
      PhoenixElxirBeam.MCP.PolicyEngine,
      {DynamicSupervisor, name: PhoenixElxirBeam.MCP.StdioServerSupervisor},
      PhoenixElxirBeam.MCP.ServerRegistry,
      PhoenixElxirBeam.MCP.MockDrift,
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
end
