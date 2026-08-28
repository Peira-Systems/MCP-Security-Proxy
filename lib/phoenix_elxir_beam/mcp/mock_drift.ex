defmodule PhoenixElxirBeam.MCP.MockDrift do
  @moduledoc """
  Demo-only switch that makes a mock MCP server's `tools/list` drift, so the
  rug-pull / tool-drift scanner has something to catch without a real
  malicious server.

  When a mock `server_id` is "poisoned", `PhoenixElxirBeamWeb.MCP.MockServerController`
  rewrites one tool's description to carry a tool-poisoning payload. The
  dashboard's "Run rug-pull demo" button and per-server "simulate drift"
  action flip this; a re-handshake then trips `PhoenixElxirBeam.MCP.Plugins.RugPull`.
  """

  use Agent

  def start_link(_opts) do
    Agent.start_link(fn -> MapSet.new() end, name: __MODULE__)
  end

  @doc "Marks a mock server id as serving a drifted tool list."
  def poison(server_id), do: Agent.update(__MODULE__, &MapSet.put(&1, server_id))

  @doc "Clears the drift for a mock server id."
  def heal(server_id), do: Agent.update(__MODULE__, &MapSet.delete(&1, server_id))

  @doc "Whether a mock server id is currently serving a drifted tool list."
  def poisoned?(server_id), do: Agent.get(__MODULE__, &MapSet.member?(&1, server_id))
end
