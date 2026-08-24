defmodule PhoenixElxirBeam.MCP.StdioServer do
  @moduledoc """
  Speaks the MCP stdio transport directly with a real MCP server process:
  newline-delimited JSON-RPC over the process's stdin/stdout, via an Erlang
  port (no third-party bridge). One process per registered stdio server —
  `ServerRegistry` owns its lifecycle under `StdioServerSupervisor`.
  """

  use GenServer

  # Client API

  # Not restarted on crash — ServerRegistry is the sole owner of each
  # spawned process and removes it from its map on termination; an
  # auto-restarted process would leave the registry pointing at a stale pid.
  def child_spec(opts) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}, restart: :temporary}
  end

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc "Sends one JSON-RPC request (a map with string keys) and blocks for its matching response."
  def request(pid, body, timeout \\ 15_000) do
    GenServer.call(pid, {:request, body}, timeout)
  end

  # Server callbacks

  @impl true
  def init(opts) do
    cmd = Keyword.fetch!(opts, :cmd)
    args = Keyword.get(opts, :args, [])

    port = Port.open({:spawn_executable, cmd}, [:binary, :exit_status, args: args])
    {:ok, %{port: port, buffer: "", pending: %{}}}
  end

  @impl true
  def handle_call({:request, body}, from, state) do
    Port.command(state.port, Jason.encode!(body) <> "\n")
    {:noreply, put_in(state.pending[body["id"]], from)}
  end

  @impl true
  def handle_info({port, {:data, data}}, %{port: port} = state) do
    {lines, rest} = split_lines(state.buffer <> data)
    {:noreply, Enum.reduce(lines, %{state | buffer: rest}, &handle_line/2)}
  end

  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    Enum.each(state.pending, fn {_id, from} ->
      GenServer.reply(from, {:error, "server process exited with status #{status}"})
    end)

    {:stop, :normal, state}
  end

  defp split_lines(buffer) do
    case String.split(buffer, "\n") do
      [incomplete] ->
        {[], incomplete}

      parts ->
        {rest, [incomplete]} = Enum.split(parts, -1)
        {rest, incomplete}
    end
  end

  defp handle_line("", state), do: state

  defp handle_line(line, state) do
    case Jason.decode(line) do
      {:ok, %{"id" => id} = msg} ->
        case Map.pop(state.pending, id) do
          {nil, _pending} ->
            state

          {from, pending} ->
            GenServer.reply(from, {:ok, msg})
            %{state | pending: pending}
        end

      # Notifications and malformed lines carry no id we're waiting on — ignore.
      _ ->
        state
    end
  end
end
