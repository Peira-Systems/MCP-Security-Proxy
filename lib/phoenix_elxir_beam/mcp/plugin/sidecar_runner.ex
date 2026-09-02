defmodule PhoenixElxirBeam.MCP.Plugin.SidecarRunner do
  @moduledoc """
  Runs one out-of-process plugin: spawns the command, does the `initialize`
  handshake to fetch its `Manifest`, and thereafter relays JSON-RPC requests
  from `PhoenixElxirBeam.MCP.Pipeline` over the subprocess's stdin/stdout.

  Newline-delimited JSON-RPC 2.0, identical framing to
  `PhoenixElxirBeam.MCP.StdioServer` (`docs/plugin-protocol.md` §5.1). The
  plugin MUST write only protocol messages to stdout; stderr flows to the
  BEAM console.

  Failure handling (`docs/plugin-protocol.md` §10): a per-request timeout
  yields `{:error, :timeout}`; a subprocess exit replies `{:error, :down}`
  to in-flight callers and stops the runner (the supervisor restarts it,
  re-handshaking); a small circuit breaker fast-fails `{:error, :circuit_open}`
  after several consecutive failures, then half-opens.
  """

  use GenServer

  require Logger

  alias PhoenixElxirBeam.MCP.Alerts
  alias PhoenixElxirBeam.MCP.Plugin.{Manifest, Provenance}

  @circuit_threshold 5
  @circuit_cooldown_ms 30_000
  @handshake_timeout_ms 4_000
  @default_request_timeout_ms 5_000

  # Restart a killed-but-healthy sidecar (transient), but don't let a
  # hopelessly broken one crash-loop the supervisor forever.
  def child_spec(opts) do
    %{
      id: {__MODULE__, Keyword.fetch!(opts, :name)},
      start: {__MODULE__, :start_link, [opts]},
      # Always bring a dead sidecar back (re-handshaking). Crash-loop
      # protection is the SidecarSupervisor's max_restarts window.
      restart: :permanent
    }
  end

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.fetch!(opts, :name))
  end

  @doc "The plugin's manifest, fetched during the `initialize` handshake."
  @spec manifest(GenServer.server()) :: Manifest.t()
  def manifest(server), do: GenServer.call(server, :manifest)

  @doc "`:ready` when calls are flowing, `:circuit_open` when the breaker has tripped."
  @spec health(GenServer.server()) :: :ready | :circuit_open | :down
  def health(server) do
    GenServer.call(server, :health)
  catch
    :exit, _ -> :down
  end

  @doc "Sends one JSON-RPC request and blocks for its result."
  @spec request(GenServer.server(), String.t(), map(), pos_integer()) ::
          {:ok, term()} | {:error, term()}
  def request(server, method, params, timeout \\ @default_request_timeout_ms) do
    GenServer.call(server, {:request, method, params, timeout}, timeout + 1_000)
  catch
    :exit, _ -> {:error, :down}
  end

  # -- server ----------------------------------------------------------------

  @impl true
  def init(opts) do
    cmd = Keyword.fetch!(opts, :cmd)
    args = Keyword.get(opts, :args, [])
    limits = Keyword.get(opts, :limits)

    {exec, exec_args} = apply_resource_limits(cmd, args, limits)
    port = Port.open({:spawn_executable, exec}, [:binary, :exit_status, args: exec_args])

    state = %{
      port: port,
      buffer: "",
      pending: %{},
      next_id: 2,
      manifest: nil,
      config: Keyword.get(opts, :config, %{}),
      proxy: Keyword.get(opts, :proxy, %{name: "mcp-security-proxy", version: "0.1.0"}),
      failures: 0,
      breaker_opened_at: nil,
      # Provenance (M3.5): the plugin name, the configured command string, the
      # resolved args, and the operator's pin — checked once the manifest is in.
      prov: %{
        name: Keyword.get(opts, :plugin_name, to_string(Keyword.fetch!(opts, :name))),
        cmd: Keyword.get(opts, :cmd_string, cmd),
        resolved_args: args,
        pin: Keyword.get(opts, :pin)
      }
    }

    with {:ok, state} <- handshake(state),
         :ok <- check_provenance(state) do
      {:ok, state}
    else
      {:error, {:provenance, detail}} ->
        Alerts.emit(:sidecar_provenance, :critical, detail, %{plugin: state.prov.name})
        {:stop, {:provenance_mismatch, detail}}

      {:error, reason} ->
        {:stop, {:handshake_failed, reason}}
    end
  end

  defp check_provenance(state) do
    case Provenance.verify(state.prov, state.manifest) do
      {:ok, _digests} -> :ok
      {:error, detail} -> {:error, {:provenance, detail}}
    end
  end

  # Wraps the sidecar command in `prlimit` (Linux) when `limits` is configured
  # and `prlimit` is available — a best-effort address-space + CPU-time cap so a
  # runaway sidecar is killed by the kernel, not just the supervisor. The
  # production-grade option (a container per sidecar) is in docs/plugin-supply-chain.md.
  defp apply_resource_limits(cmd, args, nil), do: {cmd, args}

  defp apply_resource_limits(cmd, args, limits) do
    case System.find_executable("prlimit") do
      nil ->
        Logger.warning("SidecarRunner: prlimit not found; #{inspect(limits)} not enforced")
        {cmd, args}

      prlimit ->
        flags =
          []
          |> maybe_flag("--as", limits[:as_mb] && limits[:as_mb] * 1_048_576)
          |> maybe_flag("--cpu", limits[:cpu_s])
          |> maybe_flag("--nproc", limits[:nproc])

        {prlimit, flags ++ ["--", cmd | args]}
    end
  end

  defp maybe_flag(flags, _name, nil), do: flags
  defp maybe_flag(flags, name, value), do: flags ++ ["#{name}=#{value}"]

  defp handshake(state) do
    send_line(state.port, %{
      "jsonrpc" => "2.0",
      "id" => 1,
      "method" => "initialize",
      "params" => %{
        "protocolVersion" => "0.1",
        "proxy" => state.proxy,
        "config" => state.config
      }
    })

    with {:ok, result, state} <- await_response(state, 1, @handshake_timeout_ms) do
      send_line(state.port, %{"jsonrpc" => "2.0", "method" => "initialized"})
      {:ok, %{state | manifest: Manifest.from_wire(result)}}
    end
  end

  # Blocking read for exactly the response to `id` — only used during the
  # synchronous handshake, before the GenServer loop is serving.
  defp await_response(state, id, timeout) do
    receive do
      {port, {:data, data}} when port == state.port ->
        {lines, buffer} = split_lines(state.buffer <> data)
        state = %{state | buffer: buffer}

        Enum.find_value(lines, {:cont, state}, fn line ->
          case Jason.decode(line) do
            {:ok, %{"id" => ^id, "result" => result}} -> {:done, {:ok, result, state}}
            {:ok, %{"id" => ^id, "error" => error}} -> {:done, {:error, error}}
            _ -> nil
          end
        end)
        |> case do
          {:done, outcome} -> outcome
          {:cont, state} -> await_response(state, id, timeout)
        end

      {port, {:exit_status, status}} when port == state.port ->
        {:error, {:exited, status}}
    after
      timeout -> {:error, :handshake_timeout}
    end
  end

  @impl true
  def handle_call(:manifest, _from, state), do: {:reply, state.manifest, state}

  def handle_call(:health, _from, state) do
    {:reply, if(breaker_open?(state), do: :circuit_open, else: :ready), state}
  end

  def handle_call({:request, method, params, timeout}, from, state) do
    # `breaker_open?` is false once the cooldown elapses (half-open): the
    # request goes through and its result closes or re-arms the breaker.
    if breaker_open?(state) do
      {:reply, {:error, :circuit_open}, state}
    else
      {:noreply, send_pending(state, from, method, params, timeout)}
    end
  end

  defp send_pending(state, from, method, params, timeout) do
    id = state.next_id

    send_line(state.port, %{
      "jsonrpc" => "2.0",
      "id" => id,
      "method" => method,
      "params" => params
    })

    timer = Process.send_after(self(), {:request_timeout, id}, timeout)
    %{state | pending: Map.put(state.pending, id, {from, timer}), next_id: id + 1}
  end

  @impl true
  def handle_info({port, {:data, data}}, %{port: port} = state) do
    {lines, buffer} = split_lines(state.buffer <> data)
    {:noreply, Enum.reduce(lines, %{state | buffer: buffer}, &handle_line/2)}
  end

  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    Enum.each(state.pending, fn {_id, {from, timer}} ->
      Process.cancel_timer(timer)
      GenServer.reply(from, {:error, :down})
    end)

    Logger.warning("SidecarRunner: subprocess exited with status #{status}")
    {:stop, {:shutdown, {:port_exit, status}}, %{state | pending: %{}}}
  end

  def handle_info({:request_timeout, id}, state) do
    case Map.pop(state.pending, id) do
      {nil, _pending} ->
        {:noreply, state}

      {{from, _timer}, pending} ->
        GenServer.reply(from, {:error, :timeout})
        {:noreply, note_failure(%{state | pending: pending})}
    end
  end

  defp handle_line("", state), do: state

  defp handle_line(line, state) do
    case Jason.decode(line) do
      {:ok, %{"id" => id} = msg} ->
        case Map.pop(state.pending, id) do
          {nil, _pending} ->
            state

          {{from, timer}, pending} ->
            Process.cancel_timer(timer)

            case msg do
              %{"result" => result} ->
                GenServer.reply(from, {:ok, result})
                note_success(%{state | pending: pending})

              %{"error" => error} ->
                GenServer.reply(from, {:error, error})
                note_failure(%{state | pending: pending})
            end
        end

      _ ->
        state
    end
  end

  # -- circuit breaker -----------------------------------------------------

  defp note_success(state), do: %{state | failures: 0, breaker_opened_at: nil}

  defp note_failure(state) do
    failures = state.failures + 1

    if failures >= @circuit_threshold do
      name = sidecar_name(state)
      Logger.warning("SidecarRunner: #{name} — #{failures} consecutive failures — circuit open")

      # Alert only on the opening transition, not every further failure.
      if is_nil(state.breaker_opened_at) do
        PhoenixElxirBeam.MCP.Alerts.emit(
          :sidecar_circuit_open,
          :critical,
          "sidecar plugin #{name} circuit breaker opened after #{failures} consecutive failures",
          %{plugin: name}
        )
      end

      %{state | failures: failures, breaker_opened_at: System.monotonic_time(:millisecond)}
    else
      %{state | failures: failures}
    end
  end

  defp sidecar_name(%{manifest: %Manifest{plugin: %{name: name}}}) when is_binary(name), do: name
  defp sidecar_name(_), do: "unknown"

  defp breaker_open?(%{breaker_opened_at: nil}), do: false

  defp breaker_open?(%{breaker_opened_at: at}) do
    System.monotonic_time(:millisecond) - at < @circuit_cooldown_ms
  end

  # -- framing (mirrors StdioServer) -------------------------------------

  defp send_line(port, message), do: Port.command(port, Jason.encode!(message) <> "\n")

  defp split_lines(buffer) do
    case String.split(buffer, "\n") do
      [incomplete] -> {[], incomplete}
      parts -> parts |> Enum.split(-1) |> then(fn {lines, [rest]} -> {lines, rest} end)
    end
  end
end
