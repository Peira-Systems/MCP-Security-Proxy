defmodule PhoenixElxirBeam.MCP.Plugin.WasmRunner do
  @moduledoc """
  Runs one in-process, sandboxed Wasm plugin: compiles its `.wasm`/`.wat` file once,
  keeps a small pool of pre-instantiated guests, and relays requests from
  `PhoenixElxirBeam.MCP.Pipeline` to whichever guest is free — the Wasm counterpart of
  `PhoenixElxirBeam.MCP.Plugin.SidecarRunner`, speaking the `alloc`/`handle` guest ABI
  instead of stdio JSON-RPC (`docs/plugin-protocol.md` §5.4, `docs/wasm-plugin-plan.md` W2).

  ## Why a pool, not one instance

  A single Wasmtime instance/`Store` is not meant to serve concurrent calls the way a
  sidecar's `id`-correlated stdio stream can. Each in-flight `request/4` **checks out** one
  pool instance, runs the alloc/write/`handle`/read round trip directly against it (in the
  *caller's* process, not this GenServer's — so N callers can be genuinely concurrent, up
  to the pool size), then checks it back in. Checkout is monitored: if the caller dies
  mid-call (e.g. `Pipeline`'s own `Task.shutdown(:brutal_kill)` on a timeout) without
  checking in, this GenServer notices the `:DOWN` and reclaims the slot itself.

  ## Every checked-out slot is discarded, never reused

  Whatever happened during a call — clean success, a guest trap, a caller-side timeout —
  the instance that served it is **killed and replaced** with a fresh one instantiated
  from the cached, already-compiled `Module` before the pool considers that slot available
  again. This is not just caution: the W0 spike (`docs/wasm-plugin-plan.md`) could not
  conclusively prove a timed-out call's underlying execution is truly halted rather than
  merely abandoned by the Elixir-level timeout, so a slot that has ever timed out or
  trapped is never trusted again, full stop — re-instantiation (cheap, by design, once the
  expensive compile step has already happened) costs far less than the alternative.

  Every `Wasmex` instance this runner starts is `Process.unlink/1`'d *before* it is killed
  during a respin — `Process.exit(pid, :kill)` is an untrappable signal that propagates to
  linked processes regardless of `trap_exit`, and every instance is linked to this
  GenServer by `Wasmex.start_link/1`'s normal behavior. Skipping the unlink would crash
  this runner on its own ordinary respin, not just on a genuine instance failure.

  This runner does **not** trap exits from its instances otherwise: an instance crashing
  on its own (not via a deliberate respin-triggered kill) crashes this GenServer too, and
  `WasmSupervisor` restarts it with a fresh handshake — the same behavior
  `SidecarRunner`/`SidecarSupervisor` already have for a dead sidecar subprocess. This is a
  deliberate scope boundary, not an oversight: resuming gracefully from a single dead pool
  slot without restarting the whole plugin would need first tracking checked-out slots by
  Wasm instance pid as well as by caller monitor, for what should be a rare event.

  ## Capabilities

  Every instance is given WASI preview1 with every option at its empty default (`docs/
  plugin-protocol.md` §5.4.3) — no preopened directories (so no filesystem access at all,
  full stop), no args/env, stdio wired to nothing. This is **not optional**, and it is not
  "zero WASI" either — a guest built from Rust's `std` (needed for an ordinary JSON library
  like `serde_json`) imports a handful of WASI functions (`environ_get`,
  `environ_sizes_get`, `fd_write`, `proc_exit`) even when it makes no I/O calls itself,
  because `std`'s own init/panic machinery references them; a guest built to need none of
  that (this project's own WAT test fixtures) imports nothing and is unaffected by WASI
  being linked but unused either way. What matters for the threat model is unchanged either
  way: no filesystem, and no network capability at all, since WASI preview1 has no socket
  API to grant regardless of configuration (confirmed empirically while building W4's
  reference plugin — see `docs/wasm-plugin-plan.md`'s W4 notes).
  """

  use GenServer

  require Logger

  alias PhoenixElxirBeam.MCP.Alerts
  alias PhoenixElxirBeam.MCP.Plugin.{Manifest, Provenance}

  @page_bytes 65_536
  @default_pool_size 2
  @circuit_threshold 5
  @circuit_cooldown_ms 30_000
  @handshake_timeout_ms 4_000
  @default_request_timeout_ms 5_000

  # Bring a crashed-but-healthy runner back (transient handshake failures
  # aside); WasmSupervisor's max_restarts window guards against a
  # hopelessly broken one crash-looping forever.
  def child_spec(opts) do
    %{
      id: {__MODULE__, Keyword.fetch!(opts, :name)},
      start: {__MODULE__, :start_link, [opts]},
      restart: :permanent
    }
  end

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.fetch!(opts, :name))
  end

  @doc "The plugin's manifest, fetched during the `initialize` handshake."
  @spec manifest(GenServer.server()) :: Manifest.t()
  def manifest(server), do: GenServer.call(server, :manifest)

  @doc "`:ready` when instances are available, `:circuit_open` when the breaker has tripped."
  @spec health(GenServer.server()) :: :ready | :circuit_open | :down
  def health(server) do
    GenServer.call(server, :health)
  catch
    :exit, _ -> :down
  end

  @doc """
  Runs one request against a pooled guest instance and returns its decoded `"result"` (or
  `"error"`) — the Wasm counterpart of `SidecarRunner.request/4`. `method` is one of the
  §9 method names (`"discovery/inspect"`, `"call/evaluate"`, `"call/inspectResponse"`,
  `"call/inspectChunk"`) exactly as a sidecar would receive it; `params` is the same shape
  a sidecar's params would be. Never call this with `"initialize"` — that only happens
  once per pool instance, internally, before it is ever handed out.
  """
  @spec request(GenServer.server(), String.t(), map(), pos_integer()) ::
          {:ok, term()} | {:error, term()}
  def request(server, method, params, timeout \\ @default_request_timeout_ms) do
    case checkout(server, timeout) do
      {:ok, mon, slot} ->
        result = call_guest(slot, method, params, timeout)
        checkin(server, mon, if(match?({:ok, _}, result), do: :ok, else: :error))
        result

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp checkout(server, timeout) do
    GenServer.call(server, :checkout, timeout)
  catch
    :exit, _ -> {:error, :down}
  end

  defp checkin(server, mon, outcome) do
    GenServer.cast(server, {:checkin, mon, outcome})
  catch
    :exit, _ -> :ok
  end

  # -- server ----------------------------------------------------------------

  @impl true
  def init(opts) do
    name = Keyword.fetch!(opts, :name)
    path = Keyword.fetch!(opts, :path)
    limits = Keyword.get(opts, :limits, []) || []
    memory_pages = Keyword.get(limits, :memory_pages)

    store_limits =
      memory_pages && %Wasmex.StoreLimits{memory_size: memory_pages * @page_bytes}

    prov = %{
      name: Keyword.get(opts, :plugin_name, to_string(name)),
      path: path,
      pin: Keyword.get(opts, :pin)
    }

    with {:ok, bytes} <- File.read(path),
         {:ok, engine} <- Wasmex.Engine.new(%Wasmex.EngineConfig{}),
         {:ok, compile_store} <- Wasmex.Store.new(nil, engine),
         {:ok, module} <- Wasmex.Module.compile(compile_store, bytes) do
      state = %{
        engine: engine,
        module: module,
        store_limits: store_limits,
        available: [],
        checked_out: %{},
        manifest: nil,
        config: Keyword.get(opts, :config, %{}),
        proxy: Keyword.get(opts, :proxy, %{name: "mcp-security-proxy", version: "0.1.0"}),
        pool_size: Keyword.get(opts, :pool_size),
        failures: 0,
        breaker_opened_at: nil,
        prov: prov
      }

      with {:ok, state} <- handshake(state),
           :ok <- check_provenance(state) do
        {:ok, state}
      else
        {:error, {:provenance, detail}} ->
          Alerts.emit(:wasm_provenance, :critical, detail, %{plugin: prov.name})
          {:stop, {:provenance_mismatch, detail}}

        {:error, reason} ->
          {:stop, {:handshake_failed, reason}}
      end
    else
      {:error, reason} -> {:stop, {:compile_failed, reason}}
    end
  end

  defp check_provenance(state) do
    prov_for_verify = %{
      cmd: Path.basename(state.prov.path),
      resolved_args: [state.prov.path],
      pin: state.prov.pin,
      name: state.prov.name
    }

    case Provenance.verify(prov_for_verify, state.manifest) do
      {:ok, _digests} -> :ok
      {:error, detail} -> {:error, {:provenance, detail}}
    end
  end

  # Spins up the first instance, calls "initialize" on it to fetch the Manifest, then
  # spins up the rest of the pool (sized from the manifest's own maxConcurrency once
  # known — the pool can't be sized before the first instance exists to ask).
  defp handshake(state) do
    first = spin_instance(state)

    init_params = %{
      "protocolVersion" => "0.1",
      "proxy" => state.proxy,
      "config" => state.config
    }

    case call_guest(first, "initialize", init_params, @handshake_timeout_ms) do
      {:ok, result} ->
        manifest = Manifest.from_wire(result)
        pool_size = state.pool_size || manifest.max_concurrency || @default_pool_size
        rest = for _ <- 2..pool_size//1, do: spin_instance(state)
        {:ok, %{state | manifest: manifest, available: [first | rest]}}

      {:error, reason} ->
        Process.unlink(first.pid)
        if Process.alive?(first.pid), do: Process.exit(first.pid, :kill)
        {:error, reason}
    end
  end

  # See the moduledoc "Capabilities" section for why this is `new_wasi` with
  # empty options rather than plain `new` -- it's load-bearing, not a slip.
  defp spin_instance(state) do
    {:ok, store} = Wasmex.Store.new_wasi(%Wasmex.Wasi.WasiOptions{}, state.store_limits, state.engine)
    {:ok, pid} = Wasmex.start_link(%{store: store, module: state.module})
    {:ok, memory} = Wasmex.memory(pid)
    %{pid: pid, store: store, memory: memory}
  end

  # See the moduledoc: unlink is load-bearing here, not defensive noise.
  defp respin(old_slot, state) do
    Process.unlink(old_slot.pid)
    if Process.alive?(old_slot.pid), do: Process.exit(old_slot.pid, :kill)
    spin_instance(state)
  end

  # The §5.4.2 envelope round trip: write the request JSON into the guest's memory,
  # call handle, read the response JSON back. Runs in the CALLER's process (see
  # request/4), not this GenServer's.
  #
  # `handle` returns a SINGLE i32 pointing to an 8-byte header (`[ptr: u32 LE, len: u32
  # LE]`), not a genuine 2-value Wasm return -- `extern "C"` tuple returns lower to an
  # *unspecified* ABI on this target (confirmed empirically while building the W4
  # reference plugin: neither real multi-value nor a predictable sret parameter position),
  # so every guest, including this project's own WAT test fixtures, writes its response
  # through this one-pointer-to-a-header convention instead. See docs/plugin-protocol.md
  # §5.4.1.
  defp call_guest(%{pid: pid, store: store, memory: memory}, method, params, timeout) do
    payload = Jason.encode!(%{"method" => method, "params" => params})

    try do
      with {:ok, [in_ptr]} <- Wasmex.call_function(pid, "alloc", [byte_size(payload)], timeout),
           :ok <- Wasmex.Memory.write_binary(store, memory, in_ptr, payload),
           {:ok, [header_ptr]} <-
             Wasmex.call_function(pid, "handle", [in_ptr, byte_size(payload)], timeout) do
        <<out_ptr::little-32, out_len::little-32>> =
          Wasmex.Memory.read_binary(store, memory, header_ptr, 8)

        store
        |> Wasmex.Memory.read_binary(memory, out_ptr, out_len)
        |> decode_envelope()
      end
    catch
      # A wasmex call timeout can surface as a GenServer.call EXIT rather than a clean
      # {:error, :timeout} — confirmed in the W0 spike, load-bearing, not boilerplate.
      :exit, reason -> {:error, {:exit, reason}}
    end
  end

  defp decode_envelope(bytes) do
    case Jason.decode(bytes) do
      {:ok, %{"result" => result}} -> {:ok, result}
      {:ok, %{"error" => error}} -> {:error, error}
      {:ok, _other} -> {:error, "malformed guest response (missing result/error)"}
      {:error, _} -> {:error, "guest response was not valid JSON"}
    end
  end

  @impl true
  def handle_call(:manifest, _from, state), do: {:reply, state.manifest, state}

  def handle_call(:health, _from, state) do
    {:reply, if(breaker_open?(state), do: :circuit_open, else: :ready), state}
  end

  def handle_call(:checkout, {caller_pid, _}, state) do
    cond do
      breaker_open?(state) ->
        {:reply, {:error, :circuit_open}, state}

      state.available == [] ->
        {:reply, {:error, :pool_exhausted}, state}

      true ->
        [slot | rest] = state.available
        mon = Process.monitor(caller_pid)

        {:reply, {:ok, mon, slot},
         %{state | available: rest, checked_out: Map.put(state.checked_out, mon, slot)}}
    end
  end

  @impl true
  def handle_cast({:checkin, mon, outcome}, state), do: {:noreply, do_checkin(mon, outcome, state)}

  @impl true
  def handle_info({:DOWN, mon, :process, _pid, _reason}, state) do
    {:noreply, do_checkin(mon, :error, state)}
  end

  defp do_checkin(mon, outcome, state) do
    case Map.pop(state.checked_out, mon) do
      {nil, _checked_out} ->
        state

      {slot, checked_out} ->
        Process.demonitor(mon, [:flush])
        fresh = respin(slot, state)
        state = %{state | checked_out: checked_out, available: [fresh | state.available]}
        if outcome == :ok, do: note_success(state), else: note_failure(state)
    end
  end

  # -- circuit breaker (mirrors SidecarRunner) -----------------------------

  defp note_success(state), do: %{state | failures: 0, breaker_opened_at: nil}

  defp note_failure(state) do
    failures = state.failures + 1

    if failures >= @circuit_threshold do
      name = plugin_name(state)
      Logger.warning("WasmRunner: #{name} — #{failures} consecutive failures — circuit open")

      if is_nil(state.breaker_opened_at) do
        Alerts.emit(
          :wasm_circuit_open,
          :critical,
          "wasm plugin #{name} circuit breaker opened after #{failures} consecutive failures",
          %{plugin: name}
        )
      end

      %{state | failures: failures, breaker_opened_at: System.monotonic_time(:millisecond)}
    else
      %{state | failures: failures}
    end
  end

  defp plugin_name(%{manifest: %Manifest{plugin: %{name: name}}}) when is_binary(name), do: name
  defp plugin_name(_), do: "unknown"

  defp breaker_open?(%{breaker_opened_at: nil}), do: false

  defp breaker_open?(%{breaker_opened_at: at}) do
    System.monotonic_time(:millisecond) - at < @circuit_cooldown_ms
  end
end
