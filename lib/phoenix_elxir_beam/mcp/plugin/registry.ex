defmodule PhoenixElxirBeam.MCP.Plugin.Registry do
  @moduledoc """
  Holds the set of registered plugins, seeded from application config at
  boot and toggleable at runtime without a redeploy.

  Entries live in an ETS table (`:protected` — the GenServer writes, anyone
  reads) so the request-path lookup in `PhoenixElxirBeam.MCP.PolicyEngine`
  (`active_policies/1`) is a plain table read, not a GenServer round-trip.
  Mutations (`enable/1`, `disable/1`, `reorder/1`) go through the GenServer.

  Config shape (see `docs/plugin-protocol.md` §15.1):

      config :phoenix_elxir_beam, PhoenixElxirBeam.MCP,
        plugins: [
          {PhoenixElxirBeam.MCP.Plugins.ChainExfil, []},
          {:sidecar, name: "...", transport: :stdio, cmd: "python",
           args: [{:priv, "plugins/foo.py"}], config: %{...}, grants: %{...}}
        ]

  In-process `{Module, opts}` entries are built synchronously at boot. Each
  `{:sidecar, opts}` entry spawns a `PhoenixElxirBeam.MCP.Plugin.SidecarRunner`
  under `SidecarSupervisor` in `handle_continue/2` — so sidecar plugins come
  online a beat after boot, and a spawn / handshake failure is logged and
  skipped rather than blocking the registry.
  """

  use GenServer
  require Logger

  alias PhoenixElxirBeam.MCP.Plugin.{Manifest, SidecarRunner}

  @capability_kinds [:policy, :scanner, :audit_sink]
  @sidecar_supervisor PhoenixElxirBeam.MCP.SidecarSupervisor

  # Client API

  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc "Every registered entry, in configured order."
  @spec list(atom()) :: [map()]
  def list(table \\ __MODULE__) do
    table
    |> :ets.tab2list()
    |> Enum.map(&elem(&1, 1))
    |> Enum.sort_by(& &1.order)
  end

  @doc "Enabled `policy` entries whose `phases` include `phase`, in configured order."
  @spec active_policies(atom(), atom()) :: [map()]
  def active_policies(phase, table \\ __MODULE__) do
    table
    |> list()
    |> Enum.filter(&(&1.kind == :policy and &1.enabled and phase in &1.phases))
  end

  @doc "Enabled `scanner` entries whose `phases` include `phase`, in configured order."
  @spec active_scanners(atom(), atom()) :: [map()]
  def active_scanners(phase, table \\ __MODULE__) do
    table
    |> list()
    |> Enum.filter(&(&1.kind == :scanner and &1.enabled and phase in &1.phases))
  end

  @doc "Enabled `audit_sink` entries, in configured order."
  @spec active_sinks(atom()) :: [map()]
  def active_sinks(table \\ __MODULE__) do
    table
    |> list()
    |> Enum.filter(&(&1.kind == :audit_sink and &1.enabled))
  end

  @doc "Enabled `policy` + `scanner` entries with the `:post_call` phase, in configured order."
  @spec active_post_call(atom()) :: [map()]
  def active_post_call(table \\ __MODULE__) do
    table
    |> list()
    |> Enum.filter(&(&1.kind in [:policy, :scanner] and &1.enabled and :post_call in &1.phases))
  end

  @doc "Enabled `policy` + `scanner` entries with the `:chunk` phase, in configured order."
  @spec active_chunk(atom()) :: [map()]
  def active_chunk(table \\ __MODULE__) do
    table
    |> list()
    |> Enum.filter(&(&1.kind in [:policy, :scanner] and &1.enabled and :chunk in &1.phases))
  end

  @doc "Blocks until sidecar startup (`handle_continue/2`) has finished. Mainly for tests."
  def await(server \\ __MODULE__), do: GenServer.call(server, :await)

  def enable(name, server \\ __MODULE__), do: GenServer.call(server, {:set_enabled, name, true})
  def disable(name, server \\ __MODULE__), do: GenServer.call(server, {:set_enabled, name, false})

  @doc "Reassigns `order` to match the given list of plugin names. Unlisted entries keep their slot after listed ones."
  def reorder(names, server \\ __MODULE__) when is_list(names) do
    GenServer.call(server, {:reorder, names})
  end

  # Server

  @impl true
  def init(opts) do
    table = Keyword.get(opts, :name, __MODULE__)
    :ets.new(table, [:named_table, :protected, :set, read_concurrency: true])

    specs =
      opts
      |> Keyword.get_lazy(:plugins, &configured_plugins/0)
      |> Enum.with_index()

    {sidecars, in_process} =
      Enum.split_with(specs, fn {spec, _index} -> match?({:sidecar, _}, spec) end)

    Enum.each(in_process, fn {spec, index} -> insert_entry(table, spec, index, &build_entry/2) end)

    state = %{
      table: table,
      sidecar_supervisor: Keyword.get(opts, :sidecar_supervisor, @sidecar_supervisor)
    }

    {:ok, state, {:continue, {:start_sidecars, sidecars}}}
  end

  @impl true
  def handle_continue({:start_sidecars, sidecars}, state) do
    Enum.each(sidecars, fn {spec, index} ->
      insert_entry(state.table, spec, index, &start_sidecar(&1, &2, state.sidecar_supervisor))
    end)

    {:noreply, state}
  end

  defp insert_entry(table, spec, index, builder) do
    case builder.(spec, index) do
      {:ok, entry} -> :ets.insert(table, {entry.name, entry})
      {:error, reason} -> Logger.error("Plugin.Registry: skipping #{inspect(spec)}: #{reason}")
    end
  end

  @impl true
  def handle_call(:await, _from, state), do: {:reply, :ok, state}

  def handle_call({:set_enabled, name, value}, _from, state) do
    case :ets.lookup(state.table, name) do
      [{^name, entry}] ->
        :ets.insert(state.table, {name, %{entry | enabled: value}})
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:reorder, names}, _from, state) do
    slots = names |> Enum.with_index() |> Map.new()
    tail_base = map_size(slots)

    state.table
    |> :ets.tab2list()
    |> Enum.each(fn {name, entry} ->
      order = Map.get(slots, name, tail_base + entry.order)
      :ets.insert(state.table, {name, %{entry | order: order}})
    end)

    {:reply, :ok, state}
  end

  # Entry construction

  defp build_entry({module, opts}, index) when is_atom(module) and is_list(opts) do
    manifest = Manifest.normalize(module.manifest())
    grants = Keyword.get(opts, :grants, %{})

    case Enum.find(@capability_kinds, &Map.has_key?(manifest.capabilities, &1)) do
      nil ->
        {:error, "manifest declares no supported capability"}

      kind ->
        entry =
          kind
          |> capability_entry(manifest, grants, index)
          |> Map.merge(%{
            module: module,
            impl: {:module, module},
            config: Keyword.get(opts, :config, %{})
          })

        {:ok, entry}
    end
  rescue
    error -> {:error, Exception.message(error)}
  end

  defp build_entry(other, _index), do: {:error, "unrecognized plugin spec: #{inspect(other)}"}

  # Spawns the sidecar subprocess, fetches its manifest, and builds an entry
  # keyed on `impl: {:sidecar, runner_name}`.
  defp start_sidecar({:sidecar, opts}, index, supervisor) do
    with {:ok, name} <- Keyword.fetch(opts, :name),
         cmd when is_binary(cmd) <- resolve_cmd(Keyword.get(opts, :cmd)),
         runner = Module.concat(SidecarRunner, name),
         {:ok, _pid} <-
           DynamicSupervisor.start_child(
             supervisor,
             {SidecarRunner,
              name: runner,
              cmd: cmd,
              args: Enum.map(Keyword.get(opts, :args, []), &resolve_arg/1),
              config: Keyword.get(opts, :config, %{})}
           ),
         %Manifest{} = manifest <- SidecarRunner.manifest(runner),
         kind when not is_nil(kind) <-
           Enum.find(@capability_kinds, &Map.has_key?(manifest.capabilities, &1)) do
      grants = Keyword.get(opts, :grants, %{})

      entry =
        kind
        |> capability_entry(manifest, grants, index)
        |> Map.merge(%{
          module: nil,
          impl: {:sidecar, runner},
          transport: :stdio,
          config: Keyword.get(opts, :config, %{})
        })
        |> cap_sidecar_grants(kind, grants)

      {:ok, entry}
    else
      :error -> {:error, "sidecar spec missing :name"}
      nil -> {:error, "sidecar #{Keyword.get(opts, :name)}: manifest declares no capability"}
      {:error, reason} -> {:error, "sidecar #{Keyword.get(opts, :name)}: #{inspect(reason)}"}
      other -> {:error, "sidecar #{Keyword.get(opts, :name)}: #{inspect(other)}"}
    end
  end

  # A sidecar may only block if the operator granted it (`grants: %{block: true}`).
  defp cap_sidecar_grants(entry, :scanner, grants) do
    %{entry | can_block: entry.can_block and Map.get(grants, :block, false) == true}
  end

  defp cap_sidecar_grants(entry, _kind, _grants), do: entry

  defp resolve_cmd(nil), do: {:error, :missing_cmd}

  defp resolve_cmd(cmd) when is_binary(cmd) do
    cond do
      Path.type(cmd) == :absolute -> cmd
      exe = System.find_executable(cmd) -> exe
      true -> {:error, "command not found on PATH: #{cmd}"}
    end
  end

  defp resolve_arg({:priv, rel}),
    do: Application.app_dir(:phoenix_elxir_beam, Path.join("priv", rel))

  defp resolve_arg(arg) when is_binary(arg), do: arg

  defp capability_entry(:policy, manifest, grants, index) do
    cap = manifest.capabilities.policy

    base_entry(%{
      name: manifest.plugin.name,
      version: manifest.plugin.version,
      kind: :policy,
      phases: cap.phases,
      tool_tags: cap.tool_tags,
      timeout_ms: cap.timeout_ms,
      fail_mode: cap.fail_mode,
      can_mutate: cap_can_mutate(cap.can_mutate, grants),
      order: index,
      enabled: true
    })
  end

  defp capability_entry(:scanner, manifest, _grants, index) do
    cap = manifest.capabilities.scanner

    base_entry(%{
      name: manifest.plugin.name,
      version: manifest.plugin.version,
      kind: :scanner,
      phases: cap.phases,
      data_needs: cap.data_needs,
      timeout_ms: cap.timeout_ms,
      fail_mode: cap.fail_mode,
      can_block: cap.can_block,
      order: index,
      enabled: true
    })
  end

  defp capability_entry(:audit_sink, manifest, _grants, index) do
    base_entry(%{
      name: manifest.plugin.name,
      version: manifest.plugin.version,
      kind: :audit_sink,
      order: index,
      enabled: true
    })
  end

  defp base_entry(fields) do
    Map.merge(
      %{
        name: nil,
        version: "0.0.0",
        module: nil,
        impl: {:module, nil},
        config: %{},
        transport: :in_process,
        kind: nil,
        phases: [],
        tool_tags: [],
        data_needs: [],
        timeout_ms: 50,
        fail_mode: :fail_closed,
        can_mutate: [],
        can_block: false,
        order: 0,
        enabled: false,
        note: nil
      },
      fields
    )
  end

  defp cap_can_mutate(requested, grants) do
    granted = Map.get(grants, :mutate, [])
    Enum.filter(requested, &(&1 in granted))
  end

  defp configured_plugins do
    :phoenix_elxir_beam
    |> Application.get_env(PhoenixElxirBeam.MCP, [])
    |> Keyword.get(:plugins, [])
  end
end
