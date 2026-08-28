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
          {:sidecar, name: "...", transport: :stdio, cmd: "...", grants: %{...}}
        ]

  `{:sidecar, _}` entries are parsed and stored **disabled** with a
  `:not_implemented` note — the out-of-process runner is roadmap step 5.
  """

  use GenServer
  require Logger

  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @capability_kinds [:policy, :scanner, :audit_sink]

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

    opts
    |> Keyword.get_lazy(:plugins, &configured_plugins/0)
    |> Enum.with_index()
    |> Enum.each(fn {spec, index} ->
      case build_entry(spec, index) do
        {:ok, entry} ->
          :ets.insert(table, {entry.name, entry})

        {:error, reason} ->
          Logger.error("Plugin.Registry: skipping #{inspect(spec)}: #{reason}")
      end
    end)

    {:ok, %{table: table}}
  end

  @impl true
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

  defp build_entry({:sidecar, opts}, index) when is_list(opts) do
    {:ok,
     base_entry(%{
       name: Keyword.get(opts, :name, "sidecar-#{index}"),
       version: "0.0.0",
       module: nil,
       kind: :sidecar,
       order: index,
       enabled: false,
       note: :not_implemented
     })}
  end

  defp build_entry({module, opts}, index) when is_atom(module) and is_list(opts) do
    manifest = Manifest.normalize(module.manifest())
    grants = Keyword.get(opts, :grants, %{})

    case Enum.find(@capability_kinds, &Map.has_key?(manifest.capabilities, &1)) do
      nil ->
        {:error, "manifest declares no supported capability"}

      kind ->
        {:ok, capability_entry(kind, manifest, module, grants, index)}
    end
  rescue
    error -> {:error, Exception.message(error)}
  end

  defp build_entry(other, _index), do: {:error, "unrecognized plugin spec: #{inspect(other)}"}

  defp capability_entry(:policy, manifest, module, grants, index) do
    cap = manifest.capabilities.policy

    base_entry(%{
      name: manifest.plugin.name,
      version: manifest.plugin.version,
      module: module,
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

  defp capability_entry(kind, manifest, module, _grants, index)
       when kind in [:scanner, :audit_sink] do
    base_entry(%{
      name: manifest.plugin.name,
      version: manifest.plugin.version,
      module: module,
      kind: kind,
      order: index,
      # Neither is invoked by the pipeline yet; registered for visibility only.
      enabled: false,
      note: :not_invoked_yet
    })
  end

  defp base_entry(fields) do
    Map.merge(
      %{
        name: nil,
        version: "0.0.0",
        module: nil,
        kind: nil,
        phases: [],
        tool_tags: [],
        timeout_ms: 50,
        fail_mode: :fail_closed,
        can_mutate: [],
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
