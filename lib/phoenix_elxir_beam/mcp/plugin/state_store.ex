defmodule PhoenixElxirBeam.MCP.Plugin.StateStore do
  @moduledoc """
  Postgres persistence for the runtime-mutable bits of the plugin registry
  (M3.4b): whether a plugin is enabled, and its position in the pipeline.

  `PhoenixElxirBeam.MCP.Plugin.Registry` seeds entries from application config
  at boot, then overlays whatever is stored here — so an operator's
  enable/disable/reorder survives a restart. Everything else about a plugin
  (its manifest, capability, config) always comes from code/config.

  All calls are fail-soft: a DB error logs and returns a safe default so the
  registry still boots.
  """
  require Logger

  alias PhoenixElxirBeam.MCP.Plugin.PluginState
  alias PhoenixElxirBeam.Repo

  @type overlay :: %{optional(String.t()) => %{enabled: boolean(), position: integer() | nil}}

  @spec all() :: overlay()
  def all do
    Repo.all(PluginState)
    |> Map.new(fn s -> {s.name, %{enabled: s.enabled, position: s.position}} end)
  rescue
    e -> soft("load", e, %{})
  catch
    :exit, e -> soft("load", e, %{})
  end

  @spec put_enabled(String.t(), boolean()) :: :ok
  def put_enabled(name, enabled) when is_binary(name) and is_boolean(enabled) do
    upsert(%{name: name, enabled: enabled}, [:enabled])
  end

  @doc "Persists `name → position` for every entry in `ordered_names`."
  @spec put_order([String.t()]) :: :ok
  def put_order(ordered_names) when is_list(ordered_names) do
    ordered_names
    |> Enum.with_index()
    |> Enum.each(fn {name, pos} -> upsert(%{name: name, position: pos}, [:position]) end)
  end

  @spec upsert(map(), [atom()]) :: :ok
  defp upsert(attrs, replace_fields) do
    %PluginState{}
    |> PluginState.changeset(attrs)
    |> Repo.insert(
      on_conflict: {:replace, replace_fields ++ [:updated_at]},
      conflict_target: :name
    )

    :ok
  rescue
    e -> soft("write", e, :ok)
  catch
    :exit, e -> soft("write", e, :ok)
  end

  defp soft(op, e, default) do
    Logger.warning("Plugin.StateStore: #{op} failed (fail-soft): #{inspect(e)}")
    default
  end
end
