defmodule PhoenixElxirBeam.MCP.Plugin.StateStore do
  @moduledoc """
  Postgres persistence for the runtime-mutable bits of the plugin registry
  (M3.4b): whether a plugin is enabled, its position in the pipeline, and
  (M4.4) an operator-edited config override.

  `PhoenixElxirBeam.MCP.Plugin.Registry` seeds entries from application config
  at boot, then overlays whatever is stored here — so an operator's
  enable/disable/reorder/config edit survives a restart. A plugin's manifest
  and capability always come from code; `config` comes from code unless an
  operator has overridden it here.

  All calls are fail-soft: a DB error logs and returns a safe default so the
  registry still boots.
  """
  require Logger

  alias PhoenixElxirBeam.MCP.Plugin.PluginState
  alias PhoenixElxirBeam.Repo

  @type overlay :: %{
          optional(String.t()) => %{
            enabled: boolean(),
            position: integer() | nil,
            config: map() | nil
          }
        }

  @spec all() :: overlay()
  def all do
    Repo.all(PluginState)
    |> Map.new(fn s -> {s.name, %{enabled: s.enabled, position: s.position, config: s.config}} end)
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

  @doc "Persists an operator-edited config override for `name`."
  @spec put_config(String.t(), map()) :: :ok
  def put_config(name, config) when is_binary(name) and is_map(config) do
    upsert(%{name: name, config: config}, [:config])
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
