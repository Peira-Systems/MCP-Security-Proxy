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

  alias PhoenixElxirBeam.MCP.Plugin.{ProxySetting, PluginState}
  alias PhoenixElxirBeam.Repo

  @proxy_settings_key "global"
  @default_proxy_mode :enforcing

  @type overlay :: %{
          optional(String.t()) => %{
            enabled: boolean(),
            position: integer() | nil,
            config: map() | nil,
            mode: String.t() | nil
          }
        }

  @spec all() :: overlay()
  def all do
    Repo.all(PluginState)
    |> Map.new(fn s ->
      {s.name, %{enabled: s.enabled, position: s.position, config: s.config, mode: s.mode}}
    end)
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

  @doc """
  Persists `name`'s dry-run override: `"enforcing"` | `"dry_run"` pins it
  regardless of the global proxy mode, `nil` clears the override (inherit).
  """
  @spec put_mode(String.t(), String.t() | nil) :: :ok
  def put_mode(name, mode) when is_binary(name) and (is_binary(mode) or is_nil(mode)) do
    upsert(%{name: name, mode: mode}, [:mode])
  end

  @doc "The global proxy mode, `:enforcing` by default when no override has been saved."
  @spec proxy_mode() :: :enforcing | :dry_run
  def proxy_mode do
    case Repo.get(ProxySetting, @proxy_settings_key) do
      nil -> @default_proxy_mode
      %ProxySetting{mode: mode} -> String.to_existing_atom(mode)
    end
  rescue
    e -> soft("load", e, @default_proxy_mode)
  catch
    :exit, e -> soft("load", e, @default_proxy_mode)
  end

  @doc "Persists the global proxy mode (`:enforcing` | `:dry_run`)."
  @spec put_proxy_mode(:enforcing | :dry_run) :: :ok
  def put_proxy_mode(mode) when mode in [:enforcing, :dry_run] do
    %ProxySetting{}
    |> ProxySetting.changeset(%{key: @proxy_settings_key, mode: to_string(mode)})
    |> Repo.insert(on_conflict: {:replace, [:mode, :updated_at]}, conflict_target: :key)

    :ok
  rescue
    e -> soft("write", e, :ok)
  catch
    :exit, e -> soft("write", e, :ok)
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
