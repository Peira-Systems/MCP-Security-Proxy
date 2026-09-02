defmodule PhoenixElxirBeam.MCP.ServerStore do
  @moduledoc """
  Postgres persistence for `PhoenixElxirBeam.MCP.ServerRegistry`
  (`docs/productionization-plan.md` M2.2b). Persists the registration
  identity + connection details + the operator/scanner **overlay** (per-tool
  tags, quarantine, pinned hash) so a `docker compose restart` doesn't lose
  registered servers.

  Fresh tool descriptions / schemas are always taken from the live handshake
  on boot — only the overlay is stored here.

  Every call is wrapped: a DB failure is logged and swallowed, never raised
  (registration availability over durability, matching `PolicyStore`).
  """

  import Ecto.Query, only: [from: 2]
  require Logger

  alias PhoenixElxirBeam.MCP.ServerRegistration
  alias PhoenixElxirBeam.Repo

  @doc "Every persisted registration."
  @spec all() :: [ServerRegistration.t()]
  def all do
    Repo.all(ServerRegistration)
  rescue
    _ -> []
  catch
    :exit, _ -> []
  end

  @doc "Upserts a registration from an in-memory ServerRegistry server map."
  @spec persist(map()) :: :ok
  def persist(server) do
    attrs = %{
      id: server.id,
      name: server.name,
      transport: to_string(server.transport),
      base_url: server[:base_url],
      command: server[:command],
      args: server[:args] || [],
      command_label: server[:command_label],
      tool_state: tool_state(server[:tools] || []),
      timeout_ms: server[:timeout_ms],
      tls_verify: server[:tls_verify]
    }

    %ServerRegistration{}
    |> ServerRegistration.changeset(attrs)
    |> Repo.insert(
      on_conflict:
        {:replace,
         [
           :name,
           :base_url,
           :command,
           :args,
           :command_label,
           :tool_state,
           :timeout_ms,
           :tls_verify,
           :updated_at
         ]},
      conflict_target: :id
    )

    :ok
  rescue
    error in [DBConnection.OwnershipError] ->
      Logger.debug("ServerStore: no DB connection to persist #{server[:id]}")
      _ = error
      :ok

    error ->
      Logger.error("ServerStore: failed to persist #{server[:id]}: #{inspect(error)}")
      :ok
  catch
    :exit, _ -> :ok
  end

  @doc "Deletes a registration."
  @spec delete(String.t()) :: :ok
  def delete(id) do
    Repo.delete_all(from(r in ServerRegistration, where: r.id == ^id))
    :ok
  rescue
    _ -> :ok
  catch
    :exit, _ -> :ok
  end

  # Build the per-tool overlay from the live tool list.
  defp tool_state(tools) do
    Map.new(tools, fn tool ->
      {tool.name,
       %{
         "tags" => Enum.map(tool.tags || [], &to_string/1),
         "quarantined" => tool[:quarantined] || false,
         "quarantine_reason" => tool[:quarantine_reason],
         "hash" => tool[:description_hash]
       }}
    end)
  end
end
