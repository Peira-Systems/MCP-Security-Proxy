defmodule Mix.Tasks.Mcp.Rules.BackfillSuggestedTags do
  @shortdoc "Backfills suggested_tags for tool overlays persisted before that field existed"

  @moduledoc """
  A one-off data migration, not a CI gate. `suggested_tags` (a `TagInference`
  heuristic hint, never enforced — see `PhoenixElxirBeam.MCP.RuleCoverage`'s
  `:unreviewed` gap type) started being persisted in each server
  registration's `tool_state` overlay after a point in time; any tool row
  from before that has no `"suggested_tags"` key at all, and
  `mix mcp.rules.check` silently treats a missing key the same as "nothing
  suggested" — invisible to gap detection, not flagged as a false negative.

  This task finds every such tool and backfills `suggested_tags` by running
  `PhoenixElxirBeam.MCP.TagInference.infer/2` against the tool's **name
  alone** — no live handshake, no network/stdio I/O against the actual
  registered server, so running this is always safe and fast. This is
  strictly weaker than the full name+description heuristic a live handshake
  would see: a terse tool name with a revealing description could still be
  missed. Every tool this task backfills with an empty `suggested_tags` list
  is printed with a `(name-only)` note for exactly that reason — an empty
  result here isn't a guarantee nothing concerning exists, only that the
  name alone didn't suggest anything. Re-running `ServerRegistry.rehandshake/2`
  (or re-registering) for a server already recomputes `suggested_tags` from
  the live, full name+description heuristic and persists it — so the real
  fix for a tool this task couldn't confidently clear is a rehandshake, not
  re-running this task again.

  Idempotent: a tool that already has a `"suggested_tags"` key (even `[]`)
  is left untouched and not reported.

      mix mcp.rules.backfill_suggested_tags
      mix mcp.rules.backfill_suggested_tags --dry-run
  """

  use Mix.Task

  alias PhoenixElxirBeam.MCP.{ServerRegistration, TagInference}
  alias PhoenixElxirBeam.Repo

  @impl true
  def run(args) do
    # Same reasoning as `mix mcp.rules.check`: this task only ever needs
    # `Repo`, so it starts just that instead of the full supervision tree.
    Mix.Task.run("app.config")
    {:ok, _} = Application.ensure_all_started(:ecto_sql)

    case Repo.start_link() do
      {:ok, _} -> :ok
      {:error, {:already_started, _pid}} -> :ok
    end

    dry_run? = "--dry-run" in args

    registrations = Repo.all(ServerRegistration)
    plan = Enum.flat_map(registrations, &plan_for_registration/1)

    Enum.each(plan, fn {reg, tool_name, suggested} ->
      report_line(reg.name, tool_name, suggested, dry_run?)
    end)

    unless dry_run? do
      plan
      |> Enum.group_by(fn {reg, _tool_name, _suggested} -> reg.id end)
      |> Enum.each(fn {_id, entries} -> apply_backfill(entries) end)
    end

    server_count = plan |> Enum.map(fn {reg, _, _} -> reg.id end) |> Enum.uniq() |> length()

    verb = if dry_run?, do: "would be backfilled", else: "backfilled"
    Mix.shell().info("#{length(plan)} tool(s) #{verb} across #{server_count} server(s).")

    if dry_run? do
      Mix.shell().info("No changes written (--dry-run).")
    end
  end

  # {registration, tool_name, suggested_tags} for every tool whose overlay
  # has no "suggested_tags" key at all. A tool already carrying the key
  # (even an empty list) is left alone.
  defp plan_for_registration(reg) do
    for {tool_name, overlay} <- reg.tool_state || %{},
        not Map.has_key?(overlay, "suggested_tags") do
      suggested = TagInference.infer(tool_name, nil) |> Enum.map(&to_string/1)
      {reg, tool_name, suggested}
    end
  end

  defp report_line(server_name, tool_name, [], dry_run?) do
    verb = if dry_run?, do: "would backfill", else: "backfilled"
    Mix.shell().info("  #{verb}: #{server_name}/#{tool_name} -> [] (name-only)")
  end

  defp report_line(server_name, tool_name, suggested, dry_run?) do
    verb = if dry_run?, do: "would backfill", else: "backfilled"
    Mix.shell().info("  #{verb}: #{server_name}/#{tool_name} -> #{inspect(suggested)}")
  end

  defp apply_backfill([{reg, _tool_name, _suggested} | _] = entries) do
    updated_tool_state =
      Enum.reduce(entries, reg.tool_state, fn {_reg, tool_name, suggested}, tool_state ->
        Map.update!(tool_state, tool_name, &Map.put(&1, "suggested_tags", suggested))
      end)

    reg
    |> ServerRegistration.changeset(%{tool_state: updated_tool_state})
    |> Repo.update!()
  end
end
