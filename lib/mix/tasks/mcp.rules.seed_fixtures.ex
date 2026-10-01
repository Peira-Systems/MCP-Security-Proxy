defmodule Mix.Tasks.Mcp.Rules.SeedFixtures do
  @shortdoc "Seeds a real, representative server registration for mix mcp.rules.check to audit"

  @moduledoc """
  Registers `PhoenixElxirBeam.MCP.CiFixtureServer`'s 3-tool catalog against
  the real `ServerRegistry`, exactly as an operator registering a real
  server would — a real `initialize` + `tools/list` handshake, real
  `TagInference` suggestions, real `ServerStore.persist/1`.

  Unlike `mix mcp.rules.check` (which deliberately avoids booting the full
  app — see its own moduledoc), this task genuinely needs `ServerRegistry`
  and so boots the full application. It's a one-shot CI setup step, not the
  audit itself, so the concern that motivated keeping `mcp.rules.check`
  Repo-only (re-handshaking *stored* servers on every invocation) doesn't
  apply here — this task runs once, against a fresh, empty CI database,
  and the process exits when it's done.

  Exists because the rule-coverage CI job otherwise has nothing to audit:
  the ephemeral CI Postgres starts with zero `ServerStore` registrations,
  so `mix mcp.rules.check` always reported "0 servers registered — nothing
  to check" and passed trivially. This task seeds one real, representative
  registration so that job is a genuine regression test — see
  `.github/workflows/rule-coverage.yml` and
  `docs/superpowers/specs/2026-09-30-rule-coverage-gate-design.md`.

      mix mcp.rules.seed_fixtures

  After registering, simulates an operator who reviewed and accepted
  `TagInference`'s suggestions for the two sensitive tools
  (`read_secrets` → `:sensitive_read`, `post_webhook` → `:network_egress`)
  via `ServerRegistry.set_tool_tags/3`. `list_files` is left untagged with
  no suggestion — the clean baseline tool `RuleCoverage` should report no
  gap for either way. `config/test.exs` carries an agent-agnostic rule
  covering both sensitive tags, so a correctly-configured CI run is
  expected to find zero gaps; if someone edits that config and stops
  covering one of these tags, this seed is what makes CI catch it.
  """

  use Mix.Task

  alias PhoenixElxirBeam.MCP.{CiFixtureServer, ServerRegistry}

  @impl true
  def run(_args) do
    Mix.Task.run("app.start")

    base_url = CiFixtureServer.start!()

    {:ok, server} = ServerRegistry.register_server("ci-fixture-catalog", base_url)

    {:ok, _} = ServerRegistry.set_tool_tags(server.id, "read_secrets", [:sensitive_read])
    {:ok, _} = ServerRegistry.set_tool_tags(server.id, "post_webhook", [:network_egress])

    Mix.shell().info(
      "mcp.rules.seed_fixtures: registered \"ci-fixture-catalog\" (#{server.id}) with " <>
        "#{length(server.tools)} tool(s), tagged read_secrets/post_webhook."
    )
  end
end
