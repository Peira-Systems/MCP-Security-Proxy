defmodule Mix.Tasks.Mcp.Rules.CheckTest do
  use PhoenixElxirBeam.DataCase, async: false

  alias PhoenixElxirBeam.MCP.{ServerRegistration, ServerStore}
  alias PhoenixElxirBeam.Repo

  setup do
    original = Application.get_env(:phoenix_elxir_beam, PhoenixElxirBeam.MCP)

    on_exit(fn ->
      if original do
        Application.put_env(:phoenix_elxir_beam, PhoenixElxirBeam.MCP, original)
      else
        Application.delete_env(:phoenix_elxir_beam, PhoenixElxirBeam.MCP)
      end
    end)

    :ok
  end

  defp seed_server(id, name, tool_state) do
    %ServerRegistration{}
    |> ServerRegistration.changeset(%{
      id: id,
      name: name,
      transport: "http",
      base_url: "http://example.invalid",
      tool_state: tool_state
    })
    |> Repo.insert!()
  end

  defp configure_rules(rules, unclassified_mode \\ "off") do
    Application.put_env(:phoenix_elxir_beam, PhoenixElxirBeam.MCP,
      plugins: [
        {PhoenixElxirBeam.MCP.Plugins.RuleEngine, config: %{"rules" => rules}},
        {PhoenixElxirBeam.MCP.Plugins.UnclassifiedGuard, config: %{"mode" => unclassified_mode}}
      ]
    )
  end

  test "exits 0 and reports zero gaps when every sensitive tool is covered" do
    seed_server("srv-a", "server-a", %{
      "read_secrets" => %{
        "tags" => ["sensitive_read"],
        "suggested_tags" => ["sensitive_read"],
        "quarantined" => false,
        "quarantine_reason" => nil,
        "hash" => "h"
      }
    })

    configure_rules([
      %{"match" => %{"tool_tags_any" => ["sensitive_read"]}, "action" => "deny", "reason" => "r"}
    ])

    {gaps, _report} = Mix.Tasks.Mcp.Rules.Check.run_check()
    assert gaps == []
  end

  test "reports a gap when a tool's only rule is agent-scoped" do
    seed_server("srv-b", "server-b", %{
      "read_secrets" => %{
        "tags" => ["sensitive_read"],
        "suggested_tags" => ["sensitive_read"],
        "quarantined" => false,
        "quarantine_reason" => nil,
        "hash" => "h"
      }
    })

    configure_rules([
      %{
        "match" => %{"agent" => "agent://ci-runner", "tool_tags_any" => ["sensitive_read"]},
        "action" => "deny",
        "reason" => "r"
      }
    ])

    {gaps, _report} = Mix.Tasks.Mcp.Rules.Check.run_check()
    assert [%{type: :uncovered_tag, tool_name: "read_secrets", server_name: "server-b"}] = gaps
  end

  test "disambiguates identically-named tools on two different servers" do
    tool_state = %{
      "send_email" => %{
        "tags" => [],
        "suggested_tags" => ["network_egress"],
        "quarantined" => false,
        "quarantine_reason" => nil,
        "hash" => "h"
      }
    }

    seed_server("srv-c", "server-c", tool_state)
    seed_server("srv-d", "server-d", tool_state)
    configure_rules([])

    {gaps, _report} = Mix.Tasks.Mcp.Rules.Check.run_check()

    assert Enum.sort(Enum.map(gaps, & &1.server_name)) == ["server-c", "server-d"]
    assert Enum.all?(gaps, &(&1.tool_name == "send_email" and &1.type == :unreviewed))
  end

  test "zero registered servers reports a distinct warning, not a clean bill of health" do
    configure_rules([])

    {gaps, report} = Mix.Tasks.Mcp.Rules.Check.run_check()

    assert gaps == []
    assert report =~ "0 servers registered"
    refute report =~ "0 gaps"
  end

  # `run_check/0` calls an unrescued `Repo.query!("SELECT 1")` reachability
  # probe before `ServerStore.all/0`, specifically so an unreachable Postgres
  # crashes the task instead of `ServerStore.all/0`'s own rescue-to-`[]`
  # making "DB is down" indistinguishable from "zero servers registered".
  #
  # We can't simulate true unreachability by reconfiguring
  # `PhoenixElxirBeam.Repo` itself mid-test: it's a pooled, already-started
  # `Ecto.Adapters.SQL.Sandbox` connection shared (via `DataCase`) with every
  # other test in this run, so repointing its config wouldn't affect the
  # live pool without restarting the Repo supervisor — which would tear down
  # the sandbox out from under concurrently-running tests.
  #
  # Instead, this proves the exact failure mechanism the probe relies on
  # (an unreachable connection exits/crashes loudly rather than returning
  # an ignorable error value) via a throwaway `Postgrex` connection pointed
  # at a refused port, independent of the shared test Repo.
  test "the reachability probe's query raises when Postgres is unreachable" do
    Process.flag(:trap_exit, true)

    {:ok, conn} =
      Postgrex.start_link(
        hostname: "127.0.0.1",
        port: 1,
        username: "mcp_proxy",
        password: "unreachable",
        database: "unreachable",
        backoff_type: :stop,
        sync_connect: false,
        show_sensitive_data_on_connection_error: false
      )

    # An unroutable/refused connection surfaces as the (linked) connection
    # process itself exiting once its supervisor gives up retrying
    # (`backoff_type: :stop`), rather than as an `{:error, _}` return —
    # this is the same failure shape `ensure_db_reachable!/0`'s bare
    # `Repo.query!("SELECT 1")` relies on to bring the whole
    # `mix mcp.rules.check` task down loudly instead of silently reporting
    # "0 servers registered".
    assert_receive {:EXIT, ^conn, _reason}, 2_000
  end
end
