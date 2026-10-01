defmodule Mix.Tasks.Mcp.Rules.CheckTest do
  use PhoenixElxirBeam.DataCase, async: false

  import ExUnit.CaptureIO

  alias PhoenixElxirBeam.MCP.ServerRegistration
  alias PhoenixElxirBeam.Repo

  @generated_fixtures_path "test/support/generated_rule_fixtures.ex"

  setup do
    original = Application.get_env(:phoenix_elxir_beam, PhoenixElxirBeam.MCP)

    pre_existing? = File.exists?(@generated_fixtures_path)

    pre_existing_contents =
      if pre_existing?, do: File.read!(@generated_fixtures_path)

    on_exit(fn ->
      if original do
        Application.put_env(:phoenix_elxir_beam, PhoenixElxirBeam.MCP, original)
      else
        Application.delete_env(:phoenix_elxir_beam, PhoenixElxirBeam.MCP)
      end

      cond do
        pre_existing? -> File.write!(@generated_fixtures_path, pre_existing_contents)
        true -> File.rm(@generated_fixtures_path)
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

  test "a server-scoped deny rule covers its own server's tool" do
    seed_server("srv-scoped", "server-scoped", %{
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
        "match" => %{"server" => "srv-scoped", "tool_tags_any" => ["sensitive_read"]},
        "action" => "deny",
        "reason" => "r"
      }
    ])

    {gaps, _report} = Mix.Tasks.Mcp.Rules.Check.run_check()
    assert gaps == []
  end

  test "a server-scoped deny rule for a DIFFERENT server leaves this one uncovered" do
    seed_server("srv-other", "server-other", %{
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
        "match" => %{"server" => "srv-not-this-one", "tool_tags_any" => ["sensitive_read"]},
        "action" => "deny",
        "reason" => "r"
      }
    ])

    {gaps, _report} = Mix.Tasks.Mcp.Rules.Check.run_check()

    assert [%{type: :uncovered_tag, tool_name: "read_secrets", server_name: "server-other"}] =
             gaps
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

  # `run_check/0` used to call a separate `ensure_db_reachable!/0` probe
  # (`Repo.query!("SELECT 1")`) before `ServerStore.all/0`, specifically so
  # an unreachable Postgres crashed the task instead of `ServerStore.all/0`'s
  # own rescue-to-`[]` masking the failure as "zero servers registered".
  #
  # That probe only proved the connection worked, not that the actual query
  # `run_check/0` depends on (`Repo.all(ServerRegistration)`) would succeed —
  # a schema mismatch or any other query-specific failure would still have
  # been swallowed by `ServerStore.all/0`'s rescue. The fix (final
  # whole-branch review, finding 3) removes `ensure_db_reachable!/0` and
  # `ServerStore.all/0` from this task entirely: `run_check/0` now calls
  # `Repo.all(ServerRegistration)` directly and unrescued, so *any* failure
  # in the real query path — connection, schema, anything — propagates as an
  # exception exactly like the old probe did for connection failures alone.
  #
  # The dedicated Postgrex-against-a-refused-port test that lived here only
  # ever exercised Postgrex in isolation, never the shipped function, and
  # the function it was testing (`ensure_db_reachable!/0`) no longer exists.
  # It is removed rather than adapted: there is no separate "probe" left to
  # test, and the "zero registered servers" test above plus the two "has
  # gaps" tests below already exercise the unrescued `Repo.all/1` happy
  # path. A dedicated unreachable-DB test would need to tear down/repoint
  # the shared sandboxed `Repo` connection, which (as the removed test's own
  # comment noted) risks breaking other concurrently-running tests.

  describe "run/1 (end to end: exit behavior + generated fixture file)" do
    test "raises and writes a syntactically valid generated fixture file when gaps exist" do
      seed_server("srv-e2e-gap", "server-e2e-gap", %{
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

      output =
        capture_io(fn ->
          assert_raise Mix.Error, ~r/coverage gap/, fn ->
            Mix.Tasks.Mcp.Rules.Check.run([])
          end
        end)

      assert output =~ "uncovered_tag"
      assert output =~ "server-e2e-gap/read_secrets"

      assert File.exists?(@generated_fixtures_path)
      file_contents = File.read!(@generated_fixtures_path)
      assert file_contents =~ "server-e2e-gap/read_secrets"
      assert file_contents =~ "sensitive_read"

      # Syntactically valid, loadable Elixir — not just a string that
      # happens to look right.
      [{module, _bytecode}] = Code.compile_string(file_contents)
      assert module == PhoenixElxirBeam.MCP.GeneratedRuleFixtures

      [case] = module.cases()
      assert case.gap_type == :uncovered_tag
      assert case.call.tool_name == "read_secrets"
      assert case.call.tags == [:sensitive_read]

      # Regression test for finding 1: the generated file must always be
      # mix-format-clean, regardless of gap count.
      assert file_contents == format_elixir(file_contents)
    end

    test "exits cleanly and writes a format-clean, valid, empty-cases file when there are no gaps" do
      seed_server("srv-e2e-clean", "server-e2e-clean", %{
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
          "match" => %{"tool_tags_any" => ["sensitive_read"]},
          "action" => "deny",
          "reason" => "r"
        }
      ])

      output =
        capture_io(fn ->
          Mix.Tasks.Mcp.Rules.Check.run([])
        end)

      assert output =~ "0 gaps"

      assert File.exists?(@generated_fixtures_path)
      file_contents = File.read!(@generated_fixtures_path)

      [{module, _bytecode}] = Code.compile_string(file_contents)
      assert module == PhoenixElxirBeam.MCP.GeneratedRuleFixtures
      assert module.cases() == []

      # This is the direct regression test for finding 1: the raw
      # interpolated `def cases, do: [\n\n  ]` output is not
      # `mix format`-clean when there are zero gaps. Confirm the file as
      # written is already formatted.
      assert file_contents == format_elixir(file_contents)
    end

    @tag timeout: 30_000
    test "a genuinely fresh `mix mcp.rules.check` process never attempts to spawn a stored stdio server" do
      # Regression test for the app-boot finding: run/1 must not call
      # `Mix.Task.run("app.start")`, since that boots ServerRegistry, whose
      # `handle_continue(:restore, ...)` re-handshakes every stored server —
      # including spawning stdio commands — on every invocation. Inside
      # `mix test` the app is already running by the time any test executes,
      # so observing a pid change in-process can't tell old vs. fixed code
      # apart (`Mix.Task.run("app.start")` is a no-op on an already-started
      # app). The only way to actually observe this is a brand-new OS
      # process where the app has never booted — exactly the real CI
      # scenario.
      #
      # The sandboxed `Repo` pool this file's other tests share is wrapped
      # in a transaction the subprocess's own fresh connection can never
      # see, and manipulating `Ecto.Adapters.SQL.Sandbox`'s global mode to
      # work around that leaks into every other test using the same pool
      # (confirmed: doing so here made an unrelated "zero registered
      # servers" test see this row). So this test seeds and cleans up
      # through its own raw `Postgrex` connection instead — entirely
      # outside Ecto's sandbox, never touching `Repo`'s pool or mode.
      pg_opts = [
        hostname: System.get_env("PGHOST", "localhost"),
        port: String.to_integer(System.get_env("PGPORT", "5432")),
        username: System.get_env("PGUSER", "postgres"),
        password: System.get_env("PGPASSWORD", "postgres"),
        database: "phoenix_elxir_beam_test#{System.get_env("MIX_TEST_PARTITION")}"
      ]

      # `Postgrex.start_link/1` only offers a linked start, but `on_exit`
      # callbacks run in a separate process *after* this test process has
      # already exited — a connection still linked to this test would
      # already be dead by the time `on_exit` tried to use it for cleanup
      # (confirmed: that's exactly what silently dropped the DELETE below
      # on an earlier attempt, leaking rows across runs). `Process.unlink/1`
      # immediately after start detaches it so it outlives this test.
      {:ok, pg} = Postgrex.start_link(pg_opts)
      Process.unlink(pg)

      id = "srv-subprocess-stdio-#{System.unique_integer([:positive])}"
      now = DateTime.utc_now()

      {:ok, _} =
        Postgrex.query(
          pg,
          """
          INSERT INTO server_registrations
            (id, name, transport, command, args, tool_state, inserted_at, updated_at)
          VALUES ($1, $2, 'stdio', $3, '{}', '{}', $4, $4)
          """,
          [
            id,
            "subprocess-stdio-check",
            # A command that cannot exist on any PATH — if ServerRegistry's
            # restore path ever runs, this spawn fails and logs a warning.
            "/nonexistent/#{System.unique_integer([:positive])}/definitely-not-a-real-binary",
            now
          ]
        )

      on_exit(fn ->
        Postgrex.query!(pg, "DELETE FROM server_registrations WHERE id = $1", [id])
        GenServer.stop(pg)
      end)

      env =
        [
          {"MIX_ENV", "test"},
          {"PGUSER", System.get_env("PGUSER", "postgres")},
          {"PGPASSWORD", System.get_env("PGPASSWORD", "postgres")},
          {"PGHOST", System.get_env("PGHOST", "localhost")},
          {"PGPORT", System.get_env("PGPORT", "5432")}
        ]

      {output, _exit_code} =
        System.cmd("mix", ["mcp.rules.check"],
          env: env,
          stderr_to_stdout: true,
          cd: File.cwd!()
        )

      refute output =~ "ServerRegistry: restored",
             "mix mcp.rules.check must not boot ServerRegistry's restore path"

      refute output =~ "could not restore",
             "mix mcp.rules.check must not attempt to spawn a stored stdio server"
    end
  end

  defp format_elixir(source) do
    source
    |> Code.format_string!()
    |> IO.iodata_to_binary()
    |> Kernel.<>("\n")
  end
end
