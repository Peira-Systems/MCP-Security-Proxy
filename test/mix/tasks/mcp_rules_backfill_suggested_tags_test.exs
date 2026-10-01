defmodule Mix.Tasks.Mcp.Rules.BackfillSuggestedTagsTest do
  use PhoenixElxirBeam.DataCase, async: false

  import ExUnit.CaptureIO

  alias PhoenixElxirBeam.MCP.ServerRegistration
  alias PhoenixElxirBeam.Repo

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

  test "backfills suggested_tags for a tool whose overlay predates the field, leaving tags untouched" do
    seed_server("srv-backfill-a", "server-backfill-a", %{
      "read_secrets" => %{
        "tags" => ["sensitive_read"],
        "quarantined" => false,
        "quarantine_reason" => nil,
        "hash" => "h"
      }
    })

    output = capture_io(fn -> Mix.Tasks.Mcp.Rules.BackfillSuggestedTags.run([]) end)

    assert output =~ "server-backfill-a/read_secrets"
    assert output =~ "sensitive_read"
    assert output =~ "1 tool(s) backfilled across 1 server(s)"

    row = Repo.get(ServerRegistration, "srv-backfill-a")
    assert row.tool_state["read_secrets"]["suggested_tags"] == ["sensitive_read"]
    # The operator-assigned tags must survive untouched.
    assert row.tool_state["read_secrets"]["tags"] == ["sensitive_read"]
  end

  test "a tool whose name matches no heuristic gets an explicit empty list, not left missing" do
    seed_server("srv-backfill-b", "server-backfill-b", %{
      "list_files" => %{
        "tags" => [],
        "quarantined" => false,
        "quarantine_reason" => nil,
        "hash" => "h"
      }
    })

    capture_io(fn -> Mix.Tasks.Mcp.Rules.BackfillSuggestedTags.run([]) end)

    row = Repo.get(ServerRegistration, "srv-backfill-b")
    assert row.tool_state["list_files"]["suggested_tags"] == []
  end

  test "a tool that already has suggested_tags is left alone and not reported as backfilled" do
    seed_server("srv-backfill-c", "server-backfill-c", %{
      "read_secrets" => %{
        "tags" => ["sensitive_read"],
        "suggested_tags" => ["sensitive_read"],
        "quarantined" => false,
        "quarantine_reason" => nil,
        "hash" => "h"
      }
    })

    output = capture_io(fn -> Mix.Tasks.Mcp.Rules.BackfillSuggestedTags.run([]) end)

    assert output =~ "0 tool(s) backfilled"
    refute output =~ "server-backfill-c"
  end

  test "--dry-run reports what would change without writing anything" do
    seed_server("srv-backfill-d", "server-backfill-d", %{
      "read_secrets" => %{
        "tags" => ["sensitive_read"],
        "quarantined" => false,
        "quarantine_reason" => nil,
        "hash" => "h"
      }
    })

    output = capture_io(fn -> Mix.Tasks.Mcp.Rules.BackfillSuggestedTags.run(["--dry-run"]) end)

    assert output =~ "would backfill"
    assert output =~ "server-backfill-d/read_secrets"
    assert output =~ "No changes written"

    row = Repo.get(ServerRegistration, "srv-backfill-d")
    refute Map.has_key?(row.tool_state["read_secrets"], "suggested_tags")
  end

  test "a tool with no heuristic match is flagged as name-only, since a live handshake might see more" do
    seed_server("srv-backfill-e", "server-backfill-e", %{
      "list_files" => %{
        "tags" => [],
        "quarantined" => false,
        "quarantine_reason" => nil,
        "hash" => "h"
      }
    })

    output = capture_io(fn -> Mix.Tasks.Mcp.Rules.BackfillSuggestedTags.run([]) end)

    assert output =~ "name-only"
  end
end
