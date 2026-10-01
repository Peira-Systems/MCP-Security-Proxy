defmodule Mix.Tasks.Mcp.Rules.SeedFixturesTest do
  # Targets the real, singleton ServerRegistry (mix test already boots the
  # full app), same convention as server_registry_test.exs — async: true is
  # safe since each run gets its own generated server id.
  use PhoenixElxirBeamWeb.ConnCase, async: true

  import ExUnit.CaptureIO

  alias PhoenixElxirBeam.MCP.ServerRegistry

  test "run/1 registers the fixture catalog with read_secrets/post_webhook tagged and list_files untagged" do
    output = capture_io(fn -> Mix.Tasks.Mcp.Rules.SeedFixtures.run([]) end)

    assert output =~ "ci-fixture-catalog"
    assert output =~ "3 tool(s)"

    [server] =
      ServerRegistry.list_servers()
      |> Enum.filter(&(&1.name == "ci-fixture-catalog"))

    on_exit(fn -> ServerRegistry.remove_server(server.id) end)

    by_name = Map.new(server.tools, &{&1.name, &1})

    assert by_name["read_secrets"].tags == [:sensitive_read]
    assert :sensitive_read in by_name["read_secrets"].suggested_tags

    assert by_name["post_webhook"].tags == [:network_egress]
    assert :network_egress in by_name["post_webhook"].suggested_tags

    assert by_name["list_files"].tags == []
    assert by_name["list_files"].suggested_tags == []
  end
end
