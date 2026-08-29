defmodule PhoenixElxirBeam.MCP.ServerRegistryTest do
  use PhoenixElxirBeamWeb.ConnCase, async: true

  alias PhoenixElxirBeam.MCP.ServerRegistry

  setup do
    name = :"server_registry_#{System.unique_integer([:positive])}"
    start_supervised!({ServerRegistry, name: name})

    base_url = PhoenixElxirBeam.MCPHTTPTestServer.start!()

    %{name: name, base_url: base_url}
  end

  test "registering a server discovers its tools via a real handshake", %{
    name: name,
    base_url: base_url
  } do
    assert {:ok, server} = ServerRegistry.register_server("External files", base_url, name)
    assert server.name == "External files"
    assert server.base_url == base_url

    assert Enum.map(server.tools, & &1.name) == [
             "list_files",
             "read_secrets",
             "read_config",
             "export_all",
             "post_webhook",
             "big_export"
           ]

    assert Enum.all?(server.tools, &(&1.tags == []))

    assert ServerRegistry.list_servers(name) == [server]
    assert ServerRegistry.get_server(server.id, name) == server
  end

  test "registering an unreachable server returns an error", %{name: name} do
    assert {:error, reason} =
             ServerRegistry.register_server("Nowhere", "http://127.0.0.1:1/mcp", name)

    assert is_binary(reason)
  end

  test "set_tool_tags updates a single tool's tags", %{name: name, base_url: base_url} do
    {:ok, server} = ServerRegistry.register_server("External files", base_url, name)

    assert {:ok, updated} =
             ServerRegistry.set_tool_tags(server.id, "read_secrets", [:sensitive_read], name)

    tool = Enum.find(updated.tools, &(&1.name == "read_secrets"))
    assert tool.tags == [:sensitive_read]

    other_tool = Enum.find(updated.tools, &(&1.name == "list_files"))
    assert other_tool.tags == []
  end

  test "remove_server deletes a registered server", %{name: name, base_url: base_url} do
    {:ok, server} = ServerRegistry.register_server("External files", base_url, name)
    assert :ok = ServerRegistry.remove_server(server.id, name)
    assert ServerRegistry.get_server(server.id, name) == nil
    assert ServerRegistry.list_servers(name) == []
  end

  test "registering a stdio server discovers its tools via a real process handshake", %{
    name: name
  } do
    node = System.find_executable("node") || raise "node not found on PATH"
    fixture = Path.expand("../../support/fixtures/echo_mcp_server.js", __DIR__)

    assert {:ok, server} = ServerRegistry.register_stdio_server("Echo", node, [fixture], name)
    assert server.transport == :stdio
    assert server.base_url == nil
    assert Enum.map(server.tools, & &1.name) == ["echo"]

    assert :ok = ServerRegistry.remove_server(server.id, name)
    assert ServerRegistry.get_server(server.id, name) == nil
  end

  test "registering a stdio server with a bad command returns an error", %{name: name} do
    assert {:error, reason} =
             ServerRegistry.register_stdio_server("Bad", "/no/such/executable", [], name)

    assert is_binary(reason)
  end

  test "registration pins a description hash per tool and finds no drift on its own", %{
    name: name,
    base_url: base_url
  } do
    {:ok, server} = ServerRegistry.register_server("Files", base_url, name)

    assert Enum.all?(server.tools, &match?("sha256:" <> _, &1.description_hash))
    assert server.findings == []
    assert Enum.all?(server.tools, &(&1.quarantined == false))
  end

  test "re-handshake with no change reports no drift", %{name: name, base_url: base_url} do
    {:ok, server} = ServerRegistry.register_server("Files", base_url, name)
    {:ok, re} = ServerRegistry.rehandshake(server.id, name)

    assert re.findings == []
    assert Enum.map(re.tools, & &1.name) == Enum.map(server.tools, & &1.name)
  end

  test "re-handshake after a tool definition drifts quarantines it and keeps operator tags", %{
    name: name
  } do
    node = System.find_executable("node") || raise "node not found on PATH"
    fixture = Path.expand("../../support/fixtures/drifting_mcp_server.js", __DIR__)
    sentinel = Path.join(System.tmp_dir!(), "drift-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm(sentinel) end)

    {:ok, server} =
      ServerRegistry.register_stdio_server("Drift", node, [fixture, sentinel], name)

    {:ok, _} = ServerRegistry.set_tool_tags(server.id, "note", [:sensitive_read], name)

    # Make the server's tools/list drift, then re-handshake.
    File.write!(sentinel, "")
    {:ok, re} = ServerRegistry.rehandshake(server.id, name)

    assert [%{type: "rug_pull"}] = re.findings
    note = Enum.find(re.tools, &(&1.name == "note"))
    assert note.quarantined
    assert :sensitive_read in note.tags

    {:ok, cleared} = ServerRegistry.clear_tool_block(server.id, "note", name)
    assert Enum.find(cleared.tools, &(&1.name == "note")).quarantined == false

    ServerRegistry.remove_server(server.id, name)
  end
end
