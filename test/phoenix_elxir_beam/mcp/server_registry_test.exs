defmodule PhoenixElxirBeam.MCP.ServerRegistryTest do
  use PhoenixElxirBeamWeb.ConnCase, async: true

  alias PhoenixElxirBeam.MCP.ServerRegistry

  setup do
    name = :"server_registry_#{System.unique_integer([:positive])}"
    start_supervised!({ServerRegistry, name: name})

    port = PhoenixElxirBeamWeb.Endpoint.config(:http)[:port]
    base_url = "http://127.0.0.1:#{port}/mcp/servers/files"

    %{name: name, base_url: base_url}
  end

  test "registering a server discovers its tools via a real handshake", %{
    name: name,
    base_url: base_url
  } do
    assert {:ok, server} = ServerRegistry.register_server("External files", base_url, name)
    assert server.name == "External files"
    assert server.base_url == base_url
    assert Enum.map(server.tools, & &1.name) == ["list_files", "read_secrets"]
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
end
