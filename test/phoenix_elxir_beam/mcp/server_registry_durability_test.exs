defmodule PhoenixElxirBeam.MCP.ServerRegistryDurabilityTest do
  @moduledoc "M2.2b: ServerRegistry entries survive a restart via Postgres."
  use PhoenixElxirBeam.DataCase, async: false

  alias PhoenixElxirBeam.MCP.{ServerRegistration, ServerRegistry}

  @name :server_registry_durability

  defp start_reg, do: start_supervised!({ServerRegistry, name: @name}, id: ServerRegistry)

  defp restart_reg do
    stop_supervised!(ServerRegistry)
    pid = start_reg()
    _ = :sys.get_state(pid)
    pid
  end

  setup do
    start_reg()
    :ok
  end

  test "an http server and its operator tags come back after a restart" do
    base_url = PhoenixElxirBeam.MCPHTTPTestServer.start!()

    {:ok, server} =
      ServerRegistry.register_server(
        "dur-http-#{System.unique_integer([:positive])}",
        base_url,
        @name
      )

    {:ok, _} = ServerRegistry.set_tool_tags(server.id, "read_secrets", [:sensitive_read], @name)

    # persisted overlay
    row = Repo.get(ServerRegistration, server.id)
    assert row.transport == "http"
    assert row.base_url == base_url
    assert row.tool_state["read_secrets"]["tags"] == ["sensitive_read"]

    restart_reg()

    restored = ServerRegistry.get_server(server.id, @name)
    assert restored.name == server.name
    assert restored.base_url == base_url
    assert Enum.find(restored.tools, &(&1.name == "read_secrets")).tags == [:sensitive_read]
  end

  test "a stdio server is re-spawned and its quarantine restored after a restart" do
    node = System.find_executable("node") || raise "node not found on PATH"
    fixture = Path.expand("../../support/fixtures/echo_mcp_server.js", __DIR__)

    {:ok, server} =
      ServerRegistry.register_stdio_server("dur-stdio", node, [fixture], @name)

    {:ok, _} = ServerRegistry.set_tool_tags(server.id, "echo", [:network_egress], @name)

    row = Repo.get(ServerRegistration, server.id)
    assert row.transport == "stdio"
    assert row.command == node

    restart_reg()

    restored = ServerRegistry.get_server(server.id, @name)
    assert restored.transport == :stdio
    assert is_pid(restored.pid)
    assert Enum.find(restored.tools, &(&1.name == "echo")).tags == [:network_egress]

    ServerRegistry.remove_server(server.id, @name)
  end

  test "remove_server deletes the persisted row" do
    base_url = PhoenixElxirBeam.MCPHTTPTestServer.start!()
    {:ok, server} = ServerRegistry.register_server("dur-rm", base_url, @name)
    assert Repo.get(ServerRegistration, server.id)

    :ok = ServerRegistry.remove_server(server.id, @name)
    refute Repo.get(ServerRegistration, server.id)
  end

  test "an http server that is unreachable on boot is skipped, not fatal" do
    {:ok, %ServerRegistration{}} =
      %ServerRegistration{}
      |> ServerRegistration.changeset(%{
        id: "real-unreachable",
        name: "gone",
        transport: "http",
        base_url: "http://127.0.0.1:1/mcp"
      })
      |> Repo.insert()

    pid = restart_reg()
    assert Process.alive?(pid)
    refute ServerRegistry.get_server("real-unreachable", @name)
  end
end
