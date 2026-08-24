defmodule PhoenixElxirBeam.MCP.StdioServerTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.StdioServer

  @fixture Path.expand("../../support/fixtures/echo_mcp_server.js", __DIR__)

  setup do
    node = System.find_executable("node") || raise "node not found on PATH"
    pid = start_supervised!({StdioServer, cmd: node, args: [@fixture]})
    %{pid: pid}
  end

  test "performs a real initialize + tools/list handshake over stdio", %{pid: pid} do
    assert {:ok, %{"result" => %{"serverInfo" => %{"name" => "echo"}}}} =
             StdioServer.request(pid, %{
               "jsonrpc" => "2.0",
               "id" => 1,
               "method" => "initialize",
               "params" => %{}
             })

    assert {:ok, %{"result" => %{"tools" => [%{"name" => "echo"}]}}} =
             StdioServer.request(pid, %{
               "jsonrpc" => "2.0",
               "id" => 2,
               "method" => "tools/list",
               "params" => %{}
             })
  end

  test "returns the server's error envelope for a failed call", %{pid: pid} do
    assert {:ok, %{"error" => %{"message" => "boom"}}} =
             StdioServer.request(pid, %{
               "jsonrpc" => "2.0",
               "id" => 3,
               "method" => "fail",
               "params" => %{}
             })
  end

  test "concurrent requests are matched to the right response by id", %{pid: pid} do
    task_a =
      Task.async(fn ->
        StdioServer.request(pid, %{
          "jsonrpc" => "2.0",
          "id" => 10,
          "method" => "tools/call",
          "params" => %{"name" => "echo", "arguments" => %{"n" => 1}}
        })
      end)

    task_b =
      Task.async(fn ->
        StdioServer.request(pid, %{
          "jsonrpc" => "2.0",
          "id" => 11,
          "method" => "tools/call",
          "params" => %{"name" => "echo", "arguments" => %{"n" => 2}}
        })
      end)

    assert {:ok, %{"id" => 10}} = Task.await(task_a)
    assert {:ok, %{"id" => 11}} = Task.await(task_b)
  end
end
