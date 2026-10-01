defmodule PhoenixElxirBeam.MCP.CiFixtureServerTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.CiFixtureServer

  test "start!/0 returns a base URL whose /mcp endpoint answers a real initialize + tools/list handshake" do
    base_url = CiFixtureServer.start!()

    init_body = %{
      "jsonrpc" => "2.0",
      "id" => 1,
      "method" => "initialize",
      "params" => %{
        "protocolVersion" => "2024-11-05",
        "capabilities" => %{},
        "clientInfo" => %{"name" => "test", "version" => "0.0.1"}
      }
    }

    assert {:ok, %Req.Response{status: 200, body: init_resp}} =
             Req.post(base_url, json: init_body)

    assert %{"result" => %{"serverInfo" => %{"name" => "ci-fixture-catalog"}}} = init_resp

    list_body = %{"jsonrpc" => "2.0", "id" => 2, "method" => "tools/list", "params" => %{}}

    assert {:ok, %Req.Response{status: 200, body: list_resp}} =
             Req.post(base_url, json: list_body)

    assert %{"result" => %{"tools" => tools}} = list_resp
    assert Enum.map(tools, & &1["name"]) == CiFixtureServer.tool_names()
    assert CiFixtureServer.tool_names() == ["read_secrets", "post_webhook", "list_files"]
  end
end
