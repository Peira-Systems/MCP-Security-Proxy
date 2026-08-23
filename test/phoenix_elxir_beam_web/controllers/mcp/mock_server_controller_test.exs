defmodule PhoenixElxirBeamWeb.MCP.MockServerControllerTest do
  use PhoenixElxirBeamWeb.ConnCase, async: true

  describe "tools/list" do
    test "returns the files server's tools", %{conn: conn} do
      conn =
        post(conn, ~p"/mcp/servers/files", %{
          "jsonrpc" => "2.0",
          "id" => 1,
          "method" => "tools/list",
          "params" => %{}
        })

      assert %{"jsonrpc" => "2.0", "id" => 1, "result" => %{"tools" => tools}} =
               json_response(conn, 200)

      assert Enum.map(tools, & &1["name"]) == ["list_files", "read_secrets"]
    end

    test "returns the net server's tools", %{conn: conn} do
      conn =
        post(conn, ~p"/mcp/servers/net", %{
          "jsonrpc" => "2.0",
          "id" => 1,
          "method" => "tools/list",
          "params" => %{}
        })

      assert %{"result" => %{"tools" => tools}} = json_response(conn, 200)
      assert Enum.map(tools, & &1["name"]) == ["check_status", "post_webhook"]
    end
  end

  describe "tools/call" do
    test "returns the canned response for a known tool", %{conn: conn} do
      conn =
        post(conn, ~p"/mcp/servers/files", %{
          "jsonrpc" => "2.0",
          "id" => 2,
          "method" => "tools/call",
          "params" => %{"name" => "read_secrets", "arguments" => %{}}
        })

      assert %{"jsonrpc" => "2.0", "id" => 2, "result" => result} = json_response(conn, 200)
      assert %{"isError" => false, "content" => [%{"type" => "text", "text" => text}]} = result
      assert text =~ "simulated"
    end

    test "returns a JSON-RPC error for an unknown tool", %{conn: conn} do
      conn =
        post(conn, ~p"/mcp/servers/files", %{
          "jsonrpc" => "2.0",
          "id" => 3,
          "method" => "tools/call",
          "params" => %{"name" => "nonexistent", "arguments" => %{}}
        })

      assert %{"jsonrpc" => "2.0", "id" => 3, "error" => %{"code" => -32601}} =
               json_response(conn, 200)
    end
  end

  test "initialize returns protocol/server info", %{conn: conn} do
    conn =
      post(conn, ~p"/mcp/servers/net", %{
        "jsonrpc" => "2.0",
        "id" => 4,
        "method" => "initialize",
        "params" => %{}
      })

    assert %{"result" => %{"protocolVersion" => _, "serverInfo" => %{"name" => name}}} =
             json_response(conn, 200)

    assert name =~ "net"
  end
end
