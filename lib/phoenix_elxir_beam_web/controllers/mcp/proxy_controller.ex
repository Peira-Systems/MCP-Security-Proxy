defmodule PhoenixElxirBeamWeb.MCP.ProxyController do
  @moduledoc """
  Policy-enforcing proxy between an MCP client and a registered upstream
  server (`PhoenixElxirBeam.MCP.ServerRegistry`).

  The proxy **terminates the MCP session**: it answers `initialize` itself
  (from the tools it discovered at registration), mints its own
  `mcp-session-id`, and hands it back in the response header. Every later
  request must carry that id — a client-chosen id the proxy did not mint is
  refused, and so is any non-handshake method before
  `notifications/initialized` completes the handshake
  (`PhoenixElxirBeam.MCP.SessionStore`).

  Once a session is established, each method's disposition comes from
  `PhoenixElxirBeam.MCP.MethodPolicy` — `tools/call` runs the full policy
  pipeline, `resources/read` / `prompts/get` are forwarded then their
  content is scanned and redacted, metadata reads pass through, and every
  unknown or unmediated method is refused. No method reaches the upstream
  without an explicit decision.

  Scanned methods against a `:http` upstream stream through
  `PhoenixElxirBeam.MCP.StreamProxy`: the response body is read
  incrementally and the `chunk` phase runs over each slice, so a
  `chunk`-phase deny (`StreamGuard`) cuts a large exfiltration mid-transfer
  rather than after the whole payload has crossed. `:stdio` upstreams use
  the buffered path.
  """

  use PhoenixElxirBeamWeb, :controller

  alias PhoenixElxirBeam.MCP.{
    ApiKey,
    CallContext,
    HoldRegistry,
    HttpTransport,
    MethodPolicy,
    Pipeline,
    PolicyEngine,
    Redaction,
    ResponseContent,
    ServerRegistry,
    Session,
    SessionStore,
    StdioServer,
    StreamProxy,
    Telemetry
  }

  alias PhoenixElxirBeam.MCP.Plugin.Registry, as: PluginRegistry

  @no_server_code -32001
  @no_session_code -32001
  @forbidden_code -32001
  @chain_blocked_code -32001
  @response_withheld_code -32002
  @quarantined_code -32003
  @method_refused_code -32601

  # Newest first — `initialize` echoes the client's version if supported,
  # else offers the newest.
  @supported_protocol_versions ~w(2025-06-18 2025-03-26 2024-11-05)
  @default_protocol_version "2025-06-18"

  def handle(conn, %{"server_id" => server_id} = params) do
    method = params["method"]
    jsonrpc = params["jsonrpc"] || "2.0"
    id = params["id"]
    rpc_params = params["params"] || %{}

    cond do
      method == "initialize" ->
        handle_initialize(conn, server_id, id, jsonrpc, rpc_params)

      method == "notifications/initialized" ->
        handle_initialized(conn)

      String.starts_with?(to_string(method), "notifications/") ->
        # Client notifications are fire-and-forget: acknowledge (202), keep
        # the session warm, never error. Per-notification routing (forwarding
        # `notifications/cancelled` upstream, etc.) is a later milestone.
        touch_session(conn)
        send_resp(conn, 202, "")

      method == "ping" ->
        json(conn, %{"jsonrpc" => jsonrpc, "id" => id, "result" => %{}})

      true ->
        with_session(conn, server_id, id, jsonrpc, fn session ->
          dispatch(conn, session, method, id, jsonrpc, rpc_params)
        end)
    end
  end

  # DELETE /mcp/proxy/:server_id — explicit session teardown. Only the key
  # that opened the session may close it.
  def delete(conn, _params) do
    session_id = session_id_header(conn)

    case SessionStore.fetch(session_id) do
      {:ok, %Session{key_id: key_id}} when is_binary(key_id) ->
        if key_id == conn.assigns.api_key.key_id, do: SessionStore.close(session_id)

      _ ->
        :ok
    end

    send_resp(conn, 204, "")
  end

  # -- handshake ----------------------------------------------------------

  defp handle_initialize(conn, server_id, id, jsonrpc, rpc_params) do
    key = conn.assigns.api_key

    cond do
      ServerRegistry.get_server(server_id) == nil ->
        json(conn, error(jsonrpc, id, @no_server_code, no_server_message(server_id)))

      not ApiKey.authorize?(key, server_id) ->
        json(
          conn,
          error(
            jsonrpc,
            id,
            @forbidden_code,
            "key #{key.key_id} is not authorized for server '#{server_id}'"
          )
        )

      true ->
        server = ServerRegistry.get_server(server_id)
        protocol = negotiate_protocol(rpc_params["protocolVersion"])

        {:ok, session} =
          SessionStore.open(server_id,
            client_info: rpc_params["clientInfo"],
            protocol_version: protocol,
            agent_id: key.agent_id,
            key_id: key.key_id
          )

        :ok = PolicyEngine.ensure_session(session.id, key.agent_id)

        result = %{
          "protocolVersion" => protocol,
          "capabilities" => %{"tools" => %{"listChanged" => false}},
          "serverInfo" => %{
            "name" => "mcp-security-proxy",
            "version" => proxy_version(),
            "upstream" => server.name
          }
        }

        conn
        |> put_resp_header("mcp-session-id", session.id)
        |> json(%{"jsonrpc" => jsonrpc, "id" => id, "result" => result})
    end
  end

  defp handle_initialized(conn) do
    conn |> session_id_header() |> mark_session_ready()
    send_resp(conn, 202, "")
  end

  defp mark_session_ready(nil), do: :ok
  defp mark_session_ready(session_id), do: SessionStore.mark_ready(session_id)

  defp touch_session(conn) do
    conn |> session_id_header() |> then(&(&1 && SessionStore.fetch(&1)))
    :ok
  end

  # Resolves the `mcp-session-id` header to a live, ready session bound to
  # this server, or short-circuits with a JSON-RPC error.
  defp with_session(conn, server_id, id, jsonrpc, fun) do
    case SessionStore.fetch(session_id_header(conn)) do
      :error ->
        json(
          conn,
          error(jsonrpc, id, @no_session_code, "no active MCP session; send initialize first")
        )

      {:ok, %Session{state: :initializing}} ->
        json(
          conn,
          error(
            jsonrpc,
            id,
            @no_session_code,
            "session handshake incomplete; send notifications/initialized"
          )
        )

      {:ok, %Session{server_id: bound}} when bound != server_id ->
        json(conn, error(jsonrpc, id, @no_session_code, "session is bound to a different server"))

      {:ok, %Session{key_id: key_id}}
      when key_id != nil and key_id != conn.assigns.api_key.key_id ->
        json(conn, error(jsonrpc, id, @forbidden_code, "session belongs to a different key"))

      {:ok, %Session{} = session} ->
        if ApiKey.authorize?(conn.assigns.api_key, server_id) do
          fun.(session)
        else
          json(
            conn,
            error(
              jsonrpc,
              id,
              @forbidden_code,
              "key is no longer authorized for server '#{server_id}'"
            )
          )
        end
    end
  end

  defp dispatch(conn, %Session{} = session, method, id, jsonrpc, rpc_params) do
    case MethodPolicy.disposition(method) do
      :police ->
        route_tool_call(conn, session, id, jsonrpc, rpc_params)

      :scan_response ->
        forward_and_scan(
          conn,
          session.server_id,
          session.id,
          method,
          method,
          id,
          jsonrpc,
          rpc_params
        )

      :forward ->
        forward(conn, session.server_id, envelope(jsonrpc, id, method, rpc_params), id)

      :ack ->
        send_resp(conn, 202, "")

      :refuse ->
        json(
          conn,
          error(
            jsonrpc,
            id,
            @method_refused_code,
            "method '#{method}' is not permitted through this proxy"
          )
        )
    end
  end

  # -- tools/call --------------------------------------------------------

  defp route_tool_call(conn, %Session{} = session, id, jsonrpc_version, rpc_params) do
    server_id = session.server_id
    session_id = session.id
    tool_name = rpc_params["name"]

    case quarantine_reason(server_id, tool_name) do
      {:quarantined, reason} ->
        # A discovery scanner (e.g. rug-pull) has held this tool. Refuse
        # before the policy pipeline, but still receipt the attempt.
        PolicyEngine.record_blocked(session_id, server_id, tool_name, reason)

        json(conn, %{
          "jsonrpc" => jsonrpc_version,
          "id" => id,
          "error" => %{"code" => @quarantined_code, "message" => reason}
        })

      :ok ->
        tags = tool_tags(server_id, tool_name)

        # Idempotent — the session's policy state was created at initialize;
        # this only guards against a race with a mid-flight teardown.
        :ok = PolicyEngine.ensure_session(session_id, session.agent_id)

        args = rpc_params["arguments"] || %{}

        case PolicyEngine.record_call(session_id, server_id, tool_name, tags, PolicyEngine, args) do
          {:allow, _event} ->
            forward_and_scan(
              conn,
              server_id,
              session_id,
              "tools/call",
              tool_name,
              id,
              jsonrpc_version,
              rpc_params
            )

          {:block, event} ->
            json(conn, %{
              "jsonrpc" => jsonrpc_version,
              "id" => id,
              "error" => %{"code" => @chain_blocked_code, "message" => event.reason}
            })

          {:hold, hold_id, timeout_ms, _event} ->
            # Park the request until an operator approves/denies on the
            # dashboard (or the hold's own timeout fires).
            resolve_hold(conn, hold_id, timeout_ms, %{
              server_id: server_id,
              session_id: session_id,
              tool_name: tool_name,
              tags: tags,
              id: id,
              jsonrpc: jsonrpc_version,
              rpc_params: rpc_params
            })
        end
    end
  end

  defp resolve_hold(conn, hold_id, timeout_ms, c) do
    case HoldRegistry.await(hold_id, timeout_ms + 5_000) do
      {:ok, :approved} ->
        {:allow, _event} =
          PolicyEngine.finalize_hold(c.session_id, c.server_id, c.tool_name, c.tags, :approved)

        forward_and_scan(
          conn,
          c.server_id,
          c.session_id,
          "tools/call",
          c.tool_name,
          c.id,
          c.jsonrpc,
          c.rpc_params
        )

      {:ok, :denied} ->
        {:block, event} =
          PolicyEngine.finalize_hold(c.session_id, c.server_id, c.tool_name, c.tags, :denied)

        json(conn, %{
          "jsonrpc" => c.jsonrpc,
          "id" => c.id,
          "error" => %{"code" => @chain_blocked_code, "message" => event.reason}
        })
    end
  end

  defp quarantine_reason(server_id, tool_name) do
    with %{tools: tools} <- ServerRegistry.get_server(server_id),
         %{quarantined: true} = tool <- Enum.find(tools, &(&1.name == tool_name)) do
      {:quarantined, tool.quarantine_reason || "tool quarantined by a discovery scan"}
    else
      _ -> :ok
    end
  end

  defp envelope(jsonrpc_version, id, method, rpc_params) do
    %{"jsonrpc" => jsonrpc_version, "id" => id, "method" => method, "params" => rpc_params}
  end

  defp tool_tags(server_id, tool_name) do
    case ServerRegistry.get_server(server_id) do
      nil ->
        []

      server ->
        case Enum.find(server.tools, &(&1.name == tool_name)) do
          nil -> []
          tool -> tool.tags
        end
    end
  end

  # Metadata reads (tools/list, resources/list, …): forward verbatim, no scan.
  defp forward(conn, server_id, body, id) do
    case upstream_request(server_id, body) do
      {:ok, resp_body} -> json(conn, resp_body)
      {:error, message} -> upstream_error(conn, id, message)
    end
  end

  # Forward `method`, reading the reply incrementally so the `chunk` phase can
  # cut a large response mid-stream, then run the `post_call` content scan
  # over the reassembled result and apply redactions (or withhold the whole
  # response) before replying. `scan_label` is what the audit row records the
  # scan against — the tool name for `tools/call`, the method itself for
  # `resources/read` etc.
  defp forward_and_scan(conn, server_id, session_id, method, scan_label, id, jsonrpc, rpc_params) do
    meta = %{session_id: session_id, server_id: server_id, tool_name: scan_label, method: method}

    case fetch_streamed(server_id, envelope(jsonrpc, id, method, rpc_params), meta) do
      {:error, message} ->
        upstream_error(conn, id, message)

      {:cut, reason, findings, taint_sources, bytes} ->
        PolicyEngine.record_response_scan(
          session_id,
          server_id,
          scan_label,
          findings,
          "stream cut after #{bytes} bytes: #{reason}",
          taint_sources
        )

        json(conn, %{
          "jsonrpc" => jsonrpc,
          "id" => id,
          "error" => %{"code" => @response_withheld_code, "message" => reason}
        })

      {:ok, %{"result" => result} = resp_body, chunk_findings, chunk_taint} when is_map(result) ->
        scan_response(
          conn,
          server_id,
          session_id,
          method,
          scan_label,
          id,
          jsonrpc,
          resp_body,
          result,
          chunk_findings,
          chunk_taint
        )

      {:ok, resp_body, chunk_findings, chunk_taint} ->
        # Error result or an unexpected shape — nothing to scan, but still
        # receipt anything the chunk phase collected on the way.
        PolicyEngine.record_response_scan(
          session_id,
          server_id,
          scan_label,
          chunk_findings,
          nil,
          chunk_taint
        )

        json(conn, resp_body)
    end
  end

  # `:http` upstreams stream through `StreamProxy` (incremental read + chunk
  # phase); `:stdio` is line-delimited request/response with no streaming.
  defp fetch_streamed(server_id, body, meta) do
    case ServerRegistry.get_server(server_id) do
      nil ->
        {:error, no_server_message(server_id)}

      %{transport: :http} = server ->
        measured_upstream(:http, fn -> StreamProxy.run(server, body, meta) end)

      %{transport: :stdio, pid: pid} ->
        measured_upstream(:stdio, fn ->
          case StdioServer.request(pid, body) do
            {:ok, resp_body} -> {:ok, resp_body, [], []}
            {:error, _reason} -> {:error, "upstream real server error"}
          end
        end)
    end
  end

  # Wraps an upstream call in a `[:mcp, :upstream, :request]` telemetry span
  # (latency + ok/error rate per transport) — see PhoenixElxirBeam.MCP.Telemetry.
  defp measured_upstream(transport, fun) do
    Telemetry.span([:upstream, :request], %{transport: transport}, fn ->
      result = fun.()
      outcome = if match?({:error, _}, result), do: :error, else: :ok
      {result, %{transport: transport, outcome: outcome}}
    end)
  end

  defp scan_response(
         conn,
         server_id,
         session_id,
         method,
         scan_label,
         id,
         jsonrpc,
         resp_body,
         result,
         chunk_findings,
         chunk_taint
       ) do
    case ResponseContent.extract(method, result) do
      :skip ->
        PolicyEngine.record_response_scan(
          session_id,
          server_id,
          scan_label,
          chunk_findings,
          nil,
          chunk_taint
        )

        json(conn, resp_body)

      {content, reinject} ->
        ctx =
          CallContext.new(%{
            phase: :post_call,
            call: %{
              session_id: session_id,
              server_id: server_id,
              tool_name: scan_label,
              method: method
            },
            response: %{is_error: false, content: content}
          })

        {verdict, findings, redactions, taint_sources, reason} =
          Pipeline.run_post_call(ctx, PluginRegistry.active_post_call())

        all_findings = chunk_findings ++ findings
        all_taint = chunk_taint ++ taint_sources

        case verdict do
          :deny ->
            PolicyEngine.record_response_scan(
              session_id,
              server_id,
              scan_label,
              all_findings,
              reason || "response withheld by policy",
              all_taint
            )

            json(conn, %{
              "jsonrpc" => jsonrpc,
              "id" => id,
              "error" => %{"code" => @response_withheld_code, "message" => reason}
            })

          :allow ->
            PolicyEngine.record_response_scan(
              session_id,
              server_id,
              scan_label,
              all_findings,
              nil,
              all_taint
            )

            redacted = Redaction.apply(content, redactions)
            json(conn, Map.put(resp_body, "result", reinject.(redacted)))
        end
    end
  end

  defp upstream_request(server_id, body) do
    case ServerRegistry.get_server(server_id) do
      nil -> {:error, no_server_message(server_id)}
      server -> measured_upstream(server.transport, fn -> forward_to_upstream(server, body) end)
    end
  end

  defp forward_to_upstream(%{transport: :stdio, pid: pid}, body) do
    case StdioServer.request(pid, body) do
      {:ok, resp_body} -> {:ok, resp_body}
      {:error, _reason} -> {:error, "upstream real server error"}
    end
  end

  defp forward_to_upstream(%{transport: :http} = server, body) do
    session_headers = if server.session_id, do: [{"mcp-session-id", server.session_id}], else: []
    {url, transport_headers} = HttpTransport.prepare(server.base_url)
    headers = transport_headers ++ session_headers

    case Req.post(url,
           json: body,
           headers: headers,
           receive_timeout: HttpTransport.receive_timeout(),
           connect_options: HttpTransport.connect_options()
         ) do
      {:ok, %{status: status, body: resp_body}} when status in 200..299 -> {:ok, resp_body}
      _ -> {:error, "upstream real server error"}
    end
  end

  # -- helpers ----------------------------------------------------------

  defp session_id_header(conn) do
    conn |> get_req_header("mcp-session-id") |> List.first()
  end

  defp negotiate_protocol(requested) when requested in @supported_protocol_versions, do: requested
  defp negotiate_protocol(_requested), do: @default_protocol_version

  defp proxy_version do
    :phoenix_elxir_beam |> Application.spec(:vsn) |> to_string()
  end

  defp no_server_message(server_id), do: "no MCP server registered for '#{server_id}'"

  defp error(jsonrpc, id, code, message) do
    %{"jsonrpc" => jsonrpc, "id" => id, "error" => %{"code" => code, "message" => message}}
  end

  defp upstream_error(conn, id, message) do
    json(conn, %{
      "jsonrpc" => "2.0",
      "id" => id,
      "error" => %{"code" => -32000, "message" => message}
    })
  end
end
