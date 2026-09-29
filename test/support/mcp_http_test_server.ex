defmodule PhoenixElxirBeam.MCPHTTPTestServer do
  @moduledoc """
  Minimal MCP server over the Streamable HTTP transport, for tests that need
  to exercise the proxy / `ServerRegistry` HTTP path without a live
  third-party server. Serves the same fixed catalog as
  `test/support/fixtures/catalog_mcp_server.js`.

  Start one with `start!/0` from a test `setup`; it returns the base URL and
  tears itself down via `ExUnit` on-exit.
  """

  import Plug.Conn

  @tools [
    %{
      "name" => "list_files",
      "description" => "List files in the workspace",
      "inputSchema" => %{"type" => "object", "properties" => %{}},
      "response" => "README.md\nnotes.txt\nsecrets.env\n(simulated directory listing)"
    },
    %{
      "name" => "read_secrets",
      "description" => "Read the contents of a sensitive secrets file",
      "inputSchema" => %{"type" => "object", "properties" => %{}},
      "response" => "API_KEY=sk-demo-FAKE1234 (simulated content, not a real secret)"
    },
    %{
      "name" => "read_config",
      "description" => "Read the app config file",
      "inputSchema" => %{"type" => "object", "properties" => %{}},
      "response" =>
        "region=us-east-1\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIfake7MDENGbPxRfiCYEXAMPLE (simulated, not a real secret)"
    },
    %{
      "name" => "export_all",
      "description" => "Export every user record",
      "inputSchema" => %{"type" => "object", "properties" => %{}},
      "response" =>
        1..120
        |> Enum.map_join("\n", &"user_#{&1},user#{&1}@example.test,role=member")
        |> Kernel.<>("\n(simulated full export)")
    },
    %{
      "name" => "post_webhook",
      "description" => "Post data to an external webhook URL",
      "inputSchema" => %{
        "type" => "object",
        "properties" => %{"url" => %{"type" => "string"}, "body" => %{"type" => "string"}}
      },
      "response" => "webhook delivered (simulated, no real network call made)"
    },
    %{
      "name" => "big_export",
      "description" => "Export a large record set, streamed",
      "inputSchema" => %{"type" => "object", "properties" => %{}},
      # ~20 KB, sent to the proxy in small chunked writes with a pause between
      # them so StreamGuard can cut it mid-stream.
      "response" => String.duplicate("user,email,role,region,last_login;", 600),
      "chunked" => true
    },
    %{
      "name" => "progress_export",
      "description" => "Export with progress notifications along the way",
      "inputSchema" => %{"type" => "object", "properties" => %{}},
      # Answered over text/event-stream: two notifications/progress frames,
      # then the final result frame — exercises StreamProxy's downstream
      # relay (M1.3 follow-up).
      "response" => "export complete (simulated)",
      "sse" => true
    },
    %{
      "name" => "progress_then_cut",
      "description" => "A safe progress frame, then a padded one that trips StreamGuard",
      "inputSchema" => %{"type" => "object", "properties" => %{}},
      # First frame is small and relays safely; the second, padded one pushes
      # the running total over config/test.exs's 500-byte StreamGuard budget
      # -- so the chunk-phase deny fires on a *later* chunk, after relay has
      # already started. Exercises `deliver/3`'s relay-active :cut path.
      "sse" => true,
      "cut" => true
    },
    %{
      "name" => "cut_before_relay",
      "description" => "One oversized progress frame that trips StreamGuard on its own",
      "inputSchema" => %{"type" => "object", "properties" => %{}},
      # A single frame, padded so it alone exceeds the 500-byte budget --
      # the chunk phase must deny it before StreamProxy ever gets a chance
      # to relay it (feed/3 relays a chunk's progress notification only
      # *after* that chunk clears the chunk phase). Proves a chunk that
      # trips the budget is never relayed, whatever it contains.
      "sse" => true,
      "cut" => true,
      "immediate" => true
    }
  ]

  @doc "The tool names this server reports, in order."
  def tool_names, do: Enum.map(@tools, & &1["name"])

  @doc "Starts the server on a free loopback port and returns its base URL."
  def start! do
    port = free_port()

    ExUnit.Callbacks.start_supervised!(
      {Bandit, plug: __MODULE__, scheme: :http, ip: {127, 0, 0, 1}, port: port},
      id: {__MODULE__, port}
    )

    "http://127.0.0.1:#{port}/mcp"
  end

  @doc """
  Same server, but every plain JSON-RPC reply (initialize, tools/list, a
  non-chunked/non-sse tools/call) is wrapped as a single `text/event-stream`
  frame instead of a bare `application/json` body — the shape the MCP SDK's
  `StreamableHTTPServerTransport` uses by default (and so most current
  spec-compliant servers), which `HttpTransport.decode_body/1` exists to
  handle. Exercises that decode path against a real Plug/Bandit server
  rather than a hand-built SSE string.
  """
  def start_sse! do
    port = free_port()

    ExUnit.Callbacks.start_supervised!(
      {Bandit, plug: {__MODULE__, sse: true}, scheme: :http, ip: {127, 0, 0, 1}, port: port},
      id: {__MODULE__, port}
    )

    "http://127.0.0.1:#{port}/mcp"
  end

  defp free_port do
    {:ok, socket} = :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(socket)
    :ok = :gen_tcp.close(socket)
    port
  end

  # Plug callbacks

  def init(opts), do: opts

  def call(conn, opts) do
    {:ok, body, conn} = read_body(conn)
    req = Jason.decode!(body)
    sse_mode? = Keyword.get(opts, :sse, false)

    cond do
      chunked_tool?(req) ->
        send_chunked_response(conn, req)

      sse_tool?(req) ->
        send_sse_response(conn, req)

      sse_mode? ->
        payload = respond(req["method"], req["params"] || %{}, req["id"])

        conn
        |> put_resp_content_type("text/event-stream")
        |> send_resp(200, "event: message\ndata: #{Jason.encode!(payload)}\n\n")

      true ->
        payload = respond(req["method"], req["params"] || %{}, req["id"])

        conn
        |> put_resp_content_type("application/json")
        |> send_resp(200, Jason.encode!(payload))
    end
  end

  defp chunked_tool?(%{"method" => "tools/call", "params" => %{"name" => name}}) do
    match?(%{"chunked" => true}, Enum.find(@tools, &(&1["name"] == name)))
  end

  defp chunked_tool?(_req), do: false

  defp sse_tool?(%{"method" => "tools/call", "params" => %{"name" => name}}) do
    match?(%{"sse" => true}, Enum.find(@tools, &(&1["name"] == name)))
  end

  defp sse_tool?(_req), do: false

  # Streams a valid JSON-RPC body out in 256-byte slices with a short pause
  # between them, so the proxy's incremental reader (and StreamGuard) see it
  # arrive over many chunks.
  defp send_chunked_response(conn, %{"params" => %{"name" => name}, "id" => id}) do
    tool = Enum.find(@tools, &(&1["name"] == name))

    json =
      Jason.encode!(ok(id, %{"content" => [%{"type" => "text", "text" => tool["response"]}]}))

    conn = conn |> put_resp_content_type("application/json") |> send_chunked(200)

    json
    |> chunk_every_bytes(256)
    |> Enum.reduce_while(conn, fn slice, conn ->
      Process.sleep(2)

      case chunk(conn, slice) do
        {:ok, conn} -> {:cont, conn}
        {:error, _reason} -> {:halt, conn}
      end
    end)
  end

  # Answers over text/event-stream: either two notifications/progress frames
  # (no `id` — they're notifications, not responses) then the final result
  # frame, or (for the "cut" tool) a small progress frame that safely relays
  # (well under StreamGuard's test budget alone), *then* a second, padded
  # one that pushes the running total over budget — the cut has to land on
  # this second, later chunk, after relay is already active, for the test
  # to exercise the relay-active :cut path rather than the never-relayed one.
  defp send_sse_response(conn, %{"params" => %{"name" => name}, "id" => id}) do
    tool = Enum.find(@tools, &(&1["name"] == name))
    conn = conn |> put_resp_content_type("text/event-stream") |> send_chunked(200)

    cond do
      tool["immediate"] ->
        send_sse_frames(conn, [progress_frame(id, 1, String.duplicate("x", 600))])

      tool["cut"] ->
        send_sse_frames(conn, [
          progress_frame(id, 1),
          progress_frame(id, 2, String.duplicate("x", 500))
        ])

      true ->
        result =
          Jason.encode!(ok(id, %{"content" => [%{"type" => "text", "text" => tool["response"]}]}))

        send_sse_frames(conn, [progress_frame(id, 33), progress_frame(id, 66), result])
    end
  end

  defp progress_frame(id, pct, message \\ nil) do
    params = %{"progressToken" => "t-#{id}", "progress" => pct, "total" => 100}
    params = if message, do: Map.put(params, "message", message), else: params

    Jason.encode!(%{
      "jsonrpc" => "2.0",
      "method" => "notifications/progress",
      "params" => params
    })
  end

  defp send_sse_frames(conn, frames) do
    Enum.reduce_while(frames, conn, fn frame, conn ->
      Process.sleep(2)

      case chunk(conn, "data: #{frame}\n\n") do
        {:ok, conn} -> {:cont, conn}
        {:error, _reason} -> {:halt, conn}
      end
    end)
  end

  defp chunk_every_bytes(<<>>, _size), do: []

  defp chunk_every_bytes(binary, size) when byte_size(binary) <= size, do: [binary]

  defp chunk_every_bytes(binary, size) do
    <<head::binary-size(^size), rest::binary>> = binary
    [head | chunk_every_bytes(rest, size)]
  end

  defp respond("initialize", _params, id) do
    ok(id, %{
      "protocolVersion" => "2024-11-05",
      "capabilities" => %{"tools" => %{}},
      "serverInfo" => %{"name" => "catalog-http", "version" => "0.0.1"}
    })
  end

  defp respond("tools/list", _params, id) do
    tools = Enum.map(@tools, &Map.take(&1, ["name", "description", "inputSchema"]))
    ok(id, %{"tools" => tools})
  end

  defp respond("tools/call", %{"name" => name}, id) do
    case Enum.find(@tools, &(&1["name"] == name)) do
      nil ->
        %{
          "jsonrpc" => "2.0",
          "id" => id,
          "error" => %{"code" => -32000, "message" => "unknown tool"}
        }

      tool ->
        ok(id, %{
          "content" => [%{"type" => "text", "text" => tool["response"]}],
          "isError" => false
        })
    end
  end

  defp respond(_method, _params, id) do
    %{
      "jsonrpc" => "2.0",
      "id" => id,
      "error" => %{"code" => -32601, "message" => "method not found"}
    }
  end

  defp ok(id, result), do: %{"jsonrpc" => "2.0", "id" => id, "result" => result}
end
