defmodule PhoenixElxirBeam.MCP.StreamProxy do
  @moduledoc """
  Forwards a request to a `:http` upstream MCP server while reading the
  response body **incrementally**, running the `chunk` pipeline phase over
  each slice as it arrives.

  This is what makes `PhoenixElxirBeam.MCP.Plugins.StreamGuard` real: a
  `chunk` policy can deny partway through a large response and the proxy
  stops reading — the rest of the payload never crosses. `ResponseSizeGuard`
  (`post_call`) can only act once the whole body has been buffered.

  Bounds enforced here, independent of any plugin:

    * **buffer ceiling** — reading stops if the accumulated body passes
      `max_buffer_bytes` with no verdict (a hostile server that just floods);
    * **stream deadline** — the whole read must finish within `deadline_ms`.

  `:stdio` upstreams are line-delimited request/response with no streaming
  transport — they use the buffered path in the controller, not this module.

  ## Downstream SSE passthrough + progress relay (M1.3 follow-up)

  When the caller passes `conn:` in `opts` and the upstream answers via
  `text/event-stream`, every `notifications/progress` frame the upstream
  sends *before* its final result is relayed **live** to the downstream
  client — the proxy lazily upgrades that client's own response from a plain
  buffered JSON reply to a chunked `text/event-stream` one the moment the
  first progress notification arrives (never before; a call with no progress
  notifications still gets today's exact single-JSON-response behavior). The
  actual tool result is never relayed early — it still goes through the full
  `chunk` + `post_call` scan/redaction pipeline exactly as before and is
  written as the terminal SSE frame (or, on `:cut`/`:error`, a terminal SSE
  error frame) only once that decision is made.

  A progress notification is only ever relayed for a chunk of raw bytes
  *after* that same chunk has cleared the `chunk` phase (`feed/3` runs
  `run_chunk_phase/2` before `relay_progress/2`, and only relays if `status`
  is still `:streaming` afterward) — a `chunk`-phase `deny` on a chunk
  withholds everything in it, progress notifications included, exactly like
  it withholds tool-result content. This matters because the `chunk` phase
  is not just a byte-count budget: whatever policy plugins are configured
  for it see the notification's raw bytes (including any free-form
  `params.message` an upstream sets) before any part of it can reach the
  client, so a compromised upstream can't use a progress notification as an
  unscanned side channel for its result content.

  `run/4` returns its ordinary result (unchanged) when `opts[:conn]` is
  omitted; when given, it returns `{result, relay_conn}` — `relay_conn` is
  `nil` if no progress notification ever arrived (nothing was upgraded) or
  the `:chunked` conn to write the terminal frame to via `Plug.Conn.chunk/2`
  otherwise. See `PhoenixElxirBeamWeb.MCP.ProxyController.deliver/3`.

  Known residual gap: if the *upstream* connection fails at the transport
  level (not a decoded HTTP error — `Req.post` itself returning `{:error,
  _}`) after some progress notifications were already relayed, `relay_conn`
  comes back `nil` for that one response even though the downstream socket
  has already been upgraded to chunked — `Req`'s error tuple doesn't carry
  the accumulated private state back. The caller then falls back to its
  normal (non-relay) error response, which can raise `Plug.Conn.
  AlreadySentError` for that single request; Phoenix's own error handling
  catches it (the request fails, the app does not crash). Narrow — requires
  both relay-in-progress and a transport-level failure — and accepted rather
  than adding process-scoped state to close it.
  """

  alias PhoenixElxirBeam.MCP.{CallContext, HttpTransport, Pipeline}
  alias PhoenixElxirBeam.MCP.Plugin.Registry, as: PluginRegistry

  @default_max_buffer_bytes 8_000_000
  @default_deadline_ms 30_000

  @type call_meta :: %{
          session_id: String.t() | nil,
          server_id: String.t(),
          tool_name: String.t() | nil,
          method: String.t()
        }

  @type result ::
          {:ok, map(), [map()], [map()], String.t() | nil}
          | {:cut, String.t(), [map()], [map()], non_neg_integer()}
          | {:error, String.t()}

  @doc """
  Runs `body` against `server` (a `:http` registered server), streaming the
  reply. Returns `result()` — see the moduledoc — or, when `opts[:conn]` is
  given, `{result(), Plug.Conn.t() | nil}`:

    * `{:ok, response_map, chunk_findings, chunk_taint_sources, shadow_reason}` —
      the full JSON-RPC response, plus anything the chunk phase collected on
      the way; `shadow_reason` is the reason a `:dry_run`-mode chunk policy
      would have cut the stream, or `nil` if none did;
    * `{:cut, reason, findings, taint_sources, bytes_read}` — a chunk policy
      denied mid-stream; nothing further was read;
    * `{:error, message}` — transport failure, timeout, buffer ceiling, or an
      unparseable / non-2xx reply.
  """
  @spec run(map(), map(), call_meta(), keyword()) :: result() | {result(), Plug.Conn.t() | nil}
  def run(server, body, call_meta, opts \\ []) do
    {url, transport_headers} = HttpTransport.prepare(server.base_url)

    session_headers =
      if server.session_id, do: [{"mcp-session-id", server.session_id}], else: []

    # Whether to return the wrapped `{result, relay_conn}` shape is decided
    # by whether the caller passed the `:conn` key at all — not by whether
    # its value is non-nil. `ProxyController` always passes it (sometimes
    # `nil`, when the client didn't ask for `text/event-stream`) because it
    # always wants the wrapped shape back; a caller that omits `:conn`
    # entirely (e.g. StreamProxyTest) gets today's plain, unwrapped result.
    relay? = Keyword.has_key?(opts, :conn)

    state = %{
      status: :streaming,
      buffer: "",
      bytes: 0,
      delivered: [],
      findings: [],
      taint: [],
      reason: nil,
      shadow_reason: nil,
      call_meta: call_meta,
      entries: PluginRegistry.active_chunk(),
      request_id: body["id"],
      deadline:
        System.monotonic_time(:millisecond) + (opts[:deadline_ms] || @default_deadline_ms),
      max_buffer: opts[:max_buffer_bytes] || @default_max_buffer_bytes,
      # Downstream SSE relay (M1.3 follow-up). `relay?` records whether the
      # caller wants relay-awareness at all (fixes the return shape);
      # `downstream` is the original conn to lazily send_chunked/2 from;
      # `relay_conn` becomes the chunked conn once the first progress
      # notification is relayed, and is nil until then.
      relay?: relay?,
      downstream: opts[:conn],
      relay_conn: nil,
      sse_pending: ""
    }

    into = fn {:data, data}, {req, resp} ->
      st = resp.private[:stream_proxy] || state
      st = feed(st, data, sse?(resp))
      resp = Req.Response.put_private(resp, :stream_proxy, st)
      if st.status == :streaming, do: {:cont, {req, resp}}, else: {:halt, {req, resp}}
    end

    case Req.post(url,
           json: body,
           headers: transport_headers ++ session_headers,
           receive_timeout: HttpTransport.receive_timeout(server),
           connect_options: HttpTransport.connect_options(server),
           into: into
         ) do
      {:ok, resp} ->
        finish(resp.private[:stream_proxy] || state, resp)

      {:error, %{reason: :timeout}} ->
        wrap({:error, "upstream stream timed out"}, state)

      {:error, reason} ->
        wrap({:error, "upstream stream error: #{Exception.format(:error, reason)}"}, state)
    end
  end

  # -- incremental read -------------------------------------------------

  defp feed(%{status: :streaming} = st, data, is_sse) do
    st = %{st | buffer: st.buffer <> data, bytes: st.bytes + byte_size(data)}

    st =
      cond do
        System.monotonic_time(:millisecond) > st.deadline ->
          %{st | status: :error, reason: "upstream stream exceeded its deadline"}

        st.bytes > st.max_buffer ->
          %{
            st
            | status: :error,
              reason: "upstream response exceeded the #{st.max_buffer}-byte ceiling"
          }

        st.entries == [] ->
          st

        true ->
          run_chunk_phase(st, data)
      end

    # Only relay this chunk's progress notification(s) once the chunk phase
    # has cleared this same data — see the moduledoc. `st.downstream` (not
    # just `st.relay?`) is checked here too so the frame-parsing work below
    # is skipped entirely for a client that never asked for relay.
    if is_sse and st.relay? and not is_nil(st.downstream) and st.status == :streaming do
      relay_progress(st, data)
    else
      st
    end
  end

  defp feed(st, _data, _is_sse), do: st

  defp run_chunk_phase(st, data) do
    part = %{"type" => "text", "text" => data}

    ctx =
      CallContext.new(%{
        phase: :chunk,
        call: st.call_meta,
        response: %{
          stream: true,
          chunk: part,
          chunk_index: length(st.delivered),
          delivered: st.delivered
        }
      })

    {verdict, findings, _redactions, taint, reason, shadow_reason} =
      Pipeline.run_chunk(ctx, st.entries, global_mode: PluginRegistry.proxy_mode())

    st = %{
      st
      | findings: st.findings ++ findings,
        taint: st.taint ++ taint,
        delivered: st.delivered ++ [part],
        # First shadow reason wins — later chunks may also carry one, but the
        # operator only needs to know it *would* have been cut, and when.
        shadow_reason: st.shadow_reason || shadow_reason
    }

    case verdict do
      :deny -> %{st | status: :cut, reason: reason || "stream terminated by policy"}
      :allow -> st
    end
  end

  # -- downstream progress relay ----------------------------------------

  # A single SSE frame pathologically fragmented across many tiny chunks
  # without ever completing (a blank line never arrives) would otherwise
  # make `extract_sse_frames/1` re-scan an ever-growing `sse_pending` on
  # every one of those chunks. Real progress notifications are small; cap
  # how much unterminated data we'll keep trying to complete and drop it
  # past that — a safe failure mode (the notification, if there was one,
  # just doesn't relay; the final result is unaffected either way).
  @max_pending_sse_bytes 65_536

  # Extracts complete SSE frames (records end at a blank line) from
  # `st.sse_pending <> data`, relays any `notifications/progress` message
  # found in each, and keeps whatever's left of a not-yet-complete frame.
  defp relay_progress(st, data) do
    {frames, rest} = extract_sse_frames(st.sse_pending <> data)
    rest = if byte_size(rest) > @max_pending_sse_bytes, do: "", else: rest
    st = %{st | sse_pending: rest}
    Enum.reduce(frames, st, &relay_frame/2)
  end

  defp extract_sse_frames(buffer) do
    parts = String.split(buffer, ~r/\r?\n\r?\n/)
    {complete, [incomplete]} = Enum.split(parts, -1)
    {complete, incomplete}
  end

  defp relay_frame(frame, st) do
    case progress_message(frame) do
      {:ok, msg} -> emit_progress(st, msg)
      :error -> st
    end
  end

  defp progress_message(frame) do
    frame
    |> data_lines()
    |> Enum.find_value(:error, fn line ->
      case Jason.decode(line) do
        {:ok, %{"method" => "notifications/progress"} = msg} -> {:ok, msg}
        _ -> nil
      end
    end)
  end

  defp emit_progress(%{downstream: nil} = st, _msg), do: st

  defp emit_progress(st, msg) do
    conn = st.relay_conn || start_sse(st.downstream)

    case Plug.Conn.chunk(conn, sse_data(msg)) do
      {:ok, conn} -> %{st | relay_conn: conn}
      {:error, _} -> %{st | status: :error, reason: "downstream connection closed"}
    end
  end

  defp start_sse(conn) do
    conn
    |> Plug.Conn.put_resp_content_type("text/event-stream")
    |> Plug.Conn.send_chunked(200)
  end

  @doc "Formats `msg` as one SSE `data:` record — the wire shape used for both a relayed progress notification and a terminal frame (`PhoenixElxirBeamWeb.MCP.ProxyController.deliver/3`)."
  @spec sse_data(map()) :: String.t()
  def sse_data(msg), do: "data: #{Jason.encode!(msg)}\n\n"

  # -- terminal --------------------------------------------------------

  defp finish(%{status: :cut} = st, _resp) do
    wrap({:cut, st.reason, st.findings, st.taint, st.bytes}, st)
  end

  defp finish(%{status: :error} = st, _resp) do
    wrap({:error, st.reason}, st)
  end

  defp finish(%{status: :streaming} = st, resp) do
    cond do
      resp.status not in 200..299 ->
        wrap({:error, "upstream responded with HTTP #{resp.status}"}, st)

      true ->
        case decode_body(resp, st.buffer, st.request_id) do
          {:ok, response_map} ->
            wrap({:ok, response_map, st.findings, st.taint, st.shadow_reason}, st)

          :error ->
            wrap({:error, "upstream returned an unparseable MCP response"}, st)
        end
    end
  end

  defp wrap(result, %{relay?: false}), do: result
  defp wrap(result, %{relay?: true, relay_conn: conn}), do: {result, conn}

  # `application/json` → the buffer is one JSON-RPC document.
  # `text/event-stream` → the buffer is SSE frames; pull the `data:` line
  # carrying the JSON-RPC response for this request id.
  defp decode_body(resp, buffer, request_id) do
    if sse?(resp) do
      buffer
      |> sse_data_frames()
      |> Enum.map(&Jason.decode/1)
      |> Enum.find_value(:error, fn
        {:ok, %{"id" => ^request_id} = msg} -> {:ok, msg}
        {:ok, %{"result" => _} = msg} -> {:ok, msg}
        {:ok, %{"error" => _} = msg} -> {:ok, msg}
        _ -> nil
      end)
    else
      case Jason.decode(buffer) do
        {:ok, map} -> {:ok, map}
        {:error, _} -> :error
      end
    end
  end

  defp sse?(resp) do
    resp
    |> Req.Response.get_header("content-type")
    |> Enum.any?(&String.contains?(&1, "text/event-stream"))
  end

  defp sse_data_frames(buffer), do: data_lines(buffer)

  # Shared by `progress_message/1` (one already-isolated frame) and
  # `sse_data_frames/1` (a whole raw buffer, possibly several frames) — the
  # `data:` line format is the same either way.
  defp data_lines(text) do
    text
    |> String.split(~r/\r?\n/)
    |> Enum.flat_map(fn
      "data: " <> rest -> [rest]
      "data:" <> rest -> [String.trim_leading(rest)]
      _ -> []
    end)
  end
end
