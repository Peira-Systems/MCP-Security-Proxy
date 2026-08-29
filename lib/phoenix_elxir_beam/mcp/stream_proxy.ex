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
  """

  alias PhoenixElxirBeam.MCP.{CallContext, HttpTransport, Pipeline}
  alias PhoenixElxirBeam.MCP.Plugin.Registry, as: PluginRegistry

  @default_max_buffer_bytes 8_000_000
  @default_deadline_ms 30_000
  @receive_timeout_ms 15_000

  @type call_meta :: %{
          session_id: String.t() | nil,
          server_id: String.t(),
          tool_name: String.t() | nil,
          method: String.t()
        }

  @type result ::
          {:ok, map(), [map()], [map()]}
          | {:cut, String.t(), [map()], [map()], non_neg_integer()}
          | {:error, String.t()}

  @doc """
  Runs `body` against `server` (a `:http` registered server), streaming the
  reply. Returns:

    * `{:ok, response_map, chunk_findings, chunk_taint_sources}` — the full
      JSON-RPC response, plus anything the chunk phase collected on the way;
    * `{:cut, reason, findings, taint_sources, bytes_read}` — a chunk policy
      denied mid-stream; nothing further was read;
    * `{:error, message}` — transport failure, timeout, buffer ceiling, or an
      unparseable / non-2xx reply.
  """
  @spec run(map(), map(), call_meta(), keyword()) :: result()
  def run(server, body, call_meta, opts \\ []) do
    {url, transport_headers} = HttpTransport.prepare(server.base_url)

    session_headers =
      if server.session_id, do: [{"mcp-session-id", server.session_id}], else: []

    state = %{
      status: :streaming,
      buffer: "",
      bytes: 0,
      delivered: [],
      findings: [],
      taint: [],
      reason: nil,
      call_meta: call_meta,
      entries: PluginRegistry.active_chunk(),
      request_id: body["id"],
      deadline:
        System.monotonic_time(:millisecond) + (opts[:deadline_ms] || @default_deadline_ms),
      max_buffer: opts[:max_buffer_bytes] || @default_max_buffer_bytes
    }

    into = fn {:data, data}, {req, resp} ->
      st = feed(resp.private[:stream_proxy] || state, data)
      resp = Req.Response.put_private(resp, :stream_proxy, st)
      if st.status == :streaming, do: {:cont, {req, resp}}, else: {:halt, {req, resp}}
    end

    case Req.post(url,
           json: body,
           headers: transport_headers ++ session_headers,
           receive_timeout: @receive_timeout_ms,
           into: into
         ) do
      {:ok, resp} ->
        finish(resp.private[:stream_proxy] || state, resp)

      {:error, %{reason: :timeout}} ->
        {:error, "upstream stream timed out"}

      {:error, reason} ->
        {:error, "upstream stream error: #{Exception.format(:error, reason)}"}
    end
  end

  # -- incremental read -------------------------------------------------

  defp feed(%{status: :streaming} = st, data) do
    st = %{st | buffer: st.buffer <> data, bytes: st.bytes + byte_size(data)}

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
  end

  defp feed(st, _data), do: st

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

    {verdict, findings, _redactions, taint, reason} = Pipeline.run_chunk(ctx, st.entries)

    st = %{
      st
      | findings: st.findings ++ findings,
        taint: st.taint ++ taint,
        delivered: st.delivered ++ [part]
    }

    case verdict do
      :deny -> %{st | status: :cut, reason: reason || "stream terminated by policy"}
      :allow -> st
    end
  end

  # -- terminal --------------------------------------------------------

  defp finish(%{status: :cut} = st, _resp) do
    {:cut, st.reason, st.findings, st.taint, st.bytes}
  end

  defp finish(%{status: :error} = st, _resp) do
    {:error, st.reason}
  end

  defp finish(%{status: :streaming} = st, resp) do
    cond do
      resp.status not in 200..299 ->
        {:error, "upstream responded with HTTP #{resp.status}"}

      true ->
        case decode_body(resp, st.buffer, st.request_id) do
          {:ok, response_map} -> {:ok, response_map, st.findings, st.taint}
          :error -> {:error, "upstream returned an unparseable MCP response"}
        end
    end
  end

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

  defp sse_data_frames(buffer) do
    buffer
    |> String.split("\n")
    |> Enum.flat_map(fn
      "data: " <> rest -> [rest]
      "data:" <> rest -> [String.trim_leading(rest)]
      _ -> []
    end)
  end
end
