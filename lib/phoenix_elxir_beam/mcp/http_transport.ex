defmodule PhoenixElxirBeam.MCP.HttpTransport do
  @moduledoc """
  Shared request shaping for talking to a real MCP server over the
  Streamable HTTP transport — used by both `ServerRegistry` (discovery
  handshake) and `ProxyController` (forwarded `tools/call`s), so the two
  paths can't drift apart.

  `prepare/1` turns the registered base URL into the `{url, headers}` the
  request should actually use. Two adjustments happen here:

    * **Accept.** MCP's Streamable HTTP transport requires the client to
      accept *both* `application/json` and `text/event-stream`; servers such
      as the JetBrains IDE plugin reject an `application/json`-only request
      with HTTP 406.

    * **Loopback bridging.** When the proxy runs in a container it can't
      reach an MCP server on the *host's* loopback via `127.0.0.1`. If
      `MCP_HOST_LOOPBACK_ALIAS` is set (the compose file sets it to
      `host.docker.internal`), a `localhost` / `127.0.0.1` / `::1` target is
      dialed through that alias instead — while the `Host` header is pinned
      back to the original loopback authority, because servers bound to
      `127.0.0.1` (the JetBrains plugin again) answer any non-loopback
      `Host` with HTTP 403. Outside a container the env var is unset and
      loopback URLs are used verbatim.

  `decode_body/1` handles the other half: a POST response may come back as
  plain `application/json` or as a single `text/event-stream` frame — both
  are valid per spec, and current MCP servers commonly default to the
  latter, so a client that only decodes JSON can't talk to them.
  """

  @accept "application/json, text/event-stream"
  @loopback_hosts ~w(localhost 127.0.0.1 ::1)
  @receive_timeout_ms 15_000

  @doc """
  Per-request receive timeout for an upstream MCP call. `source` is a
  registered server map (or anything else `Access`-compatible) whose
  `:timeout_ms` overrides the proxy-wide default when set
  (`docs/productionization-plan.md` M1.5 follow-up — per-server
  `timeout_ms`). Omit `source`, or leave the field unset/`nil`, for the
  default.
  """
  def receive_timeout(source \\ %{}) do
    get(source, :timeout_ms) || @receive_timeout_ms
  end

  @doc """
  Req `connect_options` for an upstream request. Req/Finch verify TLS against
  the system CA store by default, so this returns `[]` normally.
  `source`'s `:tls_verify` (a registered server map, typically), when set,
  overrides `config :phoenix_elxir_beam, :upstream_tls_verify` for just that
  server; falls back to the proxy-wide default otherwise.
  """
  def connect_options(source \\ %{}) do
    verify? =
      case get(source, :tls_verify) do
        nil -> Application.get_env(:phoenix_elxir_beam, :upstream_tls_verify, true)
        override -> override
      end

    if verify? do
      []
    else
      [transport_opts: [verify: :verify_none]]
    end
  end

  defp get(source, key) when is_map(source), do: Map.get(source, key)
  defp get(source, key) when is_list(source), do: Keyword.get(source, key)

  @doc "Returns the `{url, headers}` to use for an MCP JSON-RPC POST to `base_url`."
  def prepare(base_url) do
    uri = URI.parse(base_url)

    cond do
      # Explicit bridge hostname — still needs the Host mask, no URL rewrite.
      uri.host == "host.docker.internal" ->
        {base_url, [{"accept", @accept}, {"host", loopback_authority("127.0.0.1", uri.port)}]}

      uri.host in @loopback_hosts and is_binary(loopback_alias()) ->
        rewritten = URI.to_string(%{uri | host: loopback_alias()})
        {rewritten, [{"accept", @accept}, {"host", loopback_authority(uri.host, uri.port)}]}

      true ->
        {base_url, [{"accept", @accept}]}
    end
  end

  defp loopback_authority(host, nil), do: host
  defp loopback_authority(host, port), do: "#{host}:#{port}"

  defp loopback_alias do
    Application.get_env(:phoenix_elxir_beam, :host_loopback_alias)
  end

  @doc """
  Decodes a non-streaming Streamable HTTP response body into the single
  JSON-RPC message it carries, whichever of the two shapes the spec allows
  a server to answer a POST with:

    * `application/json` — Req already decoded this into a map; pass through.
    * `text/event-stream` — one `event: message` frame containing the
      response. Current MCP servers (the SDK's `StreamableHTTPServerTransport`
      defaults to this) require the client to accept both types
      (`prepare/1` sends that `Accept` header) and may answer either way, so
      a client that only understands `application/json` can no longer talk
      to a growing share of real servers. This does not handle a genuinely
      *streaming* SSE response (multiple frames, e.g. progress
      notifications before a final result) — that path is `ProxyController`'s
      `StreamProxy` relay, which reads the raw connection instead of Req.

  Returns `{:ok, decoded_map}` or `{:error, reason}`.
  """
  def decode_body(%Req.Response{body: body}) when is_map(body) do
    {:ok, body}
  end

  def decode_body(%Req.Response{body: body} = resp) when is_binary(body) do
    if event_stream?(resp) do
      decode_sse(body)
    else
      case Jason.decode(body) do
        {:ok, decoded} -> {:ok, decoded}
        {:error, _} -> {:error, "could not decode response body"}
      end
    end
  end

  def decode_body(_resp), do: {:error, "could not decode response body"}

  defp event_stream?(resp) do
    resp
    |> Req.Response.get_header("content-type")
    |> Enum.any?(&String.contains?(&1, "text/event-stream"))
  end

  # A single-response SSE body is one `event: ...` frame: a handful of
  # `field: value` lines, blank-line terminated. The JSON-RPC payload lives
  # in its `data:` line(s) — per the SSE spec, multiple `data:` lines in one
  # frame concatenate with `\n` before decoding.
  defp decode_sse(body) do
    data =
      body
      |> String.split("\n")
      |> Enum.filter(&String.starts_with?(&1, "data:"))
      |> Enum.map_join("\n", &(&1 |> String.trim_leading("data:") |> String.trim_leading(" ")))

    case data do
      "" -> {:error, "event-stream response carried no data frame"}
      json -> Jason.decode(json) |> decode_result("could not decode event-stream data frame")
    end
  end

  defp decode_result({:ok, decoded}, _err_msg), do: {:ok, decoded}
  defp decode_result({:error, _}, err_msg), do: {:error, err_msg}
end
