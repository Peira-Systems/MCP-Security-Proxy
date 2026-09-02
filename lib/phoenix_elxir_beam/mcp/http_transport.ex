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
end
