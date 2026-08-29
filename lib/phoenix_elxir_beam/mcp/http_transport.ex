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

  @doc "Default per-request receive timeout for an upstream MCP call."
  def receive_timeout, do: @receive_timeout_ms

  @doc """
  Req `connect_options` for an upstream request. Req/Finch verify TLS against
  the system CA store by default, so this returns `[]` normally;
  `config :phoenix_elxir_beam, :upstream_tls_verify, false` disables
  verification for a single self-signed dev server.
  """
  def connect_options do
    if Application.get_env(:phoenix_elxir_beam, :upstream_tls_verify, true) do
      []
    else
      [transport_opts: [verify: :verify_none]]
    end
  end

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
