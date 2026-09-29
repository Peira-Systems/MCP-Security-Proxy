defmodule PhoenixElxirBeam.MCP.HttpTransportTest do
  use ExUnit.Case, async: false

  alias PhoenixElxirBeam.MCP.HttpTransport

  setup do
    original_alias = Application.get_env(:phoenix_elxir_beam, :host_loopback_alias)
    original_verify = Application.get_env(:phoenix_elxir_beam, :upstream_tls_verify)

    on_exit(fn ->
      restore(:host_loopback_alias, original_alias)
      restore(:upstream_tls_verify, original_verify)
    end)

    :ok
  end

  defp restore(key, nil), do: Application.delete_env(:phoenix_elxir_beam, key)
  defp restore(key, value), do: Application.put_env(:phoenix_elxir_beam, key, value)

  test "always advertises both MCP media types" do
    {_url, headers} = HttpTransport.prepare("http://example.test:9000/mcp")
    assert {"accept", "application/json, text/event-stream"} in headers
  end

  test "without a loopback alias, a localhost target is used verbatim" do
    Application.delete_env(:phoenix_elxir_beam, :host_loopback_alias)

    {url, headers} = HttpTransport.prepare("http://127.0.0.1:64342/stream")

    assert url == "http://127.0.0.1:64342/stream"
    refute List.keymember?(headers, "host", 0)
  end

  test "with a loopback alias, a localhost target is dialed through the alias with a pinned Host" do
    Application.put_env(:phoenix_elxir_beam, :host_loopback_alias, "host.docker.internal")

    {url, headers} = HttpTransport.prepare("http://127.0.0.1:64342/stream")

    assert url == "http://host.docker.internal:64342/stream"
    assert {"host", "127.0.0.1:64342"} in headers
  end

  test "an explicit host.docker.internal target keeps its URL but gets a loopback Host" do
    {url, headers} = HttpTransport.prepare("http://host.docker.internal:64342/stream")

    assert url == "http://host.docker.internal:64342/stream"
    assert {"host", "127.0.0.1:64342"} in headers
  end

  # -- per-server timeout_ms / tls_verify overrides (M1.5 follow-up) -------

  test "receive_timeout/0 defaults to the fixed 15s when no source is given" do
    assert HttpTransport.receive_timeout() == 15_000
  end

  test "receive_timeout/1 uses a server's timeout_ms when set" do
    assert HttpTransport.receive_timeout(%{timeout_ms: 45_000}) == 45_000
  end

  test "receive_timeout/1 falls back to the default when timeout_ms is nil or absent" do
    assert HttpTransport.receive_timeout(%{timeout_ms: nil}) == 15_000
    assert HttpTransport.receive_timeout(%{}) == 15_000
  end

  test "connect_options/0 verifies TLS by default" do
    assert HttpTransport.connect_options() == []
  end

  test "connect_options/1 falls back to the global :upstream_tls_verify when tls_verify is nil" do
    Application.put_env(:phoenix_elxir_beam, :upstream_tls_verify, false)

    assert HttpTransport.connect_options(%{tls_verify: nil}) == [
             transport_opts: [verify: :verify_none]
           ]

    Application.put_env(:phoenix_elxir_beam, :upstream_tls_verify, true)
    assert HttpTransport.connect_options(%{tls_verify: nil}) == []
  end

  test "connect_options/1 lets a server's tls_verify: false override a global true default" do
    Application.put_env(:phoenix_elxir_beam, :upstream_tls_verify, true)

    assert HttpTransport.connect_options(%{tls_verify: false}) == [
             transport_opts: [verify: :verify_none]
           ]
  end

  test "connect_options/1 lets a server's tls_verify: true override a global false default" do
    Application.put_env(:phoenix_elxir_beam, :upstream_tls_verify, false)
    assert HttpTransport.connect_options(%{tls_verify: true}) == []
  end

  # -- decode_body/1 --------------------------------------------------

  test "decode_body/1 passes an already-decoded JSON body through" do
    resp = %Req.Response{status: 200, body: %{"result" => %{"ok" => true}}}
    assert HttpTransport.decode_body(resp) == {:ok, %{"result" => %{"ok" => true}}}
  end

  test "decode_body/1 JSON-decodes a plain application/json string body" do
    resp =
      %Req.Response{status: 200, body: ~s({"result":{"ok":true}})}
      |> Req.Response.put_header("content-type", "application/json")

    assert HttpTransport.decode_body(resp) == {:ok, %{"result" => %{"ok" => true}}}
  end

  test "decode_body/1 decodes a single text/event-stream frame's data line" do
    body = "event: message\nid: abc-123\ndata: {\"result\":{\"ok\":true}}\n\n"

    resp =
      %Req.Response{status: 200, body: body}
      |> Req.Response.put_header("content-type", "text/event-stream")

    assert HttpTransport.decode_body(resp) == {:ok, %{"result" => %{"ok" => true}}}
  end

  test "decode_body/1 concatenates multiple data: lines in one SSE frame per spec" do
    body = "event: message\ndata: {\"result\":\ndata: {\"ok\":true}}\n\n"

    resp =
      %Req.Response{status: 200, body: body}
      |> Req.Response.put_header("content-type", "text/event-stream")

    assert HttpTransport.decode_body(resp) == {:ok, %{"result" => %{"ok" => true}}}
  end

  test "decode_body/1 errors on an event-stream body with no data: line" do
    resp =
      %Req.Response{status: 200, body: "event: message\n\n"}
      |> Req.Response.put_header("content-type", "text/event-stream")

    assert {:error, _reason} = HttpTransport.decode_body(resp)
  end

  test "decode_body/1 errors on malformed JSON in an event-stream data: line" do
    resp =
      %Req.Response{status: 200, body: "data: not json\n\n"}
      |> Req.Response.put_header("content-type", "text/event-stream")

    assert {:error, _reason} = HttpTransport.decode_body(resp)
  end

  test "decode_body/1 errors on malformed JSON in a plain-JSON body" do
    resp =
      %Req.Response{status: 200, body: "not json"}
      |> Req.Response.put_header("content-type", "application/json")

    assert {:error, _reason} = HttpTransport.decode_body(resp)
  end
end
