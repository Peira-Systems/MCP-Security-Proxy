defmodule PhoenixElxirBeam.MCP.HttpTransportTest do
  use ExUnit.Case, async: false

  alias PhoenixElxirBeam.MCP.HttpTransport

  setup do
    original = Application.get_env(:phoenix_elxir_beam, :host_loopback_alias)
    on_exit(fn -> restore(:host_loopback_alias, original) end)
    :ok
  end

  defp restore(_key, nil), do: Application.delete_env(:phoenix_elxir_beam, :host_loopback_alias)
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
end
