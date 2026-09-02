defmodule PhoenixElxirBeam.MCP.TaintMarkerTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.TaintMarker

  @secret "API_KEY=sk-demo-FAKE1234abcd"

  test "markers are session-scoped and opaque" do
    a = TaintMarker.markers_for_secret("session-a", @secret)
    b = TaintMarker.markers_for_secret("session-b", @secret)

    assert a != []
    assert MapSet.disjoint?(MapSet.new(a), MapSet.new(b))
    assert Enum.all?(a, &String.starts_with?(&1, "tm:"))
    refute Enum.any?(a, &String.contains?(&1, "sk-demo"))
  end

  test "short values are not marked" do
    assert TaintMarker.markers_for_secret("s", "short") == []
  end

  test "tainted?/3 catches the raw secret and its encodings" do
    markers = TaintMarker.markers_for_secret("s", @secret)

    assert TaintMarker.tainted?("s", %{"body" => "x #{@secret} y"}, markers)
    assert TaintMarker.tainted?("s", %{"body" => Base.encode64(@secret)}, markers)
    assert TaintMarker.tainted?("s", Base.encode16(@secret, case: :lower), markers)
    assert TaintMarker.tainted?("s", %{"nested" => %{"k" => @secret}}, markers)

    refute TaintMarker.tainted?("s", %{"body" => "nothing to see"}, markers)
    # a different session's markers don't match
    refute TaintMarker.tainted?("other", %{"body" => @secret}, markers)
  end

  test "candidate_markers decodes tokens too, so a base64 token matches a raw-only mark" do
    raw_marker =
      "tm:" <>
        (:crypto.mac(:hmac, :sha256, session_key("s"), @secret) |> Base.encode16(case: :lower))

    # only the raw representation is stored; the agent sends it base64-encoded
    assert TaintMarker.tainted?("s", Base.encode64(@secret, padding: false), [raw_marker])
  end

  defp session_key(sid),
    do: :crypto.mac(:hmac, :sha256, "dev-and-test-taint-marker-key-not-a-secret", "taint|" <> sid)
end
