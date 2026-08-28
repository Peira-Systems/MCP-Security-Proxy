defmodule PhoenixElxirBeam.MCP.RedactionTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.Redaction

  defp content(text), do: [%{"type" => "text", "text" => text}]

  test "replaces a literal match at content[0].text" do
    result =
      Redaction.apply(content("API_KEY=sk-demo-FAKE1234 trailing"), [
        %{path: "content[0].text", match: "API_KEY=sk-demo-FAKE1234", replacement: "‹redacted›"}
      ])

    assert result == [%{"type" => "text", "text" => "‹redacted› trailing"}]
  end

  test "applies multiple redactions to one part" do
    result =
      Redaction.apply(content("a=SECRET1 b=SECRET2"), [
        %{path: "content[0].text", match: "SECRET1", replacement: "X"},
        %{path: "content[0].text", match: "SECRET2", replacement: "Y"}
      ])

    assert result == [%{"type" => "text", "text" => "a=X b=Y"}]
  end

  test "supports a slash-wrapped regex match (sidecar form)" do
    result =
      Redaction.apply(content("id AKIAIOSFODNN7EXAMPLE end"), [
        %{"path" => "content[0].text", "match" => "/AKIA[0-9A-Z]{16}/", "replacement" => "‹key›"}
      ])

    assert result == [%{"type" => "text", "text" => "id ‹key› end"}]
  end

  test "a match that is not present is a no-op" do
    original = content("nothing sensitive here")

    assert Redaction.apply(original, [
             %{path: "content[0].text", match: "AKIA0000000000000000", replacement: "x"}
           ]) == original
  end

  test "an out-of-range or malformed path is ignored" do
    original = content("text")

    assert Redaction.apply(original, [%{path: "content[7].text", match: "text", replacement: "x"}]) ==
             original

    assert Redaction.apply(original, [%{path: "bogus", match: "text", replacement: "x"}]) ==
             original
  end

  test "non-list content is returned unchanged" do
    assert Redaction.apply(nil, [%{path: "content[0].text", match: "a", replacement: "b"}]) == nil
  end
end
