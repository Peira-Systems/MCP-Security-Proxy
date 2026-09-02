defmodule PhoenixElxirBeam.MCP.ResponseContentTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.ResponseContent

  test "tools/call round-trips content" do
    result = %{"content" => [%{"type" => "text", "text" => "hi"}], "isError" => false}
    {content, reinject} = ResponseContent.extract("tools/call", result)

    assert content == [%{"type" => "text", "text" => "hi"}]
    redacted = [%{"type" => "text", "text" => "‹redacted›"}]
    assert reinject.(redacted) == %{"content" => redacted, "isError" => false}
  end

  test "resources/read maps contents text and writes it back, keeping uri/mimeType" do
    result = %{
      "contents" => [
        %{"uri" => "config://app", "mimeType" => "text/plain", "text" => "secret=abc"},
        %{"uri" => "img://x", "mimeType" => "image/png", "blob" => "…"}
      ]
    }

    {content, reinject} = ResponseContent.extract("resources/read", result)

    assert content == [%{"type" => "text", "text" => "secret=abc"}, %{"type" => "opaque"}]

    updated =
      reinject.([%{"type" => "text", "text" => "secret=‹redacted›"}, %{"type" => "opaque"}])

    assert updated == %{
             "contents" => [
               %{
                 "uri" => "config://app",
                 "mimeType" => "text/plain",
                 "text" => "secret=‹redacted›"
               },
               %{"uri" => "img://x", "mimeType" => "image/png", "blob" => "…"}
             ]
           }
  end

  test "prompts/get maps message content text and writes it back" do
    result = %{
      "messages" => [%{"role" => "user", "content" => %{"type" => "text", "text" => "hi abc"}}]
    }

    {content, reinject} = ResponseContent.extract("prompts/get", result)
    assert content == [%{"type" => "text", "text" => "hi abc"}]

    updated = reinject.([%{"type" => "text", "text" => "hi ‹x›"}])

    assert updated == %{
             "messages" => [
               %{"role" => "user", "content" => %{"type" => "text", "text" => "hi ‹x›"}}
             ]
           }
  end

  test "skips shapes with no scannable text" do
    assert ResponseContent.extract("tools/list", %{"tools" => []}) == :skip
    assert ResponseContent.extract("resources/read", %{}) == :skip
  end
end
