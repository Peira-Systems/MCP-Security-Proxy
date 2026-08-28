defmodule PhoenixElxirBeam.MCP.Plugins.SecretLeakTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.CallContext
  alias PhoenixElxirBeam.MCP.Plugins.SecretLeak

  defp ctx(text_parts) do
    CallContext.new(%{
      phase: :post_call,
      call: %{session_id: "s1", server_id: "files", tool_name: "read_secrets"},
      response: %{
        is_error: false,
        content: Enum.map(text_parts, &%{"type" => "text", "text" => &1})
      }
    })
  end

  test "flags an AWS access key and proposes a matching redaction" do
    assert {:ok, [finding], decision} =
             SecretLeak.scan(:post_call, ctx(["key is AKIAIOSFODNN7EXAMPLE done"]))

    assert finding.type == "secret_leak"
    assert finding.severity == :high

    assert [%{path: "content[0].text", match: "AKIAIOSFODNN7EXAMPLE", replacement: replacement}] =
             decision.mutations.redact_response

    assert replacement =~ "redacted"
  end

  test "flags the mock read_secrets credential assignment" do
    text = "API_KEY=sk-demo-FAKE1234 (simulated content, not a real secret)"

    assert {:ok, [finding], decision} = SecretLeak.scan(:post_call, ctx([text]))
    assert finding.type == "secret_leak"
    assert [%{match: "API_KEY=sk-demo-FAKE1234"}] = decision.mutations.redact_response
  end

  test "points redactions at the correct content index" do
    assert {:ok, [finding], decision} =
             SecretLeak.scan(:post_call, ctx(["nothing here", "token: abcdefgh12345678"]))

    assert finding.locator == %{path: "content[1].text"}
    assert [%{path: "content[1].text"}] = decision.mutations.redact_response
  end

  test "clean content yields no findings and no redactions" do
    assert {:ok, [], decision} = SecretLeak.scan(:post_call, ctx(["just some ordinary text"]))
    assert decision.mutations.redact_response == []
  end

  test "manifest declares a non-blocking post_call scanner" do
    manifest = SecretLeak.manifest()

    assert manifest.plugin.name == "secret-leak"
    assert %{scanner: scanner} = manifest.capabilities
    assert scanner.phases == [:post_call]
    assert scanner.can_block == false
    assert scanner.fail_mode == :fail_open
    assert "response.content" in scanner.data_needs
  end
end
