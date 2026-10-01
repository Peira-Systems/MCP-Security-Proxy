defmodule PhoenixElxirBeam.MCP.Plugins.ProvenanceTaintTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.CallContext
  alias PhoenixElxirBeam.MCP.Plugins.ProvenanceTaint

  defp ctx(tags, text \\ "ordinary, non-credential response text") do
    CallContext.new(%{
      phase: :post_call,
      call: %{session_id: "s1", server_id: "web", tool_name: "scrape_page", tags: tags},
      response: %{
        is_error: false,
        content: [%{"type" => "text", "text" => text}]
      }
    })
  end

  test "an untrusted-tagged tool's response taints the session even with no credential content" do
    assert {:ok, [], decision} = ProvenanceTaint.scan(:post_call, ctx([:untrusted_source]))

    assert [source] = decision.mutations.add_taint_sources
    assert source.origin_tool == "scrape_page"
    assert source.finding_type == "untrusted_provenance"
    assert %DateTime{} = source.at
    assert source.markers == []
    assert source.hint == "untrusted response"
  end

  test "a tool without the untrusted tag taints nothing" do
    assert {:ok, [], decision} = ProvenanceTaint.scan(:post_call, ctx([]))
    refute Map.has_key?(decision.mutations, :add_taint_sources)
  end

  test "an unrelated tag does not taint the session" do
    assert {:ok, [], decision} = ProvenanceTaint.scan(:post_call, ctx([:network_egress]))
    refute Map.has_key?(decision.mutations, :add_taint_sources)
  end

  test "produces no findings — it is a silent taint feed, not a visible detection" do
    assert {:ok, findings, _decision} = ProvenanceTaint.scan(:post_call, ctx([:untrusted_source]))
    assert findings == []
  end

  test "manifest declares a non-blocking post_call scanner" do
    manifest = ProvenanceTaint.manifest()

    assert manifest.plugin.name == "provenance-taint"
    assert %{scanner: scanner} = manifest.capabilities
    assert scanner.phases == [:post_call]
    assert scanner.can_block == false
    assert scanner.fail_mode == :fail_open
    assert "call.tags" in scanner.data_needs
  end
end
