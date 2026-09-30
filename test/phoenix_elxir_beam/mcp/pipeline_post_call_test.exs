defmodule PhoenixElxirBeam.MCP.PipelinePostCallTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias PhoenixElxirBeam.MCP.{CallContext, Decision, Finding, Pipeline}

  defmodule RedactScanner do
    def scan(:post_call, _ctx) do
      finding = Finding.new(%{type: "secret_leak", severity: :high, title: "leak"})

      {:ok, [finding],
       %Decision{
         verdict: :annotate,
         mutations: %{
           redact_response: [%{path: "content[0].text", match: "X", replacement: "Y"}],
           add_taint_sources: [%{origin_tool: "read_config", finding_type: "secret_leak"}]
         }
       }}
    end
  end

  defmodule PlainScanner do
    def scan(:post_call, _ctx), do: {:ok, []}
  end

  defmodule BlockingScanner do
    def scan(:post_call, _ctx) do
      {:ok, [], %Decision{verdict: :deny, reason: "not allowed"}}
    end
  end

  defmodule WithholdPolicy do
    def evaluate(:post_call, _ctx), do: Decision.deny(:high, "response withheld by policy")
  end

  defmodule BoomScanner do
    def scan(:post_call, _ctx), do: raise("kaboom")
  end

  defp entry(module, opts \\ []) do
    %{
      name: Keyword.get(opts, :name, inspect(module)),
      version: "1.0.0",
      module: module,
      impl: {:module, module},
      config: %{},
      kind: Keyword.get(opts, :kind, :scanner),
      phases: Keyword.get(opts, :phases, [:post_call]),
      tool_tags: [],
      data_needs: [],
      timeout_ms: 200,
      fail_mode: Keyword.get(opts, :fail_mode, :fail_open),
      can_mutate: [],
      can_block: Keyword.get(opts, :can_block, false),
      order: Keyword.get(opts, :order, 0),
      enabled: Keyword.get(opts, :enabled, true),
      mode: Keyword.get(opts, :mode, nil)
    }
  end

  defp ctx do
    CallContext.new(%{
      phase: :post_call,
      call: %{session_id: "s", server_id: "files", tool_name: "read_secrets"},
      response: %{is_error: false, content: [%{"type" => "text", "text" => "X"}]}
    })
  end

  test "merges findings, redactions and taint sources and allows" do
    entries = [entry(RedactScanner, order: 0), entry(PlainScanner, order: 1)]

    assert {:allow, [%{type: "secret_leak"}], [redaction], [taint], nil, nil} =
             Pipeline.run_post_call(ctx(), entries)

    assert redaction.path == "content[0].text"
    assert taint.origin_tool == "read_config"
  end

  test "a scanner :deny is ignored without the can_block grant" do
    assert {:allow, _findings, _redactions, _taint, nil, nil} =
             Pipeline.run_post_call(ctx(), [entry(BlockingScanner)])
  end

  test "a can_block scanner :deny withholds the response" do
    assert {:deny, _findings, _redactions, _taint, "not allowed", nil} =
             Pipeline.run_post_call(ctx(), [entry(BlockingScanner, can_block: true)])
  end

  test "a policy :deny withholds the response" do
    assert {:deny, _findings, _redactions, _taint, "response withheld by policy", nil} =
             Pipeline.run_post_call(ctx(), [entry(WithholdPolicy, kind: :policy)])
  end

  test "an entry without the :post_call phase is skipped" do
    assert {:allow, [], [], [], nil, nil} =
             Pipeline.run_post_call(ctx(), [entry(RedactScanner, phases: [:discovery])])
  end

  test "a raising scanner is dropped (fail_open) with a plugin_error finding" do
    capture_log(fn ->
      assert {:allow, [%{type: "plugin_error"}], [], [], nil, nil} =
               Pipeline.run_post_call(ctx(), [entry(BoomScanner, name: "boom")])
    end)
  end

  test "a raising scanner with fail_closed withholds the response" do
    capture_log(fn ->
      assert {:deny, [%{type: "plugin_error"}], [], [], _reason, nil} =
               Pipeline.run_post_call(ctx(), [
                 entry(BoomScanner, name: "boom", fail_mode: :fail_closed)
               ])
    end)
  end

  describe "dry-run mode" do
    test "global dry_run downgrades a would-be withhold to allow with a shadow reason" do
      entries = [entry(WithholdPolicy, kind: :policy)]

      assert {:allow, _findings, _redactions, _taint, nil, "response withheld by policy"} =
               Pipeline.run_post_call(ctx(), entries, global_mode: :dry_run)
    end

    test "global enforcing (default) still withholds for real, with no shadow reason" do
      entries = [entry(WithholdPolicy, kind: :policy)]

      assert {:deny, _findings, _redactions, _taint, "response withheld by policy", nil} =
               Pipeline.run_post_call(ctx(), entries)
    end

    test "a plugin pinned :dry_run is downgraded even when the global mode is enforcing" do
      entries = [entry(WithholdPolicy, kind: :policy, mode: :dry_run)]

      assert {:allow, _findings, _redactions, _taint, nil, "response withheld by policy"} =
               Pipeline.run_post_call(ctx(), entries)
    end

    test "a can_block scanner pinned :enforcing still withholds when the global mode is dry_run" do
      entries = [entry(BlockingScanner, can_block: true, mode: :enforcing)]

      assert {:deny, _findings, _redactions, _taint, "not allowed", nil} =
               Pipeline.run_post_call(ctx(), entries, global_mode: :dry_run)
    end
  end
end
