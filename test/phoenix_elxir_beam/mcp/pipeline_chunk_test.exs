defmodule PhoenixElxirBeam.MCP.PipelineChunkTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias PhoenixElxirBeam.MCP.{CallContext, Decision, Finding, Pipeline}

  defmodule PassPolicy do
    def evaluate(:chunk, _ctx), do: Decision.allow()
  end

  defmodule CutPolicy do
    def evaluate(:chunk, _ctx), do: Decision.deny(:high, "over budget")
  end

  defmodule RedactScanner do
    def scan(:chunk, _ctx) do
      finding = Finding.new(%{type: "secret_leak", severity: :high, title: "leak"})

      {:ok, [finding],
       %Decision{
         verdict: :annotate,
         mutations: %{redact_response: [%{path: "content[0].text", match: "X", replacement: "Y"}]}
       }}
    end
  end

  defmodule BoomPolicy do
    def evaluate(:chunk, _ctx), do: raise("kaboom")
  end

  defp entry(module, opts \\ []) do
    %{
      name: Keyword.get(opts, :name, inspect(module)),
      version: "1.0.0",
      module: module,
      impl: {:module, module},
      config: %{},
      kind: Keyword.get(opts, :kind, :policy),
      phases: Keyword.get(opts, :phases, [:chunk]),
      tool_tags: [],
      data_needs: [],
      timeout_ms: 200,
      fail_mode: Keyword.get(opts, :fail_mode, :fail_open),
      can_mutate: [],
      can_block: Keyword.get(opts, :can_block, false),
      order: Keyword.get(opts, :order, 0),
      enabled: Keyword.get(opts, :enabled, true)
    }
  end

  defp ctx do
    CallContext.new(%{
      phase: :chunk,
      call: %{session_id: "s", server_id: "files", tool_name: "stream_export"},
      response: %{
        stream: true,
        chunk: %{"type" => "text", "text" => "X"},
        chunk_index: 3,
        delivered: []
      }
    })
  end

  test "allows a chunk when no policy objects" do
    assert {:allow, [], [], nil} = Pipeline.run_chunk(ctx(), [entry(PassPolicy)])
  end

  test "a policy :deny cuts the stream" do
    assert {:deny, _findings, _redactions, "over budget"} =
             Pipeline.run_chunk(ctx(), [entry(CutPolicy)])
  end

  test "collects findings and redactions from a chunk scanner" do
    assert {:allow, [%{type: "secret_leak"}], [redaction], nil} =
             Pipeline.run_chunk(ctx(), [entry(RedactScanner, kind: :scanner)])

    assert redaction.path == "content[0].text"
  end

  test "an entry without the :chunk phase is skipped" do
    assert {:allow, [], [], nil} =
             Pipeline.run_chunk(ctx(), [entry(CutPolicy, phases: [:post_call])])
  end

  test "a raising chunk policy with fail_open does not cut the stream" do
    capture_log(fn ->
      assert {:allow, [%{type: "plugin_error"}], [], nil} =
               Pipeline.run_chunk(ctx(), [entry(BoomPolicy, name: "boom")])
    end)
  end

  test "a raising chunk policy with fail_closed cuts the stream" do
    capture_log(fn ->
      assert {:deny, [%{type: "plugin_error"}], [], _reason} =
               Pipeline.run_chunk(ctx(), [
                 entry(BoomPolicy, name: "boom", fail_mode: :fail_closed)
               ])
    end)
  end
end
