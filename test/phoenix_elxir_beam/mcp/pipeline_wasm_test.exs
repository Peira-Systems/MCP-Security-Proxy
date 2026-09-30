defmodule PhoenixElxirBeam.MCP.PipelineWasmTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias PhoenixElxirBeam.MCP.{CallContext, Pipeline}
  alias PhoenixElxirBeam.MCP.Plugin.WasmRunner

  @allow_fixture Path.expand("../../support/fixtures/wasm_echo_scanner.wat", __DIR__)
  @deny_fixture Path.expand("../../support/fixtures/wasm_deny_policy.wat", __DIR__)

  defp start_wasm(path) do
    name = :"pipeline_wasm_#{System.unique_integer([:positive])}"
    start_supervised!({WasmRunner, name: name, path: path}, id: name)
    name
  end

  defp scanner_entry(name, opts \\ []) do
    %{
      name: "wasm-echo-scanner",
      version: "0.1.0",
      impl: {:wasm, name},
      config: %{},
      kind: :scanner,
      phases: Keyword.get(opts, :phases, [:discovery]),
      data_needs: [],
      timeout_ms: 1000,
      fail_mode: Keyword.get(opts, :fail_mode, :fail_open),
      can_block: Keyword.get(opts, :can_block, false),
      can_mutate: [],
      tool_tags: [],
      order: 0,
      enabled: true
    }
  end

  defp policy_entry(name, opts \\ []) do
    %{
      name: "wasm-deny-policy",
      version: "0.1.0",
      impl: {:wasm, name},
      config: %{},
      kind: :policy,
      phases: Keyword.get(opts, :phases, [:pre_call]),
      data_needs: [],
      timeout_ms: 1000,
      fail_mode: Keyword.get(opts, :fail_mode, :fail_closed),
      can_block: false,
      can_mutate: [],
      tool_tags: [],
      order: 0,
      enabled: true
    }
  end

  defp discovery_ctx do
    CallContext.new(%{
      phase: :discovery,
      discovery: %{
        server: %{id: "real-x", name: "x", transport: :http},
        tools: [
          %{
            name: "note",
            description: "Save a note",
            input_schema: %{},
            tags: [],
            description_hash: "sha256:x"
          }
        ],
        previous_hashes: %{}
      }
    })
  end

  defp post_call_ctx do
    CallContext.new(%{
      phase: :post_call,
      call: %{session_id: "s", server_id: "net", tool_name: "fetch_page"},
      response: %{is_error: false, content: [%{"type" => "text", "text" => "hello"}]}
    })
  end

  defp pre_call_ctx do
    CallContext.new(%{
      phase: :pre_call,
      call: %{session_id: "s", server_id: "net", tool_name: "post_webhook"}
    })
  end

  # -- discovery: routes to wasm exactly like a sidecar would ---------------

  test "run_discovery routes to a wasm scanner and merges its (empty) result" do
    name = start_wasm(@allow_fixture)
    assert {:ok, [], []} = Pipeline.run_discovery(discovery_ctx(), [scanner_entry(name)])
  end

  test "a dead wasm discovery scanner fails open with a plugin_error finding" do
    name = start_wasm(@allow_fixture)
    :ok = stop_supervised(name)

    capture_log(fn ->
      assert {:ok, [%{type: "plugin_error"}], []} =
               Pipeline.run_discovery(discovery_ctx(), [scanner_entry(name)])
    end)
  end

  # -- post_call: allow (scanner) and deny/withhold (policy) ----------------

  test "run_post_call routes to a wasm scanner and returns its allow verdict" do
    name = start_wasm(@allow_fixture)

    assert {:allow, [], [], [], nil, nil} =
             Pipeline.run_post_call(post_call_ctx(), [scanner_entry(name, phases: [:post_call])])
  end

  test "run_post_call routes to a wasm policy and withholds on its deny verdict" do
    name = start_wasm(@deny_fixture)

    assert {:deny, [], [], [], "denied by wasm-deny-policy (test fixture)", nil} =
             Pipeline.run_post_call(post_call_ctx(), [policy_entry(name, phases: [:post_call])])
  end

  test "a dead wasm post_call scanner fails open with a plugin_error finding" do
    name = start_wasm(@allow_fixture)
    :ok = stop_supervised(name)

    capture_log(fn ->
      assert {:allow, [%{type: "plugin_error"}], [], [], nil, nil} =
               Pipeline.run_post_call(post_call_ctx(), [scanner_entry(name, phases: [:post_call])])
    end)
  end

  # -- pre_call: the ordered policy chain (run/3) ----------------------------

  test "run/3 routes to a wasm policy and short-circuits the chain on deny" do
    name = start_wasm(@deny_fixture)

    assert {:deny, decision, findings} =
             Pipeline.run(:pre_call, pre_call_ctx(), [policy_entry(name)])

    assert decision.deciding_plugin == "wasm-deny-policy"
    assert decision.reason == "denied by wasm-deny-policy (test fixture)"
    assert findings == []
  end

  test "a dead wasm pre_call policy fails closed (its declared fail_mode)" do
    name = start_wasm(@deny_fixture)
    :ok = stop_supervised(name)

    capture_log(fn ->
      assert {:deny, decision, _findings} =
               Pipeline.run(:pre_call, pre_call_ctx(), [policy_entry(name)])

      assert decision.reason =~ "unavailable"
    end)
  end
end
