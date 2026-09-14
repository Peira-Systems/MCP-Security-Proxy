defmodule PhoenixElxirBeam.MCP.Plugins.RuleEngineWasmParityTest do
  @moduledoc """
  The actual acceptance bar for W4 (`docs/wasm-plugin-plan.md`): not "the Wasm plugin
  compiles and runs," but verdict-for-verdict agreement with the trusted Elixir
  `RuleEngine` across the exact same corpus `RuleEngineTest` uses
  (`RuleEngineCorpus` — a single source, so the two test files can't silently drift
  apart). Runs the Wasm plugin through `WasmRunner.request/4` + `Wire.encode_context/2` /
  `decode_decision/1` — the same code path `Pipeline.policy_evaluate/3` uses in
  production, not a hand-rolled shortcut.
  """

  use ExUnit.Case, async: false

  alias PhoenixElxirBeam.MCP.CallContext
  alias PhoenixElxirBeam.MCP.Plugin.{WasmRunner, Wire}
  alias PhoenixElxirBeam.MCP.Plugins.{RuleEngine, RuleEngineCorpus}

  @wasm_path Path.expand("../../../../priv/wasm_plugins/rule_engine.wasm", __DIR__)

  setup do
    name = :"rule_engine_wasm_parity_#{System.unique_integer([:positive])}"
    start_supervised!({WasmRunner, name: name, path: @wasm_path}, id: name)
    %{name: name}
  end

  # Mirrors the shape Registry builds for a {:wasm, ...} pre_call policy entry — only the
  # fields Wire.encode_context/2 actually reads matter here. `config` is what
  # Wire.encode_context/2 sends as the wire's "pluginConfig" (NOT ctx.plugin_config,
  # which only matters for the in-process calling convention) — this is where the rules
  # for this fixture actually have to live for the Wasm side to see them.
  defp entry(name, rules) do
    %{
      impl: {:wasm, name},
      config: %{"rules" => rules},
      data_needs: ["session.seenTags", "session.taint"],
      timeout_ms: 1_000
    }
  end

  defp ctx(fixture) do
    call =
      Map.merge(
        %{
          session_id: "s",
          agent_id: "agent://demo",
          server_id: "net",
          tool_name: "post_webhook",
          tags: [:network_egress]
        },
        fixture.call
      )

    CallContext.new(%{
      phase: :pre_call,
      call: call,
      session: Map.merge(%{seen_tags: [], taint: %{sources: []}}, fixture.session),
      plugin_config: %{"rules" => fixture.rules}
    })
  end

  defp wasm_evaluate(name, ctx, rules) do
    entry = entry(name, rules)

    {:ok, result} =
      WasmRunner.request(
        name,
        "call/evaluate",
        %{"context" => Wire.encode_context(ctx, entry)},
        entry.timeout_ms
      )

    Wire.decode_decision(result)
  end

  for fixture <- RuleEngineCorpus.cases() do
    test "parity: #{fixture.name}", %{name: name} do
      fixture = unquote(Macro.escape(fixture))
      ctx = ctx(fixture)

      elixir_decision = RuleEngine.evaluate(:pre_call, ctx)
      wasm_decision = wasm_evaluate(name, ctx, fixture.rules)

      assert wasm_decision.verdict == elixir_decision.verdict,
             "verdict mismatch for #{inspect(fixture.name)}: " <>
               "elixir=#{inspect(elixir_decision.verdict)} wasm=#{inspect(wasm_decision.verdict)}"

      assert wasm_decision.reason == elixir_decision.reason
      assert wasm_decision.severity == elixir_decision.severity

      if elixir_decision.verdict == :hold do
        assert wasm_decision.hold.timeout_ms == elixir_decision.hold.timeout_ms
        assert wasm_decision.hold.on_timeout == elixir_decision.hold.on_timeout
      end
    end
  end
end
