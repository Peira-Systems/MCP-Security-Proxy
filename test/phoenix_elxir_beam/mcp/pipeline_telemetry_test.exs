defmodule PhoenixElxirBeam.MCP.PipelineTelemetryTest do
  use ExUnit.Case, async: false

  alias PhoenixElxirBeam.MCP.{CallContext, Decision, Pipeline}

  defmodule AllowAll do
    def evaluate(_phase, _ctx), do: Decision.allow()
  end

  defmodule DenyAll do
    def evaluate(_phase, _ctx), do: Decision.deny(:high, "no")
  end

  defp entry(module, opts) do
    %{
      name: Keyword.get(opts, :name, inspect(module)),
      version: "1.0.0",
      module: module,
      impl: {:module, module},
      config: %{},
      kind: :policy,
      phases: [:pre_call],
      tool_tags: [],
      timeout_ms: 200,
      fail_mode: :fail_closed,
      can_mutate: [],
      can_block: true,
      order: Keyword.get(opts, :order, 0),
      enabled: true
    }
  end

  defp ctx do
    CallContext.new(%{
      phase: :pre_call,
      call: %{tags: []},
      session: %{seen_tags: []},
      plugin_config: %{}
    })
  end

  test "run/3 emits phase, per-plugin, and decision events" do
    ref =
      :telemetry_test.attach_event_handlers(self(), [
        [:mcp, :pipeline, :run, :stop],
        [:mcp, :plugin, :run, :stop],
        [:mcp, :decision]
      ])

    on_exit(fn -> :telemetry.detach(ref) end)

    assert {:deny, _, _} =
             Pipeline.run(:pre_call, ctx(), [entry(AllowAll, order: 0), entry(DenyAll, order: 1)])

    assert_receive {[:mcp, :plugin, :run, :stop], ^ref, %{duration: d1},
                    %{plugin: "PhoenixElxirBeam.MCP.PipelineTelemetryTest.AllowAll", outcome: :ok}}
                   when is_integer(d1)

    assert_receive {[:mcp, :plugin, :run, :stop], ^ref, %{duration: _},
                    %{
                      plugin: "PhoenixElxirBeam.MCP.PipelineTelemetryTest.DenyAll",
                      verdict: :deny
                    }}

    assert_receive {[:mcp, :pipeline, :run, :stop], ^ref, %{duration: _},
                    %{phase: :pre_call, verdict: :deny}}

    assert_receive {[:mcp, :decision], ^ref, %{count: 1}, %{verdict: :deny, phase: :pre_call}}
  end

  test "a plugin timeout is recorded with outcome :timeout" do
    defmodule Slow do
      def evaluate(_phase, _ctx) do
        Process.sleep(1_000)
        Decision.allow()
      end
    end

    ref = :telemetry_test.attach_event_handlers(self(), [[:mcp, :plugin, :run, :stop]])
    on_exit(fn -> :telemetry.detach(ref) end)

    Pipeline.run(:pre_call, ctx(), [entry(Slow, name: "slow") |> Map.put(:timeout_ms, 20)])

    assert_receive {[:mcp, :plugin, :run, :stop], ^ref, %{duration: _}, %{outcome: :timeout}},
                   2_000
  end
end
