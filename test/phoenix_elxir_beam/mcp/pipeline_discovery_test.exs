defmodule PhoenixElxirBeam.MCP.PipelineDiscoveryTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias PhoenixElxirBeam.MCP.{CallContext, Finding, Pipeline}

  defmodule TagScanner do
    def scan(:discovery, _ctx) do
      {:ok, [], [%{name: "a", add_tags: [:sensitive_read]}]}
    end
  end

  defmodule DriftScanner do
    def scan(:discovery, _ctx) do
      finding = Finding.new(%{type: "rug_pull", severity: :high, title: "a changed"})
      {:ok, [finding], [%{name: "a", quarantine: true, reason: "changed"}]}
    end
  end

  defmodule BoomScanner do
    def scan(:discovery, _ctx), do: raise("kaboom")
  end

  defp entry(module, opts) do
    %{
      name: Keyword.get(opts, :name, inspect(module)),
      version: "1.0.0",
      module: module,
      impl: {:module, module},
      config: %{},
      kind: :scanner,
      phases: Keyword.get(opts, :phases, [:discovery]),
      timeout_ms: 200,
      fail_mode: :fail_open,
      order: Keyword.get(opts, :order, 0),
      enabled: Keyword.get(opts, :enabled, true)
    }
  end

  defp ctx do
    CallContext.new(%{
      phase: :discovery,
      discovery: %{
        server: %{id: "s", name: "s", transport: :http},
        tools: [],
        previous_hashes: %{}
      }
    })
  end

  test "merges findings and per-tool updates across scanners" do
    entries = [entry(TagScanner, order: 0), entry(DriftScanner, order: 1)]

    assert {:ok, [%{type: "rug_pull"}], [update]} = Pipeline.run_discovery(ctx(), entries)

    assert update.name == "a"
    assert update.quarantine == true
    assert update.add_tags == [:sensitive_read]
    assert update.reason == "changed"
  end

  test "a scanner without the :discovery phase is skipped" do
    assert {:ok, [], []} =
             Pipeline.run_discovery(ctx(), [entry(DriftScanner, phases: [:post_call])])
  end

  test "a disabled scanner is skipped" do
    assert {:ok, [], []} =
             Pipeline.run_discovery(ctx(), [entry(DriftScanner, enabled: false)])
  end

  test "a crashing scanner is dropped (fail_open) and recorded as a plugin_error finding" do
    capture_log(fn ->
      assert {:ok, [%{type: "plugin_error"}], []} =
               Pipeline.run_discovery(ctx(), [entry(BoomScanner, name: "boom")])
    end)
  end
end
