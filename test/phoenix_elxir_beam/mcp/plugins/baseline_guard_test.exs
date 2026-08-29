defmodule PhoenixElxirBeam.MCP.Plugins.BaselineGuardTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.CallContext
  alias PhoenixElxirBeam.MCP.Plugins.BaselineGuard

  # `recent_calls` newest-first, `n` entries carrying `tags`, spaced `spacing_ms`
  # apart ending "now".
  defp recent(n, tags, spacing_ms \\ 1_000) do
    now = DateTime.utc_now()

    for i <- 0..(n - 1) do
      %{tags: tags, at: DateTime.add(now, -i * spacing_ms, :millisecond)}
    end
  end

  defp ctx(recent_calls, config) do
    CallContext.new(%{
      phase: :pre_call,
      call: %{
        session_id: "s",
        server_id: "files",
        tool_name: "read_secrets",
        tags: [:sensitive_read]
      },
      session: %{seen_tags: [], recent_calls: recent_calls},
      plugin_config: config
    })
  end

  @cfg %{"window_ms" => 10_000, "max_calls" => 3, "watch_tags" => ["sensitive_read"]}

  test "allows while at or below the baseline" do
    assert %{verdict: :allow} =
             BaselineGuard.evaluate(:pre_call, ctx(recent(3, [:sensitive_read]), @cfg))
  end

  test "denies once the watched-call count in the window exceeds max_calls" do
    assert %{verdict: :deny, severity: :high, reason: reason} =
             BaselineGuard.evaluate(:pre_call, ctx(recent(4, [:sensitive_read]), @cfg))

    assert reason =~ "baseline exceeded"
    assert reason =~ "sensitive_read"
    assert reason =~ "4"
  end

  test "only counts calls inside the window" do
    # 2 recent + 3 old (20s ago, outside the 10s window) = 2 in-window → allow
    old =
      for i <- 0..2,
          do: %{
            tags: [:sensitive_read],
            at: DateTime.add(DateTime.utc_now(), -20_000 - i * 1_000, :millisecond)
          }

    recent_in = recent(2, [:sensitive_read])

    assert %{verdict: :allow} = BaselineGuard.evaluate(:pre_call, ctx(recent_in ++ old, @cfg))
  end

  test "only counts calls carrying a watched tag" do
    mixed = recent(2, [:sensitive_read]) ++ recent(5, [:network_egress])
    assert %{verdict: :allow} = BaselineGuard.evaluate(:pre_call, ctx(mixed, @cfg))
  end

  test "falls back to defaults on missing / junk config" do
    # default max_calls is 5; 6 sensitive reads trips it
    assert %{verdict: :deny} =
             BaselineGuard.evaluate(:pre_call, ctx(recent(6, [:sensitive_read]), %{}))

    assert %{verdict: :allow} =
             BaselineGuard.evaluate(:pre_call, ctx(recent(5, [:sensitive_read]), %{}))
  end

  test "tolerates string-keyed config values" do
    cfg = %{"window_ms" => "10000", "max_calls" => "2", "watch_tags" => ["sensitive_read"]}

    assert %{verdict: :deny} =
             BaselineGuard.evaluate(:pre_call, ctx(recent(3, [:sensitive_read]), cfg))
  end

  test "manifest: pre_call policy, evaluates every call, fail_open" do
    manifest = BaselineGuard.manifest()

    assert manifest.plugin.name == "baseline-guard"
    assert %{policy: policy} = manifest.capabilities
    assert policy.phases == [:pre_call]
    assert policy.tool_tags == []
    assert policy.fail_mode == :fail_open
    assert "session.recentCalls" in policy.data_needs
  end
end
