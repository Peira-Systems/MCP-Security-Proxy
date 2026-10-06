defmodule PhoenixElxirBeam.MCP.Plugins.LoopGuardTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.{CallContext, Decision}
  alias PhoenixElxirBeam.MCP.Plugins.LoopGuard
  alias PhoenixElxirBeam.MCP.CallFingerprint

  @session_id "session-loop-guard-test"

  defp entry(tool_name, fingerprint, at) do
    %{tool_name: tool_name, arg_fingerprint: fingerprint, tags: [], at: at}
  end

  defp fp(args), do: CallFingerprint.compute(@session_id, args)

  # `current_args` are the arguments of the call under evaluation — the
  # plugin fingerprints these itself from `ctx.call.arguments` (keyed to
  # `ctx.call.session_id`), so callers must pass real arguments here (never
  # a bare pre-computed fingerprint) for `ctx.call` to be consistent with
  # any `recent_calls` history built from the same arguments via `entry/3`.
  # All fixtures in this file share `@session_id` so fingerprints computed
  # here and fingerprints computed by the plugin under test agree.
  defp ctx(tool_name, current_args, recent, cfg) do
    now = DateTime.utc_now()
    fingerprint = fp(current_args)

    CallContext.new(%{
      phase: :pre_call,
      call: %{
        tool_name: tool_name,
        session_id: @session_id,
        arguments: current_args,
        tags: []
      },
      session: %{recent_calls: recent ++ [entry(tool_name, fingerprint, now)]},
      plugin_config: cfg
    })
  end

  describe "evaluate/2 — tight threshold (same tool + same arguments)" do
    test "allows when the identical call hasn't repeated past the threshold" do
      args = %{"path" => "/x"}
      now = DateTime.utc_now()
      recent = for _ <- 1..2, do: entry("write_file", fp(args), now)

      assert %Decision{verdict: :allow} =
               LoopGuard.evaluate(
                 :pre_call,
                 ctx("write_file", args, recent, %{"max_identical_calls" => 3})
               )
    end

    test "denies once the identical tool+arguments pair repeats past the threshold" do
      args = %{"path" => "/x"}
      now = DateTime.utc_now()
      recent = for _ <- 1..3, do: entry("write_file", fp(args), now)

      assert %Decision{verdict: :deny, reason: reason} =
               LoopGuard.evaluate(
                 :pre_call,
                 ctx("write_file", args, recent, %{"max_identical_calls" => 3})
               )

      assert reason =~ "write_file"
      assert reason =~ "identical"
    end

    test "different arguments to the same tool do not count toward the tight threshold" do
      args_a = %{"path" => "/x"}
      args_b = %{"path" => "/y"}
      now = DateTime.utc_now()
      recent = for _ <- 1..3, do: entry("write_file", fp(args_a), now)

      assert %Decision{verdict: :allow} =
               LoopGuard.evaluate(
                 :pre_call,
                 ctx("write_file", args_b, recent, %{"max_identical_calls" => 3})
               )
    end
  end

  describe "evaluate/2 — loose threshold (same tool, any arguments)" do
    test "denies once the same tool repeats past the looser threshold even with varying arguments" do
      now = DateTime.utc_now()

      recent =
        for i <- 1..5, do: entry("search", fp(%{"page" => i}), now)

      ctx =
        ctx("search", %{"page" => 6}, recent, %{
          "max_identical_calls" => 100,
          "max_same_tool_calls" => 5
        })

      assert %Decision{verdict: :deny, reason: reason} = LoopGuard.evaluate(:pre_call, ctx)
      assert reason =~ "search"
    end
  end

  describe "evaluate/2 — defensive handling" do
    test "treats entries missing tool_name/arg_fingerprint as non-matching, not a crash" do
      now = DateTime.utc_now()
      stale_entry = %{tags: [], at: now}

      ctx =
        CallContext.new(%{
          phase: :pre_call,
          call: %{tool_name: "write_file", session_id: @session_id, arguments: %{}, tags: []},
          session: %{recent_calls: [stale_entry, entry("write_file", fp(%{}), now)]},
          plugin_config: %{}
        })

      assert %Decision{verdict: :allow} = LoopGuard.evaluate(:pre_call, ctx)
    end

    test "several stale entries (missing the new fields) never count toward either threshold" do
      # Three stale entries plus a threshold of 1 would trip if stale
      # entries were (incorrectly) treated as matching — proves the
      # defensive `Map.get`-based matching actually excludes them, not
      # just that it doesn't crash.
      now = DateTime.utc_now()
      stale_entries = for _ <- 1..3, do: %{tags: [], at: now}

      ctx =
        CallContext.new(%{
          phase: :pre_call,
          call: %{tool_name: "write_file", session_id: @session_id, arguments: %{}, tags: []},
          session: %{recent_calls: stale_entries},
          plugin_config: %{"max_identical_calls" => 1, "max_same_tool_calls" => 1}
        })

      assert %Decision{verdict: :allow} = LoopGuard.evaluate(:pre_call, ctx)
    end

    test "only counts entries within the configured window" do
      args = %{}
      old = DateTime.add(DateTime.utc_now(), -60, :second)
      recent = for _ <- 1..3, do: entry("write_file", fp(args), old)

      assert %Decision{verdict: :allow} =
               LoopGuard.evaluate(
                 :pre_call,
                 ctx("write_file", args, recent, %{
                   "window_ms" => 5_000,
                   "max_identical_calls" => 3
                 })
               )
    end

    test "tolerates string-keyed numeric config values, same convention as BaselineGuard" do
      args = %{"path" => "/x"}
      now = DateTime.utc_now()
      recent = for _ <- 1..2, do: entry("write_file", fp(args), now)

      cfg = %{"window_ms" => "10000", "max_identical_calls" => "2"}

      assert %Decision{verdict: :deny} =
               LoopGuard.evaluate(:pre_call, ctx("write_file", args, recent, cfg))
    end

    test "falls back to defaults on missing / junk config" do
      args = %{"path" => "/x"}
      now = DateTime.utc_now()
      # default max_identical_calls is 3; 4 identical calls trips it
      recent = for _ <- 1..4, do: entry("write_file", fp(args), now)

      assert %Decision{verdict: :deny} =
               LoopGuard.evaluate(:pre_call, ctx("write_file", args, recent, %{}))
    end
  end

  test "manifest declares pre_call, fail_open, and session.recentCalls data need" do
    manifest = LoopGuard.manifest()
    assert manifest.capabilities.policy.phases == [:pre_call]
    assert manifest.capabilities.policy.fail_mode == :fail_open
    assert "session.recentCalls" in manifest.capabilities.policy.data_needs
  end
end
