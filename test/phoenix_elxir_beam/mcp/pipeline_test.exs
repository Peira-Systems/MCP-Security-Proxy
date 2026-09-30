defmodule PhoenixElxirBeam.MCP.PipelineTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias PhoenixElxirBeam.MCP.{CallContext, Decision, Pipeline}

  defmodule AllowAll do
    def evaluate(_phase, _ctx), do: Decision.allow()
  end

  defmodule DenyAll do
    def evaluate(_phase, _ctx), do: Decision.deny(:high, "denied by DenyAll")
  end

  defmodule Boom do
    def evaluate(_phase, _ctx), do: raise("kaboom")
  end

  defmodule Slow do
    def evaluate(_phase, _ctx) do
      Process.sleep(5_000)
      Decision.allow()
    end
  end

  defmodule Recorder do
    def evaluate(_phase, ctx) do
      send(ctx.plugin_config.notify, {:invoked, __MODULE__})
      Decision.allow()
    end
  end

  defmodule Tagger do
    def evaluate(_phase, _ctx) do
      Decision.annotate(mutations: %{add_tags: [:tainted]})
    end
  end

  defmodule TagObserver do
    def evaluate(_phase, ctx) do
      if :tainted in ctx.session.seen_tags do
        Decision.deny(:medium, "saw :tainted")
      else
        Decision.allow()
      end
    end
  end

  defmodule Holder do
    def evaluate(_phase, _ctx) do
      Decision.hold("needs sign-off", %{prompt: "ok?", timeout_ms: 1000, on_timeout: :deny})
    end
  end

  defp entry(module, opts \\ []) do
    %{
      name: Keyword.get(opts, :name, inspect(module)),
      version: "1.0.0",
      module: module,
      impl: {:module, module},
      config: %{},
      kind: :policy,
      phases: Keyword.get(opts, :phases, [:pre_call]),
      tool_tags: Keyword.get(opts, :tool_tags, []),
      timeout_ms: Keyword.get(opts, :timeout_ms, 200),
      fail_mode: Keyword.get(opts, :fail_mode, :fail_closed),
      can_mutate: Keyword.get(opts, :can_mutate, []),
      order: Keyword.get(opts, :order, 0),
      enabled: Keyword.get(opts, :enabled, true),
      mode: Keyword.get(opts, :mode, nil)
    }
  end

  defp ctx(opts \\ []) do
    CallContext.new(%{
      phase: :pre_call,
      call: %{tags: Keyword.get(opts, :call_tags, [])},
      session: %{seen_tags: Keyword.get(opts, :seen_tags, [])},
      plugin_config: %{notify: self()}
    })
  end

  test "an empty chain allows" do
    assert {:allow, %Decision{verdict: :allow}, []} = Pipeline.run(:pre_call, ctx(), [])
  end

  test "a single allow plugin allows" do
    assert {:allow, _decision, []} = Pipeline.run(:pre_call, ctx(), [entry(AllowAll)])
  end

  test "a deny is final and names the deciding plugin" do
    assert {:deny, decision, _} =
             Pipeline.run(:pre_call, ctx(), [entry(DenyAll, name: "denier")])

    assert decision.verdict == :deny
    assert decision.reason == "denied by DenyAll"
    assert decision.deciding_plugin == "denier"
  end

  test "the first deny short-circuits: later plugins are not invoked" do
    entries = [entry(DenyAll, order: 0), entry(Recorder, order: 1)]

    assert {:deny, _, _} = Pipeline.run(:pre_call, ctx(), entries)
    refute_receive {:invoked, Recorder}
  end

  test "a plugin whose tool_tags do not intersect the call is skipped" do
    entries = [entry(DenyAll, tool_tags: [:network_egress])]

    assert {:allow, _, _} = Pipeline.run(:pre_call, ctx(call_tags: [:sensitive_read]), entries)
  end

  test "a plugin whose tool_tags intersect the call is invoked" do
    entries = [entry(DenyAll, tool_tags: [:network_egress])]

    assert {:deny, _, _} = Pipeline.run(:pre_call, ctx(call_tags: [:network_egress]), entries)
  end

  test "fail_closed turns a crash into a deny with a plugin_error finding" do
    log =
      capture_log(fn ->
        assert {:deny, decision, findings} =
                 Pipeline.run(:pre_call, ctx(), [
                   entry(Boom, name: "boom", fail_mode: :fail_closed)
                 ])

        assert decision.reason =~ "unavailable"
        assert [%{type: "plugin_error"}] = findings
      end)

    assert log =~ "boom"
  end

  test "fail_open turns a crash into an allow with a plugin_error finding" do
    capture_log(fn ->
      assert {:allow, _decision, [%{type: "plugin_error"}]} =
               Pipeline.run(:pre_call, ctx(), [entry(Boom, fail_mode: :fail_open)])
    end)
  end

  test "a plugin that exceeds its timeout is failed per fail_mode" do
    capture_log(fn ->
      assert {:deny, decision, _} =
               Pipeline.run(:pre_call, ctx(), [
                 entry(Slow, timeout_ms: 20, fail_mode: :fail_closed)
               ])

      assert decision.reason =~ "unavailable"
    end)
  end

  test "a granted add_tags mutation is visible to the next plugin in the chain" do
    entries = [
      entry(Tagger, order: 0, can_mutate: [:add_tags]),
      entry(TagObserver, order: 1)
    ]

    assert {:deny, decision, _} = Pipeline.run(:pre_call, ctx(seen_tags: []), entries)
    assert decision.reason == "saw :tainted"
  end

  test "an ungranted add_tags mutation is dropped" do
    entries = [
      entry(Tagger, order: 0, can_mutate: []),
      entry(TagObserver, order: 1)
    ]

    assert {:allow, _, _} = Pipeline.run(:pre_call, ctx(seen_tags: []), entries)
  end

  test "a :hold verdict is returned, not coerced to :deny" do
    assert {:hold, decision, _} =
             Pipeline.run(:pre_call, ctx(), [entry(Holder, name: "holder")])

    assert decision.verdict == :hold
    assert decision.deciding_plugin == "holder"
    assert decision.hold.prompt == "ok?"
  end

  test "a :hold short-circuits: later plugins are not invoked" do
    entries = [entry(Holder, order: 0), entry(Recorder, order: 1)]
    assert {:hold, _, _} = Pipeline.run(:pre_call, ctx(), entries)
    refute_receive {:invoked, Recorder}
  end

  describe "dry-run mode" do
    test "global dry_run downgrades a deny to allow with a shadow_verdict" do
      entries = [entry(DenyAll, name: "denier")]

      assert {:allow, decision, _} =
               Pipeline.run(:pre_call, ctx(), entries, global_mode: :dry_run)

      assert decision.shadow_verdict == :deny
      assert decision.deciding_plugin == "denier"
      assert decision.reason == "denied by DenyAll"
    end

    test "global dry_run downgrades a hold to allow with a shadow_verdict" do
      entries = [entry(Holder, name: "holder")]

      assert {:allow, decision, _} =
               Pipeline.run(:pre_call, ctx(), entries, global_mode: :dry_run)

      assert decision.shadow_verdict == :hold
      assert decision.deciding_plugin == "holder"
    end

    test "global enforcing mode is unaffected (default) — a deny still blocks for real" do
      entries = [entry(DenyAll, name: "denier")]

      assert {:deny, decision, _} = Pipeline.run(:pre_call, ctx(), entries)
      assert decision.shadow_verdict == nil
    end

    test "a plugin pinned :dry_run is downgraded even when the global mode is enforcing" do
      entries = [entry(DenyAll, name: "denier", mode: :dry_run)]

      assert {:allow, decision, _} = Pipeline.run(:pre_call, ctx(), entries)
      assert decision.shadow_verdict == :deny
    end

    test "a plugin pinned :enforcing still blocks for real even when the global mode is dry_run" do
      entries = [entry(DenyAll, name: "denier", mode: :enforcing)]

      assert {:deny, decision, _} =
               Pipeline.run(:pre_call, ctx(), entries, global_mode: :dry_run)

      assert decision.shadow_verdict == nil
    end

    test "the chain continues past a shadow deny so later plugins still run" do
      entries = [
        entry(DenyAll, name: "denier", order: 0),
        %{entry(Recorder, order: 1) | config: %{notify: self()}}
      ]

      assert {:allow, _decision, _} =
               Pipeline.run(:pre_call, ctx(), entries, global_mode: :dry_run)

      assert_receive {:invoked, Recorder}
    end

    test "the first shadow verdict wins deciding_plugin; a later real deny does not override it" do
      entries = [
        entry(DenyAll, name: "first-denier", order: 0),
        entry(DenyAll, name: "second-denier", order: 1)
      ]

      assert {:allow, decision, _} =
               Pipeline.run(:pre_call, ctx(), entries, global_mode: :dry_run)

      assert decision.shadow_verdict == :deny
      assert decision.deciding_plugin == "first-denier"
    end

    test "mutations from a plugin allowed for real (before a later shadow deny) still apply" do
      entries = [
        entry(Tagger, order: 0, can_mutate: [:add_tags]),
        entry(TagObserver, order: 1)
      ]

      assert {:allow, decision, _} =
               Pipeline.run(:pre_call, ctx(seen_tags: []), entries, global_mode: :dry_run)

      assert decision.shadow_verdict == :deny
      assert decision.reason == "saw :tainted"
    end
  end
end
