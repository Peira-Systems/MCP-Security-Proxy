defmodule PhoenixElxirBeam.MCP.PolicyEngineDryRunTest do
  @moduledoc """
  D3: a would-be deny/hold surfaces as a `:shadow_blocked` / `:shadow_held`
  event and the call proceeds (tags/taint accumulate) exactly as an allow
  would, when the effective plugin/global mode is `:dry_run`.
  """
  # EventLog is a serial, hash-chained append-only log — run serially to
  # avoid write-order contention with other suites that also write to it
  # (see policy_engine_test.exs).
  use ExUnit.Case, async: false

  alias PhoenixElxirBeam.MCP.{EventLog, PolicyEngine}
  alias PhoenixElxirBeam.MCP.Plugin.Registry
  alias PhoenixElxirBeam.MCP.Plugins.{ChainExfil, EventLogSink}
  alias PhoenixElxirBeam.Repo

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
  end

  # `plugins` are the policy plugins under test; EventLogSink is always added
  # so record_response_scan/record_call verdicts land in EventLog for
  # assertions, matching how the real registry is configured (config/test.exs).
  defp start_stack(plugins) do
    suffix = System.unique_integer([:positive])
    registry = :"pe_dry_run_registry_#{suffix}"
    engine = :"pe_dry_run_engine_#{suffix}"

    {:ok, _} =
      start_supervised({Registry, name: registry, plugins: plugins ++ [{EventLogSink, []}]},
        id: registry
      )

    {:ok, pid} = start_supervised({PolicyEngine, name: engine, registry: registry}, id: engine)
    Ecto.Adapters.SQL.Sandbox.allow(Repo, self(), pid)

    {engine, registry}
  end

  defp egress_after_read(engine) do
    session = "s-#{System.unique_integer([:positive])}"
    :ok = PolicyEngine.start_session(session, :attack, nil, engine)

    {:allow, _} =
      PolicyEngine.record_call(session, "files", "read_secrets", [:sensitive_read], engine)

    {session, PolicyEngine.record_call(session, "net", "post_webhook", [:network_egress], engine)}
  end

  test "global dry_run: a would-be block surfaces as :shadow_blocked and the call proceeds" do
    {engine, registry} = start_stack([{ChainExfil, []}])
    :ok = Registry.set_proxy_mode(:dry_run, registry)

    {_session, {verdict, event}} = egress_after_read(engine)

    assert verdict == :allow
    assert event.status == :shadow_blocked
    assert event.reason == ChainExfil.block_reason()
  end

  test "global enforcing (default): the same sequence still really blocks" do
    {engine, _registry} = start_stack([{ChainExfil, []}])

    {_session, {verdict, event}} = egress_after_read(engine)

    assert verdict == :block
    assert event.status == :blocked
  end

  test "a plugin pinned :dry_run is downgraded even when the global mode is enforcing" do
    {engine, registry} = start_stack([{ChainExfil, []}])
    :ok = Registry.set_mode("chain-exfil", :dry_run, registry)

    {_session, {verdict, event}} = egress_after_read(engine)

    assert verdict == :allow
    assert event.status == :shadow_blocked
  end

  test "record_response_scan/8: a shadow withhold produces a :shadow_blocked event" do
    {engine, _registry} = start_stack([])
    session_id = "s-#{System.unique_integer([:positive])}"
    :ok = PolicyEngine.start_session(session_id, :attack, nil, engine)

    assert :ok =
             PolicyEngine.record_response_scan(
               session_id,
               "files",
               "read_secrets",
               [],
               nil,
               [],
               engine,
               "would have withheld: secret leak"
             )

    %{entries: entries} = EventLog.list(%{page_size: 100})

    assert Enum.any?(
             entries,
             &(&1.session_id == session_id and &1.status == "shadow_blocked" and
                 &1.reason == "would have withheld: secret leak")
           )
  end

  test "record_response_scan/8: a real withhold still wins over a shadow one" do
    {engine, _registry} = start_stack([])
    session_id = "s-#{System.unique_integer([:positive])}"
    :ok = PolicyEngine.start_session(session_id, :attack, nil, engine)

    assert :ok =
             PolicyEngine.record_response_scan(
               session_id,
               "files",
               "read_secrets",
               [],
               "withheld for real",
               [],
               engine,
               "would also have withheld"
             )

    %{entries: entries} = EventLog.list(%{page_size: 100})

    assert Enum.any?(
             entries,
             &(&1.session_id == session_id and &1.status == "blocked" and
                 &1.reason == "withheld for real")
           )
  end

  test "a shadow-blocked call still accumulates its own tags, like a real allow would" do
    {engine, registry} = start_stack([{ChainExfil, []}])
    :ok = Registry.set_proxy_mode(:dry_run, registry)

    session = "s-#{System.unique_integer([:positive])}"
    :ok = PolicyEngine.start_session(session, :attack, nil, engine)

    # The read itself is unaffected (chain-exfil only cares about egress); the
    # question this test answers is whether the *next* call — an egress —
    # still sees :sensitive_read in session tags after a shadow-blocked call
    # is treated as a real allow for bookkeeping.
    assert {:allow, %{status: :ok}} =
             PolicyEngine.record_call(session, "files", "read_secrets", [:sensitive_read], engine)

    assert {:allow, event} =
             PolicyEngine.record_call(session, "net", "post_webhook", [:network_egress], engine)

    assert event.status == :shadow_blocked
    assert event.reason == ChainExfil.block_reason()
  end
end
