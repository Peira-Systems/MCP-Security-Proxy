defmodule PhoenixElxirBeam.MCP.HoldFatigueMonitorTest do
  use ExUnit.Case, async: false

  alias PhoenixElxirBeam.MCP.{Alerts, HoldFatigueMonitor}

  setup do
    HoldFatigueMonitor.reset()
    on_exit(fn -> HoldFatigueMonitor.reset() end)

    Application.put_env(:phoenix_elxir_beam, :approval_gate_alert,
      rate: 0.8,
      min_samples: 5,
      window: 10
    )

    on_exit(fn -> Application.delete_env(:phoenix_elxir_beam, :approval_gate_alert) end)
    Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, Alerts.topic())
    :ok
  end

  test "does not alert below the minimum sample size, even at 100% approved" do
    for _ <- 1..4, do: HoldFatigueMonitor.record(:approved)
    refute_receive {:alert, %{key: :approval_gate_fatigue}}, 50
  end

  test "does not alert when the approval rate is below the configured threshold" do
    for _ <- 1..3, do: HoldFatigueMonitor.record(:approved)
    for _ <- 1..2, do: HoldFatigueMonitor.record(:denied)
    refute_receive {:alert, %{key: :approval_gate_fatigue}}, 50
  end

  test "alerts once the approval rate crosses the threshold with enough samples" do
    for _ <- 1..4, do: HoldFatigueMonitor.record(:approved)
    HoldFatigueMonitor.record(:timeout)

    HoldFatigueMonitor.record(:approved)

    assert_receive {:alert, %{key: :approval_gate_fatigue, severity: :warning, detail: detail}}
    assert detail =~ "rubber-stamping"
  end

  test "only the outcomes within the configured window count" do
    for _ <- 1..10, do: HoldFatigueMonitor.record(:approved)

    # window is 10 — 5 denied pushes out 5 of the approved, landing at 50%;
    # intermediate ticks cross the threshold on the way down, so only the
    # final state (after all 5) is asserted.
    for _ <- 1..5, do: HoldFatigueMonitor.record(:denied)
    flush_alerts()

    HoldFatigueMonitor.record(:approved)
    HoldFatigueMonitor.record(:denied)
    refute_receive {:alert, %{key: :approval_gate_fatigue}}, 50
  end

  defp flush_alerts do
    receive do
      {:alert, _} -> flush_alerts()
    after
      0 -> :ok
    end
  end
end
