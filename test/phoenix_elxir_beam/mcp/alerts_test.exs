defmodule PhoenixElxirBeam.MCP.AlertsTest do
  use ExUnit.Case, async: false

  alias PhoenixElxirBeam.MCP.Alerts

  test "emit/4 broadcasts on the alerts topic, records history, and counts telemetry" do
    Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, Alerts.topic())

    ref = :telemetry_test.attach_event_handlers(self(), [[:mcp, :alert]])
    on_exit(fn -> :telemetry.detach(ref) end)

    :ok = Alerts.emit(:sidecar_circuit_open, :critical, "boom", %{plugin: "x"})

    assert_receive {:alert, %{key: :sidecar_circuit_open, severity: :critical, detail: "boom"}}
    assert_receive {[:mcp, :alert], ^ref, %{count: 1}, %{key: :sidecar_circuit_open}}

    assert Enum.any?(Alerts.recent(), &(&1.key == :sidecar_circuit_open and &1.detail == "boom"))
  end

  test "recent/0 returns newest first" do
    Alerts.emit(:upstream_unreachable, :warning, "first")
    Alerts.emit(:upstream_unreachable, :warning, "second")
    details = Alerts.recent() |> Enum.map(& &1.detail)

    assert Enum.find_index(details, &(&1 == "second")) <
             Enum.find_index(details, &(&1 == "first"))
  end
end
