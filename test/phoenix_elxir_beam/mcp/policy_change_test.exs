defmodule PhoenixElxirBeam.MCP.PolicyChangeTest do
  use PhoenixElxirBeam.DataCase, async: false

  alias PhoenixElxirBeam.MCP.{EventLog, PolicyChange}

  setup do
    Ecto.Adapters.SQL.Sandbox.mode(PhoenixElxirBeam.Repo, {:shared, self()})
    :ok
  end

  test "record/1 lands a policy_change row on the hash chain and broadcasts" do
    Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, PolicyChange.topic())

    assert {:ok, event_id} =
             PolicyChange.record(%{
               kind: :plugin_enabled,
               target: "secret-leak",
               actor: "op@example.test",
               before: true,
               after: false
             })

    assert_receive {:policy_change, %{event_id: ^event_id, kind: :plugin_enabled}}

    assert :ok = EventLog.verify_chain()

    [latest | _] = PolicyChange.recent(5)
    assert latest.event_id == event_id
    assert latest.kind == "plugin_enabled"
    assert latest.actor == "op@example.test"
    assert latest.after == false
    assert latest.summary =~ "disabled plugin secret-leak"
  end
end
