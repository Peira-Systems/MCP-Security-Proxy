defmodule PhoenixElxirBeam.MCP.PolicyEngineDurabilityTest do
  @moduledoc "M2.2: PolicyEngine session state survives a restart via Postgres."
  use PhoenixElxirBeam.DataCase, async: false

  import Ecto.Query

  alias PhoenixElxirBeam.MCP.{PolicyEngine, PolicySession, PolicyStore}

  @name :policy_engine_durability

  defp start_engine, do: start_supervised!({PolicyEngine, name: @name}, id: PolicyEngine)

  defp restart_engine do
    stop_supervised!(PolicyEngine)
    start_engine()
  end

  setup do
    start_engine()
    :ok
  end

  test "an accumulated tag persists and still blocks after a restart" do
    sid = "dur-tag-#{System.unique_integer([:positive])}"

    :ok = PolicyEngine.ensure_session(sid, "agent://acme", @name)
    {:allow, _} = PolicyEngine.record_call(sid, "files", "read_secrets", [:sensitive_read], @name)

    persisted = PolicyStore.load(sid)
    assert MapSet.member?(persisted.tags, :sensitive_read)
    assert persisted.agent_id == "agent://acme"
    assert Repo.get(PolicySession, sid).tags == ["sensitive_read"]

    restart_engine()

    {:block, _event} =
      PolicyEngine.record_call(sid, "net", "post_webhook", [:network_egress], @name)
  end

  test "taint persists (raw secret stripped) and still blocks egress after a restart" do
    sid = "dur-taint-#{System.unique_integer([:positive])}"

    :ok = PolicyEngine.ensure_session(sid, nil, @name)
    # untagged read — no tag-based rule fires, only the response scan taints
    {:allow, _} = PolicyEngine.record_call(sid, "files", "read_config", [], @name)

    :ok =
      PolicyEngine.record_response_scan(
        sid,
        "files",
        "read_config",
        [],
        nil,
        [
          %{
            origin_tool: "read_config",
            finding_type: "secret_leak",
            secret: "sk-SECRET",
            hint: "sk-***"
          }
        ],
        @name
      )

    [source] = PolicyStore.load(sid).taint
    refute Map.has_key?(source, "secret")
    assert source["origin_tool"] == "read_config"
    refute Enum.any?(Repo.get(PolicySession, sid).taint, &Map.has_key?(&1, "secret"))

    restart_engine()

    # fresh cache — TaintGuard must still see the reloaded taint
    {:block, event} =
      PolicyEngine.record_call(sid, "net", "post_webhook", [:network_egress], @name)

    assert event.reason =~ "secret"
  end

  test "a session unknown to both cache and Postgres still fails closed" do
    {:block, event} =
      PolicyEngine.record_call("never-seen", "net", "post_webhook", [:network_egress], @name)

    assert event.status == :blocked
  end

  test "drop_session removes the persisted row" do
    sid = "drop-#{System.unique_integer([:positive])}"
    :ok = PolicyEngine.ensure_session(sid, nil, @name)
    assert PolicyStore.load(sid)

    :ok = PolicyEngine.drop_session(sid, @name)
    refute PolicyStore.load(sid)
  end

  test "the sweep deletes stale rows" do
    sid = "sweep-#{System.unique_integer([:positive])}"
    :ok = PolicyEngine.ensure_session(sid, nil, @name)

    # backdate it
    Repo.update_all(
      from(s in PolicySession, where: s.session_id == ^sid),
      set: [updated_at: DateTime.add(DateTime.utc_now(), -2, :day)]
    )

    assert PolicyStore.sweep(3600) >= 1
    refute PolicyStore.load(sid)
  end
end
