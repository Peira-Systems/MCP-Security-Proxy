defmodule PhoenixElxirBeam.MCP.AuditIntegrityTest do
  @moduledoc "M2.3: scheduled audit-chain verification + off-DB checkpoint anchoring."
  use PhoenixElxirBeam.DataCase, async: false

  import Ecto.Query

  alias PhoenixElxirBeam.MCP.{AuditCheckpoint, AuditEvent, AuditIntegrity, EventLog, PolicyEvent}

  @name :audit_integrity_test

  setup do
    File.rm(Application.get_env(:phoenix_elxir_beam, AuditCheckpoint)[:path])
    start_supervised!({AuditIntegrity, name: @name, first_delay_ms: 60_000})
    :ok
  end

  defp log_event(status \\ "ok") do
    {:ok, _} =
      EventLog.record(%AuditEvent{
        event_id: Ecto.UUID.generate(),
        session_id: "s-#{System.unique_integer([:positive])}",
        status: status,
        occurred_at: DateTime.utc_now()
      })
  end

  test "a clean chain checks ok and writes a checkpoint" do
    for _ <- 1..3, do: log_event()

    assert :ok = AuditIntegrity.check_now(@name)

    cp = AuditCheckpoint.latest()
    assert cp.count == 3
    assert cp.hash == EventLog.last_hash()
    assert AuditCheckpoint.valid?(Map.new(cp, fn {k, v} -> {to_string(k), v} end))
  end

  test "detects a tampered row" do
    log_event()
    log_event()
    assert :ok = AuditIntegrity.check_now(@name)

    first_id = Repo.one(from e in PolicyEvent, order_by: [asc: e.id], limit: 1, select: e.id)
    Repo.update_all(from(e in PolicyEvent, where: e.id == ^first_id), set: [reason: "tampered"])

    assert {:broken, detail} = AuditIntegrity.check_now(@name)
    assert detail =~ "row"
  end

  test "detects a truncated log via the checkpoint" do
    for _ <- 1..4, do: log_event()
    assert :ok = AuditIntegrity.check_now(@name)

    # delete the last two rows — the remaining chain still verifies internally
    ids =
      Repo.all(from e in PolicyEvent, order_by: [desc: e.id], limit: 2, select: e.id)

    Repo.delete_all(from e in PolicyEvent, where: e.id in ^ids)
    assert :ok = EventLog.verify_chain()

    assert {:broken, detail} = AuditIntegrity.check_now(@name)
    assert detail =~ "truncated" or detail =~ "no longer present"
  end

  test "status reports the last check" do
    log_event()
    AuditIntegrity.check_now(@name)

    status = AuditIntegrity.status(@name)
    assert %{last_check: %{result: :ok}} = status
    assert status.checkpoint.count == 1
  end

  test "a forged checkpoint (wrong signature) is ignored" do
    log_event()
    path = Application.get_env(:phoenix_elxir_beam, AuditCheckpoint)[:path]

    File.write!(
      path,
      Jason.encode!(%{
        "event_id" => "fake",
        "hash" => "sha256:deadbeef",
        "count" => 999,
        "verified_at" => "2020-01-01T00:00:00Z",
        "sig" => "notarealsignature"
      }) <> "\n"
    )

    assert AuditCheckpoint.latest() == nil
    # the check ignores the forged line and writes a fresh valid one
    assert :ok = AuditIntegrity.check_now(@name)
    assert AuditCheckpoint.latest().count == 1
  end
end
