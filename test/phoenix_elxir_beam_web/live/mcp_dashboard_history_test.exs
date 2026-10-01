defmodule PhoenixElxirBeamWeb.MCPDashboardHistoryTest do
  @moduledoc "The executive console's history table: call-chain disclosure on a blocked event."
  use PhoenixElxirBeamWeb.ConnCase, async: false

  import Phoenix.LiveViewTest
  import PhoenixElxirBeam.AccountsFixtures

  alias PhoenixElxirBeam.MCP.PolicyEngine

  setup %{conn: conn} do
    conn = conn |> log_in_user(user_fixture(role: :admin))
    %{conn: conn}
  end

  test "a blocked event's history row shows a call-chain disclosure with the prior calls", %{
    conn: conn
  } do
    session_id = "s-#{System.unique_integer([:positive])}"
    :ok = PolicyEngine.start_session(session_id, :attack, nil)

    {:allow, _} =
      PolicyEngine.record_call(session_id, "files", "list_files", [])

    {:allow, _} =
      PolicyEngine.record_call(session_id, "files", "read_secrets", [:sensitive_read])

    {:block, _event} =
      PolicyEngine.record_call(session_id, "net", "post_webhook", [:network_egress])

    {:ok, view, _html} = live(conn, ~p"/")
    view |> element("button", "history") |> render_click()

    html = render(view)
    assert html =~ "chain (2)"
    assert html =~ "read_secrets"
    assert html =~ "list_files"
  end

  test "an allowed event's history row has no call-chain disclosure", %{conn: conn} do
    session_id = "s-#{System.unique_integer([:positive])}"
    :ok = PolicyEngine.start_session(session_id, :benign, nil)

    {:allow, _} =
      PolicyEngine.record_call(session_id, "files", "list_files", [])

    {:ok, view, _html} = live(conn, ~p"/")
    view |> element("button", "history") |> render_click()

    refute render(view) =~ "chain ("
  end
end
