defmodule PhoenixElxirBeamWeb.MCPDashboardDryRunTest do
  @moduledoc "D4: the dashboard's global dry-run toggle and per-plugin mode control."
  use PhoenixElxirBeamWeb.ConnCase, async: false

  import Phoenix.LiveViewTest
  import PhoenixElxirBeam.AccountsFixtures

  alias PhoenixElxirBeam.MCP.PolicyEngine
  alias PhoenixElxirBeam.MCP.Plugin.Registry

  setup %{conn: conn} do
    on_exit(fn -> Registry.set_proxy_mode(:enforcing) end)
    on_exit(fn -> Registry.set_mode("chain-exfil", nil) end)

    conn = conn |> log_in_user(user_fixture(role: :admin))
    %{conn: conn}
  end

  test "the plugins panel shows the current global mode as enforcing by default", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/?page=config&config_tab=plugins")

    assert has_element?(view, "#dry-run-toggle")
    html = render(view)
    assert html =~ "Enforcing"
  end

  test "an operator can flip the global mode to dry-run from the dashboard", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/?page=config&config_tab=plugins")

    view |> element("#dry-run-toggle") |> render_click()

    assert Registry.proxy_mode() == :dry_run
    assert render(view) =~ "Dry-run"
  end

  test "flipping the global mode is recorded as a policy change", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/?page=config&config_tab=plugins")

    view |> element("#dry-run-toggle") |> render_click()

    assert render(view) =~ "dry-run"
  end

  test "an operator can pin a single plugin's mode independent of the global switch", %{
    conn: conn
  } do
    {:ok, view, _html} = live(conn, ~p"/?page=config&config_tab=plugins")

    view
    |> element("#plugin-mode-chain-exfil")
    |> render_change(%{"name" => "chain-exfil", "mode" => "dry_run"})

    assert [%{name: "chain-exfil", mode: :dry_run}] =
             Registry.list() |> Enum.filter(&(&1.name == "chain-exfil"))
  end

  test "a plugin's mode control can be reset to inherit", %{conn: conn} do
    :ok = Registry.set_mode("chain-exfil", :dry_run)
    {:ok, view, _html} = live(conn, ~p"/?page=config&config_tab=plugins")

    view
    |> element("#plugin-mode-chain-exfil")
    |> render_change(%{"name" => "chain-exfil", "mode" => "inherit"})

    assert [%{name: "chain-exfil", mode: nil}] =
             Registry.list() |> Enum.filter(&(&1.name == "chain-exfil"))
  end

  test "a shadow-blocked call shows up in the live feed with its own status label", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/?page=config&config_tab=plugins")

    view |> element("#dry-run-toggle") |> render_click()
    view |> element("button", "Executive view") |> render_click()

    session_id = "s-#{System.unique_integer([:positive])}"
    :ok = PolicyEngine.start_session(session_id, :attack, nil)

    {:allow, _} =
      PolicyEngine.record_call(session_id, "files", "read_secrets", [:sensitive_read])

    {:allow, event} =
      PolicyEngine.record_call(session_id, "net", "post_webhook", [:network_egress])

    assert event.status == :shadow_blocked

    html = render(view)
    assert html =~ "would block"
    assert html =~ "text-warning"
  end
end
