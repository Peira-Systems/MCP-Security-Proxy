defmodule PhoenixElxirBeamWeb.MCPDashboardUntrustedSourceTest do
  @moduledoc "The dashboard's per-tool :untrusted_source toggle (P1 provenance taint)."
  use PhoenixElxirBeamWeb.ConnCase, async: false

  import Phoenix.LiveViewTest
  import PhoenixElxirBeam.AccountsFixtures

  alias PhoenixElxirBeam.MCP.ServerRegistry

  @catalog_fixture Path.expand("../../support/fixtures/catalog_mcp_server.js", __DIR__)

  setup %{conn: conn} do
    node = System.find_executable("node") || raise "node not found on PATH"

    {:ok, server} =
      ServerRegistry.register_stdio_server(
        "catalog-#{System.unique_integer([:positive])}",
        node,
        [@catalog_fixture]
      )

    on_exit(fn -> ServerRegistry.remove_server(server.id) end)

    conn = conn |> log_in_user(user_fixture(role: :admin))
    %{conn: conn, sid: server.id}
  end

  test "an operator can toggle a tool's untrusted-source tag from the dashboard", %{
    conn: conn,
    sid: sid
  } do
    {:ok, view, _html} = live(conn, ~p"/?page=config&config_tab=servers")

    view |> element("#toggle-server-drawer-#{sid}") |> render_click()

    toggle = view |> element("#toggle-tag-untrusted_source-#{sid}-list_files")
    refute render(toggle) =~ "bg-warning/20"

    render_click(toggle)

    assert [%{name: "list_files", tags: [:untrusted_source]}] =
             ServerRegistry.get_server(sid).tools |> Enum.filter(&(&1.name == "list_files"))

    toggle = view |> element("#toggle-tag-untrusted_source-#{sid}-list_files")
    assert render(toggle) =~ "bg-warning/20"
  end

  test "toggling untrusted-source off removes the tag", %{conn: conn, sid: sid} do
    {:ok, _} = ServerRegistry.set_tool_tags(sid, "list_files", [:untrusted_source])

    {:ok, view, _html} = live(conn, ~p"/?page=config&config_tab=servers")
    view |> element("#toggle-server-drawer-#{sid}") |> render_click()

    view |> element("#toggle-tag-untrusted_source-#{sid}-list_files") |> render_click()

    assert [%{name: "list_files", tags: []}] =
             ServerRegistry.get_server(sid).tools |> Enum.filter(&(&1.name == "list_files"))
  end
end
