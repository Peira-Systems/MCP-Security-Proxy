defmodule PhoenixElxirBeamWeb.MCPDashboardStdioRegistrationTest do
  use PhoenixElxirBeamWeb.ConnCase, async: false

  import Phoenix.LiveViewTest
  import PhoenixElxirBeam.AccountsFixtures

  alias PhoenixElxirBeam.MCP.ServerRegistry

  setup %{conn: conn} do
    on_exit(fn ->
      for server <- ServerRegistry.list_servers(), do: ServerRegistry.remove_server(server.id)
    end)

    conn = conn |> log_in_user(user_fixture(role: :admin))
    %{conn: conn}
  end

  test "toggling to stdio swaps the registration form fields", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/?page=config")

    refute has_element?(view, "#register-stdio-server-form")
    assert has_element?(view, "#register-server-form")

    view |> element("#register-transport-stdio") |> render_click()

    assert has_element?(view, "#register-stdio-server-form")
    refute has_element?(view, "#register-server-form")
  end

  test "registering a stdio server via the form discovers its tools", %{conn: conn} do
    node = System.find_executable("node") || raise "node not found on PATH"
    fixture = Path.expand("../../support/fixtures/echo_mcp_server.js", __DIR__)

    {:ok, view, _html} = live(conn, ~p"/?page=config")

    view |> element("#register-transport-stdio") |> render_click()

    view
    |> form("#register-stdio-server-form", %{
      "name" => "echo-stdio",
      "command" => node,
      "args" => fixture
    })
    |> render_submit()

    # Registration runs in a spawned Task that messages the LiveView's own
    # mailbox once the real subprocess handshake completes; poll for that
    # instead of sleeping a fixed amount (no process exit to Process.monitor
    # here — it's a live server process, not one that's expected to die).
    eventually(fn -> render(view) =~ "Registered echo-stdio" end)

    assert render(view) =~ "Registered echo-stdio"
    assert has_element?(view, "button", "echo-stdio")

    assert [registered] = ServerRegistry.list_servers()
    assert registered.transport == :stdio
    assert Enum.map(registered.tools, & &1.name) == ["echo"]
  end

  test "rejects stdio registration with a blank command", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/?page=config")

    view |> element("#register-transport-stdio") |> render_click()

    html =
      view
      |> form("#register-stdio-server-form", %{
        "name" => "no-command",
        "command" => "",
        "args" => ""
      })
      |> render_submit()

    assert html =~ "Name and command are both required"
    assert ServerRegistry.list_servers() == []
  end

  defp eventually(condition, deadline \\ System.monotonic_time(:millisecond) + 5_000) do
    case condition.() do
      result when result != false and result != nil ->
        result

      _ ->
        if System.monotonic_time(:millisecond) >= deadline do
          flunk("condition did not become true within the timeout")
        else
          Process.sleep(25)
          eventually(condition, deadline)
        end
    end
  end
end
