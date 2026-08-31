defmodule PhoenixElxirBeamWeb.UserAuth do
  @moduledoc """
  Session authentication + role authorization for the operator console (M3.4).

  Replaces the M1.4 HTTP Basic auth on the dashboard / `/dev`. A random session
  token is stored in `user_tokens` and referenced from the signed session
  cookie; roles are `:viewer < :operator < :admin`
  (`PhoenixElxirBeam.Accounts`).
  """
  use PhoenixElxirBeamWeb, :verified_routes

  import Plug.Conn
  import Phoenix.Controller

  alias PhoenixElxirBeam.Accounts

  @session_key "user_token"

  ## Plugs

  def log_in_user(conn, user, _params \\ %{}) do
    token = Accounts.create_session_token(user)
    return_to = get_session(conn, :user_return_to)

    conn
    |> renew_session()
    |> put_session(@session_key, token)
    |> put_session(:live_socket_id, "users_sessions:#{Base.url_encode64(token)}")
    |> redirect(to: return_to || ~p"/")
  end

  def log_out_user(conn) do
    if token = get_session(conn, @session_key), do: Accounts.delete_session_token(token)

    if live_socket_id = get_session(conn, :live_socket_id) do
      PhoenixElxirBeamWeb.Endpoint.broadcast(live_socket_id, "disconnect", %{})
    end

    conn
    |> renew_session()
    |> redirect(to: ~p"/login")
  end

  def fetch_current_user(conn, _opts) do
    token = get_session(conn, @session_key)
    user = token && Accounts.get_user_by_session_token(token)
    assign(conn, :current_user, user)
  end

  def require_authenticated_user(conn, _opts) do
    if conn.assigns[:current_user] do
      conn
    else
      conn
      |> put_flash(:error, "You must log in to access that page.")
      |> maybe_store_return_to()
      |> redirect(to: ~p"/login")
      |> halt()
    end
  end

  def redirect_if_user_is_authenticated(conn, _opts) do
    if conn.assigns[:current_user] do
      conn |> redirect(to: ~p"/") |> halt()
    else
      conn
    end
  end

  @doc "Plug builder: `plug PhoenixElxirBeamWeb.UserAuth, :require_operator`."
  def require_operator(conn, _opts), do: require_role(conn, :operator)
  def require_admin(conn, _opts), do: require_role(conn, :admin)

  defp require_role(conn, role) do
    if conn.assigns[:current_user] && Accounts.role_at_least?(conn.assigns.current_user, role) do
      conn
    else
      conn
      |> put_flash(:error, "That action requires the #{role} role.")
      |> redirect(to: ~p"/")
      |> halt()
    end
  end

  ## LiveView on_mount

  def on_mount(:mount_current_user, _params, session, socket) do
    {:cont, mount_current_user(socket, session)}
  end

  def on_mount(:ensure_authenticated, _params, session, socket) do
    socket = mount_current_user(socket, session)

    if socket.assigns.current_user do
      {:cont, socket}
    else
      {:halt,
       socket
       |> Phoenix.LiveView.put_flash(:error, "You must log in to access that page.")
       |> Phoenix.LiveView.redirect(to: ~p"/login")}
    end
  end

  defp mount_current_user(socket, session) do
    Phoenix.Component.assign_new(socket, :current_user, fn ->
      if token = session[@session_key], do: Accounts.get_user_by_session_token(token)
    end)
  end

  ## helpers

  defp maybe_store_return_to(%{method: "GET"} = conn) do
    put_session(conn, :user_return_to, current_path(conn))
  end

  defp maybe_store_return_to(conn), do: conn

  defp renew_session(conn) do
    delete_csrf_token()

    conn
    |> configure_session(renew: true)
    |> clear_session()
  end
end
