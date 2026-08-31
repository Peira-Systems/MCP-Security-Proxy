defmodule PhoenixElxirBeamWeb.SessionController do
  @moduledoc "Operator login / logout (M3.4). See `PhoenixElxirBeamWeb.UserAuth`."
  use PhoenixElxirBeamWeb, :controller

  alias PhoenixElxirBeam.Accounts
  alias PhoenixElxirBeamWeb.UserAuth

  def new(conn, _params) do
    render(conn, :new, error_message: nil)
  end

  def create(conn, %{"user" => %{"email" => email, "password" => password}}) do
    case Accounts.get_user_by_email_and_password(email, password) do
      nil ->
        # Do not reveal which half was wrong.
        render(conn, :new, error_message: "Invalid email or password")

      user ->
        conn
        |> put_flash(:info, "Welcome back.")
        |> UserAuth.log_in_user(user)
    end
  end

  def delete(conn, _params) do
    conn
    |> put_flash(:info, "Logged out.")
    |> UserAuth.log_out_user()
  end
end
