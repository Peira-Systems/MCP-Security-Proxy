defmodule PhoenixElxirBeam.AccountsFixtures do
  @moduledoc "Test fixtures for `PhoenixElxirBeam.Accounts` (M3.4)."

  alias PhoenixElxirBeam.Accounts

  def valid_password, do: "correct horse battery staple"

  def unique_email, do: "operator#{System.unique_integer([:positive])}@example.test"

  def user_fixture(attrs \\ %{}) do
    {:ok, user} =
      attrs
      |> Enum.into(%{email: unique_email(), password: valid_password(), role: :operator})
      |> Accounts.create_user()

    user
  end

  @doc "Puts a live session token for `user` into `conn`'s session."
  def log_in_user(conn, user) do
    token = Accounts.create_session_token(user)

    conn
    |> Phoenix.ConnTest.init_test_session(%{})
    |> Plug.Conn.put_session(:user_token, token)
  end
end
