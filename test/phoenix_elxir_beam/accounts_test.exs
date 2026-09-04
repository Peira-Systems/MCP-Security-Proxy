defmodule PhoenixElxirBeam.AccountsTest do
  use PhoenixElxirBeam.DataCase, async: true

  import PhoenixElxirBeam.AccountsFixtures

  alias PhoenixElxirBeam.Accounts
  alias PhoenixElxirBeam.Accounts.User

  describe "create_user/1" do
    test "hashes the password and lowercases the email" do
      {:ok, user} =
        Accounts.create_user(%{
          email: "Op@Example.Test",
          password: valid_password(),
          role: :operator
        })

      assert user.email == "op@example.test"
      assert is_binary(user.hashed_password)
      refute user.hashed_password == valid_password()
      assert user.role == :operator
    end

    test "rejects a short password and a duplicate email" do
      assert {:error, cs} =
               Accounts.create_user(%{email: unique_email(), password: "short", role: :viewer})

      assert %{password: [_]} = errors_on(cs)

      email = unique_email()
      {:ok, _} = Accounts.create_user(%{email: email, password: valid_password(), role: :viewer})

      assert {:error, cs} =
               Accounts.create_user(%{email: email, password: valid_password(), role: :viewer})

      assert %{email: [_]} = errors_on(cs)
    end
  end

  describe "get_user_by_email_and_password/2" do
    test "returns the user only on a correct pair for an enabled account" do
      user = user_fixture()
      assert %User{id: id} = Accounts.get_user_by_email_and_password(user.email, valid_password())
      assert id == user.id
      refute Accounts.get_user_by_email_and_password(user.email, "wrong")
      refute Accounts.get_user_by_email_and_password("nobody@example.test", valid_password())

      {:ok, user} = Accounts.set_user_disabled(user, true)
      refute Accounts.get_user_by_email_and_password(user.email, valid_password())
    end
  end

  describe "session tokens" do
    test "round-trip, and disabling a user kills their sessions" do
      user = user_fixture()
      token = Accounts.create_session_token(user)
      assert %User{id: id} = Accounts.get_user_by_session_token(token)
      assert id == user.id

      {:ok, _} = Accounts.set_user_disabled(user, true)
      refute Accounts.get_user_by_session_token(token)
    end
  end

  describe "role_at_least?/2" do
    test "orders viewer < operator < admin" do
      assert Accounts.role_at_least?(%User{role: :admin}, :operator)
      assert Accounts.role_at_least?(%User{role: :operator}, :operator)
      refute Accounts.role_at_least?(%User{role: :viewer}, :operator)
    end
  end

  describe "seed_admin/0" do
    test "creates an admin from env when that email has no account yet" do
      System.put_env("ADMIN_EMAIL", "boot-admin@example.test")
      System.put_env("ADMIN_PASSWORD", valid_password())

      on_exit(fn ->
        System.delete_env("ADMIN_EMAIL")
        System.delete_env("ADMIN_PASSWORD")
      end)

      assert :ok = Accounts.seed_admin()
      assert %User{role: :admin} = Accounts.get_user_by_email("boot-admin@example.test")

      # second run is a no-op (that email already has an account)
      count = Accounts.count_users()
      Accounts.seed_admin()
      assert Accounts.count_users() == count
    end

    test "still seeds the admin when other users already exist" do
      {:ok, _other} =
        Accounts.create_user(%{
          email: "someone-else@example.test",
          password: valid_password(),
          role: :viewer
        })

      System.put_env("ADMIN_EMAIL", "boot-admin@example.test")
      System.put_env("ADMIN_PASSWORD", valid_password())

      on_exit(fn ->
        System.delete_env("ADMIN_EMAIL")
        System.delete_env("ADMIN_PASSWORD")
      end)

      assert :ok = Accounts.seed_admin()
      assert %User{role: :admin} = Accounts.get_user_by_email("boot-admin@example.test")
    end

    test "does not touch an existing account with the seed email" do
      {:ok, existing} =
        Accounts.create_user(%{
          email: "boot-admin@example.test",
          password: valid_password(),
          role: :viewer
        })

      System.put_env("ADMIN_EMAIL", "boot-admin@example.test")
      System.put_env("ADMIN_PASSWORD", valid_password())

      on_exit(fn ->
        System.delete_env("ADMIN_EMAIL")
        System.delete_env("ADMIN_PASSWORD")
      end)

      assert :ok = Accounts.seed_admin()
      reloaded = Accounts.get_user!(existing.id)
      assert reloaded.role == :viewer
    end
  end
end
