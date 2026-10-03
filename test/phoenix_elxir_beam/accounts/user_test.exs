defmodule PhoenixElxirBeam.Accounts.UserTest do
  use PhoenixElxirBeam.DataCase, async: true

  alias PhoenixElxirBeam.Accounts.User
  import Ecto.Changeset

  describe "sso_registration_changeset/2" do
    test "is valid with email and role, no password" do
      changeset =
        User.sso_registration_changeset(%User{}, %{email: "sso.user@example.com", role: :viewer})

      assert changeset.valid?
      assert get_change(changeset, :auth_source) == :sso
      refute get_change(changeset, :hashed_password)
    end

    test "requires a valid email" do
      changeset =
        User.sso_registration_changeset(%User{}, %{email: "not-an-email", role: :viewer})

      refute changeset.valid?
    end
  end
end
