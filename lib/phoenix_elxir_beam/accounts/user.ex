defmodule PhoenixElxirBeam.Accounts.User do
  @moduledoc """
  An operator account for the dashboard / policy-management console (M3.4).

  Roles, least to most privileged:

    * `viewer` — read-only: the dashboard, feeds, history, plugin list.
    * `operator` — everything a viewer can do, plus runtime policy changes
      (enable/disable/reorder plugins, tag assignment, clear a quarantine,
      resolve holds). Every change is audited (`PhoenixElxirBeam.MCP.PolicyChange`).
    * `admin` — everything, plus user management, API-key issuance/revocation,
      and the `/dev` tools (LiveDashboard).
  """
  use Ecto.Schema
  import Ecto.Changeset

  @roles ~w(viewer operator admin)a
  @auth_sources ~w(local sso)a

  schema "users" do
    field :email, :string
    field :role, Ecto.Enum, values: @roles, default: :viewer
    field :auth_source, Ecto.Enum, values: @auth_sources, default: :local
    field :hashed_password, :string, redact: true
    field :password, :string, virtual: true, redact: true
    field :disabled_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec)
  end

  @doc "The full set of roles, least privileged first."
  def roles, do: @roles

  @doc """
  Changeset for creating a user (admin-issued) or a first-run seed. Requires a
  valid email, a role, and a password of at least 12 characters.
  """
  def registration_changeset(user, attrs) do
    user
    |> cast(attrs, [:email, :role, :password])
    |> validate_email()
    |> validate_required([:role])
    |> validate_inclusion(:role, @roles)
    |> validate_password()
  end

  @doc """
  Changeset for admin-provisioning an SSO-authenticated account. No password
  is set or settable via this changeset -- `auth_source: :sso` accounts
  never have a `hashed_password`, so local password login can never
  authenticate them (see `Accounts.get_user_by_email_and_password/2`).
  """
  def sso_registration_changeset(user, attrs) do
    user
    |> cast(attrs, [:email, :role])
    |> put_change(:auth_source, :sso)
    |> validate_email()
    |> validate_required([:role])
    |> validate_inclusion(:role, @roles)
  end

  @doc "Changeset for an admin changing another user's role."
  def role_changeset(user, attrs) do
    user
    |> cast(attrs, [:role])
    |> validate_required([:role])
    |> validate_inclusion(:role, @roles)
  end

  @doc "Changeset for a password change (self-service or admin reset)."
  def password_changeset(user, attrs) do
    user
    |> cast(attrs, [:password])
    |> validate_password()
  end

  defp validate_email(changeset) do
    changeset
    |> update_change(:email, fn email ->
      email |> to_string() |> String.downcase() |> String.trim()
    end)
    |> validate_required([:email])
    |> validate_format(:email, ~r/^[^@\s]+@[^@\s]+$/, message: "must be a valid email")
    |> validate_length(:email, max: 160)
    |> unsafe_validate_unique(:email, PhoenixElxirBeam.Repo)
    |> unique_constraint(:email, name: :users_email_index)
  end

  defp validate_password(changeset) do
    changeset
    |> validate_required([:password])
    |> validate_length(:password, min: 12, max: 200)
    |> put_hashed_password()
  end

  defp put_hashed_password(changeset) do
    case get_change(changeset, :password) do
      nil ->
        changeset

      password ->
        changeset
        |> put_change(:hashed_password, Pbkdf2.hash_pwd_salt(password))
        |> delete_change(:password)
    end
  end

  @doc """
  Verifies `password` against `user`, in constant time. Returns `false` (still
  spending a hash) when `user` is `nil` so callers don't leak account existence.
  """
  def valid_password?(%__MODULE__{hashed_password: hashed}, password)
      when is_binary(hashed) and byte_size(password) > 0 do
    Pbkdf2.verify_pass(password, hashed)
  end

  def valid_password?(_, _) do
    Pbkdf2.no_user_verify()
    false
  end
end
