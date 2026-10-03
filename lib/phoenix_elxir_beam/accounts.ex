defmodule PhoenixElxirBeam.Accounts do
  @moduledoc """
  Operator accounts for the dashboard / policy-management console (M3.4).

  Admin-issued only — there is no public registration. An admin is seeded
  from `ADMIN_EMAIL` / `ADMIN_PASSWORD` on every boot if that email doesn't
  already have an account (see `Accounts.seed_admin/0`, called at boot).
  Session auth is handled by `PhoenixElxirBeamWeb.UserAuth`.
  """
  import Ecto.Query

  alias PhoenixElxirBeam.Accounts.{User, UserToken}
  alias PhoenixElxirBeam.Repo

  require Logger

  ## Lookup

  def get_user!(id), do: Repo.get!(User, id)
  def get_user(id), do: Repo.get(User, id)

  def get_user_by_email(email) when is_binary(email) do
    Repo.one(
      from u in User, where: fragment("lower(?)", u.email) == ^String.downcase(String.trim(email))
    )
  end

  def list_users, do: Repo.all(from u in User, order_by: [asc: u.email])

  def count_users, do: Repo.aggregate(User, :count)

  @doc "Returns the user if the email/password pair is valid and the account is enabled."
  def get_user_by_email_and_password(email, password)
      when is_binary(email) and is_binary(password) do
    user = get_user_by_email(email)

    cond do
      user && user.auth_source != :local -> nil
      user && not is_nil(user.disabled_at) -> nil
      User.valid_password?(user, password) -> user
      true -> nil
    end
  end

  ## Mutation

  @doc "Creates a user. `attrs` needs `:email`, `:password`, `:role`."
  def create_user(attrs) do
    %User{}
    |> User.registration_changeset(attrs)
    |> Repo.insert()
  end

  @doc "Admin-provisions an SSO-authenticated account. `attrs` needs `:email` and `:role`."
  def create_sso_user(attrs) do
    %User{}
    |> User.sso_registration_changeset(attrs)
    |> Repo.insert()
  end

  def change_user_role(%User{} = user, role) do
    user |> User.role_changeset(%{role: role}) |> Repo.update()
  end

  def set_user_password(%User{} = user, password) do
    user |> User.password_changeset(%{password: password}) |> Repo.update()
  end

  def set_user_disabled(%User{} = user, disabled?) do
    at = if disabled?, do: DateTime.utc_now(), else: nil

    user
    |> Ecto.Changeset.change(disabled_at: at)
    |> Repo.update()
    |> tap(fn
      {:ok, u} -> if disabled?, do: delete_all_sessions(u)
      _ -> :ok
    end)
  end

  def delete_user(%User{} = user), do: Repo.delete(user)

  ## Session tokens

  def create_session_token(user) do
    {token, struct} = UserToken.build_session_token(user)
    Repo.insert!(struct)
    token
  end

  def get_user_by_session_token(token) when is_binary(token) do
    Repo.one(UserToken.verify_session_token_query(token))
  end

  def get_user_by_session_token(_), do: nil

  def delete_session_token(token) do
    Repo.delete_all(UserToken.by_token_and_context_query(token, "session"))
    :ok
  end

  def delete_all_sessions(%User{} = user) do
    Repo.delete_all(UserToken.by_user_and_contexts_query(user, :all))
    :ok
  end

  ## Boot seed

  @doc """
  Seeds an admin from `ADMIN_EMAIL` / `ADMIN_PASSWORD` on every boot, unless a
  user with that email already exists. Does not touch the role or password of
  an existing account — set both env vars once and they keep re-asserting the
  account exists without overwriting anything an operator has since changed.
  Fail-soft.
  """
  def seed_admin do
    with email when is_binary(email) <- System.get_env("ADMIN_EMAIL"),
         password when is_binary(password) <- System.get_env("ADMIN_PASSWORD"),
         nil <- get_user_by_email(email) do
      case create_user(%{email: email, password: password, role: :admin}) do
        {:ok, user} ->
          Logger.info("Accounts: seeded admin #{user.email}")

        {:error, changeset} ->
          Logger.warning("Accounts: admin seed failed: #{inspect(changeset.errors)}")
      end
    else
      %User{} -> :ok
      _ -> :ok
    end
  rescue
    error -> Logger.warning("Accounts: admin seed skipped: #{Exception.message(error)}")
  end

  ## Authorization

  @doc "Whether `user` holds at least `required` (`:viewer < :operator < :admin`)."
  def role_at_least?(%User{role: role}, required), do: rank(role) >= rank(required)
  def role_at_least?(_, _), do: false

  defp rank(:viewer), do: 0
  defp rank(:operator), do: 1
  defp rank(:admin), do: 2
end
