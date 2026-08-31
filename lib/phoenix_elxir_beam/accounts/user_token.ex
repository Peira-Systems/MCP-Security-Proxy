defmodule PhoenixElxirBeam.Accounts.UserToken do
  @moduledoc """
  Opaque session tokens for operator accounts (M3.4). A random 32-byte token is
  stored server-side and put in the signed session cookie; deleting the row logs
  that session out. Sessions older than `@session_validity_days` are rejected.
  """
  use Ecto.Schema
  import Ecto.Query

  @rand_size 32
  @session_validity_days 30

  schema "user_tokens" do
    field :token, :binary
    field :context, :string
    field :inserted_at, :utc_datetime_usec

    belongs_to :user, PhoenixElxirBeam.Accounts.User
  end

  @doc "Builds a fresh session token for `user`; returns `{raw_token, struct}`."
  def build_session_token(user) do
    token = :crypto.strong_rand_bytes(@rand_size)

    {token,
     %__MODULE__{
       token: token,
       context: "session",
       user_id: user.id,
       inserted_at: DateTime.utc_now()
     }}
  end

  @doc "Query for the (live, non-expired) user owning `token` in the session context."
  def verify_session_token_query(token) do
    from t in by_token_and_context_query(token, "session"),
      join: u in assoc(t, :user),
      where: t.inserted_at > ago(@session_validity_days, "day"),
      where: is_nil(u.disabled_at),
      select: u
  end

  def by_token_and_context_query(token, context) do
    from __MODULE__, where: [token: ^token, context: ^context]
  end

  def by_user_and_contexts_query(user, :all) do
    from t in __MODULE__, where: t.user_id == ^user.id
  end
end
