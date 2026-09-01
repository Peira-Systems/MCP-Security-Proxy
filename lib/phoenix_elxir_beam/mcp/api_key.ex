defmodule PhoenixElxirBeam.MCP.ApiKey do
  @moduledoc """
  Signed API keys for authenticating the downstream MCP client
  (`docs/productionization-plan.md` M1.4). A key is:

    * a public `key_id` (`mcpk_<hex>`) and a high-entropy secret, presented
      together as `Authorization: Bearer mcpk_<hex>.<secret>`;
    * bound to a `principal` (the caller) and an `agent_id` — the agent
      identity is a property of the authenticated key, not a client-asserted
      header;
    * scoped to the registered servers it may reach (`all_servers`, or an
      explicit `granted_server_ids` list).

  Only `sha256(secret)` is stored. The secret is a 256-bit random value, so a
  plain SHA-256 (constant-time compared) is sufficient — there is nothing to
  brute-force. The full token is shown exactly once, at issuance.

  `authenticate/1` reads through `ApiKeyCache` (short-TTL, invalidated
  explicitly on `revoke/1` / `set_grants/2`) so a proxied request doesn't pay
  a `SELECT` every time — see `docs/latency-budget.md`.
  """

  use Ecto.Schema

  import Ecto.Changeset
  import Ecto.Query

  alias PhoenixElxirBeam.MCP.ApiKeyCache
  alias PhoenixElxirBeam.Repo
  alias __MODULE__

  @key_id_prefix "mcpk_"

  schema "api_keys" do
    field :key_id, :string
    field :token_hash, :binary
    field :principal, :string
    field :agent_id, :string
    field :description, :string
    field :all_servers, :boolean, default: false
    field :granted_server_ids, {:array, :string}, default: []
    field :disabled_at, :utc_datetime_usec
    field :last_used_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec)
  end

  @doc """
  Issues a new key. `attrs` needs `:principal` and `:agent_id`; optionally
  `:description`, `:all_servers` (default false), `:granted_server_ids`.

  Returns `{:ok, key, token}` — `token` is the full bearer token and is the
  only time it is available.
  """
  @spec issue(map()) :: {:ok, ApiKey.t(), String.t()} | {:error, Ecto.Changeset.t()}
  def issue(attrs) do
    key_id = @key_id_prefix <> (:crypto.strong_rand_bytes(9) |> Base.encode16(case: :lower))
    secret = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

    params =
      attrs
      |> Map.new()
      |> Map.merge(%{key_id: key_id, token_hash: hash(secret)})

    case %ApiKey{} |> changeset(params) |> Repo.insert() do
      {:ok, key} -> {:ok, key, key_id <> "." <> secret}
      {:error, cs} -> {:error, cs}
    end
  end

  @doc """
  Authenticates a bearer token. Returns `{:ok, key}` for a live key whose
  secret matches, else `{:error, reason}`.
  """
  @spec authenticate(String.t() | nil) ::
          {:ok, ApiKey.t()} | {:error, :malformed | :unknown_key | :disabled | :bad_secret}
  def authenticate(token) when is_binary(token) do
    case String.split(token, ".", parts: 2) do
      [key_id, secret] when byte_size(secret) > 0 ->
        verify(key_id, secret)

      _ ->
        {:error, :malformed}
    end
  end

  def authenticate(_token), do: {:error, :malformed}

  defp verify(key_id, secret) do
    case ApiKeyCache.get(key_id) do
      {:ok, key} -> check_secret(key, secret)
      :miss -> verify_from_db(key_id, secret)
    end
  end

  defp verify_from_db(key_id, secret) do
    case Repo.get_by(ApiKey, key_id: key_id) do
      nil ->
        {:error, :unknown_key}

      %ApiKey{disabled_at: disabled} when not is_nil(disabled) ->
        {:error, :disabled}

      %ApiKey{} = key ->
        # last_used_at is touched here, on the DB round-trip, rather than on
        # every cache hit — its granularity becomes ~ttl_ms under load, which
        # is plenty for the dashboard display and avoids reintroducing a
        # per-request write on the path this cache exists to shorten.
        touch_last_used(key)
        ApiKeyCache.put(key_id, key)
        check_secret(key, secret)
    end
  end

  defp check_secret(key, secret) do
    if Plug.Crypto.secure_compare(hash(secret), key.token_hash) do
      {:ok, key}
    else
      {:error, :bad_secret}
    end
  end

  @doc "Whether `key` is allowed to reach the registered server `server_id`."
  @spec authorize?(ApiKey.t(), String.t()) :: boolean()
  def authorize?(%ApiKey{all_servers: true}, _server_id), do: true
  def authorize?(%ApiKey{granted_server_ids: ids}, server_id), do: server_id in ids
  def authorize?(_key, _server_id), do: false

  @doc "Every key, newest first (dashboard). Never includes the secret."
  @spec list() :: [ApiKey.t()]
  def list, do: Repo.all(from k in ApiKey, order_by: [desc: k.inserted_at])

  @dashboard_key_id "mcpk_dashboard"
  @dashboard_token_term {__MODULE__, :dashboard_token}

  @doc """
  Mints (or rotates) the internal all-servers key the dashboard's manual
  "Call tool" flow authenticates with. Called once at boot: a fresh secret
  each start, hashed into a fixed `mcpk_dashboard` row, with the raw token
  held in `:persistent_term` for `dashboard_token/0`.
  """
  def ensure_dashboard_key do
    secret = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

    attrs = %{
      key_id: @dashboard_key_id,
      token_hash: hash(secret),
      principal: "dashboard",
      agent_id: "agent://dashboard",
      description: "internal — dashboard manual tool calls",
      all_servers: true
    }

    case Repo.get_by(ApiKey, key_id: @dashboard_key_id) do
      nil ->
        %ApiKey{} |> changeset(attrs) |> Repo.insert!()

      key ->
        key
        |> change(token_hash: attrs.token_hash, all_servers: true, disabled_at: nil)
        |> Repo.update!()
    end

    ApiKeyCache.invalidate(@dashboard_key_id)
    :persistent_term.put(@dashboard_token_term, @dashboard_key_id <> "." <> secret)
    :ok
  end

  @doc "The current dashboard bearer token, or nil if `ensure_dashboard_key/0` has not run."
  def dashboard_token, do: :persistent_term.get(@dashboard_token_term, nil)

  @doc "Disables a key by `key_id`. Idempotent."
  @spec revoke(String.t()) :: :ok | {:error, :not_found}
  def revoke(key_id) do
    case Repo.get_by(ApiKey, key_id: key_id) do
      nil ->
        {:error, :not_found}

      key ->
        result = key |> change(disabled_at: DateTime.utc_now()) |> Repo.update() |> ok()
        ApiKeyCache.invalidate(key_id)
        result
    end
  end

  @doc "Replaces a key's server grants."
  @spec set_grants(String.t(), all_servers: boolean(), server_ids: [String.t()]) ::
          {:ok, ApiKey.t()} | {:error, :not_found}
  def set_grants(key_id, opts) do
    case Repo.get_by(ApiKey, key_id: key_id) do
      nil ->
        {:error, :not_found}

      key ->
        result =
          key
          |> change(%{
            all_servers: Keyword.get(opts, :all_servers, key.all_servers),
            granted_server_ids: Keyword.get(opts, :server_ids, key.granted_server_ids)
          })
          |> Repo.update()

        ApiKeyCache.invalidate(key_id)
        result
    end
  end

  @fields ~w(key_id token_hash principal agent_id description all_servers granted_server_ids)a
  @required ~w(key_id token_hash principal agent_id)a

  defp changeset(key, params) do
    key
    |> cast(params, @fields)
    |> validate_required(@required)
    |> unique_constraint(:key_id)
  end

  defp hash(secret), do: :crypto.hash(:sha256, secret)

  defp touch_last_used(%ApiKey{} = key) do
    from(k in ApiKey, where: k.id == ^key.id)
    |> Repo.update_all(set: [last_used_at: DateTime.utc_now()])
  rescue
    _ -> :ok
  end

  defp ok({:ok, _}), do: :ok
  defp ok(other), do: other

  @type t :: %__MODULE__{}
end
