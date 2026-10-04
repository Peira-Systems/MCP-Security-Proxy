defmodule PhoenixElxirBeam.MCP.AgentCredential do
  @moduledoc """
  A verifiable identity an agent presents independently of the API key that
  authenticates its connection (Phase 1 identity work). Lets a shared API
  key be used by multiple distinct agents without collapsing them into one
  `agent_id` for policy matching -- see
  `docs/superpowers/specs/2026-10-02-per-agent-identity-design.md`.

  Shaped the same way `PhoenixElxirBeam.MCP.ApiKey` already is: only
  `sha256(secret)` is stored, the full token is returned once at issuance.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias PhoenixElxirBeam.Repo
  alias __MODULE__

  schema "agent_credentials" do
    field :agent_id, :string
    field :token_hash, :binary
    field :description, :string
    field :disabled_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec)
  end

  @doc "Issues a credential. `attrs` needs `:agent_id`; optionally `:description`."
  @spec issue(map()) :: {:ok, AgentCredential.t(), String.t()} | {:error, Ecto.Changeset.t()}
  def issue(attrs) do
    secret = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    params = attrs |> Map.new() |> Map.put(:token_hash, hash(secret))

    case %AgentCredential{} |> changeset(params) |> Repo.insert() do
      {:ok, cred} -> {:ok, cred, cred_token(params, secret)}
      {:error, cs} -> {:error, cs}
    end
  end

  defp cred_token(%{agent_id: agent_id}, secret), do: agent_id <> "." <> secret

  @doc """
  Authenticates a presented `<agent_id>.<secret>` token.

  Splits on the LAST `.`, not the first: `agent_id` may itself contain dots
  (e.g. `"agent://bot.acme.com"`), while the secret -- `Base.url_encode64/2`
  output -- never does (base64url's alphabet is `A-Za-z0-9-_`). Splitting on
  the first dot would silently truncate such an `agent_id`.
  """
  @spec authenticate(String.t() | nil) ::
          {:ok, AgentCredential.t()}
          | {:error, :malformed | :unknown_agent | :disabled | :bad_secret}
  def authenticate(token) when is_binary(token) do
    case String.split(token, ".") do
      [_single] -> {:error, :malformed}
      parts -> split_last(parts)
    end
  end

  def authenticate(_token), do: {:error, :malformed}

  # `parts` is the full token split on every `.`; the secret is the last
  # element (never empty, since base64url never produces one), and the
  # `agent_id` is everything before it rejoined with `.`.
  defp split_last(parts) do
    {agent_parts, [secret]} = Enum.split(parts, -1)
    agent_id = Enum.join(agent_parts, ".")

    if agent_id != "" and byte_size(secret) > 0 do
      verify(agent_id, secret)
    else
      {:error, :malformed}
    end
  end

  defp verify(agent_id, secret) do
    case Repo.get_by(AgentCredential, agent_id: agent_id) do
      nil -> {:error, :unknown_agent}
      %AgentCredential{disabled_at: disabled} when not is_nil(disabled) -> {:error, :disabled}
      %AgentCredential{} = cred -> check_secret(cred, secret)
    end
  end

  defp check_secret(cred, secret) do
    if Plug.Crypto.secure_compare(hash(secret), cred.token_hash) do
      {:ok, cred}
    else
      {:error, :bad_secret}
    end
  end

  @doc "Disables a credential by `agent_id`. Idempotent."
  @spec revoke(String.t()) :: :ok | {:error, :not_found}
  def revoke(agent_id) do
    case Repo.get_by(AgentCredential, agent_id: agent_id) do
      nil -> {:error, :not_found}
      cred -> cred |> change(disabled_at: DateTime.utc_now()) |> Repo.update() |> ok()
    end
  end

  @fields ~w(agent_id token_hash description)a
  @required ~w(agent_id token_hash)a

  defp changeset(cred, params) do
    cred
    |> cast(params, @fields)
    |> validate_required(@required)
    |> unique_constraint(:agent_id)
  end

  defp hash(secret), do: :crypto.hash(:sha256, secret)
  defp ok({:ok, _}), do: :ok
  defp ok(other), do: other

  @type t :: %__MODULE__{}
end
