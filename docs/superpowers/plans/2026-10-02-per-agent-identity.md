# Per-Agent Identity Propagation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an agent assert and have verified its own `agent_id` per session, independent of which API key authenticated the connection — so a shared API key doesn't force every agent behind it into the same policy-matching identity, and `agent_id` becomes a verified claim instead of an operator-typed default.

**Architecture:** A new `AgentCredential` schema (mirroring `ApiKey`'s id/secret-hash pattern) and a new `AgentCredentialAuth` plug, placed after `ApiKeyAuth` in the `:mcp_api` pipeline. The plug reads an optional `X-Agent-Credential` header and, on a valid match, assigns `conn.assigns.verified_agent_id`. `ProxyController`'s `initialize` handler prefers that over `key.agent_id` when opening a session. No header present → identical behavior to today.

**Tech Stack:** Elixir, Ecto/Postgres, Plug, ExUnit + `PhoenixElxirBeam.DataCase`/`ConnCase`.

**Spec:** `docs/superpowers/specs/2026-10-02-per-agent-identity-design.md`

## Global Constraints

- `mix precommit` must pass before any commit.
- Per `AGENTS.md`: never use `String.to_atom/1` on user input — the `X-Agent-Credential` header value is parsed as strings only, same as `ApiKeyAuth.bearer_token/1` already does for its header.
- A request presenting an invalid `X-Agent-Credential` header must be rejected (401), never silently fall back to the key's default `agent_id` — this is the spec's explicit anti-probing decision and the single most important behavior this plan must get right.
- Zero behavior change for any request that doesn't send the new header — existing deployments and test suites must pass unmodified except where this plan explicitly adds new tests.

## Review Focus

- **A malformed `X-Agent-Credential` header (no dot separator, empty secret).** Must 401, matching `ApiKeyAuth`'s existing `:malformed` handling shape, not crash the plug.
- **A well-formed header with an unknown `agent_id` or wrong secret.** Must 401 — the core anti-probing requirement; a test must assert this explicitly, not just the "valid header works" happy path.
- **A disabled `AgentCredential`.** Must 401 even though the row exists, mirroring `ApiKey.verify_from_db/2`'s `disabled_at` check.
- **The header present but the request's `Authorization` bearer token is itself invalid.** `ApiKeyAuth` runs first in the pipeline and already halts before `AgentCredentialAuth` ever runs — confirm this ordering with a test rather than assuming pipeline order is preserved correctly, since a plug-ordering mistake here would mean an agent credential alone (no valid API key) could authenticate a request.
- **A `RuleEngine` rule scoped to the asserted `agent_id`, not the key's default.** The spec's stated goal is policy matching on the *verified* agent identity — a test must prove a rule written for `agent://specific-bot` actually matches when that identity came from `X-Agent-Credential`, not merely that `conn.assigns.verified_agent_id` got set correctly in isolation.

---

### Task 1: `AgentCredential` schema and issuance/verification

**Files:**
- Create: `priv/repo/migrations/<timestamp>_create_agent_credentials.exs`
- Create: `lib/phoenix_elxir_beam/mcp/agent_credential.ex`
- Test: `test/phoenix_elxir_beam/mcp/agent_credential_test.exs`

**Interfaces:**
- Produces: `AgentCredential.issue(attrs :: map()) :: {:ok, AgentCredential.t(), token :: String.t()} | {:error, Ecto.Changeset.t()}` — `attrs` needs `:agent_id`.
- Produces: `AgentCredential.authenticate(token :: String.t() | nil) :: {:ok, AgentCredential.t()} | {:error, :malformed | :unknown_agent | :disabled | :bad_secret}`.
- Produces: `AgentCredential.revoke(agent_id :: String.t()) :: :ok | {:error, :not_found}`.

- [ ] **Step 1: Write the migration**

```elixir
defmodule PhoenixElxirBeam.Repo.Migrations.CreateAgentCredentials do
  use Ecto.Migration

  def change do
    create table(:agent_credentials) do
      add :agent_id, :string, null: false
      add :token_hash, :binary, null: false
      add :description, :string
      add :disabled_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:agent_credentials, [:agent_id])
  end
end
```

- [ ] **Step 2: Run the migration**

Run: `mix ecto.migrate`
Expected: applies cleanly.

- [ ] **Step 3: Write failing tests mirroring `ApiKeyTest`'s shape**

```elixir
defmodule PhoenixElxirBeam.MCP.AgentCredentialTest do
  use PhoenixElxirBeam.DataCase, async: true

  alias PhoenixElxirBeam.MCP.AgentCredential

  defp issue(attrs \\ %{}) do
    {:ok, cred, token} = AgentCredential.issue(Map.merge(%{agent_id: "agent://specific-bot"}, attrs))
    {cred, token}
  end

  test "issue returns a token once and stores only a hash" do
    {cred, token} = issue()

    assert String.starts_with?(token, cred.agent_id <> ".")
    assert cred.token_hash != nil
    refute token =~ Base.encode16(cred.token_hash, case: :lower)
  end

  test "authenticate accepts the real token, rejects tampered ones" do
    {cred, token} = issue()

    assert {:ok, authed} = AgentCredential.authenticate(token)
    assert authed.id == cred.id

    assert {:error, :bad_secret} = AgentCredential.authenticate(cred.agent_id <> ".wrong")
    assert {:error, :unknown_agent} = AgentCredential.authenticate("agent://nope.whatever")
    assert {:error, :malformed} = AgentCredential.authenticate("no-dot")
    assert {:error, :malformed} = AgentCredential.authenticate(nil)
  end

  test "a disabled credential is rejected even with the correct secret" do
    {cred, token} = issue()
    :ok = AgentCredential.revoke(cred.agent_id)

    assert {:error, :disabled} = AgentCredential.authenticate(token)
  end

  test "revoke is idempotent and reports :not_found for an unknown agent_id" do
    {cred, _token} = issue()
    assert :ok = AgentCredential.revoke(cred.agent_id)
    assert :ok = AgentCredential.revoke(cred.agent_id)
    assert {:error, :not_found} = AgentCredential.revoke("agent://never-existed")
  end
end
```

Note `agent_id` values like `"agent://specific-bot"` contain no `.` character, so splitting the presented token on the *first* `.` only (`String.split(token, ".", parts: 2)`, same as `ApiKey.authenticate/1` already does) is safe — confirmed by inspecting real `agent_id` values used elsewhere in this codebase (`rule_engine.ex`'s own `"agent://ci-runner"` example), none of which contain a literal dot.

- [ ] **Step 4: Run to verify failure**

Run: `mix test test/phoenix_elxir_beam/mcp/agent_credential_test.exs -v`
Expected: FAIL — module undefined.

- [ ] **Step 5: Implement `AgentCredential`**

```elixir
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
  import Ecto.Query

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

  @doc "Authenticates a presented `<agent_id>.<secret>` token."
  @spec authenticate(String.t() | nil) ::
          {:ok, AgentCredential.t()} | {:error, :malformed | :unknown_agent | :disabled | :bad_secret}
  def authenticate(token) when is_binary(token) do
    case String.split(token, ".", parts: 2) do
      [agent_id, secret] when byte_size(secret) > 0 -> verify(agent_id, secret)
      _ -> {:error, :malformed}
    end
  end

  def authenticate(_token), do: {:error, :malformed}

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
```

- [ ] **Step 6: Run to verify tests pass**

Run: `mix test test/phoenix_elxir_beam/mcp/agent_credential_test.exs -v`
Expected: PASS.

- [ ] **Step 7: Run `mix precommit`**

Run: `mix precommit`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add priv/repo/migrations lib/phoenix_elxir_beam/mcp/agent_credential.ex \
        test/phoenix_elxir_beam/mcp/agent_credential_test.exs priv/repo/structure.sql
git commit -m "Add AgentCredential: a verifiable identity independent of API keys

Mirrors ApiKey's id/secret-hash pattern. Doesn't grant server access on
its own -- it exists to let an agent assert a verified agent_id
distinct from whichever API key its connection happens to use."
```

---

### Task 2: `AgentCredentialAuth` plug

**Files:**
- Create: `lib/phoenix_elxir_beam_web/plugs/agent_credential_auth.ex`
- Modify: `lib/phoenix_elxir_beam_web/router.ex`
- Test: `test/phoenix_elxir_beam_web/plugs/agent_credential_auth_test.exs`

**Interfaces:**
- Consumes: `AgentCredential.authenticate/1` (Task 1).
- Produces: `conn.assigns.verified_agent_id :: String.t() | nil`, consumed by Task 3's `ProxyController` change.

- [ ] **Step 1: Write the plug**

```elixir
defmodule PhoenixElxirBeamWeb.Plugs.AgentCredentialAuth do
  @moduledoc """
  Reads an optional `X-Agent-Credential: <agent_id>.<secret>` header and, on
  a valid match, assigns `conn.assigns.verified_agent_id` -- letting an
  agent assert its own identity independent of which API key authenticated
  the connection (`PhoenixElxirBeamWeb.Plugs.ApiKeyAuth` runs first in the
  pipeline and already rejected the request if the bearer token itself was
  invalid).

  Absent header: no-op, `verified_agent_id` stays unset, callers fall back
  to the API key's own `agent_id` exactly as before this plug existed.
  Present but invalid header: the request is rejected the same way a bad
  API key is -- silently falling back to the key's default `agent_id`
  instead would let an attacker probe for valid `agent_id` strings for
  free, since a wrong guess would otherwise just quietly succeed at the
  lower trust level.
  """

  import Plug.Conn

  alias PhoenixElxirBeam.MCP.AgentCredential

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    case get_req_header(conn, "x-agent-credential") do
      [] ->
        conn

      [token] ->
        case AgentCredential.authenticate(token) do
          {:ok, cred} -> assign(conn, :verified_agent_id, cred.agent_id)
          {:error, _reason} -> deny(conn)
        end
    end
  end

  defp deny(conn) do
    body =
      Jason.encode!(%{
        "jsonrpc" => "2.0",
        "id" => nil,
        "error" => %{"code" => -32001, "message" => "invalid agent credential"}
      })

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(401, body)
    |> halt()
  end
end
```

- [ ] **Step 2: Add the plug to the `:mcp_api` pipeline, after `ApiKeyAuth`**

In `lib/phoenix_elxir_beam_web/router.ex`:

```elixir
  pipeline :mcp_api do
    plug :accepts, ["json"]
    plug PhoenixElxirBeamWeb.Plugs.RequestLimits
    plug PhoenixElxirBeamWeb.Plugs.ApiKeyAuth
    plug PhoenixElxirBeamWeb.Plugs.AgentCredentialAuth
    plug PhoenixElxirBeamWeb.Plugs.RateLimit
  end
```

- [ ] **Step 3: Write failing plug tests**

```elixir
defmodule PhoenixElxirBeamWeb.Plugs.AgentCredentialAuthTest do
  use PhoenixElxirBeamWeb.ConnCase, async: true

  alias PhoenixElxirBeam.MCP.AgentCredential
  alias PhoenixElxirBeamWeb.Plugs.AgentCredentialAuth

  defp issue(attrs \\ %{}) do
    {:ok, cred, token} = AgentCredential.issue(Map.merge(%{agent_id: "agent://specific-bot"}, attrs))
    {cred, token}
  end

  test "no header is a no-op", %{conn: conn} do
    conn = AgentCredentialAuth.call(conn, [])
    refute Map.has_key?(conn.assigns, :verified_agent_id)
    refute conn.halted
  end

  test "a valid header assigns verified_agent_id", %{conn: conn} do
    {_cred, token} = issue()

    conn =
      conn
      |> Plug.Conn.put_req_header("x-agent-credential", token)
      |> AgentCredentialAuth.call([])

    assert conn.assigns.verified_agent_id == "agent://specific-bot"
    refute conn.halted
  end

  test "an unknown agent_id in the header halts with 401", %{conn: conn} do
    conn =
      conn
      |> Plug.Conn.put_req_header("x-agent-credential", "agent://nope.whatever")
      |> AgentCredentialAuth.call([])

    assert conn.halted
    assert conn.status == 401
  end

  test "a wrong secret halts with 401, does not fall back silently", %{conn: conn} do
    {cred, _token} = issue()

    conn =
      conn
      |> Plug.Conn.put_req_header("x-agent-credential", cred.agent_id <> ".wrong")
      |> AgentCredentialAuth.call([])

    assert conn.halted
    assert conn.status == 401
    refute Map.has_key?(conn.assigns, :verified_agent_id)
  end

  test "a disabled credential halts with 401", %{conn: conn} do
    {cred, token} = issue()
    :ok = AgentCredential.revoke(cred.agent_id)

    conn =
      conn
      |> Plug.Conn.put_req_header("x-agent-credential", token)
      |> AgentCredentialAuth.call([])

    assert conn.halted
    assert conn.status == 401
  end
end
```

- [ ] **Step 4: Run to verify failure, then implement, then pass**

Run: `mix test test/phoenix_elxir_beam_web/plugs/agent_credential_auth_test.exs -v`
Expected: FAIL first (module undefined), PASS once Step 1 is in place.

- [ ] **Step 5: Confirm pipeline ordering with a router-level test**

Add to whichever existing test file already exercises the `:mcp_api` pipeline end-to-end (likely `test/phoenix_elxir_beam_web/controllers/mcp/proxy_controller_test.exs` — confirm with `find test -iname "*proxy_controller*"`):

```elixir
  test "an invalid Authorization bearer token is rejected before X-Agent-Credential is ever checked" do
    conn =
      build_conn()
      |> put_req_header("authorization", "Bearer mcpk_nope.whatever")
      |> put_req_header("x-agent-credential", "agent://irrelevant.also-whatever")
      |> post(~p"/mcp/proxy/some-server", %{})

    assert json_response(conn, 401)
    # The agent-credential error code must never appear -- proof ApiKeyAuth
    # halted first and AgentCredentialAuth never ran.
    refute conn.resp_body =~ "invalid agent credential"
  end
```

- [ ] **Step 6: Run to verify this passes (it should, given Plug pipeline ordering, but confirm rather than assume)**

Run: `mix test test/phoenix_elxir_beam_web/controllers/mcp/proxy_controller_test.exs -v`
Expected: PASS — `ApiKeyAuth` halts the conn before `AgentCredentialAuth` runs at all, standard Plug pipeline semantics, but this test exists specifically so that guarantee is enforced by the suite, not just believed.

- [ ] **Step 7: Run `mix precommit`**

Run: `mix precommit`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add lib/phoenix_elxir_beam_web/plugs/agent_credential_auth.ex \
        lib/phoenix_elxir_beam_web/router.ex \
        test/phoenix_elxir_beam_web/plugs/agent_credential_auth_test.exs \
        test/phoenix_elxir_beam_web/controllers/mcp/proxy_controller_test.exs
git commit -m "Add AgentCredentialAuth plug: optional, fails closed on a bad header

Placed after ApiKeyAuth in the :mcp_api pipeline. No header is a
no-op; an invalid one halts the request rather than silently falling
back to the API key's default agent_id, so a bad guess can't probe
for valid agent_id strings for free."
```

---

### Task 3: Wire `verified_agent_id` into session open

**Files:**
- Modify: `lib/phoenix_elxir_beam_web/controllers/mcp/proxy_controller.ex:143-151`
- Test: `test/phoenix_elxir_beam_web/controllers/mcp/proxy_controller_test.exs`

**Interfaces:**
- Consumes: `conn.assigns[:verified_agent_id]` (Task 2).

- [ ] **Step 1: Write a failing end-to-end test**

In `proxy_controller_test.exs`, find the existing `initialize` test setup (reuse its server-registration and API-key-issuance helpers) and add:

```elixir
  test "a verified X-Agent-Credential overrides the API key's default agent_id for session open" do
    # Reuse this file's existing helpers for registering a server and issuing
    # an API key -- confirm their exact names/signatures by reading the
    # existing `initialize` tests in this file before writing this one, since
    # this plan does not know their exact shape without reading the file.
    {:ok, _cred, agent_token} =
      PhoenixElxirBeam.MCP.AgentCredential.issue(%{agent_id: "agent://specific-bot"})

    conn =
      build_conn()
      |> put_req_header("authorization", "Bearer " <> shared_key_token())
      |> put_req_header("x-agent-credential", agent_token)
      |> post(~p"/mcp/proxy/#{server_id}", initialize_params())

    assert json_response(conn, 200)

    session = PhoenixElxirBeam.MCP.SessionStore.get!(session_id_from(conn))
    assert session.agent_id == "agent://specific-bot"
  end

  test "a RuleEngine rule scoped to the verified agent_id actually matches it" do
    # Uses the rule ALREADY configured in config/test.exs (do not add a new
    # one): a deny rule for agent://ci-runner + network_egress tag. The API
    # key used for this test must NOT itself carry agent_id: "agent://ci-runner"
    # (if it already does, this test would pass even without this plan's
    # fix, since the key's own default would already match the rule -- use
    # a key issued with a different, non-matching agent_id, e.g.
    # "agent://unrelated", so the only way the rule can fire is via the
    # verified X-Agent-Credential overriding it).
    {:ok, _cred, agent_token} =
      PhoenixElxirBeam.MCP.AgentCredential.issue(%{agent_id: "agent://ci-runner"})

    conn =
      build_conn()
      |> put_req_header("authorization", "Bearer " <> shared_key_token())
      |> put_req_header("x-agent-credential", agent_token)
      |> post(~p"/mcp/proxy/#{server_id}", initialize_params())

    assert json_response(conn, 200)
    session_id = session_id_from(conn)

    # Call a network_egress-tagged tool -- follow this file's existing
    # pattern for making a tools/call request and reading its JSON-RPC
    # response (same pattern the file already uses for other RuleEngine
    # deny-path assertions).
    call_conn =
      build_conn()
      |> put_req_header("authorization", "Bearer " <> shared_key_token())
      |> put_req_header("x-agent-credential", agent_token)
      |> post(~p"/mcp/proxy/#{server_id}", tools_call_params(session_id, network_egress_tool()))

    response = json_response(call_conn, 200)
    assert response["error"]["message"] =~ "policy: agent ci-runner may not perform network egress"
  end
```

Both test bodies above intentionally reference "this file's existing helpers" rather than inventing new ones — `shared_key_token/0`, `server_id`, `initialize_params/0`, `session_id_from/1`, `tools_call_params/2`, and `network_egress_tool/0` are placeholders for whatever this file's real equivalents are called (a helper that returns a registered tool name/definition already tagged `network_egress` almost certainly already exists, since `MetadataEgressGuard`'s own tests and this file's existing RuleEngine deny-path tests need one). Read `proxy_controller_test.exs`'s current `initialize` and `tools/call` tests first and adapt these two to its actual helper names before running Step 2 — guessing at the fixture API here would produce a test that never compiles. If no existing helper returns a `network_egress`-tagged tool/server fixture, use whatever this file's tests already use to get a `ChainExfil`/`MetadataEgressGuard`-covered tool call working end-to-end, since one of those must already exist for the file's other plugin-coverage tests to work at all.

- [ ] **Step 2: Run to verify failure**

Run: `mix test test/phoenix_elxir_beam_web/controllers/mcp/proxy_controller_test.exs -v`
Expected: FAIL — `session.agent_id` is still the key's default, not the verified one.

- [ ] **Step 3: Implement the override**

In `lib/phoenix_elxir_beam_web/controllers/mcp/proxy_controller.ex`, modify `handle_initialize/4`:

```elixir
        agent_id = conn.assigns[:verified_agent_id] || key.agent_id

        {:ok, session} =
          SessionStore.open(server_id,
            client_info: rpc_params["clientInfo"],
            protocol_version: protocol,
            agent_id: agent_id,
            key_id: key.key_id
          )

        :ok = PolicyEngine.ensure_session(session.id, agent_id)
```

- [ ] **Step 4: Run to verify both new tests pass**

Run: `mix test test/phoenix_elxir_beam_web/controllers/mcp/proxy_controller_test.exs -v`
Expected: PASS.

- [ ] **Step 5: Run the full test suite**

Run: `mix test`
Expected: PASS — no regressions anywhere else that reads `key.agent_id` from this call site.

- [ ] **Step 6: Run `mix precommit`**

Run: `mix precommit`
Expected: PASS.

- [ ] **Step 7: Update `docs/product-guide.md` and `docs/threat-model.md`**

In `docs/product-guide.md`, add a short section on issuing an `AgentCredential` (currently via `mix run -e`, same bootstrap caveat as the SSO plan's admin-provisioning step) and the `X-Agent-Credential` header format.

In `docs/threat-model.md`, update or add a line noting that `agent_id` can now be independently verified per-session via `AgentCredentialAuth`, narrowing (not fully closing — a key with no agent credential presented still uses its static default) the "API key = fixed identity" limitation.

- [ ] **Step 8: Commit**

```bash
git add lib/phoenix_elxir_beam_web/controllers/mcp/proxy_controller.ex \
        test/phoenix_elxir_beam_web/controllers/mcp/proxy_controller_test.exs \
        docs/product-guide.md docs/threat-model.md
git commit -m "Prefer a verified agent credential over the API key's default agent_id

Closes the gap where every agent sharing one API key was forced into
the same policy-matching identity. A key with no X-Agent-Credential
presented behaves exactly as before."
```
