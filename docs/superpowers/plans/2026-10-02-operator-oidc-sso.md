# Operator OIDC/OAuth2 SSO Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator log in via the customer's own OIDC-compliant IdP (Okta, Entra, Google Workspace), as an addition to existing local password login — SSO authenticates an already-admin-provisioned account, never auto-creates or auto-authorizes one.

**Architecture:** `ueberauth` + `ueberauth_oidcc` handle the OIDC authorization-code flow via standard `.well-known/openid-configuration` discovery. A new `auth_source` field on `users` (`:local` | `:sso`) separates the two login paths so an SSO-provisioned account can never be logged into via a guessed/leaked password. A new `SsoSessionController`, parallel to the existing `SessionController`, handles the IdP redirect and callback, then calls the same `UserAuth.log_in_user/2` local login already uses — nothing downstream of login needs to know which method was used.

**Tech Stack:** Elixir, Phoenix, `ueberauth` + `ueberauth_oidcc` (new deps), Ecto/Postgres, ExUnit + `Phoenix.ConnTest`.

**Spec:** `docs/superpowers/specs/2026-10-02-operator-oidc-sso-design.md`

## Global Constraints

- `mix precommit` (format + compile with warnings-as-errors + test) must pass before any commit.
- SSO must be fully opt-in at the deployment level: when `OIDC_ISSUER_URL` is unset, the app must boot and behave identically to today — no new routes registered, no UI referencing SSO, no new required config. Existing deployments upgrading must see zero behavior change until they explicitly configure the three new env vars.
- No auto-provisioning: an `auth_source: :sso` account is never created by the login flow itself, only by an admin via `Accounts.create_sso_user/1` (new function, Task 2).
- Per `AGENTS.md`: never use `String.to_atom/1` on user input — the `auth_source` enum values come from a fixed `Ecto.Enum` list, and the IdP's email claim is compared as a string via `get_user_by_email/1`, never converted to an atom.
- Per `AGENTS.md`: `if/else` only, never `else if`/`elseif` — use `cond`/`case` for the multi-branch login-outcome logic in Task 4.

## Review Focus

- **An IdP that omits or sets `email_verified: false`.** Must be rejected outright, not silently treated as verified — this is the spec's explicit trust-boundary decision and the single easiest thing to get wrong by skipping the claim check.
- **An SSO callback for an email with no matching `users` row.** Must show a clear "no account provisioned" message and must not create one — a session-fixation or confused-deputy risk if this silently redirected to local signup/creation instead of failing closed.
- **An SSO-provisioned account attempting local password login.** `get_user_by_email_and_password/2` must refuse it even though the account exists and is enabled — covered explicitly since this is exactly the "stray password hash" risk the spec calls out.
- **Case-sensitivity of the email match.** The IdP may return `User@Example.com` while the admin provisioned `user@example.com` — must match via the same `String.downcase/1` normalization `get_user_by_email/1` already applies, not a second, possibly-inconsistent comparison.
- **SSO configured but the IdP is unreachable at callback time (network failure, bad issuer URL).** Must show a clear error and allow falling back to the local login page, not crash the controller or strand the user on a blank page — `ueberauth_oidcc`'s failure flow needs an explicit `Ueberauth.Failure` handling clause, not just the success-case `Ueberauth.Auth` clause.

---

### Task 1: Add dependencies and opt-in runtime configuration

**Files:**
- Modify: `mix.exs`
- Modify: `config/runtime.exs`
- Modify: `config/config.exs`

**Interfaces:**
- Produces: `Application.get_env(:phoenix_elxir_beam, :oidc_sso_enabled?, false)` — a boolean other tasks (router, login template) read to decide whether to register SSO routes/UI at all.
- Produces: `Application.get_env(:ueberauth, Ueberauth)` providers config (standard `ueberauth` config shape), consumed by `ueberauth_oidcc` and Task 3's controller.

- [ ] **Step 1: Add the dependencies**

In `mix.exs`, add to `defp deps do`:

```elixir
      {:ueberauth, "~> 0.10"},
      {:ueberauth_oidcc, "~> 0.3"},
```

- [ ] **Step 2: Fetch dependencies**

Run: `mix deps.get`
Expected: `ueberauth` and `ueberauth_oidcc` (and their transitive deps, including `oidcc`) resolve and compile cleanly.

- [ ] **Step 3: Add the opt-in config block**

In `config/runtime.exs`, find the section reading other per-deployment env vars (near `SECRET_KEY_BASE` / `DATABASE_URL` handling) and add:

```elixir
  oidc_issuer_url = System.get_env("OIDC_ISSUER_URL")

  config :phoenix_elxir_beam, :oidc_sso_enabled?, is_binary(oidc_issuer_url)

  if is_binary(oidc_issuer_url) do
    oidc_client_id =
      System.get_env("OIDC_CLIENT_ID") ||
        raise "OIDC_CLIENT_ID is required when OIDC_ISSUER_URL is set"

    oidc_client_secret =
      System.get_env("OIDC_CLIENT_SECRET") ||
        raise "OIDC_CLIENT_SECRET is required when OIDC_ISSUER_URL is set"

    config :ueberauth_oidcc,
      issuers: [
        %{
          name: :operator_sso,
          issuer: oidc_issuer_url
        }
      ]

    config :ueberauth, Ueberauth,
      providers: [
        operator_sso:
          {Ueberauth.Strategy.Oidcc,
           [
             issuer: :operator_sso,
             client_id: oidc_client_id,
             client_secret: oidc_client_secret,
             scopes: ~w(openid email profile)
           ]}
      ]
  else
    config :phoenix_elxir_beam, :oidc_sso_enabled?, false
  end
```

- [ ] **Step 4: Add a compile-time default so dev/test boot without the env vars set**

In `config/config.exs`, add:

```elixir
config :phoenix_elxir_beam, :oidc_sso_enabled?, false
```

(`config/runtime.exs` overrides this at boot when `OIDC_ISSUER_URL` is set; this default keeps `mix test` / `mix phx.server` in dev working unchanged when it isn't.)

- [ ] **Step 5: Verify the app still boots with no OIDC env vars set**

Run: `mix compile`
Expected: compiles cleanly with no warnings.

Run: `MIX_ENV=test mix test --include skip_if_no_db 2>&1 | tail -20` (or simply `mix test` if the suite doesn't use that tag) to confirm nothing broke from the config changes alone — no feature code has been added yet, so this should be identical to the pre-change test run.

- [ ] **Step 6: Commit**

```bash
git add mix.exs mix.lock config/runtime.exs config/config.exs
git commit -m "Add ueberauth + ueberauth_oidcc, gated behind OIDC_ISSUER_URL

No behavior change when OIDC_ISSUER_URL is unset -- oidc_sso_enabled?
stays false and no provider config is registered, so an existing
deployment upgrading sees nothing different until it opts in."
```

---

### Task 2: Add `auth_source` to `users` and the SSO provisioning path

**Files:**
- Create: `priv/repo/migrations/<timestamp>_add_auth_source_to_users.exs`
- Modify: `lib/phoenix_elxir_beam/accounts/user.ex`
- Modify: `lib/phoenix_elxir_beam/accounts.ex`
- Test: `test/phoenix_elxir_beam/accounts_test.exs` (or wherever existing `Accounts` tests live — confirm the path with `find test -iname "*accounts*"` before creating a new file)

**Interfaces:**
- Produces: `User.auth_source()` type (`:local | :sso`), `users.auth_source` DB column, default `:local`.
- Produces: `Accounts.create_sso_user/1` — `(attrs :: map()) :: {:ok, User.t()} | {:error, Ecto.Changeset.t()}`. `attrs` needs `:email` and `:role`, no `:password`. Task 4's test setup and any future admin-UI work call this.
- Modifies: `Accounts.get_user_by_email_and_password/2` to refuse an `auth_source: :sso` account.

- [ ] **Step 1: Write the migration**

```elixir
defmodule PhoenixElxirBeam.Repo.Migrations.AddAuthSourceToUsers do
  use Ecto.Migration

  def change do
    alter table(:users) do
      add :auth_source, :string, null: false, default: "local"
    end
  end
end
```

(Use the actual current UTC timestamp as the filename prefix, matching the existing `YYYYMMDDHHMMSS_` convention visible in `priv/repo/migrations/`.)

- [ ] **Step 2: Run the migration**

Run: `mix ecto.migrate`
Expected: migration applies cleanly; `\d users` in `psql` (or `mix ecto.migrate --log-sql`) shows the new `auth_source` column.

- [ ] **Step 3: Write a failing test for the SSO changeset requiring no password**

Find or create the test file for `PhoenixElxirBeam.Accounts.User` changesets (likely `test/phoenix_elxir_beam/accounts/user_test.exs` — check with `find test -iname "user_test.exs"` first) and add:

```elixir
  describe "sso_registration_changeset/2" do
    test "is valid with email and role, no password" do
      changeset =
        User.sso_registration_changeset(%User{}, %{email: "sso.user@example.com", role: :viewer})

      assert changeset.valid?
      assert get_change(changeset, :auth_source) == :sso
      refute get_change(changeset, :hashed_password)
    end

    test "requires a valid email" do
      changeset = User.sso_registration_changeset(%User{}, %{email: "not-an-email", role: :viewer})
      refute changeset.valid?
    end
  end
```

- [ ] **Step 4: Run it to verify it fails**

Run: `mix test test/phoenix_elxir_beam/accounts/user_test.exs -v`
Expected: FAIL — `User.sso_registration_changeset/2 is undefined`

- [ ] **Step 5: Add `auth_source` to the schema and implement `sso_registration_changeset/2`**

In `lib/phoenix_elxir_beam/accounts/user.ex`:

```elixir
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
```

Add alongside the existing `registration_changeset/2`:

```elixir
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
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `mix test test/phoenix_elxir_beam/accounts/user_test.exs -v`
Expected: PASS.

- [ ] **Step 7: Write a failing test for `Accounts.create_sso_user/1` and the password-login refusal**

In the `Accounts` test file:

```elixir
  describe "create_sso_user/1" do
    test "creates an auth_source: :sso user with no password" do
      assert {:ok, user} = Accounts.create_sso_user(%{email: "sso@example.com", role: :operator})
      assert user.auth_source == :sso
      assert is_nil(user.hashed_password)
    end
  end

  describe "get_user_by_email_and_password/2 with an sso account" do
    test "refuses login even with a password set out-of-band" do
      {:ok, user} = Accounts.create_sso_user(%{email: "sso2@example.com", role: :viewer})
      # Simulate a stray hash existing (e.g. from a hypothetical future bug or manual DB edit) --
      # the function must still refuse based on auth_source, not just absence of a hash.
      {:ok, _} =
        user
        |> Ecto.Changeset.change(hashed_password: Pbkdf2.hash_pwd_salt("somepassword123"))
        |> PhoenixElxirBeam.Repo.update()

      refute Accounts.get_user_by_email_and_password("sso2@example.com", "somepassword123")
    end
  end
```

- [ ] **Step 8: Run both tests to verify they fail**

Run: `mix test test/phoenix_elxir_beam/accounts_test.exs -v`
Expected: FAIL — `Accounts.create_sso_user/1 is undefined`; once that's added, the refusal test fails because the current `get_user_by_email_and_password/2` doesn't check `auth_source`.

- [ ] **Step 9: Implement `create_sso_user/1` and the refusal check**

In `lib/phoenix_elxir_beam/accounts.ex`:

```elixir
  @doc "Admin-provisions an SSO-authenticated account. `attrs` needs `:email` and `:role`."
  def create_sso_user(attrs) do
    %User{}
    |> User.sso_registration_changeset(attrs)
    |> Repo.insert()
  end
```

Modify `get_user_by_email_and_password/2`:

```elixir
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
```

- [ ] **Step 10: Run both tests to verify they pass**

Run: `mix test test/phoenix_elxir_beam/accounts_test.exs -v`
Expected: PASS.

- [ ] **Step 11: Run the full Accounts test suite to confirm no regression**

Run: `mix test test/phoenix_elxir_beam/accounts_test.exs test/phoenix_elxir_beam/accounts/user_test.exs -v`
Expected: PASS — every existing test plus the new ones.

- [ ] **Step 12: Run `mix precommit`**

Run: `mix precommit`
Expected: PASS.

- [ ] **Step 13: Commit**

```bash
git add priv/repo/migrations lib/phoenix_elxir_beam/accounts/user.ex \
        lib/phoenix_elxir_beam/accounts.ex test/phoenix_elxir_beam/accounts_test.exs \
        test/phoenix_elxir_beam/accounts/user_test.exs priv/repo/structure.sql
git commit -m "Add auth_source to users; SSO accounts can never use password login

An admin-provisioned SSO account (auth_source: :sso) has no password
and get_user_by_email_and_password/2 now refuses it outright, even if
a hashed_password somehow existed on the row -- auth_source is the
authority, not merely the absence of a hash."
```

---

### Task 3: SSO callback controller and routes

**Files:**
- Create: `lib/phoenix_elxir_beam_web/controllers/sso_session_controller.ex`
- Modify: `lib/phoenix_elxir_beam_web/router.ex`
- Test: `test/phoenix_elxir_beam_web/controllers/sso_session_controller_test.exs`

**Interfaces:**
- Consumes: `Accounts.get_user_by_email/1` (existing), `UserAuth.log_in_user/2` (existing), `Application.get_env(:phoenix_elxir_beam, :oidc_sso_enabled?)` (Task 1).
- Produces: `GET /auth/:provider` and `GET/POST /auth/:provider/callback` routes, only registered when `oidc_sso_enabled?` is true — consumed by Task 4's login-page link.

- [ ] **Step 1: Write the controller**

```elixir
defmodule PhoenixElxirBeamWeb.SsoSessionController do
  @moduledoc """
  OIDC SSO login callback (Phase 1 identity work). Authenticates an
  already-admin-provisioned `auth_source: :sso` account by verified email
  claim; never creates or authorizes an account on its own. See
  `docs/superpowers/specs/2026-10-02-operator-oidc-sso-design.md`.
  """
  use PhoenixElxirBeamWeb, :controller

  plug Ueberauth

  alias PhoenixElxirBeam.Accounts
  alias PhoenixElxirBeamWeb.UserAuth

  def request(conn, _params), do: conn

  def callback(%{assigns: %{ueberauth_failure: _failure}} = conn, _params) do
    conn
    |> put_flash(:error, "SSO sign-in failed. Try again or use your password, if you have one.")
    |> redirect(to: ~p"/login")
  end

  def callback(%{assigns: %{ueberauth_auth: auth}} = conn, _params) do
    with {:ok, email} <- verified_email(auth),
         %Accounts.User{auth_source: :sso} = user <- Accounts.get_user_by_email(email) do
      conn
      |> put_flash(:info, "Welcome back.")
      |> UserAuth.log_in_user(user)
    else
      _ ->
        conn
        |> put_flash(
          :error,
          "No SSO account is provisioned for that identity. Ask an admin to create one."
        )
        |> redirect(to: ~p"/login")
    end
  end

  defp verified_email(%Ueberauth.Auth{info: %{email: email}, extra: extra}) when is_binary(email) do
    if email_verified?(extra), do: {:ok, email}, else: :error
  end

  defp verified_email(_auth), do: :error

  defp email_verified?(%Ueberauth.Auth.Extra{raw_info: raw_info}) do
    raw_info
    |> get_in([Access.key(:claims, %{})])
    |> Kernel.||(%{})
    |> Map.get("email_verified", false)
    |> Kernel.==(true)
  end

  defp email_verified?(_extra), do: false
end
```

Note: `Ueberauth.Auth.Extra`'s exact `raw_info` shape depends on `ueberauth_oidcc`'s implementation — Step 2 below verifies this against the library's actual test fixtures/docs before trusting the shape above, since this is exactly the kind of "assumed library internals" detail a plan must not guess at silently.

- [ ] **Step 2: Verify the `Ueberauth.Auth.Extra` shape against the installed library**

Run: `mix deps.get` (if not already done in Task 1), then inspect the installed library's source for how it populates `claims`/`email_verified`:

Run: `grep -rn "email_verified\|raw_info" deps/ueberauth_oidcc/lib/ 2>/dev/null`

If the actual field/path differs from the `email_verified?/1` implementation above, adjust the function to match what's actually there before proceeding — do not guess further; read the library source directly, since this is the one place a wrong assumption silently defeats the spec's core trust-boundary decision (accepting an unverified email as verified).

- [ ] **Step 3: Add the routes, gated on `oidc_sso_enabled?`**

In `lib/phoenix_elxir_beam_web/router.ex`, add after the existing login scope:

```elixir
  if Application.compile_env(:phoenix_elxir_beam, :oidc_sso_enabled?, false) do
    scope "/auth", PhoenixElxirBeamWeb do
      pipe_through [:browser, :redirect_if_authenticated]

      get "/:provider", SsoSessionController, :request
      get "/:provider/callback", SsoSessionController, :callback
      post "/:provider/callback", SsoSessionController, :callback
    end
  end
```

Note this uses `Application.compile_env/3`, not `get_env/3` — SSO route registration is a compile-time decision (consistent with the existing `dev_routes` pattern already in this router), so a deployment toggling `OIDC_ISSUER_URL` requires a rebuild/restart to take effect, same as any other compile-time config in this app.

- [ ] **Step 4: Write a failing test for the successful-login path**

```elixir
defmodule PhoenixElxirBeamWeb.SsoSessionControllerTest do
  use PhoenixElxirBeamWeb.ConnCase, async: true

  alias PhoenixElxirBeam.Accounts

  describe "callback/2 with a verified ueberauth_auth assign" do
    test "logs in an existing auth_source: :sso account", %{conn: conn} do
      {:ok, user} = Accounts.create_sso_user(%{email: "ops@example.com", role: :operator})

      auth = %Ueberauth.Auth{
        info: %Ueberauth.Auth.Info{email: "ops@example.com"},
        extra: %Ueberauth.Auth.Extra{raw_info: %{claims: %{"email_verified" => true}}}
      }

      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Plug.Conn.assign(:ueberauth_auth, auth)
        |> PhoenixElxirBeamWeb.SsoSessionController.callback(%{})

      assert Phoenix.Flash.get(conn.assigns.flash, :info) == "Welcome back."
      assert get_session(conn, "user_token")
      refute is_nil(user)
    end

    test "rejects login when email_verified is false", %{conn: conn} do
      {:ok, _user} = Accounts.create_sso_user(%{email: "unverified@example.com", role: :viewer})

      auth = %Ueberauth.Auth{
        info: %Ueberauth.Auth.Info{email: "unverified@example.com"},
        extra: %Ueberauth.Auth.Extra{raw_info: %{claims: %{"email_verified" => false}}}
      }

      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Plug.Conn.assign(:ueberauth_auth, auth)
        |> PhoenixElxirBeamWeb.SsoSessionController.callback(%{})

      refute get_session(conn, "user_token")
      assert redirected_to(conn) == ~p"/login"
    end

    test "rejects login when no matching users row exists", %{conn: conn} do
      auth = %Ueberauth.Auth{
        info: %Ueberauth.Auth.Info{email: "nobody@example.com"},
        extra: %Ueberauth.Auth.Extra{raw_info: %{claims: %{"email_verified" => true}}}
      }

      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Plug.Conn.assign(:ueberauth_auth, auth)
        |> PhoenixElxirBeamWeb.SsoSessionController.callback(%{})

      refute get_session(conn, "user_token")
      assert redirected_to(conn) == ~p"/login"
    end
  end

  describe "callback/2 with a ueberauth_failure assign" do
    test "redirects to login with an error flash", %{conn: conn} do
      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Plug.Conn.assign(:ueberauth_failure, %Ueberauth.Failure{})
        |> PhoenixElxirBeamWeb.SsoSessionController.callback(%{})

      assert redirected_to(conn) == ~p"/login"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "SSO sign-in failed"
    end
  end
end
```

Adjust the `extra.raw_info` construction in this test to match whatever Step 2 actually found the library's real shape to be — the test must exercise the real shape the controller consumes, not the assumed one, if Step 2 revealed a difference.

- [ ] **Step 5: Run the tests to verify the expected failures**

Run: `mix test test/phoenix_elxir_beam_web/controllers/sso_session_controller_test.exs -v`
Expected: FAIL until Step 1's controller (adjusted per Step 2) and Step 3's routes exist. If routes are compile-time-gated and `oidc_sso_enabled?` is `false` in `config/test.exs`, calling the controller action directly (as these tests do, not via an HTTP round-trip through the router) still works regardless of route registration — confirm this is the case, since testing the controller function directly sidesteps the compile-time route gate entirely, which is intentional here (these are controller unit tests, not router integration tests).

- [ ] **Step 6: Run the tests to verify they pass**

Run: `mix test test/phoenix_elxir_beam_web/controllers/sso_session_controller_test.exs -v`
Expected: PASS.

- [ ] **Step 7: Run `mix precommit`**

Run: `mix precommit`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add lib/phoenix_elxir_beam_web/controllers/sso_session_controller.ex \
        lib/phoenix_elxir_beam_web/router.ex \
        test/phoenix_elxir_beam_web/controllers/sso_session_controller_test.exs
git commit -m "Add SSO callback controller: authenticates, never provisions

Looks up the IdP's verified email claim against an existing
auth_source: :sso user and reuses UserAuth.log_in_user/2 -- the same
session-creation path local login uses. No matching account or an
unverified email claim both fail closed to the login page, never to
account creation."
```

---

### Task 4: Login page SSO link and end-to-end smoke test

**Files:**
- Modify: `lib/phoenix_elxir_beam_web/controllers/session_html/new.html.heex` (confirm exact path with `find lib -iname "*session*html*"` first — template path may differ slightly from this guess)
- Modify: `lib/phoenix_elxir_beam_web/controllers/session_controller.ex` (to pass the `oidc_sso_enabled?` flag to the template)
- Test: `test/phoenix_elxir_beam_web/controllers/session_controller_test.exs` (confirm path first)

**Interfaces:**
- Consumes: `Application.get_env(:phoenix_elxir_beam, :oidc_sso_enabled?)` (Task 1).

- [ ] **Step 1: Find the exact login template path**

Run: `find lib -iname "*session*"`

- [ ] **Step 2: Write a failing test asserting the SSO link's conditional presence**

```elixir
  describe "GET /login with SSO configured" do
    setup do
      Application.put_env(:phoenix_elxir_beam, :oidc_sso_enabled?, true)
      on_exit(fn -> Application.put_env(:phoenix_elxir_beam, :oidc_sso_enabled?, false) end)
    end

    test "shows a sign-in-with-SSO link", %{conn: conn} do
      conn = get(conn, ~p"/login")
      assert html_response(conn, 200) =~ "Sign in with SSO"
    end
  end

  describe "GET /login without SSO configured" do
    test "does not show a sign-in-with-SSO link", %{conn: conn} do
      conn = get(conn, ~p"/login")
      refute html_response(conn, 200) =~ "Sign in with SSO"
    end
  end
```

- [ ] **Step 3: Run to verify the "with SSO" test fails**

Run: `mix test test/phoenix_elxir_beam_web/controllers/session_controller_test.exs -v`
Expected: FAIL on the "shows a sign-in-with-SSO link" test (no such link exists yet); the "without SSO" test should already pass since nothing has changed yet.

- [ ] **Step 4: Pass the flag into the template and render the link conditionally**

In `session_controller.ex`'s `new/2`:

```elixir
  def new(conn, _params) do
    render(conn, :new,
      error_message: nil,
      sso_enabled?: Application.get_env(:phoenix_elxir_beam, :oidc_sso_enabled?, false)
    )
  end
```

In the login template, add (near the existing password form, following this project's existing HEEx conventions — e.g. `<.link>` for navigation, matching whatever style the rest of that template already uses):

```heex
<div :if={@sso_enabled?} class="mt-4 text-center">
  <.link href={~p"/auth/operator_sso"} class="text-sm font-medium underline">
    Sign in with SSO
  </.link>
</div>
```

- [ ] **Step 5: Run both tests to verify they pass**

Run: `mix test test/phoenix_elxir_beam_web/controllers/session_controller_test.exs -v`
Expected: PASS for both.

- [ ] **Step 6: Run the full test suite**

Run: `mix test`
Expected: PASS — everything from this plan plus the pre-existing suite, no regressions.

- [ ] **Step 7: Run `mix precommit`**

Run: `mix precommit`
Expected: PASS.

- [ ] **Step 8: Update `docs/product-guide.md` with SSO setup instructions**

Add a short section (matching the existing doc's style) covering: the three env vars, that SSO requires admin pre-provisioning via `Accounts.create_sso_user/1` (note: if there's no admin-UI affordance for this yet, state plainly that it currently requires a `mix run -e` one-off or an `iex -S mix` console command — do not imply a dashboard button exists if Task 4 didn't add one), and that local password login remains available for any account not explicitly provisioned as `auth_source: :sso`.

- [ ] **Step 9: Commit**

```bash
git add lib/phoenix_elxir_beam_web/controllers/session_controller.ex \
        lib/phoenix_elxir_beam_web/controllers/session_html/new.html.heex \
        test/phoenix_elxir_beam_web/controllers/session_controller_test.exs \
        docs/product-guide.md
git commit -m "Show a conditional SSO login link when OIDC is configured

Nothing renders when oidc_sso_enabled? is false -- the login page is
byte-for-byte unchanged for any deployment that hasn't opted in."
```
