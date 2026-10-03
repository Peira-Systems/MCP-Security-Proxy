# Operator OIDC/OAuth2 SSO — design spec

Date: 2026-10-02

## Problem

Operator dashboard login (`PhoenixElxirBeamWeb.UserAuth`, `SessionController`)
is password-only: an admin creates a `users` row with an email/password
(`Accounts.User.registration_changeset/2`), and `SessionController.create/2`
verifies that password directly. There is no way for an enterprise customer
to require their operators to sign in through the organization's own
identity provider (Okta, Microsoft Entra, Google Workspace) — a hard
requirement for most enterprise security teams, and one every competitor
surveyed in the competitive-landscape research (Runlayer specifically) has
already shipped via WorkOS-backed OIDC/SAML/SCIM.

## Goal

Let an operator log in via the customer's own OIDC-compliant IdP, as an
addition to — not a replacement for — local password login. Local accounts
stay the only path for the seeded admin account (the deployment's own
bootstrap/break-glass access, per `docs/deployment.md`'s "every boot seeds an
admin from `ADMIN_EMAIL`/`ADMIN_PASSWORD`" description) and remain available
for anyone an admin chooses to keep on password auth.

## Decisions

### Library: `ueberauth` + `ueberauth_oidcc`

`ueberauth_oidcc` implements a generic OIDC strategy via the standard
`<issuer>/.well-known/openid-configuration` discovery document, so one
strategy configuration covers Okta, Entra, and Google Workspace without
provider-specific code — the operator supplies an issuer URL, client ID, and
client secret per their own IdP, and the library handles the rest. This
avoids hand-rolling OIDC's authorization-code flow, nonce/state validation,
and JWKS fetching/caching, all of which are exactly the kind of
security-sensitive, easy-to-get-subtly-wrong code this project should not
write itself when a maintained library already does it correctly.

### Provisioning: admin pre-provisions, SSO only authenticates

**An admin must create the `users` row (email + role) before that email can
log in via SSO.** SSO login looks up the verified email claim from the IdP
against existing `users`, and denies login (not auto-create) if no matching
account exists. This matches the existing "admin-issued" account model
(`Accounts.User.registration_changeset/2`'s own moduledoc already describes
local accounts as "admin-issued") and avoids a specific real risk:
auto-provisioning on first SSO login means trusting the IdP's email claim
(and, worse, any group/role claim) to grant dashboard access and a role
implicitly. A misconfigured IdP app registration, or an IdP tenant that
includes more users than the customer intended to grant proxy access to,
would otherwise silently create operator or admin accounts. Requiring
explicit admin provisioning first means SSO is purely an *authentication*
method for an already-authorized account, never an *authorization* grant on
its own — consistent with this project's existing default-deny posture
elsewhere (`docs/threat-model.md`).

A `users` row provisioned for SSO has no `hashed_password` (local password
login is independently disabled for that account, not just unused) — see
Task 2.

### Linking: by verified email claim only

No `sub`-based linking, no separate "identity" table. The existing `users`
schema already has a unique, validated `email` field
(`Accounts.User.validate_email/1`); SSO login matches the IdP's `email`
claim against it case-insensitively (reusing the existing
`String.downcase/1` normalization already applied to local accounts).
`ueberauth_oidcc` surfaces whether the IdP marked the email verified
(`email_verified` claim); a login attempt where the IdP does not assert
`email_verified: true` is rejected — an unverified email claim is not a
trustworthy identifier to match an account against.

## Out of scope

- SAML — OIDC covers the three named IdPs (Okta, Entra, Google Workspace all
  speak standard OIDC); SAML support is a separate, larger effort noted but
  not planned here.
- SCIM-based user provisioning/deprovisioning sync — a larger platform
  feature (ties into the Phase 3 "multi-tenant" / fleet-console roadmap
  item, not Phase 1 identity). Account creation stays admin-driven via the
  dashboard, same as today, for this spec.
- Per-agent identity propagation (calling-agent OAuth client identity,
  on-behalf-of tokens) — that's the separate per-agent-identity spec/plan in
  this same Phase 1 batch; this spec is operator-dashboard login only.
- Role mapping from IdP group/claim data — explicitly rejected above as a
  trust boundary violation for this spec; role stays admin-assigned on the
  `users` row exactly as today.

## Changes

### 1. Add `ueberauth` + `ueberauth_oidcc` dependencies and per-deployment config

New optional runtime config (unset = SSO disabled entirely, password login
only — this must be true by default so existing deployments are unaffected
by upgrading): `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`
environment variables, read in `config/runtime.exs` the same way other
per-deployment secrets already are. When unset, the `/auth/oidc/*` routes
and the "Sign in with SSO" link are not registered/rendered at all — no
partial, confusing UI for a deployment that hasn't configured SSO.

### 2. Add an `auth_source` field to `users` distinguishing local vs. SSO accounts

An admin-provisioned SSO account should not also be log-in-able by a guessed
or leaked password (there is none to guess, since `registration_changeset`
still requires one today — Task 2 of the plan adds an SSO-specific
provisioning changeset that never sets `hashed_password` at all, and
`Accounts.get_user_by_email_and_password/2` must refuse an `auth_source:
:sso` account even if a stray password hash existed from a prior conversion).

### 3. Add the OIDC callback controller and wire `ueberauth`'s plug pipeline

A new `SsoSessionController` (parallel to the existing `SessionController`,
not a modification of it) handles `/auth/oidc` (redirect to IdP) and
`/auth/oidc/callback` (verify the response, look up the account, call the
existing `UserAuth.log_in_user/2` — reusing the exact same session-creation
path local login already uses, so nothing downstream of "a user is logged
in" needs to know or care which method got them there).

### 4. Dashboard login page: add a conditional "Sign in with SSO" link

Only rendered when SSO is configured (per point 1). Local email/password
form stays as the primary/only option when it isn't.

## Testing strategy

- Unit tests on the new SSO-specific user-provisioning changeset (no
  password, `auth_source: :sso`) and on `Accounts.get_user_by_email_and_password/2`
  refusing an SSO-sourced account.
- Controller tests on `SsoSessionController` using `ueberauth`'s test
  support for simulating a callback (`Ueberauth.Auth` struct construction),
  covering: successful login to a pre-provisioned matching account; rejected
  login when no matching `users` row exists; rejected login when the IdP's
  `email_verified` claim is false/absent.
- No end-to-end test against a real IdP — out of scope for this repo's test
  suite; the library's own test suite covers the OIDC protocol handshake
  itself.
