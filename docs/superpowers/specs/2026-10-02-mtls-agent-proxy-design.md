# mTLS between agent and proxy — design spec

Date: 2026-10-02

## Correcting the roadmap's framing

The build-out roadmap describes mTLS as something to "promote from an
opt-in reverse-proxy layer to a first-class, documented configuration."
Reading `config/runtime.exs` shows there is no mTLS capability in this
codebase today at any level:

- The `https:` block (`config/runtime.exs:251-263`) configures **server**
  TLS only — `certfile`/`keyfile` for Bandit to present to clients. It has
  no `verify`, `cacertfile`, or any client-certificate option.
- The reverse-proxy note in that same block ("Docker Compose reference
  setup puts a reverse proxy in front for TLS instead") describes
  *server*-side TLS termination choice (terminate in the app vs. in
  Caddy/nginx in front of it), not mutual TLS. There is no Caddy/nginx
  config file in this repo configuring client-cert verification either.
- `ApiKeyAuth` (`lib/phoenix_elxir_beam_web/plugs/api_key_auth.ex`) is the
  only authentication the `:mcp_api` pipeline performs — a bearer token,
  nothing TLS-layer-based.

So this spec is not "promoting" or "documenting" an existing opt-in
feature — it's adding mTLS support from nothing. Worth being precise about
this in any public-facing roadmap or fundraising material downstream of
this plan: claiming to "formalize an existing opt-in layer" when no such
layer exists would be an overclaim a technical diligence review would
catch immediately.

## Goal

Let a deployment that terminates TLS inside this app (Bandit, via the
existing `SSL_CERT_PATH`/`SSL_KEY_PATH` config) require and verify a client
certificate from the connecting agent, as an additional authentication
factor layered on top of — not replacing — the existing API-key bearer
token. Entirely opt-in: a deployment that doesn't set the new env vars
sees zero behavior change.

## Decisions

### Scope: Bandit-terminated TLS only, not the reverse-proxy path

`config/runtime.exs`'s own comment already states the Docker Compose
reference setup terminates TLS at a reverse proxy (Caddy/nginx) in front of
the app, not in Bandit. Mutual TLS verification has to happen at whichever
layer terminates TLS, since that's the only layer that ever sees the raw
TLS handshake and the client's presented certificate. **This spec covers
the Bandit-terminates-TLS path only** (`SSL_CERT_PATH`/`SSL_KEY_PATH` set),
since that's the path this codebase actually controls. A deployment using
the reverse-proxy path that wants mTLS must configure client-cert
verification in that proxy's own config (Caddy/nginx) and forward the
verified client cert's identity to the app via a header the proxy sets
after verifying the handshake — documented as an operator responsibility,
not built by this plan, since this repo doesn't own or ship that proxy's
configuration.

### Mechanism: standard Erlang `:ssl` peer verification via Bandit's transport options

Bandit (on Thousand Island, on Erlang's `:ssl`) accepts `certfile`/`keyfile`
as top-level convenience keys in the endpoint's `https:` list (this
codebase already uses exactly that shape, `config/runtime.exs:251-259`),
but per Bandit's own docs those convenience keys are shorthand for setting
the same-named option inside
`thousand_island_options: [transport_options: [...]]` — which is also
already a pattern this codebase uses for a different Thousand Island option
(`num_connections`, `config/runtime.exs:235`, with a comment explicitly
warning about a very similar naming trap: `max_connections` doesn't exist
and crash-loops the release). `verify`, `cacertfile`, and
`fail_if_no_peer_cert` have no top-level convenience alias, so they must be
set directly under `thousand_island_options: [transport_options: [...]]`,
not alongside `certfile`/`keyfile` in the outer `https:` list — getting
this nesting wrong produces exactly the kind of silent-until-prod-boot
failure that existing comment warns about. No new dependency: this is
OTP's own TLS stack, already a transitive dependency of Bandit.

### What "verified" means for policy purposes: TLS-layer only, not identity propagation

This spec adds **connection-level** mutual authentication — the TLS
handshake fails closed if the client doesn't present a cert signed by the
configured CA. It does **not** attempt to extract an identity from the
client certificate's subject/SAN and feed it into `agent_id` or
`ctx.call[:agent_id]` — that's a meaningfully different, larger feature
(mapping a cert's DN to a policy-relevant identity, with its own trust and
revocation-checking questions, e.g. CRL/OCSP) that overlaps with but is
distinct from the separate per-agent-identity spec in this same Phase 1
batch. Keeping them separate avoids conflating "is this connection from a
holder of a trusted client cert" (this spec) with "which specific agent is
this, for policy-matching purposes" (the other spec, solved via
`X-Agent-Credential` instead, which doesn't require operating a private CA
at all). A future spec could combine them; this one deliberately doesn't.

## Out of scope

- Client-certificate identity extraction / mapping to `agent_id` — see
  above.
- CRL or OCSP revocation checking for presented client certs — `cacertfile`
  verification without revocation checking is a real, if incomplete,
  security improvement (the agent must hold a key signed by a trusted CA at
  all) and is consistent with this project's existing posture of shipping
  an incremental, documented improvement rather than a complete PKI
  lifecycle in one pass.
- Reverse-proxy-terminated mTLS configuration (Caddy/nginx client-cert
  verification + header-forwarding convention) — documented as an operator
  responsibility, not built here, per the Scope decision above.
- Any change to `ApiKeyAuth` or the bearer-token flow — mTLS is additive,
  layered underneath it at the transport level, not a replacement.

## Changes

### 1. New opt-in env vars: `MTLS_CA_CERT_PATH`, `MTLS_REQUIRED`

Read in `config/runtime.exs`, only meaningful when `SSL_CERT_PATH`/
`SSL_KEY_PATH` are already set (Bandit terminates TLS). When
`MTLS_CA_CERT_PATH` is set, the `https:` option list gains `cacertfile`,
`verify: :verify_peer`. `MTLS_REQUIRED` (boolean, default `false` when
`MTLS_CA_CERT_PATH` is set) controls `fail_if_no_peer_cert` — `false` lets
an operator roll this out in a "log but don't yet enforce" mode first
(verify-if-presented), consistent with this project's existing dry-run
rollout convention used elsewhere (`MetadataEgressGuard`'s own dry-run-pin
note, the dashboard's per-plugin dry-run mode).

### 2. Document the reverse-proxy alternative path

A new section in `docs/deployment.md` stating plainly: if TLS terminates
at a reverse proxy instead of Bandit, mTLS must be configured there, and
giving a concrete, minimal Caddy example (`client_auth` directive) as a
starting point an operator can adapt — not a maintained, tested config
this repo ships, but enough to not leave an operator with nothing.

## Testing strategy

- No unit test can exercise a real TLS handshake with a client cert inside
  this repo's existing `ExUnit`/`ConnTest` suite, which talks to the
  Endpoint in-process, not over a real socket. This spec's testing is
  necessarily a **manual verification procedure**, documented in the plan,
  not an automated test — stated explicitly rather than invented as a fake
  automated test that wouldn't actually prove anything.
- The one thing that *can* be tested automatically: that `config/runtime.exs`
  produces the expected keyword list shape given each combination of the
  new env vars (set/unset `MTLS_CA_CERT_PATH`, set/unset `MTLS_REQUIRED`) —
  a pure function extraction worth doing specifically so this logic has
  some automated coverage, covered in the plan below.
