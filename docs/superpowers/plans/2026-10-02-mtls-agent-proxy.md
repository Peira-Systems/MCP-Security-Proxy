# mTLS Agent-Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a deployment that terminates TLS inside Bandit (via the existing `SSL_CERT_PATH`/`SSL_KEY_PATH` config) require and verify an agent's client certificate, as an opt-in addition to the existing API-key bearer-token auth — zero behavior change for any deployment that doesn't set the new env vars.

**Architecture:** Two new env vars (`MTLS_CA_CERT_PATH`, `MTLS_REQUIRED`) read in `config/runtime.exs`, producing `verify: :verify_peer`, `cacertfile`, and `fail_if_no_peer_cert` nested under `thousand_island_options: [transport_options: [...]]` in the endpoint's `https:` config — not as top-level `https:` keys, since Bandit only special-cases `certfile`/`keyfile` that way; everything else must go through `transport_options` or it's silently ignored. The option-building logic is extracted into a small, independently testable pure function so this one genuinely tricky piece of config has automated coverage, since the actual TLS handshake itself cannot be exercised by this repo's existing in-process `ConnTest` suite.

**Tech Stack:** Elixir, Bandit 1.12.5 (already a dependency), Erlang `:ssl` (OTP, already a transitive dependency), ExUnit.

**Spec:** `docs/superpowers/specs/2026-10-02-mtls-agent-proxy-design.md`

## Global Constraints

- `mix precommit` must pass before any commit.
- Zero behavior change when `MTLS_CA_CERT_PATH` is unset — the existing `SSL_CERT_PATH`/`SSL_KEY_PATH`-only path must produce byte-for-byte the same config it does today.
- `MTLS_CA_CERT_PATH` is only meaningful when `SSL_CERT_PATH`/`SSL_KEY_PATH` are also set (Bandit must be terminating TLS at all for peer verification to apply) — setting `MTLS_CA_CERT_PATH` alone, without the base TLS cert/key, must fail loudly at boot, not silently do nothing.
- Per the spec: `verify`/`cacertfile`/`fail_if_no_peer_cert` go under `thousand_island_options: [transport_options: [...]]`, never as top-level `https:` keys — this is the one detail most likely to be gotten wrong by pattern-matching on the nearby `certfile`/`keyfile` lines, which genuinely are top-level.

## Review Focus

- **`MTLS_CA_CERT_PATH` set without `SSL_CERT_PATH`/`SSL_KEY_PATH`.** Must raise a clear boot-time error naming the actual problem, not silently produce a `https:` config missing `certfile`/`keyfile` that then fails obscurely deep inside Bandit's own option validation.
- **`MTLS_REQUIRED` unset but `MTLS_CA_CERT_PATH` set.** Per the spec's rollout design, this must default to "verify if presented, don't require" (`fail_if_no_peer_cert: false`) — not silently default to the stricter behavior (which would surprise an operator rolling this out gradually) and not silently default to no verification at all (which would make `MTLS_CA_CERT_PATH` appear configured but do nothing).
- **The existing `SSL_CERT_PATH`/`SSL_KEY_PATH`-only deployment path (no mTLS vars at all).** Must produce exactly the same `https:` keyword list as before this plan — a regression test pinning the full expected shape, not just "it still boots."
- **A `thousand_island_options` key that might already carry other options** (it already does: `num_connections` is set there today in the `http:` block — confirm whether `https:` has its own separate `thousand_island_options` or shares config with `http:`'s, since merging this wrong could silently drop the existing `num_connections` setting from whichever block is edited).

---

### Task 1: Extract and test the mTLS option-building logic as a pure function

**Files:**
- Create: `lib/phoenix_elxir_beam/mtls_config.ex`
- Test: `test/phoenix_elxir_beam/mtls_config_test.exs`

**Interfaces:**
- Produces: `MtlsConfig.build(ssl_cert_set? :: boolean(), ca_cert_path :: String.t() | nil, required :: boolean() | nil) :: keyword() | no_return()` — returns the `thousand_island_options` keyword list to merge into the endpoint's `https:` options (empty list `[]` when `ca_cert_path` is `nil`), or raises with a clear message for the invalid "CA path set without base TLS" combination. Task 2 calls this from `config/runtime.exs`.

This task exists specifically so the config-building logic has automated
test coverage independent of actually booting the Endpoint — `config/runtime.exs`
itself isn't practically unit-testable in this codebase's existing suite,
so pulling the actual decision logic into a plain function is what makes it
testable at all.

- [ ] **Step 1: Write the failing tests**

```elixir
defmodule PhoenixElxirBeam.MtlsConfigTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MtlsConfig

  test "returns an empty keyword list when no CA path is configured" do
    assert MtlsConfig.build(true, nil, nil) == []
    assert MtlsConfig.build(false, nil, nil) == []
  end

  test "raises when a CA path is set but base TLS (cert/key) is not" do
    assert_raise RuntimeError, ~r/MTLS_CA_CERT_PATH.*SSL_CERT_PATH/, fn ->
      MtlsConfig.build(false, "/path/to/ca.pem", nil)
    end
  end

  test "defaults to verify-but-not-require when MTLS_REQUIRED is unset" do
    result = MtlsConfig.build(true, "/path/to/ca.pem", nil)

    assert result[:transport_options][:verify] == :verify_peer
    assert result[:transport_options][:cacertfile] == "/path/to/ca.pem"
    assert result[:transport_options][:fail_if_no_peer_cert] == false
  end

  test "honours MTLS_REQUIRED: true to enforce a client cert" do
    result = MtlsConfig.build(true, "/path/to/ca.pem", true)
    assert result[:transport_options][:fail_if_no_peer_cert] == true
  end

  test "honours MTLS_REQUIRED: false explicitly" do
    result = MtlsConfig.build(true, "/path/to/ca.pem", false)
    assert result[:transport_options][:fail_if_no_peer_cert] == false
  end
end
```

- [ ] **Step 2: Run to verify failure**

Run: `mix test test/phoenix_elxir_beam/mtls_config_test.exs -v`
Expected: FAIL — module undefined.

- [ ] **Step 3: Implement `MtlsConfig`**

```elixir
defmodule PhoenixElxirBeam.MtlsConfig do
  @moduledoc """
  Builds the `thousand_island_options` keyword list for optional mutual TLS
  between an agent and this proxy (Phase 1 identity work). Pulled out of
  `config/runtime.exs` as a plain function specifically so this logic has
  automated test coverage -- see
  `docs/superpowers/specs/2026-10-02-mtls-agent-proxy-design.md`.

  `verify`, `cacertfile`, and `fail_if_no_peer_cert` have no top-level
  `https:` convenience alias the way `certfile`/`keyfile` do (per Bandit's
  own docs), so they must land under `transport_options` here, not beside
  `certfile`/`keyfile` in the caller's `https:` list.
  """

  @doc """
  `ssl_cert_set?` is whether `SSL_CERT_PATH`/`SSL_KEY_PATH` are both
  present (Bandit is terminating TLS at all). `ca_cert_path` is
  `MTLS_CA_CERT_PATH`'s raw value (`nil` if unset -- mTLS stays off).
  `required` is `MTLS_REQUIRED`'s parsed boolean, or `nil` if unset
  (defaults to `false`: verify a presented cert, don't require one).

  Returns `[]` when `ca_cert_path` is `nil`. Raises when `ca_cert_path` is
  set but `ssl_cert_set?` is `false` -- there's no TLS handshake for peer
  verification to attach to in that case, and silently producing a
  `transport_options` block with no `certfile`/`keyfile` alongside it would
  fail obscurely deep inside Bandit's own startup validation instead of
  here, with a clear message, at config-build time.
  """
  @spec build(boolean(), String.t() | nil, boolean() | nil) :: keyword() | no_return()
  def build(_ssl_cert_set?, nil, _required), do: []

  def build(false, ca_cert_path, _required) when is_binary(ca_cert_path) do
    raise "MTLS_CA_CERT_PATH is set but SSL_CERT_PATH/SSL_KEY_PATH are not -- " <>
            "mutual TLS requires this proxy to be terminating TLS itself first."
  end

  def build(true, ca_cert_path, required) when is_binary(ca_cert_path) do
    [
      transport_options: [
        verify: :verify_peer,
        cacertfile: ca_cert_path,
        fail_if_no_peer_cert: required || false
      ]
    ]
  end
end
```

- [ ] **Step 4: Run to verify tests pass**

Run: `mix test test/phoenix_elxir_beam/mtls_config_test.exs -v`
Expected: PASS.

- [ ] **Step 5: Run `mix precommit`**

Run: `mix precommit`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add lib/phoenix_elxir_beam/mtls_config.ex test/phoenix_elxir_beam/mtls_config_test.exs
git commit -m "Add MtlsConfig: pure-function option building for optional agent mTLS

Pulled out of config/runtime.exs specifically so this logic has
automated test coverage -- the actual TLS handshake it configures
can't be exercised by this repo's in-process ConnTest suite, but the
decision logic (what thousand_island_options to produce for a given
combination of env vars) can be, and is the part most likely to be
gotten subtly wrong (verify_peer/cacertfile have no top-level https:
alias the way certfile/keyfile do)."
```

---

### Task 2: Wire `MtlsConfig` into `config/runtime.exs`

**Files:**
- Modify: `config/runtime.exs`

**Interfaces:**
- Consumes: `MtlsConfig.build/3` (Task 1).

- [ ] **Step 1: Confirm `http:` and `https:` have independent `thousand_island_options`**

Phoenix's Endpoint starts one Bandit child process per configured scheme —
`http:` and `https:` are two separate listeners, each receiving only its
own keyword list as that listener's options. The existing
`thousand_island_options: [num_connections: 16_384]` under `http:`
(`config/runtime.exs:235`) therefore has no bearing on `https:`'s own
options — Task 2's change adds a fresh `thousand_island_options` under
`https:`, it does not need to merge with or preserve anything from the
`http:` block. Before writing Step 2, run
`grep -n "thousand_island_options" config/runtime.exs` to confirm there
isn't already one under the `https:` block from some change made after this
plan was written — if there is, merge into it with `Keyword.merge/2` rather
than appending a second, conflicting `thousand_island_options` key (a
`case`/keyword-list literal with a duplicate key doesn't error in Elixir,
it silently keeps only the last one, which would be an easy way to lose
whichever side's value comes first).

- [ ] **Step 2: Add the new env var reads and wire `MtlsConfig.build/3` into the `https:` block**

In `config/runtime.exs`, modify the existing `case {System.get_env("SSL_CERT_PATH"), ...}` block:

```elixir
  mtls_ca_cert_path = System.get_env("MTLS_CA_CERT_PATH")

  mtls_required =
    case System.get_env("MTLS_REQUIRED") do
      nil -> nil
      value -> value in ~w(true 1 yes)
    end

  case {System.get_env("SSL_CERT_PATH"), System.get_env("SSL_KEY_PATH")} do
    {cert, key} when is_binary(cert) and is_binary(key) ->
      mtls_options = PhoenixElxirBeam.MtlsConfig.build(true, mtls_ca_cert_path, mtls_required)

      config :phoenix_elxir_beam, PhoenixElxirBeamWeb.Endpoint,
        https:
          [
            port: String.to_integer(System.get_env("SSL_PORT", "443")),
            cipher_suite: :strong,
            certfile: cert,
            keyfile: key
          ] ++ mtls_options

    _ ->
      # Still validate: a misconfigured MTLS_CA_CERT_PATH with no base TLS
      # must fail loudly at boot, not silently do nothing.
      PhoenixElxirBeam.MtlsConfig.build(false, mtls_ca_cert_path, mtls_required)
      :ok
  end
```

(Adjust the exact merge shape per what Step 1 found — if `https:`'s
`thousand_island_options` must merge with an existing one rather than being
appended fresh, use `Keyword.merge/3` with an explicit conflict resolution
instead of `++`, and say so in this step's own code rather than leaving the
`++` version in if Step 1 found it to be wrong.)

- [ ] **Step 3: Verify the existing `SSL_CERT_PATH`-only path is unchanged**

Since `config/runtime.exs` only runs under `MIX_ENV=prod` (`Config.config_env() == :prod` typically gates the whole `if` block this lives in — confirm this), it cannot be exercised by `mix test` directly. Instead, write a small script-based check:

Run: `MIX_ENV=prod SECRET_KEY_BASE=$(mix phx.gen.secret) PHX_HOST=test.example.com SSL_CERT_PATH=/tmp/fake-cert.pem SSL_KEY_PATH=/tmp/fake-key.pem mix run -e 'IO.inspect(Application.get_env(:phoenix_elxir_beam, PhoenixElxirBeamWeb.Endpoint)[:https])'`

Expected output: `[port: 443, cipher_suite: :strong, certfile: "/tmp/fake-cert.pem", keyfile: "/tmp/fake-key.pem"]` — no `transport_options` key at all, confirming zero change to the existing path when `MTLS_CA_CERT_PATH` is unset. (This reads config only; it does not actually start the Endpoint or require the fake cert files to be valid/readable, since `mix run -e` with a config-reading one-liner doesn't trigger Bandit's own startup validation — if it does in practice, adjust to use `mix eval` against just the config compilation step, or touch empty files at those paths first so the read doesn't fail for an unrelated reason.)

- [ ] **Step 4: Verify the new mTLS path produces the expected shape**

Run the same style of command with `MTLS_CA_CERT_PATH=/tmp/fake-ca.pem` added, and confirm the output's `https:` value includes `transport_options: [verify: :verify_peer, cacertfile: "/tmp/fake-ca.pem", fail_if_no_peer_cert: false]` nested correctly per whatever Step 1 determined the correct merge shape to be.

- [ ] **Step 5: Verify the invalid combination raises at config-build time**

Run the same command with `MTLS_CA_CERT_PATH` set but `SSL_CERT_PATH`/`SSL_KEY_PATH` unset — expect the command to fail with the `MtlsConfig.build/3` raise's message surfaced, not a silent no-op and not an obscure Bandit startup crash.

- [ ] **Step 6: Run `mix precommit`**

Run: `mix precommit`
Expected: PASS. (Note `mix precommit` runs under `MIX_ENV=test`/dev as applicable per this repo's existing alias definition — confirm it doesn't also need a `MIX_ENV=prod mix compile` check; if `docs/ci-cd.md` mentions one, run that too per its documented command.)

- [ ] **Step 7: Document the new env vars and the reverse-proxy alternative**

In `docs/deployment.md`, add a section documenting `MTLS_CA_CERT_PATH` and
`MTLS_REQUIRED` (only meaningful alongside `SSL_CERT_PATH`/`SSL_KEY_PATH`),
and the reverse-proxy-terminated-TLS alternative per the spec's Scope
decision — a short, explicitly-unmaintained-by-this-repo example Caddy
`client_auth` directive as a starting point for an operator using that
topology instead.

- [ ] **Step 8: Commit**

```bash
git add config/runtime.exs docs/deployment.md
git commit -m "Wire optional mTLS into the Bandit-terminated TLS path

MTLS_CA_CERT_PATH/MTLS_REQUIRED are no-ops unless SSL_CERT_PATH/
SSL_KEY_PATH are also set; setting the CA path without base TLS fails
loudly at boot via MtlsConfig.build/3's raise rather than silently
doing nothing. A deployment terminating TLS at a reverse proxy instead
needs to configure client-cert verification there -- documented, not
built, since this repo doesn't own that proxy's config."
```
