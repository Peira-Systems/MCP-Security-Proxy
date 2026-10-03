# Phase 1 — Identity & Trust Boundary: Plan Index

Date: 2026-10-02

This indexes four independent spec+plan pairs implementing the Build-Out
Roadmap's Phase 1 ("Identity & trust boundary") — the roadmap itself is a
published artifact (`MCP Proxy Build-Out Roadmap`), not a file in this
repo; see that document for the full 7-phase sequence this is one piece
of. Each plan here produces working, shippable software on its own — none
depend on another completing first, and they can be implemented and merged
in any order, or in parallel by different people.

## Why four plans instead of one

Phase 1 bundles four independent pieces of work. Per this project's
planning conventions, a spec covering multiple independent subsystems gets
split into one plan per subsystem rather than one large plan, so each
piece carries its own test cycle and review gate.

## Corrections made while researching these plans

Writing these specs required reading the actual code behind each roadmap
item, which surfaced three places where the original roadmap's framing was
inaccurate. Each correction is documented in full in its own spec; summarized
here for visibility:

1. **DNS-rebinding fix** — the roadmap implied the proxy could "pin the
   resolved IP through to the actual outbound request." It can't: the
   vulnerable fetch happens inside the *upstream MCP server's own process*,
   not inside this proxy, which never makes that request itself. The spec
   re-scopes to what's actually achievable from this component (check every
   DNS answer, escalate severity on a suspiciously short TTL) and documents
   the residual, architecturally-unclosable gap precisely instead of
   implying it's fully fixable from here.
2. **Per-agent identity** — the roadmap described this as "API key = tenant,"
   implying no agent-level identity exists today. In fact `agent_id` is
   already a first-class, rule-matchable field
   (`RuleEngine`'s `agent(ctx), do: ctx.call[:agent_id]`) — the real gap is
   narrower: `agent_id` is a fixed string an admin types in at key-issuance
   time, not a claim the calling agent proves. The spec targets that
   narrower, more precise gap.
3. **mTLS** — the roadmap described promoting mTLS "from an opt-in
   reverse-proxy layer to a first-class configuration," implying partial
   support exists. There is no mTLS capability anywhere in this codebase
   today, at any layer. The spec builds it from nothing and is explicit
   that no prior art is being "promoted."

These corrections matter beyond engineering accuracy: the roadmap and
comparison documents built on top of this project's current-state claims
feed directly into fundraising material. Overclaiming a capability as
"partially there" when it doesn't exist, or describing a fix as achievable
when it structurally isn't, is exactly the kind of gap a technical
diligence reviewer would catch — better caught here.

## The four plans

| # | Spec | Plan | Scope |
|---|------|------|-------|
| 1 | [`2026-10-02-dns-rebinding-hardening-design.md`](../specs/2026-10-02-dns-rebinding-hardening-design.md) | [`2026-10-02-dns-rebinding-hardening.md`](2026-10-02-dns-rebinding-hardening.md) | Check every DNS answer `MetadataEgressGuard` resolves (not just the first), escalate severity on a short-TTL forbidden hit. 3 tasks. |
| 2 | [`2026-10-02-operator-oidc-sso-design.md`](../specs/2026-10-02-operator-oidc-sso-design.md) | [`2026-10-02-operator-oidc-sso.md`](2026-10-02-operator-oidc-sso.md) | OIDC SSO login for operators (Okta/Entra/Google Workspace) via `ueberauth` + `ueberauth_oidcc`, admin-pre-provisioned accounts only. 4 tasks. |
| 3 | [`2026-10-02-per-agent-identity-design.md`](../specs/2026-10-02-per-agent-identity-design.md) | [`2026-10-02-per-agent-identity.md`](2026-10-02-per-agent-identity.md) | A new `AgentCredential` + `X-Agent-Credential` header lets an agent assert a verified `agent_id`, independent of the API key authenticating its connection. 3 tasks. |
| 4 | [`2026-10-02-mtls-agent-proxy-design.md`](../specs/2026-10-02-mtls-agent-proxy-design.md) | [`2026-10-02-mtls-agent-proxy.md`](2026-10-02-mtls-agent-proxy.md) | Optional client-certificate verification when Bandit terminates TLS, via `thousand_island_options: [transport_options: [...]]`. 2 tasks. |

## Suggested implementation order

No hard dependencies exist between these four, but if sequencing for a
single implementer's convenience:

1. **DNS-rebinding hardening** first — smallest, single-file, no new
   dependencies, good warm-up to validate the team's process on this
   codebase.
2. **Per-agent identity** second — also no new dependencies, and its
   `AgentCredential` pattern directly mirrors the already-proven `ApiKey`
   pattern, so it's a good second step before introducing new external
   dependencies.
3. **OIDC SSO** third — introduces two new dependencies (`ueberauth`,
   `ueberauth_oidcc`) and a migration; most externally-facing of the four
   (an enterprise buyer's first question in a sales conversation).
4. **mTLS** last — smallest in task count but requires manual verification
   against a real TLS handshake outside the automated test suite (see that
   plan's Testing Strategy), so it benefits from being done once the team
   has a deployment environment set up from the earlier three.

## What's left in Phase 1 after these four

The original roadmap's Phase 1 is now fully covered by these four plans.
Phase 2 (detection depth: ML injection classifier, split-secret detection,
baselining v2, side-channel mitigation) is the next roadmap phase and has
no plans written yet.
