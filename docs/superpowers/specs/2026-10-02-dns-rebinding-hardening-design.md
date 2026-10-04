# DNS-rebinding hardening for MetadataEgressGuard — design spec

Date: 2026-10-02

## Problem

`MetadataEgressGuard` (`lib/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard.ex`)
resolves every `http(s)://` host found in a `:network_egress`-tagged call's
arguments and denies the call if the resolved address is loopback,
link-local/cloud-metadata, or RFC1918. This closes the straightforward SSRF
case: an agent is tricked into passing a URL whose hostname resolves directly
to a forbidden address.

The threat model (`docs/threat-model.md`) names a specific gap this doesn't
close: **DNS rebinding**. An attacker controls a hostname's DNS record and
serves two different answers close together in time — a public IP on the
lookup `MetadataEgressGuard` performs, and a private/metadata IP on a lookup
made *after* the guard has already allowed the call. If anything downstream
re-resolves the same hostname and uses the second answer, the guard's check
was defeated by a TOCTOU (time-of-check-to-time-of-use) race.

### The architectural fact that changes the fix's scope

The proxy does **not** make the outbound request that `MetadataEgressGuard`
is protecting against. Confirmed by reading the code:

- `MetadataEgressGuard.evaluate/2` only resolves hostnames to decide
  `allow`/`deny` (`metadata_egress_guard.ex:44-53`). It never issues the
  actual request.
- The only outbound HTTP call the proxy itself makes per forwarded
  `tools/call` is `Req.post(url, ...)` in
  `lib/phoenix_elxir_beam_web/controllers/mcp/proxy_controller.ex:639`, where
  `url` comes from `HttpTransport.prepare(server.base_url)` — the
  **registered upstream server's own fixed, operator-set base URL**, never
  from the call's arguments.
- The agent-controlled URL that `MetadataEgressGuard` inspects travels to the
  upstream server as JSON-RPC **payload** (inside `call.arguments`). What
  that server's own tool implementation does with that URL — including
  whether and when it makes its own outbound fetch — happens entirely inside
  the upstream server's process, outside this proxy's address space and
  outside its trust boundary.

This means there is no second, proxy-owned outbound connection to "pin the
resolved IP through to," the way earlier roadmap language phrased it
(`docs/superpowers/plans/` roadmap, Phase 1). The rebinding race, if it
happens, happens inside the upstream server, between that server's own
resolution and its own fetch — a gap this proxy cannot observe or control at
all once the call is forwarded.

## What this spec actually fixes

Given the above, full closure of DNS rebinding is out of reach from the
proxy's position in the architecture. This spec narrows to the two things
that genuinely are in reach and reduce real risk:

1. **Shrink the proxy's own TOCTOU window to zero.** Today's resolution
   already happens in `pre_call`, immediately before the pipeline forwards
   the call — so there is no meaningfully earlier or later point to move the
   check to within this proxy. Confirm this explicitly (a test pinning
   "resolution happens in the same pipeline pass that forwards the call, not
   cached from an earlier phase") rather than assume it.

2. **Treat a low-TTL or multi-answer DNS response as a stronger signal.**
   Rebinding attacks rely on a very short TTL (often 0-60s) so the attacker's
   second answer takes effect quickly, and often return multiple A records
   mixing a public decoy with a private target. `MetadataEgressGuard`
   currently takes `:inet.gethostbyname/1`'s *first* returned address and
   ignores TTL entirely. Checking **every** returned address (not just the
   first) and escalating severity when the TTL is suspiciously low is a
   real, proxy-side mitigation: it doesn't close the race, but it catches
   the common case where the attacker's forbidden-range answer is present
   in the *same* response the guard already sees, just not first in the
   list.

### Explicitly not fixed by this spec (documented, not solved)

- A rebinding attack where the forbidden answer is served **only** on a
  second lookup, made by the upstream server itself after the proxy's
  check — this requires the upstream server's own cooperation (resolve once,
  connect by the resolved IP, pin via SNI/Host) and is outside this proxy's
  control. `docs/threat-model.md`'s "Explicitly out of scope" section should
  be updated to state this precisely instead of implying the gap is purely a
  future proxy-side fix.
- Any DNS answer that changes between the Nth tool call and the N+1th in the
  same session — `MetadataEgressGuard` re-resolves on every call already (no
  caching across calls), so this case is already covered; confirmed by
  reading `resolve/1`, which performs a fresh `:inet.gethostbyname/1` call
  every invocation with no memoization.

## Changes

### 1. Check every resolved address, not just the first

`resolve/1` (`metadata_egress_guard.ex:86-98`) pattern-matches
`{:hostent, _, _, _, _, [ip_tuple | _]}` — the first address only. A
multi-answer response mixing a benign public IP first and a forbidden IP
second currently passes. Change `resolve/1` to return the full address list,
and `forbidden_target/1` to deny if **any** resolved address is forbidden.

### 2. Surface the TTL when available and escalate severity on a short one

`:inet_res.resolve/3` (lower-level than `:inet.gethostbyname/1`) exposes the
DNS response's TTL; `:inet.gethostbyname/1` does not. Switch resolution to
`:inet_res.resolve/3` to get TTL data, and when the shortest TTL among
returned records is below a threshold (60 seconds — long enough to exclude
ordinary low-TTL CDN records' typical floor, short enough to catch rebinding
tooling's defaults), include that fact in the deny reason and bump
`Finding` severity from the plugin's existing `:high` to `:critical` so it's
visibly distinguished in the audit log and dashboard — operators reviewing
a denied call should be able to tell "ordinary forbidden-range hit" from
"this smells like active rebinding" without reading plugin source.

### 3. Document the residual risk precisely

Update `docs/threat-model.md`'s DNS-rebinding bullet (currently under
"Explicitly out of scope") to state the architectural reason precisely (no
second proxy-owned request exists to pin to) rather than describing it as
solvable by a future proxy-side fix. This matters for the fundraising/
compliance narrative built on this threat model: overclaiming a fixable gap
as "on the roadmap" when it structurally cannot be fixed from this
component is a diligence risk if ever audited.

## Out of scope

- Any change to `ChainExfil`, `TaintGuard`, or other plugins.
- A general-purpose DNS-pinning library or custom resolver cache — evaluated
  and rejected: it would only protect a proxy-owned second request, which
  doesn't exist here (see "architectural fact" above).
- Asking upstream MCP servers to adopt resolve-once-connect-by-IP themselves
  — a protocol-level ask outside this repo's control, worth a line in
  `docs/threat-model.md` as a noted mitigation an operator could request of
  their own upstream vendors, not something to build.

## Testing strategy

- Unit tests on `MetadataEgressGuard` with a fake resolver (inject via
  existing test patterns in `metadata_egress_guard_test.exs`) covering:
  multi-answer responses with the forbidden IP in a non-first position;
  TTL-based severity escalation; confirm a single-answer, normal-TTL,
  non-forbidden case still allows unchanged (no regression).
- No new integration test needed — this plugin is already exercised through
  the standard pipeline `pre_call` phase tests.
