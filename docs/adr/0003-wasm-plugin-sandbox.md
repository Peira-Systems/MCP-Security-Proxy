# ADR 0003 — Wasm plugin sandbox

**Status:** Proposed · **Date:** 2026-09-14 · **Supersedes:** ADR-0001 §3 (Wasm clause)

## Context

ADR-0001 named three plugin bindings and deliberately built only two:

- **in-process** Elixir modules — fastest, but only as trustworthy as the release image
  itself; a bug crashes the same BEAM the proxy runs in.
- **sidecar** (stdio/HTTP JSON-RPC) — the polyglot answer, shipped in step 5. Crash
  isolation is free (a separate OS process), but that isolation is coarse: a sidecar has
  whatever filesystem/network access the host or container grants it, a hung call leaves
  the subprocess running until something else notices (`SidecarRunner`'s per-request
  timeout stops *waiting*, it does not stop the process), and every call pays real IPC
  latency (`docs/plugin-protocol.md` §5.1).
- **Wasm** — deferred with the explicit note "revisit once a concrete 'untrusted fast
  policy' need exists" (ADR-0001 §3).

That need is now concrete enough to act on, for two independent reasons:

1. **A stronger isolation story than a sidecar can offer, in-process.** Wasmtime enforces
   memory safety on the *compiled bytecode itself* — a guest cannot read or write outside
   its own linear memory no matter what it executes, and a runaway loop is interrupted by
   the host, not merely abandoned. This is a materially different trust boundary than "an
   OS process the operator has to sandbox separately" (`docs/plugin-supply-chain.md`'s
   sidecar section: `prlimit` is explicitly *best-effort* and Linux-only). It is also a
   different trust boundary than the native-NIF option ADR-0001 rejected outright — a NIF
   crash can bring down the VM; a Wasm trap cannot, because the code that runs is
   compiler-verified before Wasmtime will execute it at all.
2. **Lower latency than a sidecar's IPC round-trip**, because there is no subprocess and no
   line-based JSON-RPC framing to parse — the call is a direct (if cross-runtime) function
   invocation inside the same OS process, bounded by Wasmtime's own interrupt mechanism
   rather than a BEAM `Task` racing a subprocess that may not actually stop.

This ADR keeps ADR-0001's core design intact — **one contract, many bindings**
(`docs/plugin-protocol.md`): `CallContext`, `Decision`, `Finding`, and the manifest are
unchanged. Wasm becomes a **third binding** of the same contract, not a new plugin model.

## Decision

### 1. Scope: first-party plugins only, not a third-party upload path

Wasm plugins are **built from source in this repo and pinned like sidecars are today**
(code digest + manifest digest, `docs/plugin-supply-chain.md`). There is no dashboard
upload of an operator-supplied `.wasm` file, no plugin marketplace, no registry of
external plugin binaries. The goal is *a faster, more strongly sandboxed way to run our own
plugins*, not opening the proxy to arbitrary untrusted bytecode from other authors.

**Why:** accepting arbitrary uploaded bytecode at runtime is a fundamentally different,
larger threat model — storage, format validation, signing, an upload-authz story, and
*someone else's* code running with whatever WASI capabilities get granted. That is a
follow-on ADR if a concrete need for it ever shows up (third-party contributors, a plugin
gallery). Building the runtime plumbing first, against plugins we already trust and already
have a known-good Elixir reference for, is the lower-risk order.

### 2. Wire contract: reuse the sidecar's JSON schema, not WASI Components/WIT

A Wasm plugin speaks the **same JSON shapes** as a sidecar — `CallContext`, `Decision`,
`Finding`, `Manifest` (`docs/plugin-protocol.md` §7–8) — over a minimal guest ABI (§5.4,
added by this ADR's implementation plan), not a typed WASI Component Model / WIT interface.

**Why:** `PhoenixElxirBeam.MCP.Plugin.Wire` already encodes/decodes this exact schema and is
transport-agnostic — it operates on structs in, maps out, with no knowledge of *how* those
maps cross a boundary. Reusing it as-is for Wasm (only the transport call changes: a
function invocation instead of a line written to a `Port`) means a plugin author who already
knows the sidecar protocol needs to learn one new thing — the guest ABI — not a second data
model. The WASI Component Model is the more "correct" long-term interface (typed, generated
bindings, no hand-rolled byte-passing), but its tooling and the Elixir binding story for it
are still immature; adopting it now would be optimizing an interface this project doesn't
have two real consumers of yet, for the same reason ADR-0001 avoided the same mistake with
the v0.1 sidecar contract itself ("expect this to change as it meets its first real
implementation" — plugin-protocol.md's own framing).

**Considered and rejected: depending on the Extism host SDK instead of raw `wasmex`.**
Extism (also built by `wasmex`'s maintainer, also on Wasmtime) already solves exactly this
"pass JSON/bytes in, get bytes out, sandbox the guest" problem, with mature PDKs in several
languages. It was not chosen for v1 because (a) its Elixir host SDK is itself a wrapper
around `wasmex` — a second dependency layer to trust and pin, not a lighter one — and (b)
its plugin-side calling convention (`call("op_name", input)` per exported op) doesn't match
the single `handle(request) -> response` dispatch this proxy's sidecars already use, which
would mean writing the ABI adapter either way. The guest ABI specified here is *modeled on*
Extism's proven `alloc`/set-output pattern rather than invented from nothing, and this
choice is worth revisiting if the hand-rolled version proves fiddlier than expected during
implementation.

### 3. Runtime library: `wasmex` (Wasmtime), as ADR-0001 already named

No change from ADR-0001's original proposal. `wasmex` wraps Wasmtime through a Rust NIF,
ships precompiled NIF binaries (so this does **not** require a Rust toolchain on every
build/deploy machine — only wherever a plugin's *guest* `.wasm` is compiled, which is a
one-time build artifact checked into the repo like `prompt_injection_scanner.py` is today),
and gives per-call timeouts that interrupt a running guest and leave the runtime reusable
for the next call — not a hard kill of an OS process.

**Risk carried forward explicitly:** `bcrypt_elixir`'s NIF would not build on this project's
Windows dev box, which is why the codebase runs on `pbkdf2_elixir` instead
(`productionization-roadmap.md`). `wasmex` is also a Rust NIF. Its precompiled-binary
coverage for this exact dev environment is **not yet confirmed** — that is the first thing
the implementation plan verifies (W0), before any further design work is treated as
load-bearing. If precompiled NIFs are unavailable for this Windows box specifically, the
fallback is developing/testing against the Linux CI runner and the Docker build stage only
— annoying, not fatal, since production only ever runs the Linux release image.

### 4. CPU/time bound: reuse `entry.timeout_ms`, no new per-plugin config

A Wasm call is bounded by the **same `timeout_ms` every plugin already declares** in its
manifest — no separate fuel budget, no new manifest field. `wasmex`'s per-call timeout
already interrupts guest execution at that boundary (confirmed against a wall-clock
deadline, not merely "stop waiting" the way a sidecar timeout does today), and the existing
`Pipeline` `Task.yield`/`Task.shutdown(:brutal_kill)` wrapper (`pipeline.ex`) wraps the Wasm
call exactly as it already wraps every other binding — a second, independent bound with zero
new code. This is a genuine improvement over the sidecar path, not just parity with it: a
sidecar that ignores its deadline keeps burning CPU until something else (the circuit
breaker, an operator) notices; a Wasm call that hits its deadline is actually stopped.

Memory is capped per-instance via `wasmex`'s engine/store configuration (linear memory page
limit) — a new `limits: [memory_pages: N]` key on the plugin spec, parallel to the
sidecar's `limits: [as_mb:, cpu_s:, nproc:]`, but **enforced by the Wasm runtime itself**
rather than best-effort via `prlimit` (which needs `util-linux` on the host and is a no-op
elsewhere). This is a second concrete hardening win, not just a config-shape parallel.

### 5. Capability grants: no network, no filesystem, by default — structurally, not by policy

A Wasm guest gets **no WASI imports linked** beyond what it needs to run at all (no
filesystem preopens, no sockets, no environment variables). This is enforced by the host
simply not providing those import functions — a guest that tries to call an unlinked import
fails to instantiate, not "is trusted not to." This is strictly stronger than the sidecar
model's `requiresNetwork` flag, which today is **declarative only** — the operator vets it,
but a sidecar subprocess otherwise has whatever OS-level network access the host or
container permits (`docs/plugin-protocol.md` §12: "the operator vets those grants"). Network
access for a Wasm plugin is out of scope for v1 entirely (no plugin in this plan needs it);
revisit if a concrete Wasm plugin ever does, the same way OTel export was deferred until
there was a concrete consumer for it.

### 6. Reference plugin: port `RuleEngine`, prove parity, don't replace it

The first Wasm plugin is a Rust port of `PhoenixElxirBeam.MCP.Plugins.RuleEngine` — pure,
config-driven, no I/O, no secret handling, easy to diff call-for-call against the trusted
Elixir original. It ships **alongside** the existing in-process `RuleEngine`, disabled by
default, not as a replacement — the acceptance bar is a parity test asserting identical
`Decision`s across a shared corpus of `(rules, CallContext)` inputs, not merely "it runs."

## Consequences

**Positive**

- A materially stronger sandbox for plugin logic than a sidecar offers, with less
  operational surface (no subprocess lifecycle, no `prlimit` dependency, no per-call IPC).
- A concrete, measurable safety improvement even for plugins that don't strictly need it:
  a Wasm call that misbehaves is actually interrupted; a sidecar call that misbehaves keeps
  running.
- No change to the wire contract or to `Pipeline`'s bounded-evaluation machinery — the new
  binding slots into `entry.impl` exactly where `{:sidecar, name}` does today.

**Negative / costs**

- A new native dependency (`wasmex`) with an unconfirmed Windows precompiled-NIF story on
  this specific dev box — carried as an explicit go/no-go gate (W0), not assumed away.
- Plugin authors need a `wasm32-wasip1` Rust toolchain to build a Wasm plugin, on top of
  (not instead of) the existing sidecar option — a second build pipeline to document and
  maintain (`docs/plugin-supply-chain.md`).
- The guest ABI (§5.4) is new surface with no prior art in this codebase to lean on, unlike
  the sidecar transport which reused `StdioServer`'s existing framing almost verbatim.

**Neutral**

- The in-process Elixir binding and the sidecar binding are unchanged by this ADR. A plugin
  author still picks the binding that fits: in-process for first-party/performance-critical
  code that's fine sharing fate with the BEAM, sidecar for arbitrary languages/remote
  services, Wasm for sandboxed first-party logic on the request path.

## Roadmap

See [`docs/wasm-plugin-plan.md`](../wasm-plugin-plan.md) for the milestone-by-milestone
implementation plan (W0 runtime spike / go-no-go → W1 guest ABI + protocol doc → W2
`WasmRunner` + `Registry` integration → W3 `Pipeline` dispatch → W4 reference plugin +
parity test → W5 dashboard + docs).

## References

- ADR-0001 §3 (this ADR's direct predecessor for the Wasm clause).
- `docs/plugin-protocol.md` — the contract this ADR extends with a third binding.
- `docs/plugin-supply-chain.md` — the provenance-pinning pattern this ADR extends to Wasm.
- [Wasmtime](https://wasmtime.dev/) / [`wasmex`](https://github.com/tessi/wasmex) — the
  Elixir NIF binding this ADR depends on.
- [Extism](https://extism.org/) — considered and not adopted as a dependency (§2), but its
  guest ABI pattern informs the one specified here.
