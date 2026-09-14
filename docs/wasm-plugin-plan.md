# Wasm plugin sandbox — implementation plan

**Status:** Ready to implement · **Date:** 2026-09-14 · **Implements:** [ADR-0003](adr/0003-wasm-plugin-sandbox.md)

This is the execution plan for ADR-0003. The ADR records *what* and *why*; this document
sequences it into shippable milestones with acceptance criteria, mirroring how
`docs/productionization-plan.md` implements ADR-0002.

## Decisions locked (ADR-0003)

1. **First-party only.** No operator-uploaded `.wasm`, no third-party plugin path.
2. **JSON message-passing**, not WASI Components/WIT — reuses `Plugin.Wire` unchanged.
3. **`wasmex`/Wasmtime**, as ADR-0001 originally named.
4. **CPU bound = the existing `entry.timeout_ms`.** No new fuel/epoch config.
5. **No WASI network or filesystem capability in v1**, structurally (no imports linked).
6. **Reference plugin = a Rust port of `RuleEngine`**, shipped alongside the original,
   validated by a parity test — not a replacement.

### Explicit non-goals (this plan)

- Third-party / operator-uploaded Wasm modules (ADR-0003 §1).
- WASI networking or filesystem access for any v1 plugin.
- Porting any plugin that touches secrets/taint (`SecretLeak`, `TaintedArgGuard`) — those
  stay in-process; nothing about this plan changes how raw secret material is handled, and
  the reference plugin is deliberately chosen to avoid touching that question at all.
- Fuel-based (instruction-counted) limiting — deferred; revisit only if wall-clock epoch
  interruption proves insufficient in practice.

---

## Milestone map

| Milestone | Goal | Gate |
|---|---|---|
| **W0 — Runtime spike** | Confirm `wasmex` actually loads and runs on every environment this project builds on. | **Go/no-go.** Nothing below is committed until this passes. |
| **W1 — Guest ABI + protocol doc** | The wire-level contract a Wasm plugin implements is written down and worked-example'd. | Doc review. |
| **W2 — `WasmRunner` + `Registry`** | A `{:wasm, opts}` plugin spec spawns, handshakes, and is provenance-checked, independent of any pipeline dispatch. | Hermetic echo-fixture test green. |
| **W3 — `Pipeline` dispatch** | `entry.impl == {:wasm, name}` flows through `pre_call` / `post_call` / `discovery` exactly like `{:sidecar, name}` does today. | `pipeline_wasm_test` green. |
| **W4 — Reference plugin** | `rule-engine-wasm` matches `RuleEngine`'s verdicts call-for-call. | Parity suite green. |
| **W5 — Dashboard + docs** | Operators can see a Wasm plugin's health/transport in the existing Plugins panel; supply-chain docs cover it. | Manual verification + doc sync. |

Do not skip W0. It is cheap (a few hours) and the one place this plan could be wrong in a
way that isn't a design decision — a missing precompiled NIF for this dev box is a fact to
discover, not a risk to accept silently, the same lesson `bcrypt_elixir` already taught this
project once.

---

## W0 — Runtime spike (go/no-go)

**Do this before writing any of W1–W5's real code.** A throwaway branch is fine.

1. Add `{:wasmex, "~> 0.15"}` (confirm the current version on hex.pm at implementation
   time) to `mix.exs`. `mix deps.get`.
2. Confirm the NIF loads with **no Rust toolchain present** (i.e. the precompiled binary
   path, not a source build) on:
   - this Windows dev box (`mix run --no-start -e 'Wasmex.Engine.new(...)' ` or similar —
     the exact smoke check depends on `wasmex`'s current top-level API; the point is
     "loads without invoking `cargo`");
   - the `ci.yml` Linux runner (a scratch step, removed before merging real work);
   - the `Dockerfile` `builder` stage image (`hexpm/elixir:...-debian-bookworm...`).
3. While in there, confirm against the *actual* current `wasmex` docs (not this plan's
   description of them, which was written from hexdocs at spec time and may drift):
   - the exact engine/store API for capping linear memory (a page-count or byte limit);
   - the exact WASI-linking API (how to instantiate **without** filesystem/socket imports
     — confirm the "no `wasi: true`" / no-WASI path actually omits all ambient authority,
     not just filesystem);
   - whether `call_function/3,4`'s timeout is a true interruption (the store stays usable
     afterward) or something narrower — this plan's §"CPU bound" design in ADR-0003 depends
     on it being real interruption, not just "stop waiting."
   - whether multi-value returns (`(i32, i32)`) come back from `call_function` as a plain
     list, as this plan's guest ABI (W1) assumes.
4. Write a 5-line Rust "echo" guest (`wasm32-wasip1` target, exports `alloc`/`handle`,
   echoes its input JSON back as its output JSON), compile it, call it from `iex -S mix`.

**Go:** all of the above works, or works with a documented, acceptable narrowing (e.g. "no
Windows precompiled NIF — development and testing happen against Linux CI /
`docker compose` only, same as `bcrypt_elixir`'s situation today, which is already how this
project works around it"). Proceed to W1.

**No-go:** if `wasmex` cannot be loaded in *any* form on the Linux CI runner or the
production image (not just this Windows box), stop and bring the finding back — that
would mean re-opening ADR-0003 §3's runtime-library choice, not silently proceeding.

### Findings (2026-09-14) — **GO**, with two concrete follow-ups

Ran on a throwaway `spike/wasm-w0` branch: `{:wasmex, "~> 0.15"}` added to `mix.exs`,
`mix deps.get`, then a WAT-authored (no external toolchain needed —
`Wasmex.Wat.to_wasm/1` compiles WAT text via the NIF itself) spike module exercising
instantiation, a plain call, the full `alloc`/`handle` guest-ABI round trip (§W1), a
deliberately infinite-looping export against a timeout, and `Wasmex.StoreLimits` memory
capping. Run twice: natively on this Windows dev box, and inside a container built from
the **exact** `hexpm/elixir:1.17.3-erlang-27.1.2-debian-bookworm-20241202-slim` image the
`Dockerfile` builder stage and `ci.yml` both pin — covering all three target environments
with one script. Results were **identical** on both platforms.

**Confirmed good:**

- Precompiled NIFs exist and load with **no Rust/cargo toolchain present** for both
  `x86_64-pc-windows-msvc` and `x86_64-unknown-linux-gnu` — the core go/no-go question.
  `bcrypt_elixir`'s Windows build failure does **not** recur here; `wasmex` ships a
  binary for this exact box.
- The `alloc`/`handle` guest ABI (§W1) works exactly as specced: host writes N bytes into
  guest linear memory at a pointer returned by `alloc`, calls `handle(ptr, len)`, gets back
  a `(ptr, len)` pair via genuine Wasm multi-value return, reads those bytes back — a real
  JSON `call/evaluate`-shaped payload round-tripped byte-for-byte.
- `Wasmex.StoreLimits{memory_size: N}` enforces a hard cap — `memory.grow` past it returns
  Wasm's own `-1` failure sentinel (not a crash, not a silent no-op), confirming the
  `limits: [memory_pages: N]` design (ADR-0003 §4) is directly implementable.
- An infinite-loop export (`(loop $l (br $l))`) against `call_function/4`'s timeout does
  not hang the caller, the runtime, or the instance's process — `Process.alive?/1` stays
  `true` and other instances keep responding normally throughout.
- `Wasmex.Wat.to_wasm/1` means every fixture this plan needs (the W2 echo fixture, W4's
  hermetic tests) can be authored as inline WAT text in a `.exs` test file — no `wasm32-
  wasip1` Rust toolchain needed for *fixtures*, only for the real `rule-engine-wasm`
  plugin itself (W4).

**Two concrete follow-ups this finding adds to the plan:**

1. ~~`wasmex` 0.15.1 declares `elixir: "~> 1.18"`; this project pins Elixir
   `1.17.3`~~ — **done, 2026-09-14.** Bumped `Dockerfile` (`ELIXIR_VERSION` 1.17.3→1.18.5,
   `OTP_VERSION` 27.1.2→27.3.4.17, same Debian base — `bookworm`, just a newer snapshot
   date to match a published `hexpm/elixir` tag), `ci.yml` and `load.yml`'s matching env
   vars, and `mix.exs`'s own `elixir: "~> 1.17"` → `"~> 1.18"` (it was understating the
   real constraint once `wasmex` became a dependency). Picked the latest OTP **27.x**
   patch paired with Elixir 1.18.5 rather than jumping to OTP 28 — smallest change that
   actually satisfies `wasmex`'s floor, not a speculative bigger upgrade. Re-ran the full
   W0 spike script against the new exact pinned builder image
   (`hexpm/elixir:1.18.5-erlang-27.3.4.17-debian-bookworm-20260824-slim`) — the
   `elixir: "~> 1.18"` warning is gone, every other result unchanged.
2. **`WasmRunner.request/4` (W2) must `catch :exit` around `Wasmex.call_function/4`** —
   still open, this is a W2 implementation detail, not a pre-W2 blocker.
2. **`call_function/4`'s timeout can surface as a caller-side `GenServer.call` EXIT
   rather than a clean `{:error, :timeout}` return** — observed consistently on both
   platforms (elapsed time lands right at the nominal deadline, e.g. 301ms for a 300ms
   budget; the interrupt itself is prompt, but the reply plumbing racing the identical
   client-side `GenServer.call` timeout value means the client sometimes gives up a beat
   before the reply would have arrived). **`WasmRunner.request/4` (W2) must wrap its call
   to `Wasmex.call_function/4` in `try/catch :exit` and translate that into
   `{:error, :timeout}`**, exactly the way `SidecarRunner.request/4` already does for a
   dead port (`catch :exit, _ -> {:error, :down}`) — this was already the plan's intent
   structurally, but the spike confirms it is **load-bearing**, not defensive-programming
   boilerplate: without it, a single slow Wasm call would crash whatever process called
   `WasmRunner.request/4` synchronously (the `Pipeline` `Task` wrapper would absorb this
   as an `{:exit, reason}` → its existing `fail_mode` handling either way, so the request
   path itself stays safe regardless — but `WasmRunner`'s own internal bookkeeping, e.g.
   returning the instance to its pool, must not be skipped because of an unhandled exit).

**Residual, explicitly unresolved by this spike:** whether a timed-out call's underlying
Wasmtime execution is *truly, immediately* halted at the OS-thread level, or whether the
Elixir-level timeout merely stops *waiting* while some worker thread keeps running a beat
longer (the same distinction that matters for a sidecar timeout today, per ADR-0003's
Context). The observed behavior — prompt, bounded-latency responses from other calls
throughout, `wasmex`'s own documentation describing genuine interruption, and Wasmtime's
documented epoch/fuel mechanism being a forced trap-unwind rather than passive abandonment
— is consistent with real interruption, but this spike did not instrument OS-level
thread/CPU usage to prove it conclusively (a plain BEAM scheduler-time check would not have
shown it either way, since `wasmex`'s async design runs Wasm execution on its own Tokio
thread pool, not a BEAM scheduler). Because of this, **W2's pool design must discard, not
reuse, any instance that has timed out or trapped** — re-instantiate that pool slot fresh
from the cached `Module` rather than returning the possibly-still-executing instance to
service. The plan already specified this (§W2); this finding is why it is not optional.

**Not yet checked** (lower risk, deferred to whoever picks up W2 — needs a real release
build, not just the builder-stage container used here): whether the compiled `.so` NIF's
runtime linkage is satisfied by the Dockerfile's **runner** stage (`debian:bookworm-slim`
+ `libstdc++6 openssl libncurses6`, not the full builder image) once an actual `mix
release` exists to test with.

---

## W1 — Guest ABI + protocol doc amendment

### Guest ABI (what a Wasm plugin's `.wasm` file must export)

```
alloc(size: i32) -> i32                    // reserve `size` bytes, return a pointer
handle(in_ptr: i32, in_len: i32) -> (i32, i32)   // process one request, return (out_ptr, out_len)
```

No `dealloc` export is required. Each call gets a **freshly instantiated** guest (§ W2 —
instances are drawn from a small pool and are not reused for a second call), so a guest may
use a trivial bump allocator and simply let its whole linear memory be discarded when the
instance is torn down after the call. This trades a small amount of instantiation overhead
(Wasmtime instantiation from an already-compiled `Module` is the fast path it's designed
for) for a strictly simpler, leak-proof guest contract — no plugin author can get memory
management wrong in a way that outlives one call.

**Request/response envelope** — deliberately simpler than the sidecar's real JSON-RPC 2.0
framing, because a Wasm call is a synchronous in-process function invocation with no
multiplexing, no `id` correlation, and no notifications to distinguish:

```jsonc
// host -> guest, at in_ptr/in_len
{"method": "initialize" | "discovery/inspect" | "call/evaluate" |
            "call/inspectResponse" | "call/inspectChunk",
 "params": { /* identical shape to the sidecar method of the same name, §8-9 */ }}

// guest -> host, at out_ptr/out_len
{"result": { /* identical shape to the sidecar's JSON-RPC result for that method */ }}
// or
{"error": {"code": -32000, "message": "..."}}
```

`initialize` is called once per pool-instance at `WasmRunner` startup (§W2), with the same
params shape as the sidecar `initialize` (`docs/plugin-protocol.md` §8.1) minus the
`jsonrpc`/`id` wrapper, and its result is decoded with the **existing**
`Manifest.from_wire/1` unchanged. `ping` is not needed — a Wasm instance either instantiates
and answers or it doesn't; there is no long-lived process to health-check between calls.

### Protocol doc amendment

Add to `docs/plugin-protocol.md`:

- A new **§5.4 Wasm (in-process, sandboxed)** transport section (after §5.3 In-process
  Elixir), containing the guest ABI above, a worked example mirroring the style of §16.1–
  16.4, and an explicit statement that `CallContext` / `Decision` / `Finding` / `Manifest`
  are byte-identical in shape to the sidecar binding — only the framing differs.
- Update the "Not built yet" paragraph near the top (currently lists HTTP sidecar
  transport, real streaming, etc.) — Wasm moves from "deferred" (ADR-0001 §3) to "in
  progress, see ADR-0003" once W2 starts, and to "built" once W4 ships.
- §12 Security considerations gains a paragraph contrasting the Wasm binding's
  *structural* capability enforcement (no import linked = physically unreachable) against
  the sidecar binding's *declarative* one (`requiresNetwork` is operator-trusted, not
  enforced) — this is the sharpest concrete difference between the two out-of-process
  bindings and belongs in the doc a plugin author reads to decide which to use.
- §18 Open questions: remove the "Wasm... revisit once a concrete need exists" framing
  (that need is now this ADR) and replace with whatever new open questions W2–W4 surface
  (expect at least: pool sizing heuristics, whether `discovery`-phase Wasm scanners are
  worth supporting given `discovery` runs off the request path where latency matters less).

**Acceptance:** doc changes reviewed; no code yet.

---

## W2 — `WasmRunner` + `WasmSupervisor` + `Registry` integration

### `PhoenixElxirBeam.MCP.Plugin.WasmRunner`

A GenServer parallel to `SidecarRunner`, but owning a **pool** of instances instead of one
subprocess (a Wasm call is not naturally concurrent-safe the way a sidecar's `id`-correlated
stdio stream is — each in-flight call needs its own instance).

```elixir
def start_link(opts)
# opts: name, path (the .wasm file), pool_size (default from manifest.max_concurrency,
# else 2), config, pin, limits (memory_pages), proxy

@spec manifest(GenServer.server()) :: Manifest.t()
@spec health(GenServer.server()) :: :ready | :down
@spec request(GenServer.server(), method :: String.t(), params :: map(), timeout_ms :: pos_integer()) ::
        {:ok, term()} | {:error, term()}
```

Behavior:

- `init/1` compiles the `.wasm` file **once** into a `Wasmex.Module` (or the current
  wasmex-idiomatic equivalent confirmed in W0), computes the code digest
  (`Provenance.wasm_code_digest/1`, new — sha256 of the raw `.wasm` bytes, simpler than the
  sidecar's cmd+args scheme since there's exactly one artifact), spawns `pool_size`
  instances up front (each: instantiate → call `initialize` → capture the `Manifest`,
  identical result from every instance so any one of them is authoritative), then runs
  `Provenance.verify/2` exactly as `SidecarRunner.init/1` does — reusing that function
  unchanged, since it only cares about `{name, cmd_or_path, resolved_args_or_none, pin}` and
  a `Manifest`.
- `request/4` picks a free pool instance (round-robin or a simple checked-out/returned
  queue — `NimblePool` if the extra dependency is worth it, a hand-rolled list otherwise;
  decide during implementation based on how much `SidecarRunner`-style bookkeeping a
  hand-rolled version would duplicate), writes the request JSON into that instance's
  memory via `alloc`, calls `handle`, reads the response, and **re-instantiates that pool
  slot from the cached `Module` before returning it to the pool** — this is what makes the
  "no dealloc, no cross-call state" guest contract (W1) actually true: every call gets a
  guest whose linear memory has never seen a previous call's bytes.
- Circuit breaker: same shape as `SidecarRunner`'s (`@circuit_threshold`,
  `@circuit_cooldown_ms`) — a Wasm trap or a timed-out call counts as a failure the same way
  a sidecar error does. Copy the pattern rather than trying to share code with
  `SidecarRunner` across a fairly different transport; a shared `PluginRunner.CircuitBreaker`
  helper module is a reasonable follow-up once both exist, not a prerequisite.

### `Provenance.wasm_code_digest/1`

```elixir
@spec wasm_code_digest(path :: String.t()) :: String.t()
def wasm_code_digest(path), do: sha256("wasm|" <> Path.basename(path) <> ":" <> sha256_hex(File.read!(path)))
```

`manifest_digest/1` is reused **unchanged** — it already operates on a `Manifest.t()`
regardless of which binding produced it.

### `Registry` changes

- `build_entry` gains a `{:wasm, opts}` clause, structurally parallel to `start_sidecar/3`:
  spawn a `WasmRunner` under a new `WasmSupervisor` (`DynamicSupervisor`, added to the
  supervision tree next to `SidecarSupervisor`), fetch its manifest, build the capability
  entry, apply `grants` the same way `cap_sidecar_grants/3` does today (a Wasm scanner may
  only `can_block` if the operator granted it — identical rule, identical code path,
  parameterized over `kind` the way it already is).
- `entry.impl` gains a third shape: `{:wasm, runner_name}`.
- Config shape (`docs/plugin-protocol.md` §15.1), parallel to the sidecar example:

  ```elixir
  {:wasm,
    name: "rule-engine-wasm",
    path: {:priv, "wasm_plugins/rule_engine.wasm"},
    config: %{"rules" => [...]},
    pin: [code: "sha256:...", manifest: "sha256:..."],
    limits: [memory_pages: 256],   # 16 MiB; wasmex/Wasmtime-enforced, not best-effort
    grants: %{mutate: [], block: false}}
  ```

**Acceptance:** a hermetic test fixture — a trivial Wasm "echo scanner" (parallel to
`test/support/fixtures/sidecar_scanner.js`) built once and checked into `test/support/
fixtures/` as a compiled `.wasm` (small enough to commit; document the one-line command to
rebuild it from its Rust source, also checked in) — proves: `Registry` spawns a
`WasmRunner`, fetches its manifest, and `WasmRunner.request/4` round-trips a `call/evaluate`
end to end. No `Pipeline` involvement yet — this milestone is the runner and registry only.

---

## W3 — `Pipeline` dispatch

Add one clause per existing sidecar clause in `lib/phoenix_elxir_beam/mcp/pipeline.ex`:

```elixir
defp policy_evaluate(%{impl: {:wasm, name}} = entry, phase, ctx) do
  ctx = %{ctx | phase: phase}

  case WasmRunner.request(name, "call/evaluate", %{"context" => Wire.encode_context(ctx, entry)}, entry.timeout_ms) do
    {:ok, result} -> Wire.decode_decision(result)
    {:error, reason} -> raise "wasm call/evaluate failed: #{inspect(reason)}"
  end
end
```

...and the equivalent for `post_call_eval/4` (`call/inspectResponse`, `call/inspectChunk`)
and `discovery_scan/2` (`discovery/inspect`, reusing `Wire.encode_discovery/1` /
`Wire.decode_discovery_result/1` unchanged). Note this is **not new design** — it is the
same three call sites the sidecar binding already has, with `SidecarRunner.request/4`
swapped for `WasmRunner.request/4`. `Wire` itself needs **zero changes**: it already
produces/consumes plain maps with no knowledge of the transport underneath.

The existing `Task.Supervisor.async_nolink` + `Task.yield(task, entry.timeout_ms)` +
`Task.shutdown(task, :brutal_kill)` wrapper in `invoke/3`, `invoke_post_call/4`, and
`invoke_discovery/2` needs **no changes** — it already wraps every binding uniformly. This
is the "defense in depth" property ADR-0003 §4 calls out: even if a future `wasmex` version's
own interrupt mechanism had a gap, the outer `Task.shutdown(:brutal_kill)` still bounds
worst-case latency the same way it does for a hung in-process call today.

**Acceptance:** `pipeline_wasm_test.exs`, structurally parallel to the existing
`pipeline_sidecar_test.exs` — the echo fixture from W2 exercised through `Pipeline.run/3`,
`run_post_call/2`, and `run_discovery/2`, asserting the same `{verdict, decision, findings}`
shapes the sidecar tests already assert. `Registry.active_policies/2` /
`active_scanners/2` / etc. need no changes — they already filter on `kind`/`enabled`/
`phases`, not on `impl`.

---

## W4 — Reference plugin: `rule-engine-wasm`

A Rust crate (`priv/wasm_plugins/rule_engine/`, `wasm32-wasip1` target) re-implementing
`PhoenixElxirBeam.MCP.Plugins.RuleEngine`'s `evaluate/2` logic exactly:

- Same match predicates: `agent`, `agent_prefix`, `tool`, `server`, `tool_tags_any`,
  `after_sensitive_read`, `if_tainted`.
- Same first-match-wins semantics, same unknown-predicate-fails-closed behavior.
- Manifest: `phases: ["pre_call"]`, `dataNeeds: ["session.seenTags", "session.taint"]`,
  `timeoutMs: 50`, `failMode: "fail_closed"` — identical to the Elixir original's.

Registered in `config/dev.exs` **alongside** (not replacing) `RuleEngine`, `enabled: false`
by default so it never affects a live decision until an operator opts in via the dashboard.

### Parity test

The actual acceptance bar for this milestone, not "it compiles and runs":

```elixir
# test/phoenix_elxir_beam/mcp/plugins/rule_engine_wasm_parity_test.exs
# A shared corpus of {rules, call_context} fixtures (reuse rule_engine_test.exs's cases —
# do not hand-write a second corpus that can silently drift from the first) is run through
# both PhoenixElxirBeam.MCP.Plugins.RuleEngine.evaluate(:pre_call, ctx) and
# WasmRunner.request(wasm_runner, "call/evaluate", ...) |> Wire.decode_decision/1,
# asserting identical verdict/reason/severity for every case.
```

**Acceptance:** parity suite green across the full existing `RuleEngine` test corpus; a
`mix precommit` pass; a manual dashboard check showing `rule-engine` and `rule-engine-wasm`
both listed in the Plugins panel (`rule-engine-wasm` disabled), with matching config.

---

## W5 — Dashboard + docs

- Dashboard Plugins panel: `entry.transport` already renders per-entry (`:in_process` /
  `:stdio` today) — add `:wasm` to whatever mapping produces its display label/badge. No
  new LiveView markup should be needed beyond that mapping; confirm during implementation
  and only add UI if the existing generic rendering doesn't already cover a third transport
  value gracefully.
- `docs/plugin-supply-chain.md`: add a "Wasm plugin provenance" section mirroring the
  existing sidecar one — `wasm_code_digest/1` replaces the cmd+args code digest, everything
  else about the pin/mismatch/alert flow is identical (reuses `Provenance.verify/2` and the
  same `:sidecar_provenance`-style alert key, possibly renamed `:wasm_provenance` or
  generalized — decide during W2 whether one alert key covers both bindings or each needs
  its own; either is fine, but document the choice).
- `docs/productionization-plan.md`'s "Explicit non-goals" bullet ("the Wasm sandboxing path
  (ADR-0001 §3) stays deferred") becomes stale once this plan starts — update it to point
  at ADR-0003 instead of asserting the deferral.
- ADR-0001 gets a short header note pointing to ADR-0003 for the Wasm clause, matching the
  existing header note ADR-0001 already carries for the productionization-era scaffolding
  removal.
- This plan's own status line flips to **Complete** once W4's acceptance criteria are met;
  W5 itself doesn't block calling the effort done, the same way `docs/productionization-
  plan.md` treated its own doc-sync milestones as real but non-blocking.

---

## Definition of done

- [x] W0: `wasmex` confirmed loadable on Windows dev **and** Linux (the exact builder-image
      tag) — 2026-09-14, see Findings above. Two follow-ups carried forward, neither
      blocking: bump the project's pinned Elixir version before W2, and `WasmRunner` must
      `catch :exit` around `Wasmex.call_function/4`.
- [x] W1: `docs/plugin-protocol.md` §5.4 written — 2026-09-14. Guest ABI (`alloc`/`handle`,
      no `dealloc`), the reduced request/response envelope, the capability/resource-limit
      contrast with sidecars (§12), a worked example (§16.6), and new open questions (§18:
      pool sizing, whether `discovery`-phase Wasm scanners are worth it) all added.
- [ ] W2: `WasmRunner`, `WasmSupervisor`, `Registry` `{:wasm, opts}`, `Provenance.
      wasm_code_digest/1` — hermetic fixture test green.
- [ ] W3: `Pipeline` `{:wasm, name}` dispatch — `pipeline_wasm_test.exs` green.
- [ ] W4: `rule-engine-wasm` — parity suite green against the full `RuleEngine` corpus.
- [ ] W5: dashboard shows the `wasm` transport; supply-chain + cross-referencing docs
      updated; `mix precommit` / `mix dialyzer` / `MIX_ENV=prod mix compile` all still pass.
