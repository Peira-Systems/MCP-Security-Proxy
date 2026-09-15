# Plugin supply chain

**Status:** Active · **Implements:** [productionization-plan.md](productionization-plan.md) M3.5

The proxy trusts its plugins to return security verdicts. This page covers what
stops a swapped or tampered plugin from being trusted silently.

## Sidecar provenance pinning

Every out-of-process (`{:sidecar, …}`) plugin is verified at startup by
[`PhoenixElxirBeam.MCP.Plugin.Provenance`](../lib/phoenix_elxir_beam/mcp/plugin/provenance.ex):

| digest | covers |
|---|---|
| **code** | the command string + the bytes of each argument that resolves to a real file (the plugin's script/binary — not the interpreter). Path-independent. |
| **manifest** | canonical JSON of the `Manifest` the sidecar reports at handshake (declared capability, grants, phases). |

Pin them in the plugin's config spec:

```elixir
{:sidecar,
 name: "prompt-injection-scanner",
 cmd: "python3",
 args: [{:priv, "plugins/prompt_injection_scanner.py"}],
 pin: [
   code: "sha256:7ed7daaa…",
   manifest: "sha256:bfc219dd…"   # optional — add from the boot log
 ],
 …}
```

- **Both match** → the sidecar comes online.
- **Either mismatch** → the runner's `init` stops with `{:provenance_mismatch, …}`,
  the plugin stays down, and a **`:sidecar_provenance` (critical)** alert fires
  (`MCP.Alerts` → structured log + dashboard banner + `mcp_alert_count`).
- **`pin` absent** → the sidecar still starts, but logs a `warning` with the
  computed digests so an operator can paste them in. Prod ships pinned.

Recompute the code digest after editing a script:

```bash
mix run --no-start -e 'IO.puts PhoenixElxirBeam.MCP.Plugin.Provenance.code_digest("python3", [Application.app_dir(:phoenix_elxir_beam, "priv/plugins/prompt_injection_scanner.py")])'
```

## Wasm plugin provenance pinning

Every `{:wasm, …}` plugin (`docs/plugin-protocol.md` §5.4) is verified the same way, at
startup, by the same `Provenance.verify/2` — a Wasm plugin's provenance is simpler than a
sidecar's because there is exactly one artifact, the `.wasm`/`.wat` file itself, not a
command plus resolved argument files:

| digest | covers |
|---|---|
| **code** | `Provenance.wasm_code_digest/1` — sha256 of the plugin file's own bytes plus its basename. Path-independent, same as the sidecar digest: moving the file changes nothing, editing its bytes does. |
| **manifest** | identical to the sidecar case — canonical JSON of the `Manifest` the plugin reports at its `initialize` handshake. |

Pin them in the plugin's config spec:

```elixir
{:wasm,
 name: "rule-engine-wasm",
 path: {:priv, "wasm_plugins/rule_engine.wasm"},
 pin: [
   code: "sha256:5ae445d3…",
   manifest: "sha256:246db3d4…"   # optional — add from the boot log
 ],
 …}
```

- **Both match** → the plugin's instance pool comes online.
- **Either mismatch** → `WasmRunner.init/1` stops with `{:provenance_mismatch, …}`, the
  plugin stays down, and a **`:wasm_provenance` (critical)** alert fires — the same
  `MCP.Alerts` path a sidecar mismatch uses, under its own key so the two bindings' alerts
  don't get confused with each other on the dashboard.
- **`pin` absent** → the plugin still starts, but logs a `warning` with the computed
  digests so an operator can paste them in — `config/dev.exs`'s `rule-engine-wasm` entry
  ships pinned; treat an unpinned Wasm plugin in prod the same way an unpinned sidecar is
  treated.

Recompute the code digest after editing a plugin (or use the one-liner
`priv/wasm_plugins/rule_engine/build.sh` prints after every build):

```bash
mix run --no-start -e 'IO.puts PhoenixElxirBeam.MCP.Plugin.Provenance.wasm_code_digest("priv/wasm_plugins/rule_engine.wasm")'
```

**Resource limits differ from the sidecar story, in a way that's a real improvement, not
just a config-shape parallel.** A sidecar's `limits: [as_mb:, cpu_s:, nproc:]` wraps its OS
process in `prlimit` — best-effort, Linux-only, a no-op without `util-linux`. A Wasm
plugin's `limits: [memory_pages: N]` (1 page = 64 KiB) is enforced by the Wasm runtime
itself (`Wasmex.StoreLimits`) regardless of host OS — growing memory past the cap fails
inside the guest (Wasm's own `memory.grow` failure return), it can't be silently skipped
the way a missing `prlimit` binary silently skips sidecar limits. CPU time needs no separate
config at all: it's bounded by the same `timeoutMs` every plugin already declares
(`docs/plugin-protocol.md` §5.4.4), and a Wasm call that hits its deadline is actually
interrupted by Wasmtime — a sidecar that ignores its deadline keeps its process running
until something else notices.

## Sidecar resource limits

`limits: [as_mb: 512, cpu_s: 30, nproc: 64]` on a sidecar spec wraps its command
in `prlimit` (address space, CPU-time, process count) so a runaway sidecar is
killed by the kernel, not merely restarted by the supervisor. This is
**best-effort**: it needs `prlimit` (util-linux) on the runtime image and is a
no-op elsewhere (a `warning` is logged).

The production-grade option — one container per sidecar with compose `cpus` /
`mem_limit` — is not wired by default because sidecars are first-party here. If
you add a third-party sidecar, run it as its own compose service with limits and
point the spec at it over stdio, rather than spawning it in-process.

## Dependency audit

CI (`.github/workflows/ci.yml`) runs on every PR:

- `mix deps.audit` — known security advisories in the dependency tree.
- `mix hex.audit` — retired / yanked packages.

Both are also in `mix ci`. A PR that changes `mix.lock` should get a dependency
review as part of code review — new transitive deps, version bumps with a wide
range, and anything pulled from git rather than Hex.

## In-process plugins

`{Module, opts}` plugins are compiled into the release from `lib/phoenix_elxir_beam/mcp/plugins/`
and are covered by the same review + `deps.audit` as the rest of the app. They
have no provenance pin because they are not a separate artifact — the release
image hash is their provenance.
