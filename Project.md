# MCP Security Proxy Demo

## Context

This is exotic, currently-relevant AI security territory: MCP (Model Context Protocol) is the JSON-RPC protocol AI agents use to call tools on MCP servers, and it's one of the least-audited attack surfaces in AI right now — a common attack shape is an agent getting tricked into chaining a "read something sensitive" tool call into a "send data out over the network" tool call (tool-chaining exfiltration). The goal is a self-contained Phoenix demo that makes this concrete and visible: a policy-enforcing proxy sits between a (simulated) AI agent and two mock MCP servers, and a LiveView dashboard shows tool calls as a live graph, lighting up red and getting blocked when a dangerous chain is detected — while a harmless session sails through untouched. Nothing performs real file reads or real network egress; the "vulnerable" tool's dangerous behavior is canned/simulated throughout, this is a visualization/education piece, not an actual exploitable service.

The app (`PhoenixElxirBeam` / `PhoenixElxirBeamWeb`) is a fresh `mix phx.new` scaffold — no contexts, LiveViews, or extra supervision children exist yet, so this is a from-scratch addition following the project's existing conventions (Req for HTTP per AGENTS.md, colocated LiveView hooks, `Layouts.app` wrapper, LiveView streams for lists).

## Architecture

```
Demo scripts (Task.Supervisor)
   │  real HTTP via Req
   ▼
ProxyController  POST /mcp/proxy/:server_id  ──consults──▶ PolicyEngine (GenServer)
   │  forwards via Req (loopback)                             │ per-session tag history
   ▼                                                            │ broadcasts events
MockServerController  POST /mcp/servers/:server_id              ▼
   (ToolCatalog: canned tool defs + responses)         PubSub "mcp:events"
                                                                  │
                                                                  ▼
                                                       MCPDashboardLive
                                                       (event stream + SVG tool graph)
```

## Files to add

```
lib/phoenix_elxir_beam/mcp/
  event.ex          PhoenixElxirBeam.MCP.Event          struct
  tool_catalog.ex    PhoenixElxirBeam.MCP.ToolCatalog     static tool defs/tags/canned responses
  policy_engine.ex    PhoenixElxirBeam.MCP.PolicyEngine    GenServer, session tag history + verdicts
  demo.ex             PhoenixElxirBeam.MCP.Demo            run_benign_session/0, run_attack_simulation/0

lib/phoenix_elxir_beam_web/controllers/mcp/
  proxy_controller.ex        PhoenixElxirBeamWeb.MCP.ProxyController        POST /mcp/proxy/:server_id
  mock_server_controller.ex  PhoenixElxirBeamWeb.MCP.MockServerController   POST /mcp/servers/:server_id

lib/phoenix_elxir_beam_web/live/
  mcp_dashboard_live.ex          PhoenixElxirBeamWeb.MCPDashboardLive
  mcp_dashboard_live.html.heex   (graph SVG + colocated hook + event stream)
```

One `MockServerController` (not two) keyed by `:server_id`, delegating to `ToolCatalog` — with only 4 tools total across 2 servers, a second layer of per-server modules isn't worth it.

## MCP/JSON-RPC shape

Three methods only, plain synchronous JSON responses (no SSE — MCP's Streamable HTTP transport permits this for simple request/response, and Bandit's chunked-response machinery isn't needed):

- `initialize` → `%{"protocolVersion" => ..., "capabilities" => %{"tools" => %{}}, "serverInfo" => %{...}}`
- `tools/list` → `%{"tools" => [...]}` (name, description, inputSchema) from `ToolCatalog`
- `tools/call` → params `%{"name" => ..., "arguments" => %{...}}`, result `%{"content" => [%{"type" => "text", "text" => ...}], "isError" => false}`

Standard envelope (`jsonrpc`/`id`/`method`/`params` in; `result` or `error` out). Session correlation uses the real MCP convention: an `mcp-session-id` request header, generated once per demo run and reused for every call — this is what `PolicyEngine` keys history on.

**Tool catalog:**

| server | tool | tags |
|---|---|---|
| `files` | `list_files` | none |
| `files` | `read_secrets` | `:sensitive_read` |
| `net` | `check_status` | none |
| `net` | `post_webhook` | `:network_egress` |

Canned responses make the simulation explicit, e.g. `read_secrets` → `"API_KEY=sk-demo-FAKE1234 (simulated content, not a real secret)"`.

## Policy rule (enforcement, per confirmed decision)

`PolicyEngine` keeps a `MapSet` of tags seen per `session_id`. A call tagged `:network_egress` is **blocked** iff `:sensitive_read` is already in that session's seen-set at the time of the call (order matters — egress before any sensitive read is not flagged). On block: `ProxyController` returns a JSON-RPC error (`-32001`, message describing the chain) and **does not forward the call** to the mock server — the mock server's dangerous tool never actually executes on the flagged path. This is the entire detection/enforcement logic — deliberately simple and legible.

## Supervision tree (`application.ex`)

Insert after PubSub, before Endpoint:

```elixir
PhoenixElxirBeam.MCP.PolicyEngine,
{Task.Supervisor, name: PhoenixElxirBeam.MCP.TaskSupervisor},
```

No Registry/DynamicSupervisor — session state is a plain `Map` in `PolicyEngine`'s GenServer state; demo runs are one-off `Task.Supervisor.start_child/2` calls. `PolicyEngine.start_link/1` accepts an overriding `:name` so tests can start isolated instances.

## Router changes

```elixir
scope "/", PhoenixElxirBeamWeb do
  pipe_through :browser
  ...
  live "/mcp/dashboard", MCPDashboardLive
end

scope "/mcp", PhoenixElxirBeamWeb.MCP do
  pipe_through :api   # NOT :browser — CSRF protection would 403 the Req-issued POSTs

  post "/proxy/:server_id", ProxyController, :call
  post "/servers/:server_id", MockServerController, :call
end
```

No `live_session` block needed (no auth/shared assigns in this scaffold).

## PubSub

Topic `"mcp:events"` on `PhoenixElxirBeam.PubSub`. `PhoenixElxirBeam.MCP.Event` struct: `[:id, :session_id, :scenario, :server_id, :tool_name, :tags, :status, :reason, :timestamp]` (`status :: :session_start | :ok | :blocked | :session_complete`).

`PolicyEngine` is the sole broadcaster (it's the one place that computes the verdict):
- `start_session/2` → broadcasts `:session_start` (LiveView resets graph/feed)
- `record_call/4` → called by `ProxyController` **only** for `tools/call` (per confirmed decision — `initialize`/`tools/list` never generate events, keeping the feed/graph focused); returns `{:allow, event}` or `{:block, event}`, broadcasts either way
- `complete_session/1` → broadcasts `:session_complete` (LiveView re-enables run buttons)

`MCPDashboardLive` subscribes in `mount/3` when `connected?(socket)`.

## Graph rendering

Node set is small and fixed (1 agent + 2 servers + 4 tools = 7 nodes, known at compile time) — no continuous force simulation needed. A colocated hook (`PhoenixElxirBeamWeb.MCPDashboardLive`'s `.ToolGraph`) does a one-time relaxation pass on `mounted()` to settle positions, then the graph is static and only edge/node CSS state toggles incrementally:

- `push_event("mcp_graph_reset", %{scenario: ...})` on `:session_start` — clears `.active`/`.blocked` classes.
- `push_event("mcp_graph_event", %{server_id:, tool_name:, status:, reason:})` on `:ok`/`:blocked` — hook pulses the relevant edges (`edge-agent-<server>`, `edge-<server>-<tool>`) via a timed CSS class, and on `:blocked` adds a persistent red/dashed class plus a reason label.

Container: `<div id="mcp-tool-graph" phx-hook=".ToolGraph" phx-update="ignore"><svg>...</svg></div>` — required since the hook owns this DOM after mount.

Separate from the graph: a plain LiveView `stream(:events, ...)` list (`phx-update="stream"`) for the scrolling event feed, newest first.

## Demo scenarios

Both via `PhoenixElxirBeam.MCP.Demo`, each a `Task.Supervisor.start_child/2` job making real `Req.post/2` calls to `http://127.0.0.1:<port>/mcp/proxy/:server_id` (port read from `PhoenixElxirBeamWeb.Endpoint.config(:http)[:port]` at runtime), ~600ms between steps for watchable pacing.

**Benign** (`run_benign_session/0`): `initialize` on `files` → `list_files` → `initialize` on `net` → `check_status`. No `:sensitive_read` tag ever seen → nothing blocked.

**Attack** (`run_attack_simulation/0`): `initialize` on `files` → `read_secrets` (`:sensitive_read`, allowed, canned fake secret returned) → `initialize` on `net` → `post_webhook` (`:network_egress`) — **blocked**, JSON-RPC error returned, mock server never invoked for this call.

Dashboard: two buttons ("Run benign session" / "Run attack simulation"), disabled while a scenario is in flight (gated on `:session_complete`) to avoid overlapping graph animations from concurrent runs.

## Verification

1. `mix precommit` (compile --warnings-as-errors, deps.unlock --unused, format, test) — required gate per AGENTS.md.
2. `test/phoenix_elxir_beam/mcp/policy_engine_test.exs` — isolated `start_supervised!({PolicyEngine, name: :test_policy})`, `async: true`: (a) benign 2-call sequence → both allowed; (b) `read_secrets` then `post_webhook` same session → second blocked with reason; (c) same tools split across two different session_ids → not blocked (no cross-session leakage).
3. `test/phoenix_elxir_beam_web/controllers/mcp/mock_server_controller_test.exs` — `Phoenix.ConnTest` POSTs for `tools/list`/`tools/call` against both servers, asserts JSON-RPC result shape.
4. `test/phoenix_elxir_beam_web/controllers/mcp/proxy_controller_test.exs` — against the real singleton `PolicyEngine`, each test uses a unique `mcp-session-id` for isolation under `async: true`: benign call → 200 with `result`; attack sequence on one session → second response has `"error"` with the block code/message.
5. Manual: start the dev server, open `/mcp/dashboard` in the browser tool, click "Run benign session" (watch feed + edge pulses, nothing red), click "Run attack simulation" (watch `read_secrets` pulse, then `post_webhook` edge turn red/blocked with reason visible in both graph and feed), screenshot the end state.