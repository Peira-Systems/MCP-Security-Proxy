# MCP Security Proxy

A policy-enforcing proxy that sits between an AI agent (MCP client) and the
MCP servers it calls tools on. Every `tools/call` is evaluated by a pipeline
of **plugins** — policy decisions, content scanners, and audit sinks — before
it is forwarded; a blocked call never reaches the upstream server. A LiveView
dashboard shows calls flowing through in real time, turning red when one is
blocked, and lets an operator curate tool tags, register servers, and browse
the tamper-evident audit history.

The common attack it targets is **tool-chaining exfiltration**: an agent is
tricked into chaining a "read something sensitive" call into a "send data out"
call. The proxy catches this with tag-based rules, session taint tracking,
response scanning, behavioural baselining, and human-in-the-loop approval.

## Status

This began as a self-contained visualization/education demo (mock MCP servers,
canned scenario buttons, a simulated streaming transport). As of the
productionization effort it is being cut over to run in front of **real MCP
traffic**:

- **Architecture** — plugin control plane: [`docs/adr/0001-plugin-architecture.md`](docs/adr/0001-plugin-architecture.md), [`docs/plugin-protocol.md`](docs/plugin-protocol.md)
- **Productionization** — [`docs/adr/0002-productionization.md`](docs/adr/0002-productionization.md) (rationale), [`docs/productionization-plan.md`](docs/productionization-plan.md) (execution plan, M0–M4)

The demo scaffolding (mock servers, scenario harness, `MockDrift`, simulated
streaming) was removed in productionization milestone M0. Real servers are
registered at runtime via the dashboard; tools are discovered through a live
`initialize` + `tools/list` handshake and start untagged until an operator
classifies them.

## Running

```
mix setup
mix phx.server
```

Dashboard at `/mcp/dashboard`. The proxy endpoint is
`POST /mcp/proxy/:server_id` (JSON-RPC over Streamable HTTP). Register an
upstream MCP server from the dashboard's "Servers & tools" panel, assign tags
to its tools, then point an MCP client at the proxy URL.

Container: `docker compose up` (see [`docker-compose.yml`](docker-compose.yml)
and [`.env.example`](.env.example)).

## Layout

```
lib/phoenix_elxir_beam/mcp/
  pipeline.ex            runs the plugin phases (discovery / pre_call / post_call / chunk)
  policy_engine.ex       canonical per-session state (tags, taint, call log); sole event broadcaster
  server_registry.ex     registered upstream MCP servers; live tool discovery + rug-pull re-handshake
  hold_registry.ex       parks calls awaiting operator approval
  event_log.ex           hash-chained audit history
  plugin/                the Policy / Scanner / AuditSink behaviours, Registry, sidecar runner
  plugins/               the shipped plugins (RuleEngine, TaintGuard, SecretLeak, …)

lib/phoenix_elxir_beam_web/
  controllers/mcp/proxy_controller.ex   POST /mcp/proxy/:server_id
  live/mcp_dashboard_live.*             the dashboard
```
