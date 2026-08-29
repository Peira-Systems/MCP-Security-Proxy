# MCP Security Proxy

A policy-enforcing proxy between an AI agent (MCP client) and the MCP servers
it calls tools on. Every `tools/call` runs through a plugin pipeline — policy
decisions, content scanners, tamper-evident audit — before it is forwarded.
A LiveView dashboard visualizes traffic and lets an operator curate policy.

See [`Project.md`](Project.md) for an overview, [`docs/adr/`](docs/adr) for the
architecture and productionization decisions, and
[`docs/productionization-plan.md`](docs/productionization-plan.md) for the
current roadmap.

## Development

```
mix setup          # install deps, create + migrate the DB, build assets
mix phx.server     # http://localhost:4000  — dashboard at /mcp/dashboard
mix precommit      # compile (warnings as errors) + format + test — the gate
```

## Deployment

Single-node Docker Compose:

```
cp .env.example .env    # then fill in SECRET_KEY_BASE etc.
docker compose up -d
```

## Stack

Phoenix 1.8 · LiveView · Bandit · Ecto/SQLite (Postgres in productionization
milestone M2). HTTP via `Req`.
