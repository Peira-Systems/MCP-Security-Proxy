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

Needs a Postgres. The compose file has one:

```
docker compose up -d postgres    # or use a local Postgres on :5432
mix setup                        # install deps, create + migrate the DB, build assets
mix phx.server                   # http://localhost:4000 — dashboard at /mcp/dashboard
mix precommit                    # compile (warnings as errors) + format + test — the gate
```

Repo connection defaults to `postgres:postgres@localhost:5432`; override with
`PGHOST` / `PGPORT` / `PGUSER` / `PGPASSWORD` / `PGDATABASE`.

`mix ci` runs the full gate CI enforces (format check, warnings-as-errors,
`deps.audit`, tests, dialyzer). See [`docs/ci-cd.md`](docs/ci-cd.md) for the
pipelines, releases, and rollback.

## Deployment

Single-node Docker Compose (`app` + `postgres`):

```
cp .env.example .env              # non-secret config: PHX_HOST, ADMIN_EMAIL/PASSWORD, ports
mkdir -p secrets                  # the three real secrets are Docker secret files:
openssl rand -hex 64    > secrets/secret_key_base.txt
openssl rand -hex 32    > secrets/audit_checkpoint_key.txt
openssl rand -base64 24 > secrets/postgres_password.txt
docker compose up -d              # the app runs migrations on start
```

First boot seeds an admin from `ADMIN_EMAIL` / `ADMIN_PASSWORD`; sign in at `/login`.

Health: `/health/live` (liveness, used by the container healthcheck) and
`/health/ready` (Postgres + upstream reachability). Metrics: Prometheus text at
`/metrics`. Add the observability stack with
`docker compose -f docker-compose.yml -f compose.observability.yml up -d` — see
[`docs/observability.md`](docs/observability.md).

## Stack

Phoenix 1.8 · LiveView · Bandit · Ecto/Postgres. HTTP via `Req`.
