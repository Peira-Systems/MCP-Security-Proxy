# CI/CD

**Status:** Active · **Implements:** [productionization-plan.md](productionization-plan.md) M3.1

## Pipelines

| Workflow | Trigger | What it does |
|---|---|---|
| [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | every PR, push to `main`/`master` | `deps.unlock --check-unused`, `format --check-formatted`, `compile --warnings-as-errors`, `mix deps.audit`, `mix test` (against a `postgres:17` service), and `mix dialyzer` in a separate job |
| [`.github/workflows/release.yml`](../.github/workflows/release.yml) | push of a `v*` tag (or manual `workflow_dispatch`) | on a **self-hosted** runner, build the runtime image and push it to `${REGISTRY_HOST}/mcp-security-proxy` tagged `:<version>`, `:<major>.<minor>`, `:<short-sha>`, and `:latest` |
| [`.github/workflows/security-review.yml`](../.github/workflows/security-review.yml) | PR touching `lib/phoenix_elxir_beam/mcp/**`, `priv/plugins/**`, `config/**` | Claude security review of the diff, posted as PR comments. Skipped unless an `ANTHROPIC_API_KEY` repo secret is set. |
| [`.github/workflows/load.yml`](../.github/workflows/load.yml) | nightly (04:00 UTC) + manual | Runs `bench/load.exs` against a fresh Postgres, publishes latency numbers to the run summary. **Non-blocking** — fails only on a >1% error rate, not the latency budget. See [`docs/latency-budget.md`](latency-budget.md). |

## Runners

Every workflow runs on a **self-hosted** runner (`runs-on: self-hosted`) — there
are no GitHub-hosted runners in use. The runner needs: Docker (service containers
for `ci.yml` / `load.yml`, image build for `release.yml`), outbound access to
hex.pm and the GitHub-hosted action/tool downloads, and network reach to the
registry. It's typically a single runner, so `ci.yml`'s `test` and `dialyzer`
jobs serialize rather than run in parallel.

## Registry

`release.yml` pushes over HTTPS to `${REGISTRY_HOST}/mcp-security-proxy`.
Configure it under Settings → Secrets and variables → Actions:

| Kind | Name | Example / note |
|---|---|---|
| Variable | `REGISTRY_HOST` | `artifact-keeper.peirasystems.com` — host only, no scheme or path |
| Secret | `REGISTRY_USER` | registry username |
| Secret | `REGISTRY_PASSWORD` | registry password / token |

The job fails fast if `REGISTRY_HOST` is unset; a bad or missing credential
fails the login step with `unauthorized`.

A red `mix test` or `mix dialyzer` blocks merge once branch protection requires
the `CI` checks (Settings → Branches → require status checks: `compile · format ·
audit · test` and `dialyzer`).

Local equivalent of the CI gate:

```bash
mix ci
```

The Elixir/OTP versions in `ci.yml` (`ELIXIR_VERSION` / `OTP_VERSION`) must stay
in sync with the `Dockerfile` args of the same name.

## Cutting a release

```bash
git tag v0.2.0
git push origin v0.2.0
```

`release.yml` builds and pushes `${REGISTRY_HOST}/mcp-security-proxy:v0.2.0`
(+ `:0.2` + `:latest`). The image is **not** deployed automatically — deploy is a
manual step on the node.

## Deploy onto the node

On the single host, with `.env` populated and `docker-compose.yml` pointed at the
registry image (`image: <REGISTRY_HOST>/mcp-security-proxy:v0.2.0` instead
of the local build):

```bash
docker compose pull app
docker compose up -d app
```

`docker-entrypoint.sh` runs `Release.migrate()` before `start`, so migrations
apply on boot. Single-node deploy has a short downtime window (old container
stops, migration runs, new container starts) — this is an accepted non-goal of
the plan (no rolling deploy).

## Rollback

Redeploy the previous image tag:

```bash
# pin docker-compose.yml (or the deploy .env) back to the prior tag, then:
docker compose pull app
docker compose up -d app
```

A migration that has to be undone is a manual `Release.rollback/2` against the
prior release (`docker compose run --rm app /app/bin/phoenix_elxir_beam eval
'PhoenixElxirBeam.Release.rollback(PhoenixElxirBeam.Repo, <version>)'`) **before**
starting the older image. Keep migrations backward-compatible with the previous
image where possible to avoid this.

## Not covered here

Metrics, health probes, and alerting are M3.2. The full operator runbook
(per-alert response, audit-chain investigation) is M4.4.
