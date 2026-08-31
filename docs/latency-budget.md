# Request-path latency budget

**Status:** Active · **Implements:** [productionization-plan.md](productionization-plan.md) M3.3

## Budget

| Metric | Budget | Notes |
|---|---|---|
| **`pipeline` `pre_call` phase, p99** | **≤ 10 ms** at 50 concurrent sessions, in-process plugins only | This is the proxy's own policy-decision cost — the number the proxy is accountable for. |
| `pipeline` `post_call` phase, p99 | ≤ 15 ms | Runs concurrently over scanners; only on methods with scannable content. |
| End-to-end `tools/call`, p99 | not budgeted | Dominated by the upstream server + per-request DB work (see below), not the pipeline. |

The [`bench/load.exs`](../bench/load.exs) driver enforces the `pre_call` p99
budget (`LOAD_BUDGET_P99_MS`, `LOAD_ENFORCE=true`). The nightly CI workflow
([`.github/workflows/load.yml`](../.github/workflows/load.yml)) runs it
**non-blocking** and publishes the numbers to the run summary.

## Where the time goes (measured, 50 concurrent, dev machine)

```
pipeline pre_call       p99 ≤ 1 ms      ← the policy pipeline is not the bottleneck
pipeline post_call      p99 ≤ 1 ms
upstream (stdio fixture) p99 ≤ 1 ms
end-to-end tools/call   p50 ≈ 230 ms, p99 ≈ 360 ms
```

The ~200 ms gap between the instrumented phases and the end-to-end figure is
**per-request work outside the pipeline**, most of it serialized:

- `Plugs.ApiKeyAuth` — a Postgres `SELECT` on `api_keys` per request.
- `PolicyEngine.record_call` — a single `GenServer.call` plus the write-through
  `policy_sessions` upsert (M2.2a).
- `EventLogSink` — the audit hash chain is an **append-only, strictly serial**
  Postgres `INSERT` per decision (M2.3). This is serial by design — each row
  hashes the previous one.
- `SessionStore` — one `GenServer.call` per request.
- the `initialize` / `notifications/initialized` / `DELETE` round-trips that
  bracket each session in the bench (real clients keep a session open longer).

At single-node scale with a 10-connection pool, these queue under load. That is
the expected shape; the pipeline budget above is what M3.3 commits to.

## Tuning levers (not yet pulled — pipeline is within budget)

- **API-key auth cache** — a short-TTL (e.g. 5 s) in-memory cache of
  `key_id → key` would remove one DB round-trip per request. Highest-value,
  lowest-risk change; flagged as a follow-up.
- **Decision cache** (protocol §18) — deferred: the pipeline is already <1 ms,
  so caching verdicts buys nothing here.
- **Per-plugin circuit-breaker tuning** — revisit if `mcp_plugin_run_stop_duration`
  shows a specific plugin regressing under load.
- **Audit-chain batching** — the serial INSERT is the sharpest per-request cost,
  but batching weakens the tamper-evidence guarantee; out of scope.

## Re-running

```bash
# needs Postgres reachable and `node` on PATH
PGPORT=5433 PORT=4090 MIX_ENV=dev mix run --no-start bench/load.exs
```

Knobs: `LOAD_CONCURRENCY`, `LOAD_DURATION_S`, `LOAD_CALLS_PER_SESSION`,
`LOAD_WARMUP_S`, `LOAD_BUDGET_P99_MS`, `LOAD_ENFORCE`.
