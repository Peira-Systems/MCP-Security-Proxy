# Rule coverage gate — design spec

Date: 2026-09-30

## Problem

`RuleEngine` rules are hand-written, agent-scoped, first-match-wins config
entries (`config/dev.exs`, `config/prod.exs`). There's no check that every
sensitive tool a real registered MCP server exposes is actually covered by a
rule. Two known blind spots exist today, both silent:

1. A tool tagged `sensitive_read` / `network_egress` (operator-assigned
   `tags`) may have no rule that resolves to `deny`/`hold` for an arbitrary
   agent — only an agent-scoped exception (e.g. `agent://ci-runner` denied,
   every other agent implicitly allowed).
2. A tool `TagInference` suggests a sensitive tag for, but which an operator
   never actually tagged, is invisible to the rule engine entirely (no tags →
   no rule match → implicit allow). `UnclassifiedGuard` is the runtime
   backstop for this, but it ships `mode: "off"` in `config/dev.exs` today —
   so this gap is live in this repo's own default config, not hypothetical.

Both are easy to introduce (register a new server, forget to tag/cover it)
and invisible until someone reads the dashboard tool-by-tool.

## Goal

A CI-run mix task, `mix mcp.rules.check`, that fails the build when a
real, currently-registered tool is not actually enforced, and (phase 2)
writes its findings as `RuleEngineCorpus`-shaped fixtures so gaps are
reviewable as readable test cases, not just a CI log line.

Out of scope: wasm-engine config drift (covered by the existing
`rule_engine_wasm_parity_test.exs`); a dashboard-side live warning; any
change to enforcement at request time (`UnclassifiedGuard`, `RuleEngine`
itself stay behaviorally unchanged — this is a build-time auditor only).

## Data source

The task connects to a real Postgres instance (a staging environment, or a
seeded dev DB with real server registrations — not a stateless/ephemeral PR
check, since there's nothing to check against without registrations) and
reads `PhoenixElxirBeam.MCP.ServerStore.all()` directly, the same source
`ServerRegistry.handle_continue(:restore, ...)` reads at boot. This avoids
spinning up the full `ServerRegistry` GenServer / re-running live handshakes
against upstream servers during CI.

**Prerequisite schema change:** today `ServerStore.persist/1`'s `tool_state`
overlay only writes `tags`, `quarantined`, `quarantine_reason`, and `hash`
per tool — `suggested_tags` is computed by `TagInference.infer/2` at
handshake time but only ever lives in `ServerRegistry`'s in-memory state,
never persisted. Without it, gap type B (unreviewed tool) can't be detected
from Postgres alone. This plan adds `"suggested_tags"` as a fourth key in
the same `tool_state` map (no migration needed — `tool_state` is already a
free-form `:map` column), written from the tool's existing in-memory
`suggested_tags` field, and read back out wherever the overlay is
reconstituted (`ServerRegistry.rebuild/3`, `rehandshaked/2`) the same way
`tags` already is.

Rules come from `Application.get_env(:phoenix_elxir_beam,
PhoenixElxirBeam.MCP)[:plugins]`, compiled at build time for whatever `MIX_ENV`
the task runs under — finding the `PhoenixElxirBeam.MCP.Plugins.RuleEngine`
tuple and its `config["rules"]`.

## Coverage semantics

For each tool with at least one sensitive tag (assigned or suggested):

**Gap type A — tagged, uncovered.** The tool has an operator-assigned tag in
one of the two tags `TagInference` knows about (`:sensitive_read`,
`:network_egress` — there's no broader sensitive-tag registry in this
codebase; these two are the whole set). Build a synthetic
call context: no `agent_id` set, `tool_name` set to the tool's name, call
tags set to its assigned `tags`, empty session (no taint, no seen_tags). Run
it through the **real** first-match-wins resolution (see below). If the
winning rule's action isn't `deny` or `hold`, or no rule matches (implicit
allow), that's a gap — report the rule (if any) that shadowed the correct
one, so the output points at the fix.

**Gap type B — unreviewed.** The tool has a non-empty `suggested_tags` but
empty `tags` (operator never reviewed it). Reported unconditionally, and
annotated with whether `UnclassifiedGuard`'s configured `mode` is `"off"`
(meaning: this tool is *actually* unenforced right now, not just a
theoretical gap) versus `"deny"`/`"hold"` (meaning `UnclassifiedGuard`
already catches it at runtime, but it's still a hygiene gap worth surfacing).

A tool with no sensitive assigned or suggested tags at all is not reported —
nothing to check.

## Reusing the real matching logic

Rather than reimplement `RuleEngine`'s predicate/match semantics in the mix
task (which would drift from the real engine over time — the exact failure
mode this feature exists to catch), extract the matching step into a public
function on `RuleEngine`:

```elixir
@doc "Returns the first rule (or nil) that matches ctx, first-match-wins."
@spec first_match([map()], CallContext.t()) :: map() | nil
def first_match(rules, ctx), do: Enum.find(rules, &matches?(&1, ctx))
```

`evaluate/2` calls through this instead of inlining `Enum.find`. No other
behavior change. The mix task calls `RuleEngine.first_match/2` directly
against its synthetic `CallContext`, so gap detection runs the same code
path production traffic does.

## CLI behavior

```
mix mcp.rules.check [--env staging]
```

Reads DB connection config the normal way (`config/runtime.exs` /
`DATABASE_URL`, whatever the target `MIX_ENV` already resolves), so no new
connection config format is introduced.

Output: a plain-text table to stdout — tool name, server name, gap type,
and (for type A) which rule won instead and why. Exits `1` if any gap
exists, `0` otherwise, printing `"N tools checked, 0 gaps"` on success.

## Phase 2 — generated fixtures as the report artifact

The same run also writes `test/support/generated_rule_fixtures.ex`, a
module shaped like `RuleEngineCorpus` (`name`, `call`, `session`, `rules`),
one case per gap found — **not** wired into `mix test`, not asserted
anywhere automatically. It exists purely as a human-reviewable, git-diffable
artifact: what exactly is uncovered, expressed the same way every other rule
engine test case already is, so an operator reading the PR diff sees
concrete "this call would currently be allowed" cases rather than a log
line. Regenerated fresh every run (not hand-edited, not merged with
previous output) — closing a gap makes its case disappear from the file on
the next run, the same way the CLI's gap count drops to zero.

```elixir
# Auto-generated by `mix mcp.rules.check` — do not hand-edit, regenerated
# every run. Case disappears once the underlying gap is closed.
defmodule PhoenixElxirBeam.MCP.GeneratedRuleFixtures do
  def cases, do: [
    %{
      name: "gap: send_email (server github-mcp) — network_egress uncovered for unknown agents",
      call: %{tool_name: "send_email"},
      session: %{},
      gap_type: :uncovered_tag
    }
  ]
end
```

## Testing

- Unit tests for `RuleEngine.first_match/2` (already implicitly covered via
  existing `RuleEngineTest`/`RuleEngineCorpus`, since `evaluate/2` now calls
  through it — no new test surface needed there beyond confirming the
  extraction didn't change behavior).
- A new test module for the gap-detection logic itself, using
  `RuleEngineCorpus`-style fixtures for tool/rule combinations (reusing the
  existing corpus pattern rather than inventing a new one): tagged +
  covered → no gap; tagged + only agent-scoped rule → gap A; untagged +
  suggested → gap B (both `UnclassifiedGuard` states); no sensitive tags at
  all → not reported.
- An integration-style test against a real (test-env) Postgres with a
  couple of `ServerStore` rows seeded, asserting the mix task's exit code
  and that the generated fixture file's contents match the detected gaps.

## CI wiring

A dedicated CI job (not part of `mix precommit`, since it needs a real DB
with real registrations — not available on every PR by default) that runs
`mix mcp.rules.check --env staging` against the staging database, gating
merges the same way the existing `security-review.yml` / `ci.yml` jobs do.
Exact trigger (every PR vs. on a schedule vs. on deploy) is a rollout
decision for the implementation plan, not the design — the mechanism above
works the same regardless of when it's invoked.
