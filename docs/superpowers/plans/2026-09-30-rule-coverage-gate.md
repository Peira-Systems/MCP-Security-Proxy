# Rule Coverage Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `mix mcp.rules.check`, a CI-run mix task that fails the build when a real, currently-registered MCP tool with a sensitive tag isn't actually enforced by the compiled `RuleEngine` config, and writes the gaps as reviewable `RuleEngineCorpus`-shaped fixtures.

**Architecture:** A public `RuleEngine.first_match/2` is extracted from the plugin's existing private matcher so the checker reuses production matching logic instead of re-implementing it. `ServerStore` gains a fourth persisted per-tool field, `suggested_tags`, so gap detection has a complete picture from Postgres alone. A new `PhoenixElxirBeam.MCP.RuleCoverage` module holds the gap-detection logic (pure, DB-agnostic — takes tools + rules, returns gaps), and `Mix.Tasks.Mcp.Rules.Check` is a thin CLI wrapper around it that fetches from `ServerStore`/app config, prints the report, writes the generated fixture file, and sets the exit code.

**Tech Stack:** Elixir 1.18, Ecto/Postgres (existing `PhoenixElxirBeam.Repo`), ExUnit, `Mix.Task`.

**Spec:** `docs/superpowers/specs/2026-09-30-rule-coverage-gate-design.md`

## Global Constraints

- The two sensitive tags are exactly `:sensitive_read` and `:network_egress` (`TagInference`'s whole set) — do not invent a third or a registry of tags.
- "Covered" means an agent-agnostic rule (no `"agent"`/`"agent_prefix"` predicate) whose `tool_tags_any` includes the tag resolves to `deny` or `hold` as the *first* match against a synthetic call from an unset/unknown agent — simulated via real first-match-wins logic, never an existence-only check.
- `UnclassifiedGuard`/`RuleEngine` runtime behavior must not change — this feature is a build-time auditor only.
- Wasm-engine config drift is explicitly out of scope (covered by `rule_engine_wasm_parity_test.exs` already).
- Generated fixtures (`test/support/generated_rule_fixtures.ex`) are a report artifact only — never wired into `mix test`, never hand-edited, fully regenerated every run.
- No migration is needed for `suggested_tags` — `tool_state` is already a free-form `:map` column; add the key, don't touch the schema.

## Review Focus

- **A tool tagged with both `:sensitive_read` and `:network_egress`, only one of which is covered.** A reasonable operator expects "partially covered" tools to still show up as a gap for the uncovered tag specifically, not be silently treated as fully covered because *a* rule matched.
- **A rule whose `tool_tags_any` matches, but whose action is `"allow"` (an explicit shield).** This must still report as a gap for that tag — "some rule matched" is not the same as "a deny/hold rule matched first."
- **Postgres is unreachable or `ServerStore.all()` raises/returns `[]` in a broken-connection way.** `ServerStore.all()` already rescues to `[]` on its own errors (by the existing module's own design) — the task must not confuse "zero servers registered" with "connection failed," since both currently look identical; the task should still exit non-zero with a clear message if it got zero tools back, rather than silently reporting "0 gaps" as if that were a clean bill of health.
- **A tool with empty `tags` AND empty `suggested_tags`.** Must produce zero findings — nothing to check, not a gap of either type. (A naive `tags == []` check without also checking `suggested_tags` would wrongly flag every untagged, unremarkable tool as gap type B.)
- **Two servers registering a tool with the identical name.** The generated fixture and CLI report must disambiguate by server, not just tool name, since `name: "gap: send_email — ..."` alone would silently merge two distinct gaps into what looks like one line.

---

## Task 1: Extract `RuleEngine.first_match/2`

**Files:**
- Modify: `lib/phoenix_elxir_beam/mcp/plugins/rule_engine.ex:58-64` (the `evaluate/2` function and the `matches?/2`+`predicate/3` clauses stay, but become reachable via a new public entry point)
- Test: `test/phoenix_elxir_beam/mcp/plugins/rule_engine_test.exs` (extend existing file)

**Interfaces:**
- Produces: `RuleEngine.first_match([map()], CallContext.t()) :: map() | nil` — the first rule (raw map, with string keys `"match"`/`"action"`/`"reason"`/etc., exactly as written in config) whose predicates all hold against `ctx`, or `nil` if none match. This is the function Task 3's gap-detection logic calls directly.

This task is pure refactor — no behavior change. `evaluate/2` currently does `ctx.plugin_config |> Map.get("rules", []) |> Enum.find(&matches?(&1, ctx)) |> to_decision()`. After this task, the `Enum.find(&matches?(&1, ctx))` part is reachable as `first_match(rules, ctx)`, and `evaluate/2` calls it.

- [ ] **Step 1: Write a test proving `first_match/2` is public and behaves like the existing `Enum.find` did**

Add to `test/phoenix_elxir_beam/mcp/plugins/rule_engine_test.exs`, using the existing `ctx/1` helper and `RuleEngineCorpus` already imported in that file:

```elixir
describe "first_match/2" do
  test "returns the matching rule map, not a Decision" do
    %{call: call_overrides, session: session_overrides, rules: rules} =
      RuleEngineCorpus.fetch!("agent and tag both match")

    call =
      Map.merge(
        %{
          session_id: "s",
          agent_id: "agent://demo",
          server_id: "net",
          tool_name: "post_webhook",
          tags: [:network_egress]
        },
        call_overrides
      )

    context =
      CallContext.new(%{
        phase: :pre_call,
        call: call,
        session: Map.merge(%{seen_tags: [], taint: %{sources: []}}, session_overrides),
        plugin_config: %{"rules" => rules}
      })

    assert %{"action" => "deny", "reason" => "no egress for ci-runner"} =
             RuleEngine.first_match(rules, context)
  end

  test "returns nil when nothing matches" do
    %{call: call_overrides, session: session_overrides, rules: rules} =
      RuleEngineCorpus.fetch!("no rules")

    call = Map.merge(%{agent_id: "agent://demo", tool_name: "x", tags: []}, call_overrides)

    context =
      CallContext.new(%{
        phase: :pre_call,
        call: call,
        session: Map.merge(%{seen_tags: [], taint: %{sources: []}}, session_overrides),
        plugin_config: %{"rules" => rules}
      })

    assert RuleEngine.first_match(rules, context) == nil
  end
end
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mix test test/phoenix_elxir_beam/mcp/plugins/rule_engine_test.exs -v`
Expected: FAIL — `RuleEngine.first_match/2 is undefined or private`

- [ ] **Step 3: Extract the public function**

In `lib/phoenix_elxir_beam/mcp/plugins/rule_engine.ex`, replace:

```elixir
  @impl true
  def evaluate(:pre_call, %CallContext{} = ctx) do
    ctx.plugin_config
    |> Map.get("rules", [])
    |> Enum.find(&matches?(&1, ctx))
    |> to_decision()
  end
```

with:

```elixir
  @impl true
  def evaluate(:pre_call, %CallContext{} = ctx) do
    ctx.plugin_config
    |> Map.get("rules", [])
    |> first_match(ctx)
    |> to_decision()
  end

  @doc """
  Returns the first rule in `rules` whose `match` predicates all hold against
  `ctx` (first-match-wins, same semantics as `evaluate/2`), or `nil` if none
  match. Exposed so callers outside the plugin pipeline — the rule coverage
  checker (`PhoenixElxirBeam.MCP.RuleCoverage`) — can ask "what would this
  engine actually do" without re-implementing predicate matching.
  """
  @spec first_match([map()], CallContext.t()) :: map() | nil
  def first_match(rules, %CallContext{} = ctx) when is_list(rules) do
    Enum.find(rules, &matches?(&1, ctx))
  end
```

- [ ] **Step 4: Run the full rule engine test suite to verify everything still passes**

Run: `mix test test/phoenix_elxir_beam/mcp/plugins/rule_engine_test.exs test/phoenix_elxir_beam/mcp/plugins/rule_engine_wasm_parity_test.exs -v`
Expected: PASS (all existing tests plus the two new ones)

- [ ] **Step 5: Commit**

```bash
git add lib/phoenix_elxir_beam/mcp/plugins/rule_engine.ex test/phoenix_elxir_beam/mcp/plugins/rule_engine_test.exs
git commit -m "Extract RuleEngine.first_match/2 for reuse outside the plugin pipeline"
```

---

## Task 2: Persist `suggested_tags` in `ServerStore`

**Files:**
- Modify: `lib/phoenix_elxir_beam/mcp/server_store.ex:92-103` (`tool_state/1` private helper)
- Test: `test/phoenix_elxir_beam/mcp/server_registry_durability_test.exs` (extend existing file — this is the file that already tests persist/restore round-trips)

**Interfaces:**
- Consumes: nothing new — `tool.suggested_tags` already exists on every tool map produced by `ServerRegistry.discovered_tools/1` (`lib/phoenix_elxir_beam/mcp/server_registry.ex:508-526`), as a list of atoms (e.g. `[:network_egress]`).
- Produces: `ServerStore.persist/1` now writes `"suggested_tags" => [String.t()]` (stringified, same convention as `"tags"`) into each tool's overlay entry, readable via `reg.tool_state["tool_name"]["suggested_tags"]`. `ServerRegistry` itself is untouched (see Step 5 below — it already recomputes `suggested_tags` fresh on every live handshake, so it never needs to read the persisted copy back). Task 4 reads the persisted copy directly via `ServerStore.all()`.

- [ ] **Step 1: Read the existing durability test to confirm the round-trip pattern**

Run: `mix test test/phoenix_elxir_beam/mcp/server_registry_durability_test.exs -v`
Expected: PASS (establishes baseline before changes)

- [ ] **Step 2: Write a failing test asserting `suggested_tags` is persisted in the overlay**

Add this test to `test/phoenix_elxir_beam/mcp/server_registry_durability_test.exs`, following the file's own existing conventions exactly: its `@name :server_registry_durability` GenServer name (already defined at the top of the file), `start_reg/0` from `setup` (already runs before every test in the file), and `PhoenixElxirBeam.MCPHTTPTestServer.start!()` for a real HTTP stub — the same helper the file's first test (`"an http server, its operator tags, ... come back after a restart"`) already uses. That stub's fixed catalog (`test/support/mcp_http_test_server.ex`) already includes a tool named `"read_secrets"`, described as `"Read the contents of a sensitive secrets file"` — this matches `TagInference`'s `@sensitive_read` regex, so `:sensitive_read` is suggested with no changes to the stub needed. Do not invent a new stub tool or modify `mcp_http_test_server.ex`.

```elixir
test "suggested_tags is persisted in the tool_state overlay" do
  base_url = PhoenixElxirBeam.MCPHTTPTestServer.start!()

  {:ok, server} =
    ServerRegistry.register_server(
      "dur-suggested-#{System.unique_integer([:positive])}",
      base_url,
      [],
      @name
    )

  tool = Enum.find(server.tools, &(&1.name == "read_secrets"))
  assert :sensitive_read in tool.suggested_tags

  row = Repo.get(ServerRegistration, server.id)
  assert "sensitive_read" in row.tool_state["read_secrets"]["suggested_tags"]
end
```

- [ ] **Step 3: Run it to verify it fails**

Run: `mix test test/phoenix_elxir_beam/mcp/server_registry_durability_test.exs -v`
Expected: FAIL — `row.tool_state["read_secrets"]["suggested_tags"]` is `nil` (the key doesn't exist yet), so `"sensitive_read" in nil` raises a `Protocol.UndefinedError` or the `assert` fails depending on Elixir version; either way it does not pass.

- [ ] **Step 4: Persist `suggested_tags` in `ServerStore.tool_state/1`**

In `lib/phoenix_elxir_beam/mcp/server_store.ex`, change:

```elixir
  defp tool_state(tools) do
    Map.new(tools, fn tool ->
      {tool.name,
       %{
         "tags" => Enum.map(tool.tags || [], &to_string/1),
         "quarantined" => tool[:quarantined] || false,
         "quarantine_reason" => tool[:quarantine_reason],
         "hash" => tool[:description_hash]
       }}
    end)
  end
```

to:

```elixir
  defp tool_state(tools) do
    Map.new(tools, fn tool ->
      {tool.name,
       %{
         "tags" => Enum.map(tool.tags || [], &to_string/1),
         "suggested_tags" => Enum.map(tool[:suggested_tags] || [], &to_string/1),
         "quarantined" => tool[:quarantined] || false,
         "quarantine_reason" => tool[:quarantine_reason],
         "hash" => tool[:description_hash]
       }}
    end)
  end
```

- [ ] **Step 5: Confirm no `ServerRegistry` change is needed — `suggested_tags` is already fresh by the time the overlay would merge it**

Both `rebuild/3` (`lib/phoenix_elxir_beam/mcp/server_registry.ex:372-404`, the Postgres-restore-on-boot path) and `rehandshaked/2` (`:423-447`, the manual re-handshake path) call `discovered_tools(raw_tools)` *before* merging the persisted overlay, and `discovered_tools/1` (`:508-526`) always sets `suggested_tags: TagInference.infer(tool["name"], tool["description"])` fresh from the live handshake response. So `tool.suggested_tags` already holds the correct, current value at the moment the overlay's `ts ->` branch runs in both functions; the overlay's `tags`/`quarantined`/`quarantine_reason` keys get pulled from the persisted overlay because those are *operator decisions* that must survive a restart even if the live tool list changes, but `suggested_tags` is a pure function of the tool's own current name/description, recomputed every time there's a live tool list to compute it from. There is no code path in this codebase that needs `suggested_tags` without also having just run `discovered_tools/1` on fresh handshake data — **leave `rebuild/3` and `rehandshaked/2` exactly as they are.**

The only consumer of the field just persisted in Step 4 is Task 4's mix task, which has no live handshake to run at all — it reads `ServerStore.all()` directly, never touches `ServerRegistry` or `discover/2`.

- [ ] **Step 6: Run the test to verify it passes**

Run: `mix test test/phoenix_elxir_beam/mcp/server_registry_durability_test.exs -v`
Expected: PASS

- [ ] **Step 7: Run the full server registry test suite to check nothing else broke**

Run: `mix test test/phoenix_elxir_beam/mcp/server_registry_test.exs test/phoenix_elxir_beam/mcp/server_registry_durability_test.exs test/phoenix_elxir_beam_web/live/mcp_dashboard_stdio_registration_test.exs -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add lib/phoenix_elxir_beam/mcp/server_store.ex test/phoenix_elxir_beam/mcp/server_registry_durability_test.exs
git commit -m "Persist suggested_tags in the ServerStore tool overlay"
```

---

## Task 3: `PhoenixElxirBeam.MCP.RuleCoverage` — pure gap-detection logic

**Files:**
- Create: `lib/phoenix_elxir_beam/mcp/rule_coverage.ex`
- Create: `test/phoenix_elxir_beam/mcp/rule_coverage_test.exs`
- Create: `test/support/rule_coverage_corpus.ex` (fixtures, following the existing `RuleEngineCorpus` naming/shape convention)

**Interfaces:**
- Consumes: `RuleEngine.first_match/2` (Task 1), `CallContext.new/1`, `TagInference`'s two known tags (hardcoded as the module attribute below — there is no shared registry to import them from).
- Produces:
  - `RuleCoverage.sensitive_tags() :: [:sensitive_read | :network_egress]` — the canonical list, so Task 4 and any future caller never hardcodes it twice.
  - `RuleCoverage.check_tool(tool :: map(), rules :: [map()], unclassified_guard_mode :: String.t()) :: [RuleCoverage.Gap.t()]` where `tool` is `%{name: String.t(), tags: [atom()], suggested_tags: [atom()]}` (server identity is threaded by the caller, not this function — see Task 4) and each `Gap` is `%RuleCoverage.Gap{type: :uncovered_tag | :unreviewed, tool_name: String.t(), tag: atom() | nil, shadowing_rule: map() | nil, unclassified_guard_mode: String.t()}`.
  - `RuleCoverage.Gap` struct, defined in the same file.

This module takes plain data in and returns plain data out — no Ecto, no `Mix.Task`, testable without a database. Task 4 is the only caller that touches Postgres or `Application.get_env`.

- [ ] **Step 1: Write the fixture corpus**

Create `test/support/rule_coverage_corpus.ex`:

```elixir
defmodule PhoenixElxirBeam.MCP.RuleCoverageCorpus do
  @moduledoc """
  Shared `(tool, rules, unclassified_guard_mode)` fixtures for
  `RuleCoverageTest` — one tool-under-test per scenario the Review Focus
  section of the coverage-gate spec calls out.
  """

  @cases [
    %{
      name: "tagged and covered by an agent-agnostic deny rule",
      tool: %{name: "read_secrets", tags: [:sensitive_read], suggested_tags: [:sensitive_read]},
      rules: [
        %{"match" => %{"tool_tags_any" => ["sensitive_read"]}, "action" => "deny", "reason" => "r"}
      ],
      unclassified_guard_mode: "off",
      expected_gap_types: []
    },
    %{
      name: "tagged but only an agent-scoped rule covers it",
      tool: %{name: "read_secrets", tags: [:sensitive_read], suggested_tags: [:sensitive_read]},
      rules: [
        %{
          "match" => %{"agent" => "agent://ci-runner", "tool_tags_any" => ["sensitive_read"]},
          "action" => "deny",
          "reason" => "r"
        }
      ],
      unclassified_guard_mode: "off",
      expected_gap_types: [:uncovered_tag]
    },
    %{
      name: "tagged but shadowed by an earlier catch-all allow",
      tool: %{name: "read_secrets", tags: [:sensitive_read], suggested_tags: [:sensitive_read]},
      rules: [
        %{"match" => %{}, "action" => "allow", "reason" => "catch-all"},
        %{"match" => %{"tool_tags_any" => ["sensitive_read"]}, "action" => "deny", "reason" => "r"}
      ],
      unclassified_guard_mode: "off",
      expected_gap_types: [:uncovered_tag]
    },
    %{
      name: "tagged but the matching rule's action is allow (explicit shield)",
      tool: %{name: "read_secrets", tags: [:sensitive_read], suggested_tags: [:sensitive_read]},
      rules: [
        %{"match" => %{"tool_tags_any" => ["sensitive_read"]}, "action" => "allow", "reason" => "r"}
      ],
      unclassified_guard_mode: "off",
      expected_gap_types: [:uncovered_tag]
    },
    %{
      name: "two tags, only one covered",
      tool: %{
        name: "fetch_and_send_key",
        tags: [:sensitive_read, :network_egress],
        suggested_tags: [:sensitive_read, :network_egress]
      },
      rules: [
        %{"match" => %{"tool_tags_any" => ["sensitive_read"]}, "action" => "deny", "reason" => "r"}
      ],
      unclassified_guard_mode: "off",
      expected_gap_types: [:uncovered_tag]
    },
    %{
      name: "untagged but suggested, unclassified guard off",
      tool: %{name: "send_email", tags: [], suggested_tags: [:network_egress]},
      rules: [],
      unclassified_guard_mode: "off",
      expected_gap_types: [:unreviewed]
    },
    %{
      name: "untagged but suggested, unclassified guard deny",
      tool: %{name: "send_email", tags: [], suggested_tags: [:network_egress]},
      rules: [],
      unclassified_guard_mode: "deny",
      expected_gap_types: [:unreviewed]
    },
    %{
      name: "no tags at all, nothing suggested",
      tool: %{name: "list_files", tags: [], suggested_tags: []},
      rules: [],
      unclassified_guard_mode: "off",
      expected_gap_types: []
    },
    %{
      name: "tagged and covered, suggested_tags now irrelevant",
      tool: %{name: "read_secrets", tags: [:sensitive_read], suggested_tags: []},
      rules: [
        %{"match" => %{"tool_tags_any" => ["sensitive_read"]}, "action" => "deny", "reason" => "r"}
      ],
      unclassified_guard_mode: "off",
      expected_gap_types: []
    }
  ]

  @doc "Every fixture, in the order above."
  def cases, do: @cases

  @doc "One fixture by name."
  def fetch!(name) do
    Enum.find(@cases, &(&1.name == name)) ||
      raise "no RuleCoverageCorpus case named #{inspect(name)}"
  end
end
```

- [ ] **Step 2: Write the failing test**

Create `test/phoenix_elxir_beam/mcp/rule_coverage_test.exs`:

```elixir
defmodule PhoenixElxirBeam.MCP.RuleCoverageTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.RuleCoverage
  alias PhoenixElxirBeam.MCP.RuleCoverageCorpus

  test "sensitive_tags/0 is exactly sensitive_read and network_egress" do
    assert Enum.sort(RuleCoverage.sensitive_tags()) ==
             Enum.sort([:sensitive_read, :network_egress])
  end

  for %{name: name} <- RuleCoverageCorpus.cases() do
    test "case: #{name}" do
      %{tool: tool, rules: rules, unclassified_guard_mode: mode, expected_gap_types: expected} =
        RuleCoverageCorpus.fetch!(unquote(name))

      gaps = RuleCoverage.check_tool(tool, rules, mode)
      assert Enum.sort(Enum.map(gaps, & &1.type)) == Enum.sort(expected)
    end
  end

  test "an uncovered_tag gap names the tag and the shadowing rule, if any" do
    %{tool: tool, rules: rules, unclassified_guard_mode: mode} =
      RuleCoverageCorpus.fetch!("tagged but shadowed by an earlier catch-all allow")

    assert [%RuleCoverage.Gap{type: :uncovered_tag, tag: :sensitive_read, shadowing_rule: rule}] =
             RuleCoverage.check_tool(tool, rules, mode)

    assert rule["action"] == "allow"
  end

  test "an unreviewed gap carries the unclassified_guard_mode for the caller to report" do
    %{tool: tool, rules: rules, unclassified_guard_mode: mode} =
      RuleCoverageCorpus.fetch!("untagged but suggested, unclassified guard deny")

    assert [%RuleCoverage.Gap{type: :unreviewed, unclassified_guard_mode: "deny"}] =
             RuleCoverage.check_tool(tool, rules, mode)
  end
end
```

- [ ] **Step 3: Run it to verify it fails**

Run: `mix test test/phoenix_elxir_beam/mcp/rule_coverage_test.exs -v`
Expected: FAIL — `PhoenixElxirBeam.MCP.RuleCoverage` module not defined

- [ ] **Step 4: Implement `RuleCoverage`**

Create `lib/phoenix_elxir_beam/mcp/rule_coverage.ex`:

```elixir
defmodule PhoenixElxirBeam.MCP.RuleCoverage do
  @moduledoc """
  Build-time audit of whether a tool's sensitive tags are actually enforced
  by the compiled `RuleEngine` config, independent of any specific agent.
  Pure: takes a tool's tags and the rule list, returns the gaps. Callers
  (`Mix.Tasks.Mcp.Rules.Check`) own fetching those inputs from Postgres /
  app config and reporting the output.

  Two gap types (`docs/superpowers/specs/2026-09-30-rule-coverage-gate-design.md`):

    * `:uncovered_tag` — the tool is tagged with a sensitive tag, but no
      agent-agnostic rule resolves to `deny`/`hold` as the first match for
      an arbitrary agent calling it.
    * `:unreviewed` — the tool has a suggested tag but empty operator tags;
      nobody has looked at it, so it's invisible to the rule engine
      regardless of what rules exist.
  """

  alias PhoenixElxirBeam.MCP.{CallContext, Plugins.RuleEngine}

  @sensitive_tags [:sensitive_read, :network_egress]

  defmodule Gap do
    @moduledoc "One coverage gap for one tool."
    defstruct [:type, :tool_name, :tag, :shadowing_rule, :unclassified_guard_mode]

    @type t :: %__MODULE__{
            type: :uncovered_tag | :unreviewed,
            tool_name: String.t(),
            tag: atom() | nil,
            shadowing_rule: map() | nil,
            unclassified_guard_mode: String.t() | nil
          }
  end

  @doc "The complete, fixed set of tags this checker cares about."
  @spec sensitive_tags() :: [atom()]
  def sensitive_tags, do: @sensitive_tags

  @doc """
  Gaps for a single tool. `tool` is `%{name:, tags:, suggested_tags:}`
  (atoms in the tag lists, matching `ServerRegistry`'s in-memory shape).
  `rules` is the `RuleEngine` plugin's raw `config["rules"]` list.
  `unclassified_guard_mode` is whatever `UnclassifiedGuard`'s plugin config
  currently has for `"mode"` (`"off"` | `"deny"` | `"hold"`), threaded
  through only to annotate `:unreviewed` gaps — it doesn't change whether a
  gap is reported, only what the caller prints about it.
  """
  @spec check_tool(map(), [map()], String.t()) :: [Gap.t()]
  def check_tool(tool, rules, unclassified_guard_mode) do
    uncovered_tag_gaps(tool, rules) ++ unreviewed_gap(tool, unclassified_guard_mode)
  end

  defp uncovered_tag_gaps(tool, rules) do
    tool.tags
    |> Enum.filter(&(&1 in @sensitive_tags))
    |> Enum.flat_map(fn tag ->
      ctx = synthetic_context(tool.name, [tag])

      case RuleEngine.first_match(rules, ctx) do
        %{"action" => action} = rule when action in ["deny", "hold"] ->
          if agent_agnostic?(rule), do: [], else: [uncovered(tool, tag, rule)]

        rule ->
          [uncovered(tool, tag, rule)]
      end
    end)
  end

  defp uncovered(tool, tag, rule) do
    %Gap{type: :uncovered_tag, tool_name: tool.name, tag: tag, shadowing_rule: rule}
  end

  defp agent_agnostic?(rule) do
    match = Map.get(rule, "match", %{})
    not Map.has_key?(match, "agent") and not Map.has_key?(match, "agent_prefix")
  end

  defp unreviewed_gap(%{tags: [], suggested_tags: suggested} = tool, mode) when suggested != [] do
    [%Gap{type: :unreviewed, tool_name: tool.name, unclassified_guard_mode: mode}]
  end

  defp unreviewed_gap(_tool, _mode), do: []

  defp synthetic_context(tool_name, tags) do
    CallContext.new(%{
      phase: :pre_call,
      call: %{tool_name: tool_name, tags: tags},
      session: %{seen_tags: [], taint: %{sources: []}},
      plugin_config: %{}
    })
  end
end
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `mix test test/phoenix_elxir_beam/mcp/rule_coverage_test.exs -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add lib/phoenix_elxir_beam/mcp/rule_coverage.ex test/phoenix_elxir_beam/mcp/rule_coverage_test.exs test/support/rule_coverage_corpus.ex
git commit -m "Add RuleCoverage: pure gap-detection logic for sensitive tools"
```

---

## Task 4: `mix mcp.rules.check` — CLI wrapper, fixture generation, exit code

**Files:**
- Create: `lib/mix/tasks/mcp.rules.check.ex`
- Create: `test/mix/tasks/mcp_rules_check_test.exs`

**Interfaces:**
- Consumes: `RuleCoverage.sensitive_tags/0`, `RuleCoverage.check_tool/3` (Task 3), `RuleEngine.first_match/2` (Task 1, used indirectly through `check_tool/3`), `PhoenixElxirBeam.MCP.ServerStore.all/0` (Task 2's persisted `suggested_tags`), `Application.get_env(:phoenix_elxir_beam, PhoenixElxirBeam.MCP)`.
- Produces: the `mix mcp.rules.check` task itself; `test/support/generated_rule_fixtures.ex` as a side-effect file (not consumed by any other task in this plan — it's a terminal report artifact).

- [ ] **Step 1: Write the failing test for the task's pure reporting logic**

Since a full end-to-end test would need a seeded Postgres instance and real app config, first test the task's internal data-shaping logic in isolation by extracting it into testable private-but-documented functions within the task module itself, tested via `Mix.Task.run/2` against seeded data in the sandbox. Create `test/mix/tasks/mcp_rules_check_test.exs`:

```elixir
defmodule Mix.Tasks.Mcp.Rules.CheckTest do
  use PhoenixElxirBeam.DataCase, async: false

  alias PhoenixElxirBeam.MCP.{ServerRegistration, ServerStore}
  alias PhoenixElxirBeam.Repo

  setup do
    original = Application.get_env(:phoenix_elxir_beam, PhoenixElxirBeam.MCP)

    on_exit(fn ->
      if original do
        Application.put_env(:phoenix_elxir_beam, PhoenixElxirBeam.MCP, original)
      else
        Application.delete_env(:phoenix_elxir_beam, PhoenixElxirBeam.MCP)
      end
    end)

    :ok
  end

  defp seed_server(id, name, tool_state) do
    %ServerRegistration{}
    |> ServerRegistration.changeset(%{
      id: id,
      name: name,
      transport: "http",
      base_url: "http://example.invalid",
      tool_state: tool_state
    })
    |> Repo.insert!()
  end

  defp configure_rules(rules, unclassified_mode \\ "off") do
    Application.put_env(:phoenix_elxir_beam, PhoenixElxirBeam.MCP,
      plugins: [
        {PhoenixElxirBeam.MCP.Plugins.RuleEngine, config: %{"rules" => rules}},
        {PhoenixElxirBeam.MCP.Plugins.UnclassifiedGuard, config: %{"mode" => unclassified_mode}}
      ]
    )
  end

  test "exits 0 and reports zero gaps when every sensitive tool is covered" do
    seed_server("srv-a", "server-a", %{
      "read_secrets" => %{
        "tags" => ["sensitive_read"],
        "suggested_tags" => ["sensitive_read"],
        "quarantined" => false,
        "quarantine_reason" => nil,
        "hash" => "h"
      }
    })

    configure_rules([
      %{"match" => %{"tool_tags_any" => ["sensitive_read"]}, "action" => "deny", "reason" => "r"}
    ])

    {gaps, _report} = Mix.Tasks.Mcp.Rules.Check.run_check()
    assert gaps == []
  end

  test "reports a gap when a tool's only rule is agent-scoped" do
    seed_server("srv-b", "server-b", %{
      "read_secrets" => %{
        "tags" => ["sensitive_read"],
        "suggested_tags" => ["sensitive_read"],
        "quarantined" => false,
        "quarantine_reason" => nil,
        "hash" => "h"
      }
    })

    configure_rules([
      %{
        "match" => %{"agent" => "agent://ci-runner", "tool_tags_any" => ["sensitive_read"]},
        "action" => "deny",
        "reason" => "r"
      }
    ])

    {gaps, _report} = Mix.Tasks.Mcp.Rules.Check.run_check()
    assert [%{type: :uncovered_tag, tool_name: "read_secrets", server_name: "server-b"}] = gaps
  end

  test "disambiguates identically-named tools on two different servers" do
    tool_state = %{
      "send_email" => %{
        "tags" => [],
        "suggested_tags" => ["network_egress"],
        "quarantined" => false,
        "quarantine_reason" => nil,
        "hash" => "h"
      }
    }

    seed_server("srv-c", "server-c", tool_state)
    seed_server("srv-d", "server-d", tool_state)
    configure_rules([])

    {gaps, _report} = Mix.Tasks.Mcp.Rules.Check.run_check()

    assert Enum.sort(Enum.map(gaps, & &1.server_name)) == ["server-c", "server-d"]
    assert Enum.all?(gaps, &(&1.tool_name == "send_email" and &1.type == :unreviewed))
  end

  test "zero registered servers reports a distinct warning, not a clean bill of health" do
    configure_rules([])

    {gaps, report} = Mix.Tasks.Mcp.Rules.Check.run_check()

    assert gaps == []
    assert report =~ "0 servers registered"
    refute report =~ "0 gaps"
  end
end
```

- [ ] **Step 2: Run it to verify it fails**

Run: `mix test test/mix/tasks/mcp_rules_check_test.exs -v`
Expected: FAIL — `Mix.Tasks.Mcp.Rules.Check` module not defined

- [ ] **Step 3: Implement the mix task**

Create `lib/mix/tasks/mcp.rules.check.ex`:

```elixir
defmodule Mix.Tasks.Mcp.Rules.Check do
  @shortdoc "Fails if a registered tool's sensitive tags aren't actually enforced"

  @moduledoc """
  Audits every tool on every currently-registered MCP server (read from
  Postgres via `PhoenixElxirBeam.MCP.ServerStore`) against the compiled
  `RuleEngine` config, and fails the build if any sensitive tool isn't
  actually enforced for an arbitrary agent.

  See `docs/superpowers/specs/2026-09-30-rule-coverage-gate-design.md` for
  the full design, and `PhoenixElxirBeam.MCP.RuleCoverage` for the
  detection logic this task is a thin wrapper around.

      mix mcp.rules.check

  Reads DB connection config the normal way for whatever `MIX_ENV` it's
  invoked under (`config/runtime.exs` / `DATABASE_URL`) — no new connection
  config is introduced. Exits 1 and prints every gap if any are found,
  exits 0 and prints a summary otherwise. Also writes
  `test/support/generated_rule_fixtures.ex`, a `RuleEngineCorpus`-shaped,
  fully-regenerated-every-run report of the same gaps, for human review in
  a PR diff — this file is never read by `mix test`.
  """

  use Mix.Task

  alias PhoenixElxirBeam.MCP.{RuleCoverage, ServerStore}

  @generated_fixtures_path "test/support/generated_rule_fixtures.ex"

  @impl true
  def run(_args) do
    Mix.Task.run("app.start")

    {gaps, report} = run_check()

    Mix.shell().info(report)
    write_generated_fixtures(gaps)

    if gaps != [] do
      Mix.raise("mcp.rules.check found #{length(gaps)} coverage gap(s) — see report above")
    end
  end

  @doc """
  Runs the check against the currently configured Repo and app config,
  without printing or exiting — used by the task's own tests and by
  `run/1` itself. Returns `{gaps, report_text}` where each gap is
  `%{type:, tool_name:, server_name:, tag:, shadowing_rule:,
  unclassified_guard_mode:}` (a plain map — the task flattens
  `RuleCoverage.Gap` and adds `server_name`, since `RuleCoverage` itself
  has no notion of which server a tool came from).
  """
  @spec run_check() :: {[map()], String.t()}
  def run_check do
    registrations = ServerStore.all()

    if registrations == [] do
      {[],
       "mcp.rules.check: 0 servers registered in this database — nothing to check.\n" <>
         "If servers are expected here, this may indicate a connection problem rather than a clean bill of health."}
    else
      rules = rule_engine_rules()
      unclassified_mode = unclassified_guard_mode()

      gaps =
        for reg <- registrations,
            {tool_name, overlay} <- reg.tool_state || %{},
            tool = tool_from_overlay(tool_name, overlay),
            gap <- RuleCoverage.check_tool(tool, rules, unclassified_mode) do
          %{
            type: gap.type,
            tool_name: tool_name,
            server_name: reg.name,
            tag: gap.tag,
            shadowing_rule: gap.shadowing_rule,
            unclassified_guard_mode: gap.unclassified_guard_mode
          }
        end

      {gaps, format_report(gaps, length(registrations))}
    end
  end

  defp tool_from_overlay(name, overlay) do
    %{
      name: name,
      tags: atoms(overlay["tags"]),
      suggested_tags: atoms(overlay["suggested_tags"])
    }
  end

  defp atoms(nil), do: []

  defp atoms(list) do
    Enum.flat_map(list, fn s ->
      [String.to_existing_atom(s)]
    rescue
      ArgumentError -> []
    end)
  end

  defp rule_engine_rules do
    :phoenix_elxir_beam
    |> Application.get_env(PhoenixElxirBeam.MCP, [])
    |> Keyword.get(:plugins, [])
    |> Enum.find_value([], fn
      {PhoenixElxirBeam.MCP.Plugins.RuleEngine, opts} -> Keyword.get(opts, :config, %{})["rules"] || []
      _ -> false
    end)
  end

  defp unclassified_guard_mode do
    :phoenix_elxir_beam
    |> Application.get_env(PhoenixElxirBeam.MCP, [])
    |> Keyword.get(:plugins, [])
    |> Enum.find_value("off", fn
      {PhoenixElxirBeam.MCP.Plugins.UnclassifiedGuard, opts} ->
        Keyword.get(opts, :config, %{})["mode"] || "off"

      _ ->
        false
    end)
  end

  defp format_report([], count) do
    "mcp.rules.check: #{count} server(s) checked, 0 gaps."
  end

  defp format_report(gaps, count) do
    lines =
      Enum.map(gaps, fn
        %{type: :uncovered_tag} = g ->
          "  [uncovered_tag] #{g.server_name}/#{g.tool_name} tag=#{g.tag} " <>
            "— first matching rule: #{inspect(g.shadowing_rule)}"

        %{type: :unreviewed} = g ->
          "  [unreviewed]    #{g.server_name}/#{g.tool_name} " <>
            "(UnclassifiedGuard mode=#{g.unclassified_guard_mode})"
      end)

    "mcp.rules.check: #{count} server(s) checked, #{length(gaps)} gap(s):\n" <>
      Enum.join(lines, "\n")
  end

  defp write_generated_fixtures(gaps) do
    body =
      gaps
      |> Enum.map(&fixture_case/1)
      |> Enum.join(",\n")

    contents = """
    # Auto-generated by `mix mcp.rules.check` — do not hand-edit, regenerated
    # every run. A case disappears once the underlying gap is closed.
    defmodule PhoenixElxirBeam.MCP.GeneratedRuleFixtures do
      @moduledoc "Coverage gaps from the most recent `mix mcp.rules.check` run."

      def cases, do: [
    #{body}
      ]
    end
    """

    File.write!(@generated_fixtures_path, contents)
  end

  defp fixture_case(%{type: :uncovered_tag} = g) do
    """
        %{
          name: #{inspect("gap: #{g.server_name}/#{g.tool_name} — #{g.tag} uncovered for unknown agents")},
          call: %{tool_name: #{inspect(g.tool_name)}, tags: [#{inspect(g.tag)}]},
          session: %{},
          gap_type: :uncovered_tag
        }
    """
  end

  defp fixture_case(%{type: :unreviewed} = g) do
    """
        %{
          name: #{inspect("gap: #{g.server_name}/#{g.tool_name} — suggested tag never reviewed")},
          call: %{tool_name: #{inspect(g.tool_name)}, tags: []},
          session: %{},
          gap_type: :unreviewed
        }
    """
  end
end
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `mix test test/mix/tasks/mcp_rules_check_test.exs -v`
Expected: PASS

- [ ] **Step 5: Manually verify the generated fixture file and exit code end to end**

Run: `mix mcp.rules.check`
Expected: against whatever's in your local dev DB, either "0 gaps" with exit 0, or a printed table and a non-zero exit (`mix` surfaces `Mix.raise/1` as a non-zero process exit). Then inspect:

Run: `cat test/support/generated_rule_fixtures.ex`
Expected: valid Elixir, one `%{...}` map per gap (or an empty list if there were none), matching what the table printed.

- [ ] **Step 6: Commit**

```bash
git add lib/mix/tasks/mcp.rules.check.ex test/mix/tasks/mcp_rules_check_test.exs
git commit -m "Add mix mcp.rules.check: CI coverage gate for sensitive tool rules"
```

---

## Task 5: Ignore the generated fixture file appropriately and wire CI

**Files:**
- Modify: `.gitignore` (decide whether the generated file is checked in or not — see step 1)
- Create: `.github/workflows/rule-coverage.yml`
- Modify: `docs/superpowers/specs/2026-09-30-rule-coverage-gate-design.md` (mark the CI-wiring section as resolved, linking to the new workflow file — this is documentation, not a behavior task, so no test)

**Interfaces:**
- Consumes: Task 4's `mix mcp.rules.check`.
- Produces: a CI job other engineers see gating PRs.

- [ ] **Step 1: Decide and record whether the generated fixture file is checked in**

The spec calls the fixture file "git-diffable" and says a reviewer should see it change in a PR diff — that only works if it's committed, not gitignored. Do **not** add `test/support/generated_rule_fixtures.ex` to `.gitignore`. Instead, the CI job (next step) regenerates it as part of the run and the workflow fails if the regenerated file differs from what's committed, the same drift-detection pattern as a formatter check — this is what actually surfaces "the coverage picture changed" in a PR diff, not merely running the check silently.

- [ ] **Step 2: Write the CI workflow**

First read the two existing workflow files to match their conventions:

Run: `cat .github/workflows/ci.yml .github/workflows/security-review.yml`

Then create `.github/workflows/rule-coverage.yml` following the same Elixir setup/service-container pattern those files already use for Postgres + `mix test` (match their `elixir`/`otp` version pins, `actions/checkout`, `mix deps.get`, and Postgres service block exactly — do not invent new version numbers). The job-specific steps, after that shared setup:

```yaml
      - name: Run rule coverage check
        run: mix mcp.rules.check

      - name: Fail if the generated fixture report is out of date
        run: |
          git diff --exit-code test/support/generated_rule_fixtures.ex || \
            (echo "::error::generated_rule_fixtures.ex is out of date — run 'mix mcp.rules.check' locally and commit the result" && exit 1)
```

Note this job needs a database with real server registrations to be meaningful (per the spec's "Data source" section) — point its `DATABASE_URL`/`PGHOST` etc. at whatever staging connection this repo's existing CI secrets already provide, following the same secret-reference pattern `ci.yml`/`security-review.yml` use for any existing staging credentials. If no such staging DB/secret exists yet in this repo's CI today, stop and ask the user which existing secret (if any) to point at, rather than inventing a connection string — this is an infrastructure decision outside this plan's file scope.

- [ ] **Step 3: Update the spec's CI-wiring section to point at the new file**

In `docs/superpowers/specs/2026-09-30-rule-coverage-gate-design.md`, find the "## CI wiring" section and append a closing note:

```markdown

Implemented as `.github/workflows/rule-coverage.yml`.
```

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/rule-coverage.yml docs/superpowers/specs/2026-09-30-rule-coverage-gate-design.md
git commit -m "Wire mix mcp.rules.check into CI as a required job"
```

---

## Task 6: `mix precommit` stays local-only; document the split

**Files:**
- Modify: `docs/superpowers/specs/2026-09-30-rule-coverage-gate-design.md` (no new section — this task is a verification + a one-line doc clarification, not new code)

**Interfaces:** none — this task has no production code change. It exists because "why isn't this in `mix precommit`" is a predictable question for the next engineer who reads this plan, and the spec already answered it but the answer is easy to miss.

- [ ] **Step 1: Confirm `mix precommit`'s alias is unchanged**

Run: `grep -n "precommit:" mix.exs`
Expected: still exactly `precommit: ["compile --warnings-as-errors", "deps.unlock --unused", "format", "test"]` — this task adds nothing to it. `mix mcp.rules.check` needs a real staging DB with real registrations to mean anything (per the spec), which a local `mix precommit` run doesn't have — it stays a CI-only job (Task 5), never added to this alias.

- [ ] **Step 2: Add a one-line pointer comment above the alias**

In `mix.exs`, immediately above the `aliases()` function's `precommit:` line, add:

```elixir
      # mix mcp.rules.check (CI-only, needs a real staging DB with real
      # server registrations — see .github/workflows/rule-coverage.yml and
      # docs/superpowers/specs/2026-09-30-rule-coverage-gate-design.md)
      # deliberately isn't in this list.
      precommit: ["compile --warnings-as-errors", "deps.unlock --unused", "format", "test"],
```

- [ ] **Step 3: Run precommit once to confirm nothing regressed across the whole plan**

Run: `mix precommit`
Expected: PASS — compiles clean with warnings-as-errors, no unused deps, formatted, full test suite green (including every test added in Tasks 1–4).

- [ ] **Step 4: Commit**

```bash
git add mix.exs
git commit -m "Document why mix mcp.rules.check is CI-only, not in mix precommit"
```
