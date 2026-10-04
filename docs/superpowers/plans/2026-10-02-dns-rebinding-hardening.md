# DNS-Rebinding Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden `MetadataEgressGuard` against DNS responses that mix a benign address with a forbidden one, and against suspiciously short TTLs — the two proxy-side signals of a DNS-rebinding attempt that are actually observable from this plugin's position in the architecture.

**Architecture:** `MetadataEgressGuard.resolve/1` currently calls `:inet.gethostbyname/1` and only inspects the first returned address. This plan switches resolution to `:inet_res.resolve/3`, which exposes TTL and the full answer list, and makes `forbidden_target/1` check every address, escalating `Decision` severity to `:critical` when any record's TTL is below 60 seconds. A resolver function is injected via a module attribute with a default, so tests can supply a fake multi-answer/low-TTL response without flaky real-DNS dependencies.

**Tech Stack:** Elixir, `:inet_res` (OTP's DNS resolver, lower-level than `:inet.gethostbyname/1`), ExUnit.

**Spec:** `docs/superpowers/specs/2026-10-02-dns-rebinding-hardening-design.md`

## Global Constraints

- No new dependencies — `:inet_res` is part of OTP's `kernel` application, already available.
- `mix precommit` (format + compile with warnings-as-errors + test) must pass before any commit per this repo's `AGENTS.md`.
- Never use `String.to_atom/1` on any resolver-returned or user-controlled data (per `AGENTS.md` Elixir guidelines) — resolver output here is tuples/integers only, no atom conversion needed, but keep this in mind if touched code changes.
- Existing `metadata_egress_guard_test.exs` tests must continue passing unmodified except where this plan explicitly says to change one.
- `Decision.deny/2`'s `severity` type is `Finding.severity()` (`lib/phoenix_elxir_beam/mcp/finding.ex`) — confirm `:critical` is a valid value in that type before using it.

## Review Focus

- **A hostname that resolves to zero addresses (NXDOMAIN via `:inet_res.resolve/3`, not just the `:inet.gethostbyname/1` error shape).** `:inet_res.resolve/3` returns a different error tuple shape than `:inet.gethostbyname/1}` on failure — a naive port of the existing `case` could crash instead of falling through to "allow, let it fail upstream" the way the existing failing-resolution test expects.
- **A response with a forbidden IP as the *first* address and a benign one second.** Easy to accidentally only fix the "benign first" ordering and regress the already-passing case where the forbidden address was already first.
- **A record with no TTL field exposed at all** (some stub/test resolvers return `0` or omit it) — must not crash computing "shortest TTL among records," and must not spuriously escalate severity from a missing-not-short TTL.
- **The existing "allows a hostname that fails to resolve" test** (`metadata_egress_guard_test.exs:71-74`, `this-host-does-not-exist.invalid`) **depends on real DNS NXDOMAIN behavior** — switching resolver functions must not turn this into a flaky network-dependent test failure in CI (sandboxed/offline CI runners may not even reach a DNS server for a `.invalid` lookup the same way).
- **IPv6 addresses.** `:inet_res.resolve/3` with the default `:a` type only looks up IPv4; a target that only has an `AAAA` record would currently be treated as "fails to resolve" → allowed, same as today — this plan does not change that behavior, but a test should pin it explicitly so it's a documented, intentional limitation rather than a silent gap discovered later.

---

### Task 1: Make the resolver injectable and preserve current behavior

**Files:**
- Modify: `lib/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard.ex`
- Test: `test/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard_test.exs`

**Interfaces:**
- Produces: `MetadataEgressGuard.resolve_all/2` — `(host :: String.t(), resolver :: (charlist() -> {:ok, [{ip :: tuple(), ttl :: non_neg_integer()}]} | :error)) :: {:ok, [{tuple(), non_neg_integer()}]} | :error`. Task 2 and Task 3 call this.
- Produces: `MetadataEgressGuard.default_resolver/1` — `(charlist() -> {:ok, [{tuple(), non_neg_integer()}]} | :error)`, the real `:inet_res`-backed implementation, used as `resolve_all/2`'s default second argument.

This task only restructures `resolve/1` into an injectable, multi-answer-returning shape with a real backing implementation — it does not yet change `forbidden_target/1`'s single-address behavior, so all existing tests must pass unchanged. Tasks 2 and 3 build the new behavior on top.

- [ ] **Step 1: Write a failing test for the new `resolve_all/2` shape with an injected fake resolver**

Add to `test/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard_test.exs`, inside the existing `describe` block (or at module level, matching the file's current flat style):

```elixir
  test "resolve_all/2 returns every address and TTL from an injected resolver" do
    fake_resolver = fn
      ~c"multi.test" -> {:ok, [{{93, 184, 216, 34}, 300}, {{169, 254, 169, 254}, 30}]}
      _ -> :error
    end

    assert {:ok, [{{93, 184, 216, 34}, 300}, {{169, 254, 169, 254}, 30}]} =
             MetadataEgressGuard.resolve_all("multi.test", fake_resolver)
  end

  test "resolve_all/2 returns :error when the injected resolver fails" do
    fake_resolver = fn _ -> :error end
    assert :error = MetadataEgressGuard.resolve_all("nowhere.test", fake_resolver)
  end

  test "resolve_all/2 parses an IP-literal host without calling the resolver" do
    fake_resolver = fn _ -> raise "resolver should not be called for an IP literal" end
    assert {:ok, [{{127, 0, 0, 1}, 0}]} = MetadataEgressGuard.resolve_all("127.0.0.1", fake_resolver)
  end
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `mix test test/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard_test.exs -v`
Expected: FAIL — `MetadataEgressGuard.resolve_all/2 is undefined or private`

- [ ] **Step 3: Implement `resolve_all/2` and `default_resolver/1`, replacing `resolve/1`**

Replace the existing `resolve/1` private function (`metadata_egress_guard.ex:86-98`) with:

```elixir
  @doc false
  @spec resolve_all(String.t(), (charlist() -> {:ok, [{tuple(), non_neg_integer()}]} | :error)) ::
          {:ok, [{tuple(), non_neg_integer()}]} | :error
  def resolve_all(host, resolver \\ &default_resolver/1) do
    charlist = String.to_charlist(host)

    case :inet.parse_address(charlist) do
      {:ok, ip_tuple} -> {:ok, [{ip_tuple, 0}]}
      {:error, :einval} -> resolver.(charlist)
    end
  end

  @doc false
  @spec default_resolver(charlist()) :: {:ok, [{tuple(), non_neg_integer()}]} | :error
  def default_resolver(charlist) do
    case :inet_res.resolve(charlist, :in, :a) do
      {:ok, dns_rec} ->
        answers =
          dns_rec
          |> :inet_dns.msg(:anlist)
          |> Enum.map(fn rr ->
            {:inet_dns.rr(rr, :data), :inet_dns.rr(rr, :ttl)}
          end)

        case answers do
          [] -> :error
          _ -> {:ok, answers}
        end

      {:error, _} ->
        :error
    end
  end
```

An IP literal gets a synthetic TTL of `0` (meaning "not DNS-derived, not subject to rebinding at all" — Task 2's severity-escalation logic must treat `0` as "no TTL signal," not as "suspiciously short"; this is covered explicitly in Task 2's tests).

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `mix test test/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard_test.exs -v`
Expected: PASS for the three new tests. The old `resolve/1`-based tests will now fail to compile (next step fixes that).

- [ ] **Step 5: Update `forbidden_target/1` to use `resolve_all/2` while keeping single-address behavior**

Replace `forbidden_target/1` (`metadata_egress_guard.ex:77-84`) with a version that calls `resolve_all/2` and, for now, only inspects the first address (preserving current behavior exactly — Task 2 extends this to all addresses):

```elixir
  defp forbidden_target(host) do
    with {:ok, [{ip_tuple, _ttl} | _rest]} <- resolve_all(host),
         true <- forbidden_ip?(ip_tuple) do
      {host, :inet.ntoa(ip_tuple) |> to_string()}
    else
      _ -> nil
    end
  end
```

- [ ] **Step 6: Run the full existing test file to confirm no regression**

Run: `mix test test/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard_test.exs -v`
Expected: PASS — all original tests plus the three new ones from Step 1.

- [ ] **Step 7: Run `mix precommit` to confirm format/compile/full-suite cleanliness**

Run: `mix precommit`
Expected: PASS (format check, compile with warnings-as-errors, full test suite).

- [ ] **Step 8: Commit**

```bash
git add lib/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard.ex test/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard_test.exs
git commit -m "Make MetadataEgressGuard's resolver injectable and multi-answer-aware

Replaces :inet.gethostbyname/1 (first-answer-only, no TTL) with an
injectable resolver returning every {ip, ttl} pair, backed by
:inet_res.resolve/3 by default. forbidden_target/1 still only checks
the first address at this commit -- Task 2 extends it to check all of
them and escalate severity on a short TTL."
```

---

### Task 2: Check every resolved address and escalate severity on a short TTL

**Files:**
- Modify: `lib/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard.ex`
- Test: `test/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard_test.exs`

**Interfaces:**
- Consumes: `resolve_all/2` from Task 1.
- Produces: `forbidden_target/1` now returns `{host, ip_string, severity}` instead of `{host, ip_string}` — Task 3 is unaffected since it doesn't touch this function, but note the shape change here for anyone reading both tasks.

- [ ] **Step 1: Write failing tests for multi-answer and TTL-escalation behavior**

Add to `test/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard_test.exs`. These tests need to inject a fake resolver into the plugin's actual `evaluate/2` path, which today has no injection seam at that level (only `resolve_all/2` is injectable). Use `Application.put_env/3` + `on_exit/1` to override the resolver used by `evaluate/2`, since that's this repo's established pattern for per-test runtime config override (see `test/support/` helpers using `Application.put_env` with `on_exit` cleanup elsewhere in this suite):

```elixir
  describe "multi-answer and TTL handling" do
    setup do
      on_exit(fn -> Application.delete_env(:phoenix_elxir_beam, :metadata_egress_resolver) end)
    end

    test "denies a call when a forbidden address appears as a non-first DNS answer" do
      Application.put_env(:phoenix_elxir_beam, :metadata_egress_resolver, fn
        ~c"sneaky.test" -> {:ok, [{{93, 184, 216, 34}, 300}, {{169, 254, 169, 254}, 300}]}
        _ -> :error
      end)

      ctx = ctx(%{"url" => "http://sneaky.test/"})

      assert %{verdict: :deny, reason: reason} = MetadataEgressGuard.evaluate(:pre_call, ctx)
      assert reason =~ "169.254.169.254"
    end

    test "escalates severity to :critical when the forbidden answer's TTL is under 60s" do
      Application.put_env(:phoenix_elxir_beam, :metadata_egress_resolver, fn
        ~c"rebinder.test" -> {:ok, [{{169, 254, 169, 254}, 15}]}
        _ -> :error
      end)

      ctx = ctx(%{"url" => "http://rebinder.test/"})

      assert %{verdict: :deny, severity: :critical, reason: reason} =
               MetadataEgressGuard.evaluate(:pre_call, ctx)

      assert reason =~ "short TTL"
    end

    test "keeps :high severity when the forbidden answer's TTL is not suspiciously short" do
      Application.put_env(:phoenix_elxir_beam, :metadata_egress_resolver, fn
        ~c"normal.test" -> {:ok, [{{169, 254, 169, 254}, 3600}]}
        _ -> :error
      end)

      ctx = ctx(%{"url" => "http://normal.test/"})

      assert %{verdict: :deny, severity: :high} = MetadataEgressGuard.evaluate(:pre_call, ctx)
    end

    test "an IP-literal host (synthetic TTL of 0) is never treated as a short-TTL rebinding signal" do
      ctx = ctx(%{"url" => "http://169.254.169.254/"})

      assert %{verdict: :deny, severity: :high, reason: reason} =
               MetadataEgressGuard.evaluate(:pre_call, ctx)

      refute reason =~ "short TTL"
    end
  end
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `mix test test/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard_test.exs -v`
Expected: FAIL — severity stays `:high` and reason text doesn't mention "short TTL" yet; the `Application.put_env`-set resolver isn't read by `evaluate/2` yet either.

- [ ] **Step 3: Confirm `:critical` is already a valid `Finding.severity()` value**

Run: `grep -n "severity" lib/phoenix_elxir_beam/mcp/finding.ex`

Expected: `@type severity :: :info | :low | :medium | :high | :critical` — `:critical` is already present, so no edit is needed here. This step is a confirmation only; if the type set differs from this, stop and reconcile before continuing, since Task 2's `deny/2` clause below assumes `:critical` is valid.

- [ ] **Step 4: Implement the resolver-override read and the multi-answer/TTL logic**

Replace `evaluate/2`, `deny/2`, and `forbidden_target/1` in `metadata_egress_guard.ex`:

```elixir
  @impl true
  def evaluate(:pre_call, %CallContext{call: call}) do
    resolver = Application.get_env(:phoenix_elxir_beam, :metadata_egress_resolver, &default_resolver/1)

    call
    |> Map.get(:arguments, %{})
    |> extract_hosts()
    |> Enum.find_value(&forbidden_target(&1, resolver))
    |> case do
      nil -> Decision.allow()
      {host, ip_string, severity} -> deny(host, ip_string, severity)
    end
  end

  @short_ttl_threshold_s 60

  defp deny(host, ip_string, :critical) do
    Decision.deny(
      :critical,
      "network egress blocked: target #{host} resolves to #{ip_string}, a disallowed address " <>
        "(short TTL on this record suggests active DNS rebinding)"
    )
  end

  defp deny(host, ip_string, severity) do
    Decision.deny(
      severity,
      "network egress blocked: target #{host} resolves to #{ip_string}, a disallowed address"
    )
  end

  defp forbidden_target(host, resolver) do
    with {:ok, answers} <- resolve_all(host, resolver),
         {ip_tuple, ttl} <- Enum.find(answers, fn {ip, _ttl} -> forbidden_ip?(ip) end) do
      severity = if ttl > 0 and ttl < @short_ttl_threshold_s, do: :critical, else: :high
      {host, :inet.ntoa(ip_tuple) |> to_string(), severity}
    else
      _ -> nil
    end
  end
```

Note `Enum.find/2` here replaces the old "take the first address only" check with "find the first *forbidden* address among all of them" — this is the actual multi-answer fix. `ttl > 0` excludes the synthetic `0` TTL used for IP literals (Task 1) from ever triggering the `:critical` escalation, per the Review Focus item on this.

- [ ] **Step 5: Run the new tests to verify they pass**

Run: `mix test test/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard_test.exs -v`
Expected: PASS for all four new tests in this task.

- [ ] **Step 6: Run the full existing test file to confirm no regression**

Run: `mix test test/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard_test.exs -v`
Expected: PASS — every test in the file, old and new.

- [ ] **Step 7: Run `mix precommit`**

Run: `mix precommit`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add lib/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard.ex \
        test/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard_test.exs
git commit -m "Check every DNS answer for a forbidden address, escalate on short TTL

A response mixing a benign address with a forbidden one previously
passed if the benign one came first (:inet.gethostbyname/1 only
returned the first record). Now every returned address is checked,
and a forbidden hit with a TTL under 60s -- the common signature of
DNS-rebinding tooling -- is reported at :critical instead of :high so
operators can tell ordinary forbidden-range hits from likely active
rebinding in the dashboard and audit log."
```

---

### Task 3: Pin the real-DNS-dependent test and document the residual risk

**Files:**
- Modify: `test/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard_test.exs`
- Modify: `docs/threat-model.md`

**Interfaces:**
- Consumes: nothing new from Tasks 1-2 beyond what's already in place.
- Produces: nothing consumed by a later task — this is the plan's final task.

- [ ] **Step 1: Make the "fails to resolve" test independent of real DNS**

The existing test at `metadata_egress_guard_test.exs:71-74` relies on
`this-host-does-not-exist.invalid` actually failing to resolve via live DNS,
which is exactly the kind of environment-dependent behavior the Review Focus
flagged as a flakiness risk once the resolver switches to `:inet_res`. Replace
it with an injected-resolver version that doesn't touch the network at all:

```elixir
  test "allows a hostname that fails to resolve (left to fail upstream, not this guard's job)" do
    Application.put_env(:phoenix_elxir_beam, :metadata_egress_resolver, fn _ -> :error end)
    on_exit(fn -> Application.delete_env(:phoenix_elxir_beam, :metadata_egress_resolver) end)

    ctx = ctx(%{"url" => "http://this-host-does-not-exist.invalid/"})
    assert %{verdict: :allow} = MetadataEgressGuard.evaluate(:pre_call, ctx)
  end
```

- [ ] **Step 2: Write a test pinning the documented IPv6 limitation**

```elixir
  test "allows a hostname with only an AAAA record (IPv6-only is not checked, by design)" do
    Application.put_env(:phoenix_elxir_beam, :metadata_egress_resolver, fn _ -> :error end)
    on_exit(fn -> Application.delete_env(:phoenix_elxir_beam, :metadata_egress_resolver) end)

    # An :a-only resolver (this plugin's default_resolver/1 queries :in, :a)
    # sees no answer for an AAAA-only host and falls through to :error, same
    # as any other unresolvable host -- allowed, same as today. This test
    # exists to make that an intentional, documented behavior rather than a
    # gap someone discovers later.
    ctx = ctx(%{"url" => "http://ipv6-only.test/"})
    assert %{verdict: :allow} = MetadataEgressGuard.evaluate(:pre_call, ctx)
  end
```

- [ ] **Step 3: Run both tests to verify they pass**

Run: `mix test test/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard_test.exs -v`
Expected: PASS.

- [ ] **Step 4: Update the threat model's DNS-rebinding entry**

In `docs/threat-model.md`, find the existing bullet under "Explicitly out of
scope (non-goals)" that begins "**DNS rebinding between check and request.**"
Replace its text with:

```markdown
- **DNS rebinding for a fetch the upstream server itself makes.**
  `MetadataEgressGuard` resolves every `http(s)://` host in a call's
  arguments at `pre_call` and now checks every returned address, escalating
  to `:critical` when a forbidden hit carries a TTL under 60 seconds (a
  rebinding-tooling signature). What it cannot close: the actual fetch for
  an agent-controlled URL happens inside the *upstream MCP server's own tool
  implementation*, not inside this proxy — there is no second, proxy-owned
  outbound request to pin a resolved address to. A rebinding attack that
  serves its forbidden answer only on the upstream server's own, later
  lookup is invisible to this proxy by construction, not by an
  implementation gap. Closing that fully requires the upstream server to
  resolve once and connect by the resolved address itself — outside this
  repo's control, though worth requesting of upstream vendors.
```

- [ ] **Step 5: Run `mix precommit`**

Run: `mix precommit`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add test/phoenix_elxir_beam/mcp/plugins/metadata_egress_guard_test.exs docs/threat-model.md
git commit -m "Pin IPv6/unresolvable-host behavior, correct the DNS-rebinding threat-model entry

The 'fails to resolve' test depended on live DNS actually failing for
an .invalid hostname; switched to an injected resolver so it can't go
flaky in an offline/sandboxed CI runner. The threat-model entry
previously implied proxy-side pinning could close DNS rebinding
entirely -- corrected to state the real constraint: the vulnerable
fetch happens inside the upstream server's own process, which this
proxy cannot observe or control."
```
