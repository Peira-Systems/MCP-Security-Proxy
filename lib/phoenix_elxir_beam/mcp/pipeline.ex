defmodule PhoenixElxirBeam.MCP.Pipeline do
  @moduledoc """
  Runs the registered plugin chain for one phase and aggregates the result.

  `run/3` — the `pre_call` `policy` chain:

    * plugins run in the operator-configured order (`entry.order`);
    * each invocation is bounded by the plugin's `timeout_ms` and, on
      timeout / crash / malformed return, its `fail_mode` is applied
      (`:fail_closed` ⇒ deny, `:fail_open` ⇒ allow + a `plugin_error`
      finding) — the deadline is enforced here, not by plugin cooperation;
    * the first `:deny` short-circuits the chain;
    * granted `add_tags` mutations from an `:allow` / `:annotate` are applied
      to the context so later plugins in the chain observe them.

  `run_discovery/2` — the `discovery` `scanner` set (server registration /
  re-handshake, off the request path): every enabled `:discovery` scanner is
  invoked (same `timeout_ms` / `fail_mode` bounding), and their `Finding`s and
  per-tool `tool_update`s are merged.

  `:pre_call` / `:post_call` scanners are not invoked yet. `:hold` is coerced
  to `:deny` until the approval UI exists (step 6).
  """

  require Logger

  alias PhoenixElxirBeam.MCP.{CallContext, Decision, Finding}
  alias PhoenixElxirBeam.MCP.Plugin.{Scanner, SidecarRunner, Wire}

  @task_supervisor PhoenixElxirBeam.MCP.TaskSupervisor

  @type entry :: %{
          name: String.t(),
          version: String.t(),
          impl: {:module, module()} | {:sidecar, atom()},
          config: map(),
          kind: :policy | :scanner | :audit_sink,
          phases: [atom()],
          tool_tags: [atom()],
          data_needs: [String.t()],
          timeout_ms: pos_integer(),
          fail_mode: :fail_open | :fail_closed,
          can_mutate: [atom()],
          can_block: boolean(),
          order: non_neg_integer(),
          enabled: boolean()
        }

  @doc """
  Runs the chain for `phase` over `ctx`.

  Returns `{verdict, decision, findings}`:

    * `verdict` — `:allow`, `:deny`, or `:hold`;
    * `decision` — on `:deny` / `:hold`, carries `reason`, `severity`,
      `deciding_plugin` (and `hold` for `:hold`); on `:allow`, a merged decision;
    * `findings` — every finding collected along the chain.
  """
  @spec run(CallContext.phase(), CallContext.t(), [entry()]) ::
          {:allow | :deny | :hold, Decision.t(), [Finding.t()]}
  def run(phase, %CallContext{} = ctx, entries) when is_list(entries) do
    entries
    |> Enum.filter(&applies?(&1, phase, ctx))
    |> Enum.sort_by(& &1.order)
    |> evaluate_chain(phase, ctx, [])
  end

  @doc """
  Runs every enabled `:discovery` scanner in `entries` over `ctx` (a
  `phase: :discovery` context) and merges the results.

  Returns `{:ok, findings, tool_updates}` where `tool_updates` are merged by
  tool name — `quarantine` is true if any scanner asked for it, `add_tags` is
  the union, and the first non-nil `reason` wins.
  """
  @spec run_discovery(CallContext.t(), [entry()]) ::
          {:ok, [Finding.t()], [Scanner.tool_update()]}
  def run_discovery(%CallContext{phase: :discovery} = ctx, entries) when is_list(entries) do
    {findings, updates} =
      entries
      |> Enum.filter(&(&1.enabled and &1.kind == :scanner and :discovery in &1.phases))
      |> Enum.sort_by(& &1.order)
      |> Enum.map(&invoke_discovery(&1, ctx))
      |> Enum.reduce({[], []}, fn {fs, us}, {facc, uacc} -> {facc ++ fs, uacc ++ us} end)

    {:ok, findings, merge_tool_updates(updates)}
  end

  @doc """
  Runs every enabled `:post_call` `scanner` / `policy` in `entries` over `ctx`
  (a `phase: :post_call` context, `response` populated), concurrently.

  Returns `{verdict, findings, redactions, reason}`:

    * `verdict` — `:deny` if any `policy` (or a `can_block` scanner) denied
      (the response is then withheld), else `:allow`;
    * `redactions` — every `redact_response` mutation, to feed
      `PhoenixElxirBeam.MCP.Redaction`.
  """
  @spec run_post_call(CallContext.t(), [entry()]) ::
          {:allow | :deny, [Finding.t()], [map()], String.t() | nil}
  def run_post_call(%CallContext{phase: :post_call} = ctx, entries) when is_list(entries) do
    results =
      entries
      |> Enum.filter(&(&1.enabled and &1.kind in [:policy, :scanner] and :post_call in &1.phases))
      |> Enum.sort_by(& &1.order)
      |> Enum.map(&invoke_post_call(&1, ctx))

    findings = Enum.flat_map(results, & &1.findings)
    redactions = Enum.flat_map(results, & &1.redactions)
    denial = Enum.find(results, &(&1.verdict == :deny))

    if denial do
      {:deny, findings, redactions, denial.reason || "response withheld by policy"}
    else
      {:allow, findings, redactions, nil}
    end
  end

  defp invoke_post_call(entry, ctx) do
    task = Task.Supervisor.async_nolink(@task_supervisor, fn -> post_call_eval(entry, ctx) end)

    case Task.yield(task, entry.timeout_ms) || Task.shutdown(task, :brutal_kill) do
      {:ok, {:ok, findings}} when is_list(findings) ->
        %{findings: findings, redactions: [], verdict: :allow, reason: nil}

      {:ok, {:ok, findings, %Decision{} = d}} when is_list(findings) ->
        %{
          findings: findings,
          redactions: redactions_of(d),
          verdict: post_call_verdict(d, entry),
          reason: d.reason
        }

      {:ok, %Decision{} = d} ->
        %{
          findings: d.findings,
          redactions: redactions_of(d),
          verdict: post_call_verdict(d, entry),
          reason: d.reason
        }

      {:ok, other} ->
        post_call_fail(entry, "returned #{inspect(other)}")

      {:exit, reason} ->
        post_call_fail(entry, "crashed (#{inspect(reason)})")

      nil ->
        post_call_fail(entry, "timed out after #{entry.timeout_ms}ms")
    end
  end

  defp post_call_eval(%{impl: {:module, mod}, kind: :scanner} = entry, ctx) do
    mod.scan(:post_call, %{ctx | plugin_config: entry.config})
  end

  defp post_call_eval(%{impl: {:module, mod}, kind: :policy} = entry, ctx) do
    mod.evaluate(:post_call, %{ctx | phase: :post_call, plugin_config: entry.config})
  end

  defp post_call_eval(%{impl: {:sidecar, name}} = entry, ctx) do
    case SidecarRunner.request(
           name,
           "call/inspectResponse",
           %{"context" => Wire.encode_context(ctx, entry)},
           entry.timeout_ms
         ) do
      {:ok, result} -> Wire.decode_decision(result)
      {:error, reason} -> raise "sidecar call/inspectResponse failed: #{inspect(reason)}"
    end
  end

  defp redactions_of(%Decision{mutations: m}) when is_map(m), do: Map.get(m, :redact_response, [])
  defp redactions_of(_), do: []

  # A scanner's `:deny` is only honoured with the `can_block` grant; `:hold` on
  # post_call has no meaning (nothing to approve after the fact) → treat as deny.
  defp post_call_verdict(%Decision{verdict: v}, %{kind: :scanner, can_block: false})
       when v in [:deny, :hold],
       do: :allow

  defp post_call_verdict(%Decision{verdict: v}, _entry) when v in [:deny, :hold], do: :deny
  defp post_call_verdict(_d, _entry), do: :allow

  defp post_call_fail(entry, detail) do
    Logger.warning("Pipeline: post_call #{entry.name} #{detail}; applying #{entry.fail_mode}")

    finding =
      Finding.new(%{
        type: "plugin_error",
        severity: :medium,
        title: "post_call #{entry.kind} #{entry.name} #{detail}",
        plugin: %{name: entry.name, version: entry.version}
      })

    case entry.fail_mode do
      :fail_closed ->
        %{
          findings: [finding],
          redactions: [],
          verdict: :deny,
          reason: "post_call plugin #{entry.name} unavailable"
        }

      :fail_open ->
        %{findings: [finding], redactions: [], verdict: :allow, reason: nil}
    end
  end

  defp invoke_discovery(entry, ctx) do
    task = Task.Supervisor.async_nolink(@task_supervisor, fn -> discovery_scan(entry, ctx) end)

    case Task.yield(task, entry.timeout_ms) || Task.shutdown(task, :brutal_kill) do
      {:ok, {:ok, findings, updates}} when is_list(findings) and is_list(updates) ->
        {findings, updates}

      {:ok, other} ->
        {[scanner_error_finding(entry, "returned #{inspect(other)}")], []}

      {:exit, reason} ->
        {[scanner_error_finding(entry, "crashed (#{inspect(reason)})")], []}

      nil ->
        {[scanner_error_finding(entry, "timed out after #{entry.timeout_ms}ms")], []}
    end
  end

  defp discovery_scan(%{impl: {:module, mod}} = entry, ctx) do
    mod.scan(:discovery, %{ctx | plugin_config: entry.config})
  end

  defp discovery_scan(%{impl: {:sidecar, name}} = entry, ctx) do
    case SidecarRunner.request(
           name,
           "discovery/inspect",
           Wire.encode_discovery(ctx),
           entry.timeout_ms
         ) do
      {:ok, result} ->
        {findings, updates} = Wire.decode_discovery_result(result)
        {:ok, findings, drop_quarantine_unless_allowed(updates, entry)}

      {:error, reason} ->
        raise "sidecar discovery/inspect failed: #{inspect(reason)}"
    end
  end

  # A sidecar's quarantine is honoured only if the operator granted blocking.
  defp drop_quarantine_unless_allowed(updates, %{can_block: true}), do: updates

  defp drop_quarantine_unless_allowed(updates, _entry) do
    Enum.map(updates, &Map.put(&1, :quarantine, false))
  end

  # Scanners are advisory (`fail_open`): a failure is dropped, not fatal, but
  # it is recorded as a finding so the operator sees the coverage gap.
  defp scanner_error_finding(entry, detail) do
    Logger.warning("Pipeline: discovery scanner #{entry.name} #{detail}; dropped")

    Finding.new(%{
      type: "plugin_error",
      severity: :medium,
      title: "discovery scanner #{entry.name} #{detail}",
      plugin: %{name: entry.name, version: entry.version}
    })
  end

  defp merge_tool_updates(updates) do
    updates
    |> Enum.group_by(& &1.name)
    |> Enum.map(fn {name, group} ->
      %{
        name: name,
        quarantine: Enum.any?(group, &Map.get(&1, :quarantine, false)),
        add_tags: group |> Enum.flat_map(&Map.get(&1, :add_tags, [])) |> Enum.uniq(),
        reason: Enum.find_value(group, &Map.get(&1, :reason))
      }
    end)
  end

  defp applies?(entry, phase, ctx) do
    entry.enabled and entry.kind == :policy and phase in entry.phases and
      tag_match?(entry.tool_tags, CallContext.call_tags(ctx))
  end

  defp tag_match?([], _call_tags), do: true
  defp tag_match?(tool_tags, call_tags), do: Enum.any?(tool_tags, &(&1 in call_tags))

  defp evaluate_chain([], _phase, _ctx, findings) do
    {:allow, %Decision{verdict: :allow, findings: findings}, findings}
  end

  defp evaluate_chain([entry | rest], phase, ctx, findings) do
    decision = invoke(entry, phase, ctx)
    findings = findings ++ decision.findings

    case decision.verdict do
      :deny ->
        {:deny, %{decision | deciding_plugin: entry.name, findings: findings}, findings}

      :hold ->
        {:hold, %{decision | deciding_plugin: entry.name, findings: findings}, findings}

      verdict when verdict in [:allow, :annotate] ->
        evaluate_chain(rest, phase, apply_mutations(ctx, entry, decision), findings)
    end
  end

  defp invoke(entry, phase, ctx) do
    task =
      Task.Supervisor.async_nolink(@task_supervisor, fn -> policy_evaluate(entry, phase, ctx) end)

    case Task.yield(task, entry.timeout_ms) || Task.shutdown(task, :brutal_kill) do
      {:ok, %Decision{} = decision} -> decision
      {:ok, other} -> fail(entry, "returned #{inspect(other)}")
      {:exit, reason} -> fail(entry, "crashed (#{inspect(reason)})")
      nil -> fail(entry, "timed out after #{entry.timeout_ms}ms")
    end
  end

  defp policy_evaluate(%{impl: {:module, mod}} = entry, phase, ctx) do
    mod.evaluate(phase, %{ctx | phase: phase, plugin_config: entry.config})
  end

  defp policy_evaluate(%{impl: {:sidecar, name}} = entry, phase, ctx) do
    ctx = %{ctx | phase: phase}

    case SidecarRunner.request(
           name,
           "call/evaluate",
           %{"context" => Wire.encode_context(ctx, entry)},
           entry.timeout_ms
         ) do
      {:ok, result} -> Wire.decode_decision(result)
      {:error, reason} -> raise "sidecar call/evaluate failed: #{inspect(reason)}"
    end
  end

  defp fail(entry, detail) do
    Logger.warning("Pipeline: policy plugin #{entry.name} #{detail}; applying #{entry.fail_mode}")

    finding =
      Finding.new(%{
        type: "plugin_error",
        severity: :medium,
        title: "policy plugin #{entry.name} #{detail}",
        plugin: %{name: entry.name, version: entry.version}
      })

    case entry.fail_mode do
      :fail_closed ->
        %{Decision.deny(:high, "policy plugin #{entry.name} unavailable") | findings: [finding]}

      :fail_open ->
        %{Decision.allow() | verdict: :annotate, findings: [finding]}
    end
  end

  defp apply_mutations(ctx, entry, %Decision{mutations: mutations}) when is_map(mutations) do
    add_tags = Map.get(mutations, :add_tags, [])

    if add_tags != [] and :add_tags in entry.can_mutate do
      CallContext.put_session_tags(ctx, add_tags)
    else
      ctx
    end
  end

  defp apply_mutations(ctx, _entry, _decision), do: ctx
end
