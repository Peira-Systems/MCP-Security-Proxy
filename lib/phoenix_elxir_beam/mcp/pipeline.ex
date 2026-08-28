defmodule PhoenixElxirBeam.MCP.Pipeline do
  @moduledoc """
  Runs the registered plugin chain for one phase of a tool call and
  aggregates the result into a single verdict.

  This step implements the `pre_call` `policy` chain only:

    * plugins run in the operator-configured order (`entry.order`);
    * each invocation is bounded by the plugin's `timeout_ms` and, on
      timeout / crash / malformed return, its `fail_mode` is applied
      (`:fail_closed` ⇒ deny, `:fail_open` ⇒ allow + a `plugin_error`
      finding) — the deadline is enforced here, not by plugin cooperation;
    * the first `:deny` short-circuits the chain;
    * granted `add_tags` mutations from an `:allow` / `:annotate` are applied
      to the context so later plugins in the chain observe them.

  Scanners and the `post_call` phase are accepted but not yet invoked
  (roadmap steps 3–4). `:hold` is coerced to `:deny` until the approval UI
  exists (step 6).
  """

  require Logger

  alias PhoenixElxirBeam.MCP.{CallContext, Decision, Finding}

  @task_supervisor PhoenixElxirBeam.MCP.TaskSupervisor

  @type entry :: %{
          name: String.t(),
          version: String.t(),
          module: module(),
          kind: :policy | :scanner | :audit_sink,
          phases: [atom()],
          tool_tags: [atom()],
          timeout_ms: pos_integer(),
          fail_mode: :fail_open | :fail_closed,
          can_mutate: [atom()],
          order: non_neg_integer(),
          enabled: boolean()
        }

  @doc """
  Runs the chain for `phase` over `ctx`.

  Returns `{verdict, decision, findings}`:

    * `verdict` — `:allow` or `:deny`;
    * `decision` — on `:deny`, carries `reason`, `severity`, and
      `deciding_plugin`; on `:allow`, a merged `:allow` decision;
    * `findings` — every finding collected along the chain.
  """
  @spec run(CallContext.phase(), CallContext.t(), [entry()]) ::
          {:allow | :deny, Decision.t(), [Finding.t()]}
  def run(phase, %CallContext{} = ctx, entries) when is_list(entries) do
    entries
    |> Enum.filter(&applies?(&1, phase, ctx))
    |> Enum.sort_by(& &1.order)
    |> evaluate_chain(phase, ctx, [])
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

    case coerce_verdict(decision.verdict, entry) do
      :deny ->
        decided = %{decision | verdict: :deny, deciding_plugin: entry.name, findings: findings}
        {:deny, decided, findings}

      :allow ->
        evaluate_chain(rest, phase, apply_mutations(ctx, entry, decision), findings)
    end
  end

  defp coerce_verdict(:deny, _entry), do: :deny
  defp coerce_verdict(:allow, _entry), do: :allow
  defp coerce_verdict(:annotate, _entry), do: :allow

  defp coerce_verdict(:hold, entry) do
    Logger.warning(
      "Pipeline: #{entry.name} returned :hold; treating as :deny (approval UI not built)"
    )

    :deny
  end

  defp invoke(entry, phase, ctx) do
    task =
      Task.Supervisor.async_nolink(@task_supervisor, fn -> entry.module.evaluate(phase, ctx) end)

    case Task.yield(task, entry.timeout_ms) || Task.shutdown(task, :brutal_kill) do
      {:ok, %Decision{} = decision} -> decision
      {:ok, other} -> fail(entry, "returned #{inspect(other)}")
      {:exit, reason} -> fail(entry, "crashed (#{inspect(reason)})")
      nil -> fail(entry, "timed out after #{entry.timeout_ms}ms")
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
