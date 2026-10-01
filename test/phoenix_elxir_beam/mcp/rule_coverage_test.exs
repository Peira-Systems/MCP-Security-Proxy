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
      %{
        tool: tool,
        server_id: server_id,
        rules: rules,
        unclassified_guard_mode: mode,
        expected_gap_types: expected
      } = RuleCoverageCorpus.fetch!(unquote(name))

      gaps = RuleCoverage.check_tool(tool, server_id, rules, mode)
      assert Enum.sort(Enum.map(gaps, & &1.type)) == Enum.sort(expected)
    end
  end

  test "case: two tags, only one covered — the uncovered gap names the correct tag" do
    %{tool: tool, server_id: server_id, rules: rules, unclassified_guard_mode: mode} =
      RuleCoverageCorpus.fetch!("two tags, only one covered")

    assert [%RuleCoverage.Gap{type: :uncovered_tag, tag: :network_egress}] =
             RuleCoverage.check_tool(tool, server_id, rules, mode)
  end

  test "an uncovered_tag gap names the tag and the shadowing rule, if any" do
    %{tool: tool, server_id: server_id, rules: rules, unclassified_guard_mode: mode} =
      RuleCoverageCorpus.fetch!("tagged but shadowed by an earlier catch-all allow")

    assert [%RuleCoverage.Gap{type: :uncovered_tag, tag: :sensitive_read, shadowing_rule: rule}] =
             RuleCoverage.check_tool(tool, server_id, rules, mode)

    assert rule["action"] == "allow"
  end

  test "an unreviewed gap carries the unclassified_guard_mode for the caller to report" do
    %{tool: tool, server_id: server_id, rules: rules, unclassified_guard_mode: mode} =
      RuleCoverageCorpus.fetch!("untagged but suggested, unclassified guard deny")

    assert [%RuleCoverage.Gap{type: :unreviewed, unclassified_guard_mode: "deny"}] =
             RuleCoverage.check_tool(tool, server_id, rules, mode)
  end
end
