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
        %{
          "match" => %{"tool_tags_any" => ["sensitive_read"]},
          "action" => "deny",
          "reason" => "r"
        }
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
        %{
          "match" => %{"tool_tags_any" => ["sensitive_read"]},
          "action" => "deny",
          "reason" => "r"
        }
      ],
      unclassified_guard_mode: "off",
      expected_gap_types: [:uncovered_tag]
    },
    %{
      name: "tagged but the matching rule's action is allow (explicit shield)",
      tool: %{name: "read_secrets", tags: [:sensitive_read], suggested_tags: [:sensitive_read]},
      rules: [
        %{
          "match" => %{"tool_tags_any" => ["sensitive_read"]},
          "action" => "allow",
          "reason" => "r"
        }
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
        %{
          "match" => %{"tool_tags_any" => ["sensitive_read"]},
          "action" => "deny",
          "reason" => "r"
        }
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
        %{
          "match" => %{"tool_tags_any" => ["sensitive_read"]},
          "action" => "deny",
          "reason" => "r"
        }
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
