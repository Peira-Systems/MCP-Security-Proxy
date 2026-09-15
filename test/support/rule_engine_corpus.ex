defmodule PhoenixElxirBeam.MCP.Plugins.RuleEngineCorpus do
  @moduledoc """
  Shared `(call_overrides, session_overrides, rules)` fixtures for
  `RuleEngineTest` and `RuleEngineWasmParityTest` — one source of scenarios so the two
  test files can't silently drift apart. `RuleEngineTest` looks up a case by `:name` to
  keep its existing named, human-readable assertions; the parity test iterates every case
  and checks the Elixir and Wasm engines agree, without needing to know any of the names.
  """

  @cases [
    %{name: "no rules", call: %{}, session: %{}, rules: []},
    %{
      name: "agent and tag both match",
      call: %{agent_id: "agent://ci-runner"},
      session: %{},
      rules: [
        %{
          "match" => %{"agent" => "agent://ci-runner", "tool_tags_any" => ["network_egress"]},
          "action" => "deny",
          "reason" => "no egress for ci-runner"
        }
      ]
    },
    %{
      name: "a partial match does not fire",
      call: %{agent_id: "agent://ci-runner"},
      session: %{},
      rules: [
        %{
          "match" => %{"agent" => "agent://ci-runner", "tool" => "read_secrets"},
          "action" => "deny",
          "reason" => "x"
        }
      ]
    },
    %{
      name: "first match wins - trusted agent is shielded",
      call: %{agent_id: "agent://trusted"},
      session: %{},
      rules: [
        %{"match" => %{"agent" => "agent://trusted"}, "action" => "allow"},
        %{
          "match" => %{"tool_tags_any" => ["network_egress"]},
          "action" => "deny",
          "reason" => "no egress"
        }
      ]
    },
    %{
      name: "first match wins - a later agent is denied",
      call: %{agent_id: "agent://other"},
      session: %{},
      rules: [
        %{"match" => %{"agent" => "agent://trusted"}, "action" => "allow"},
        %{
          "match" => %{"tool_tags_any" => ["network_egress"]},
          "action" => "deny",
          "reason" => "no egress"
        }
      ]
    },
    %{
      name: "after_sensitive_read - not yet in this session",
      call: %{},
      session: %{},
      rules: [
        %{"match" => %{"after_sensitive_read" => true}, "action" => "deny", "reason" => "sr"}
      ]
    },
    %{
      name: "after_sensitive_read - fires",
      call: %{},
      session: %{seen_tags: [:sensitive_read]},
      rules: [
        %{"match" => %{"after_sensitive_read" => true}, "action" => "deny", "reason" => "sr"}
      ]
    },
    %{
      name: "if_tainted - fires",
      call: %{},
      session: %{taint: %{sources: [%{origin_tool: "x"}]}},
      rules: [%{"match" => %{"if_tainted" => true}, "action" => "deny", "reason" => "t"}]
    },
    %{
      name: "a hold action",
      call: %{},
      session: %{},
      rules: [
        %{
          "match" => %{"tool" => "post_webhook"},
          "action" => "hold",
          "reason" => "needs sign-off",
          "timeout_ms" => 5_000
        }
      ]
    },
    %{
      name: "an unknown predicate never matches",
      call: %{},
      session: %{},
      rules: [%{"match" => %{"whoops" => "x"}, "action" => "deny", "reason" => "r"}]
    }
  ]

  @doc "Every fixture, in the order above — the parity suite iterates this directly."
  def cases, do: @cases

  @doc "One fixture by name, for RuleEngineTest's existing named assertions."
  def fetch!(name) do
    Enum.find(@cases, &(&1.name == name)) ||
      raise "no RuleEngineCorpus case named #{inspect(name)}"
  end
end
