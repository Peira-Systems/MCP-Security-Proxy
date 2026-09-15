defmodule PhoenixElxirBeam.MCP.Plugin.ConfigSchema do
  @moduledoc """
  A typed description of the `config` map each built-in plugin accepts, so
  the dashboard can render a real form — number boxes, dropdowns, checkboxes —
  instead of asking an operator to hand-edit JSON.

  Each schema is a list of field maps:

      %{
        key:     "max_bytes",     # the string key in the plugin's `config` map
        label:   "Max response size",
        type:    :integer,        # :integer | :string | :string_list | :boolean | :select | :json
        default: 4_000,           # the plugin module's own hardcoded fallback (a
                                  # stable code-level fact, independent of what this
                                  # deployment's config/*.exs currently sets)
        help:    "…",             # the hover text shown behind the "?" next to the field
        unit:    "bytes",         # optional, shown after the label
        min:     0,               # optional, :integer only
        options: [{"off", "off — no-op"}, …]  # required for :select
      }

  `build/3` turns the form params back into a `config` map, coercing each
  field to the right type and keeping any keys the schema doesn't cover
  (so a hand-set key added via the raw-JSON editor is not dropped on the
  next form save). The prose in `reference/1` is the long-form companion to
  the schema, shown under the form for the fields a simple input can't
  fully capture (chiefly `rule-engine`'s rules).
  """

  @type field :: %{
          required(:key) => String.t(),
          required(:label) => String.t(),
          required(:type) => :integer | :string | :string_list | :boolean | :select | :json,
          required(:default) => term(),
          required(:help) => String.t(),
          optional(:unit) => String.t(),
          optional(:min) => integer(),
          optional(:options) => [{String.t(), String.t()}]
        }

  @doc "The field schema for `name`, or `[]` when the plugin takes no configuration."
  @spec schema(String.t()) :: [field()]
  def schema("approval-gate") do
    [
      %{
        key: "timeout_ms",
        label: "Approval timeout",
        type: :integer,
        unit: "ms",
        min: 1_000,
        default: 120_000,
        help:
          "How long a held call waits for an operator to approve or deny before " <>
            "it is automatically denied. In milliseconds. Built-in fallback: 120000 (2 minutes)."
      }
    ]
  end

  def schema("baseline-guard") do
    [
      %{
        key: "window_ms",
        label: "Look-back window",
        type: :integer,
        unit: "ms",
        min: 0,
        default: 10_000,
        help:
          "The rolling time window, in milliseconds, over which watched calls are " <>
            "counted. Built-in fallback: 10000 (10 seconds)."
      },
      %{
        key: "max_calls",
        label: "Max calls in window",
        type: :integer,
        min: 0,
        default: 5,
        help:
          "How many watched calls are allowed inside the window before the next " <>
            "one is denied. Built-in fallback: 5."
      },
      %{
        key: "watch_tags",
        label: "Watched tags",
        type: :string_list,
        default: ["sensitive_read"],
        help:
          "Which call tags count toward the limit, entered comma-separated " <>
            "(e.g. \"sensitive_read, network_egress\"). Built-in fallback: sensitive_read."
      }
    ]
  end

  def schema("response-size-guard") do
    [
      %{
        key: "max_bytes",
        label: "Max response size",
        type: :integer,
        unit: "bytes",
        min: 0,
        default: 4_000,
        help:
          "A single tool response whose text content is larger than this is " <>
            "withheld entirely (JSON-RPC error -32002) instead of relayed. " <>
            "Built-in fallback: 4000."
      }
    ]
  end

  def schema("stream-guard") do
    [
      %{
        key: "max_bytes",
        label: "Stream byte budget",
        type: :integer,
        unit: "bytes",
        min: 0,
        default: 2_000,
        help:
          "Running total across delivered chunks plus the current one; once it is " <>
            "exceeded the stream is cut. Chunks already delivered are kept. " <>
            "Built-in fallback: 2000."
      }
    ]
  end

  def schema("unclassified-guard") do
    [
      %{
        key: "mode",
        label: "Mode",
        type: :select,
        default: "off",
        options: [
          {"off", "off — no-op (ship enabled-but-inert)"},
          {"deny", "deny — refuse with a JSON-RPC -32001 error"},
          {"hold", "hold — park for operator sign-off (5 min, then deny)"}
        ],
        help:
          "What to do with a tools/call to a tool the operator has not tagged. " <>
            "Built-in fallback: off."
      }
    ]
  end

  # rule-engine's `rules` list is edited through the dashboard's dedicated
  # visual editor (`MCPDashboardLive.rules_editor/1`), not a flat field form.
  def schema("rule-engine"), do: []

  # rule-engine-wasm takes the identical `rules` shape (docs/wasm-plugin-plan.md
  # W4 — verdict parity is checked against the same corpus) but doesn't share
  # rule-engine's bespoke editor state (`@rules_draft` is a single, unkeyed
  # assign — wiring a second plugin through it is a real refactor, not this
  # plugin's job). A generic `:json` field gives it a genuinely working, if
  # plainer, editor for the exact same data instead of the dashboard wrongly
  # claiming it "has no configurable options."
  def schema("rule-engine-wasm") do
    [
      %{
        key: "rules",
        label: "Rules",
        type: :json,
        default: [],
        help:
          "Same shape as rule-engine's rules — see its own \"details\" popup for the " <>
            "match-predicate reference. Evaluated in order; the first rule whose match " <>
            "conditions are satisfied decides the verdict."
      }
    ]
  end

  def schema(_name), do: []

  @doc "True when the dashboard renders a bespoke editor for this plugin instead of a field form."
  @spec custom_editor?(String.t()) :: boolean()
  def custom_editor?("rule-engine"), do: true
  def custom_editor?(_name), do: false

  @doc """
  Long-form prose for the config keys a plain form input can't fully
  describe — currently just `rule-engine`'s match predicates. `[]` when the
  schema fields are self-explanatory.
  """
  @spec reference(String.t()) :: [String.t()]
  def reference("rule-engine") do
    [
      "Each rule: match (object, see below), action: \"deny\" | \"allow\" | " <>
        "\"hold\", severity: \"low\" | \"medium\" | \"high\" | \"critical\" " <>
        "(default \"high\", used when action is \"deny\"), reason (string " <>
        "shown to the operator/agent), timeout_ms (integer, milliseconds, " <>
        "only used for \"hold\", default 120000).",
      "match predicates (all must hold — AND): agent / agent_prefix (exact " <>
        "/ prefix match on the call's agent id), tool / server (exact " <>
        "match), tool_tags_any (array — any of these tags on the call), " <>
        "after_sensitive_read: true (a sensitive read happened earlier " <>
        "this session), if_tainted: true (a secret has flowed through " <>
        "this session)."
    ]
  end

  def reference(_name), do: []

  @doc """
  Rebuilds a `config` map from `%{"key" => raw_value}` form params, starting
  from `existing` (so keys outside the schema survive) and coercing each
  schema field to its declared type. Returns `{:error, message}` on the
  first field that fails to parse.
  """
  @spec build(String.t(), map(), map()) :: {:ok, map()} | {:error, String.t()}
  def build(name, existing, params) when is_map(existing) and is_map(params) do
    name
    |> schema()
    |> Enum.reduce_while({:ok, existing}, fn field, {:ok, acc} ->
      case coerce(field, Map.get(params, field.key)) do
        :drop -> {:cont, {:ok, Map.delete(acc, field.key)}}
        {:ok, value} -> {:cont, {:ok, Map.put(acc, field.key, value)}}
        {:error, msg} -> {:halt, {:error, "#{field.label}: #{msg}"}}
      end
    end)
  end

  # A blank value drops the key so the plugin module's own fallback applies.
  defp coerce(%{type: :integer} = field, raw) do
    min = Map.get(field, :min, 0)

    case trimmed(raw) do
      nil ->
        :drop

      s ->
        case Integer.parse(s) do
          {n, ""} when n >= min -> {:ok, n}
          {_n, ""} -> {:error, "must be at least #{min}"}
          _ -> {:error, "must be a whole number"}
        end
    end
  end

  defp coerce(%{type: :boolean}, raw), do: {:ok, raw in [true, "true", "on", "1"]}

  defp coerce(%{type: :select, options: options}, raw) do
    values = Enum.map(options, fn {value, _label} -> value end)
    if raw in values, do: {:ok, raw}, else: :drop
  end

  defp coerce(%{type: :string_list}, raw) do
    case raw do
      s when is_binary(s) ->
        list =
          s
          |> String.split(",")
          |> Enum.map(&String.trim/1)
          |> Enum.reject(&(&1 == ""))

        if list == [], do: :drop, else: {:ok, list}

      _ ->
        :drop
    end
  end

  defp coerce(%{type: :json}, raw) do
    case trimmed(raw) do
      nil ->
        :drop

      s ->
        case Jason.decode(s) do
          {:ok, decoded} -> {:ok, decoded}
          {:error, _} -> {:error, "must be valid JSON"}
        end
    end
  end

  defp coerce(%{type: :string}, raw) do
    case trimmed(raw) do
      nil -> :drop
      s -> {:ok, s}
    end
  end

  defp trimmed(raw) when is_binary(raw) do
    case String.trim(raw) do
      "" -> nil
      s -> s
    end
  end

  defp trimmed(_raw), do: nil

  @doc "The value to seed a field's input with: the live config value, else the default."
  @spec value_for(field(), map()) :: term()
  def value_for(field, config) when is_map(config) do
    case Map.fetch(config, field.key) do
      {:ok, value} -> value
      :error -> field.default
    end
  end

  @doc "Renders a field's default (or current) value for display next to the input."
  @spec display(term()) :: String.t()
  def display(value) when is_list(value) do
    if value == [], do: "(none)", else: Enum.join(value, ", ")
  end

  def display(value) when is_binary(value), do: value
  def display(value) when is_integer(value), do: Integer.to_string(value)
  def display(value), do: inspect(value)
end
