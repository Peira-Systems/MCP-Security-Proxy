defmodule PhoenixElxirBeam.MCP.Decision do
  @moduledoc """
  A plugin's response to a `pre_call` / `post_call` evaluation — the
  in-process representation of a protocol `Decision` (`docs/plugin-protocol.md`
  §7.2).

  `verdict` is the only field the pipeline strictly requires:

    * `:allow`    — proceed.
    * `:deny`     — block the call (pre_call) or withhold the response (post_call).
    * `:hold`     — park for operator approval. Not yet honoured by the pipeline
                    (roadmap step 6); currently coerced to `:deny`.
    * `:annotate` — `:allow` plus findings / mutations worth recording.

  `mutations` are *proposals*. `PhoenixElxirBeam.MCP.Pipeline` applies only the
  ones the operator granted for the deciding plugin.
  """

  alias PhoenixElxirBeam.MCP.Finding

  defstruct verdict: :allow,
            reason: nil,
            severity: nil,
            deciding_plugin: nil,
            findings: [],
            mutations: %{},
            hold: nil,
            cache_ttl_ms: 0

  @type verdict :: :allow | :deny | :hold | :annotate

  @type mutations :: %{
          optional(:add_tags) => [atom()],
          optional(:add_taint_sources) => [map()],
          optional(:redact_response) => [map()]
        }

  @type t :: %__MODULE__{
          verdict: verdict(),
          reason: String.t() | nil,
          severity: Finding.severity() | nil,
          deciding_plugin: String.t() | nil,
          findings: [Finding.t()],
          mutations: mutations(),
          hold:
            %{prompt: String.t(), timeout_ms: non_neg_integer(), on_timeout: :deny | :allow} | nil,
          cache_ttl_ms: non_neg_integer()
        }

  @doc "An unconditional allow."
  @spec allow() :: t()
  def allow, do: %__MODULE__{verdict: :allow}

  @doc "A block, with a required human-readable reason and a severity."
  @spec deny(Finding.severity(), String.t()) :: t()
  def deny(severity, reason) when is_binary(reason) do
    %__MODULE__{verdict: :deny, severity: severity, reason: reason}
  end

  @doc "An allow that still carries findings / mutations."
  @spec annotate(keyword() | map()) :: t()
  def annotate(attrs) do
    struct!(%__MODULE__{verdict: :annotate}, attrs)
  end
end
