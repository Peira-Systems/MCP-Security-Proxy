defmodule PhoenixElxirBeam.MCP.Plugin.Manifest do
  @moduledoc """
  What a plugin declares about itself: identity, the capabilities it provides,
  the data each capability reads, and its evaluation limits — the in-process
  representation of the protocol `Manifest` (`docs/plugin-protocol.md` §8.1).

  For in-process plugins this is the return value of `c:manifest/0`. For
  sidecars (future) it is the result of the `initialize` round-trip. Either
  way `PhoenixElxirBeam.MCP.Plugin.Registry` caps it against the operator's
  `grants` before a plugin can block, mutate, or reach the network.
  """

  defmodule Policy do
    @moduledoc "The `policy` capability block of a `Manifest`."
    defstruct phases: [:pre_call],
              tool_tags: [],
              servers: [:*],
              data_needs: [],
              timeout_ms: 50,
              fail_mode: :fail_closed,
              can_mutate: []

    @type t :: %__MODULE__{
            phases: [:pre_call | :post_call],
            tool_tags: [atom()],
            servers: [String.t() | :*],
            data_needs: [String.t()],
            timeout_ms: pos_integer(),
            fail_mode: :fail_open | :fail_closed,
            can_mutate: [:add_tags | :add_taint_sources | :redact_response]
          }
  end

  defmodule Scanner do
    @moduledoc "The `scanner` capability block of a `Manifest`."
    defstruct phases: [:post_call],
              data_needs: [],
              timeout_ms: 500,
              fail_mode: :fail_open,
              can_block: false

    @type t :: %__MODULE__{
            phases: [:discovery | :pre_call | :post_call],
            data_needs: [String.t()],
            timeout_ms: pos_integer(),
            fail_mode: :fail_open | :fail_closed,
            can_block: boolean()
          }
  end

  defmodule AuditSink do
    @moduledoc "The `auditSink` capability block of a `Manifest`."
    defstruct batch: false, max_batch: 100, flush_interval_ms: 2000

    @type t :: %__MODULE__{
            batch: boolean(),
            max_batch: pos_integer(),
            flush_interval_ms: pos_integer()
          }
  end

  @enforce_keys [:plugin]
  defstruct plugin: %{},
            capabilities: %{},
            max_concurrency: nil,
            requires_network: false,
            config_schema: nil

  @type t :: %__MODULE__{
          plugin: %{
            required(:name) => String.t(),
            required(:version) => String.t(),
            optional(:vendor) => String.t(),
            optional(:description) => String.t(),
            optional(:homepage) => String.t()
          },
          capabilities: %{
            optional(:policy) => Policy.t(),
            optional(:scanner) => Scanner.t(),
            optional(:audit_sink) => AuditSink.t()
          },
          max_concurrency: pos_integer() | nil,
          requires_network: boolean(),
          config_schema: map() | nil
        }

  @doc """
  Accepts the loose map a plugin author is likely to write and returns a
  fully-populated `Manifest` with each capability block promoted to its
  struct (so defaults like `fail_mode` / `timeout_ms` are always present).
  """
  @spec normalize(t() | map()) :: t()
  def normalize(%__MODULE__{} = manifest), do: normalize(Map.from_struct(manifest))

  def normalize(attrs) when is_map(attrs) do
    capabilities =
      attrs
      |> Map.get(:capabilities, %{})
      |> Enum.into(%{}, fn {key, value} -> {key, normalize_capability(key, value)} end)

    %__MODULE__{
      plugin: Map.fetch!(attrs, :plugin),
      capabilities: capabilities,
      max_concurrency: Map.get(attrs, :max_concurrency),
      requires_network: Map.get(attrs, :requires_network, false),
      config_schema: Map.get(attrs, :config_schema)
    }
  end

  defp normalize_capability(_key, %mod{} = block)
       when mod in [Policy, Scanner, AuditSink],
       do: block

  defp normalize_capability(:policy, attrs), do: struct(Policy, attrs)
  defp normalize_capability(:scanner, attrs), do: struct(Scanner, attrs)
  defp normalize_capability(:audit_sink, attrs), do: struct(AuditSink, attrs)
end
