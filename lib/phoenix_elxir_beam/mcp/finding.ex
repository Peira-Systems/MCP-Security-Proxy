defmodule PhoenixElxirBeam.MCP.Finding do
  @moduledoc """
  A structured, advisory observation about a tool call or a tool definition —
  the in-process representation of a protocol `Finding` (`docs/plugin-protocol.md`
  §7.3). Findings never decide a verdict on their own; they are collected
  alongside a `PhoenixElxirBeam.MCP.Decision` and surfaced on the dashboard.
  """

  @enforce_keys [:type, :severity, :title]
  defstruct [
    :id,
    :type,
    :severity,
    :title,
    :detail,
    :confidence,
    :locator,
    :evidence,
    :plugin
  ]

  @type severity :: :info | :low | :medium | :high | :critical

  @type t :: %__MODULE__{
          id: String.t(),
          type: String.t(),
          severity: severity(),
          title: String.t(),
          detail: String.t() | nil,
          confidence: float() | nil,
          locator:
            %{
              optional(:path) => String.t(),
              optional(:start) => integer(),
              optional(:end) => integer()
            }
            | nil,
          evidence: String.t() | nil,
          plugin: %{name: String.t(), version: String.t()} | nil
        }

  @evidence_limit 500

  @doc """
  Builds a finding from a map. Generates an `id` when absent and truncates
  `evidence` to #{@evidence_limit} characters (the protocol makes that the
  plugin's job; we enforce it at the boundary too).
  """
  @spec new(map()) :: t()
  def new(attrs) when is_map(attrs) do
    attrs =
      attrs
      |> Map.put_new_lazy(:id, fn ->
        "f-" <> (:crypto.strong_rand_bytes(6) |> Base.encode16(case: :lower))
      end)
      |> Map.update(:evidence, nil, &truncate/1)

    struct!(__MODULE__, attrs)
  end

  defp truncate(nil), do: nil

  defp truncate(text) when is_binary(text) do
    if String.length(text) > @evidence_limit do
      String.slice(text, 0, @evidence_limit)
    else
      text
    end
  end
end
