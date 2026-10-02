defmodule PhoenixElxirBeam.MCP.HoldFatigueMonitor do
  @moduledoc """
  Watches the approval-gate's resolution outcomes for rubber-stamping.

  `[:mcp, :hold, :resolved]` (`MCP.Telemetry`) already tells you a hold fired
  and how it resolved, but raw counts don't say whether the gate is still
  doing its job. A gate that's supposed to be rare and is instead approved
  constantly is the signal that operators have started clicking through
  without reviewing — at that point the gate is decoration, not a control.

  `record/1` is called from `HoldRegistry` on every resolution (manual,
  timeout, or orphan-reap). It keeps a bounded rolling window of recent
  outcomes in `:persistent_term` (cheap to read, fine for the write rate a
  hold resolution happens at — nowhere near hot-path call volume) and raises
  `MCP.Alerts.emit(:approval_gate_fatigue, ...)` once the approval rate over
  that window crosses the configured threshold, with a minimum sample size so
  one approved hold out of one doesn't trip it.

  Config: `config :phoenix_elxir_beam, :approval_gate_alert, rate: 0.9,
  min_samples: 10, window: 50`. `rate`/`min_samples` gate whether an alert
  fires; `window` bounds how many recent outcomes are kept (oldest dropped).
  """

  alias PhoenixElxirBeam.MCP.Alerts

  @pt_key {__MODULE__, :window}
  @default_rate 0.9
  @default_min_samples 10
  @default_window 50

  @doc "Records a hold's resolution outcome and alerts if the approval rate over the window is too high."
  @spec record(:approved | :denied | :timeout | :orphaned) :: :ok
  def record(outcome) do
    window = [outcome | :persistent_term.get(@pt_key, [])] |> Enum.take(config_window())
    :persistent_term.put(@pt_key, window)

    maybe_alert(window)
    :ok
  end

  @doc false
  def reset, do: :persistent_term.erase(@pt_key)

  defp maybe_alert(window) do
    n = length(window)
    approved = Enum.count(window, &(&1 == :approved))
    rate = approved / n

    if n >= config_min_samples() and rate >= config_rate() do
      pct = Float.round(rate * 100, 1)

      Alerts.emit(
        :approval_gate_fatigue,
        :warning,
        "approval-gate: #{pct}% of the last #{n} holds were approved — " <>
          "operators may be rubber-stamping; consider reviewing the gating rule",
        %{approval_rate: rate, sample_size: n}
      )
    end
  end

  defp config, do: Application.get_env(:phoenix_elxir_beam, :approval_gate_alert, [])
  defp config_rate, do: Keyword.get(config(), :rate, @default_rate)
  defp config_min_samples, do: Keyword.get(config(), :min_samples, @default_min_samples)
  defp config_window, do: Keyword.get(config(), :window, @default_window)
end
