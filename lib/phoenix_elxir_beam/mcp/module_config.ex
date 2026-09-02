defmodule PhoenixElxirBeam.MCP.ModuleConfig do
  @moduledoc """
  Shared `config :phoenix_elxir_beam, <module>, key: value` lookup, used by
  the small always-on singletons that each keep their own tunables
  (`MCP.RateLimiter`, `MCP.ApiKeyCache`, `MCP.AuditRetention`, …) — every one
  of them had re-typed the same `Application.get_env(:phoenix_elxir_beam,
  __MODULE__, []) |> Keyword.get(key, default)` line.
  """

  @doc "Looks up `key` under `config :phoenix_elxir_beam, module, ...`, falling back to `default`."
  @spec get(module(), atom(), term()) :: term()
  def get(module, key, default \\ nil) do
    :phoenix_elxir_beam
    |> Application.get_env(module, [])
    |> Keyword.get(key, default)
  end
end
