defmodule PhoenixElxirBeam.DataCase do
  @moduledoc """
  Test case template for tests that need access to `PhoenixElxirBeam.Repo`.

  Checks out a sandboxed, per-test database connection so tests can run
  `async: true` without seeing each other's rows.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      alias PhoenixElxirBeam.Repo
    end
  end

  setup tags do
    PhoenixElxirBeam.DataCase.setup_sandbox(tags)
    :ok
  end

  @doc "Checks out a sandboxed connection, shared with other processes when `async: false`."
  def setup_sandbox(tags) do
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(PhoenixElxirBeam.Repo, shared: not tags[:async])
    ExUnit.Callbacks.on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
  end
end
