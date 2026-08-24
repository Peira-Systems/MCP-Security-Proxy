defmodule PhoenixElxirBeam.Repo do
  use Ecto.Repo,
    otp_app: :phoenix_elxir_beam,
    adapter: Ecto.Adapters.SQLite3
end
