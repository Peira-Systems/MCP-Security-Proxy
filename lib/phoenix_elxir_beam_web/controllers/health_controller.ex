defmodule PhoenixElxirBeamWeb.HealthController do
  use PhoenixElxirBeamWeb, :controller

  def show(conn, _params) do
    json(conn, %{
      status: "ok",
      app: :phoenix_elxir_beam,
      version: Application.spec(:phoenix_elxir_beam, :vsn) |> to_string(),
      timestamp: DateTime.utc_now()
    })
  end
end
