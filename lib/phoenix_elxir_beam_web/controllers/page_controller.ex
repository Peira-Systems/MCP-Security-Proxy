defmodule PhoenixElxirBeamWeb.PageController do
  use PhoenixElxirBeamWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
