defmodule PhoenixElxirBeamWeb.SessionHTML do
  use PhoenixElxirBeamWeb, :html

  def new(assigns) do
    ~H"""
    <div class="mx-auto mt-16 max-w-sm space-y-6">
      <div class="text-center">
        <h1 class="text-lg font-semibold">MCP Security Proxy</h1>
        <p class="text-sm text-base-content/60">Operator sign in</p>
      </div>

      <div
        :if={@error_message}
        class="rounded-box border border-error bg-error/10 px-3 py-2 text-sm text-error"
      >
        {@error_message}
      </div>

      <.form :let={f} for={%{}} as={:user} action={~p"/login"} class="space-y-3">
        <.input field={f[:email]} type="email" label="Email" autocomplete="username" required />
        <.input
          field={f[:password]}
          type="password"
          label="Password"
          autocomplete="current-password"
          required
        />
        <.button class="btn btn-primary w-full">Sign in</.button>
      </.form>
    </div>
    """
  end
end
