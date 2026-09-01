defmodule PhoenixElxirBeam.Repo.Migrations.AddTimeoutAndTlsVerifyToServerRegistrations do
  use Ecto.Migration

  def change do
    alter table(:server_registrations) do
      # Per-server overrides of the global receive-timeout / TLS-verify
      # defaults (docs/productionization-plan.md M1.5 follow-up). NULL means
      # "inherit the proxy-wide default" — HttpTransport falls back to
      # :upstream_tls_verify / the fixed receive timeout. :stdio servers
      # leave both NULL; they make no HTTP calls.
      add :timeout_ms, :integer
      add :tls_verify, :boolean
    end
  end
end
