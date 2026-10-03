defmodule PhoenixElxirBeam.MtlsConfig do
  @moduledoc """
  Builds the `thousand_island_options` keyword list for optional mutual TLS
  between an agent and this proxy (Phase 1 identity work). Pulled out of
  `config/runtime.exs` as a plain function specifically so this logic has
  automated test coverage -- see
  `docs/superpowers/specs/2026-10-02-mtls-agent-proxy-design.md`.

  `verify`, `cacertfile`, and `fail_if_no_peer_cert` have no top-level
  `https:` convenience alias the way `certfile`/`keyfile` do (per Bandit's
  own docs), so they must land under `transport_options` here, not beside
  `certfile`/`keyfile` in the caller's `https:` list.
  """

  @doc """
  `ssl_cert_set?` is whether `SSL_CERT_PATH`/`SSL_KEY_PATH` are both
  present (Bandit is terminating TLS at all). `ca_cert_path` is
  `MTLS_CA_CERT_PATH`'s raw value (`nil` if unset -- mTLS stays off).
  `required` is `MTLS_REQUIRED`'s parsed boolean, or `nil` if unset
  (defaults to `false`: verify a presented cert, don't require one).

  Returns `[]` when `ca_cert_path` is `nil`. Raises when `ca_cert_path` is
  set but `ssl_cert_set?` is `false` -- there's no TLS handshake for peer
  verification to attach to in that case, and silently producing a
  `transport_options` block with no `certfile`/`keyfile` alongside it would
  fail obscurely deep inside Bandit's own startup validation instead of
  here, with a clear message, at config-build time.
  """
  @spec build(boolean(), String.t() | nil, boolean() | nil) :: keyword() | no_return()
  def build(_ssl_cert_set?, nil, _required), do: []

  def build(false, ca_cert_path, _required) when is_binary(ca_cert_path) do
    raise "MTLS_CA_CERT_PATH is set but SSL_CERT_PATH/SSL_KEY_PATH are not -- " <>
            "mutual TLS requires this proxy to be terminating TLS itself first."
  end

  def build(true, ca_cert_path, required) when is_binary(ca_cert_path) do
    [
      transport_options: [
        verify: :verify_peer,
        cacertfile: ca_cert_path,
        fail_if_no_peer_cert: required || false
      ]
    ]
  end
end
