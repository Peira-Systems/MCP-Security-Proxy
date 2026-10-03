defmodule PhoenixElxirBeam.MtlsConfigTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MtlsConfig

  test "returns an empty keyword list when no CA path is configured" do
    assert MtlsConfig.build(true, nil, nil) == []
    assert MtlsConfig.build(false, nil, nil) == []
  end

  test "raises when a CA path is set but base TLS (cert/key) is not" do
    assert_raise RuntimeError, ~r/MTLS_CA_CERT_PATH.*SSL_CERT_PATH/, fn ->
      MtlsConfig.build(false, "/path/to/ca.pem", nil)
    end
  end

  test "defaults to verify-but-not-require when MTLS_REQUIRED is unset" do
    result = MtlsConfig.build(true, "/path/to/ca.pem", nil)

    assert result[:transport_options][:verify] == :verify_peer
    assert result[:transport_options][:cacertfile] == "/path/to/ca.pem"
    assert result[:transport_options][:fail_if_no_peer_cert] == false
  end

  test "honours MTLS_REQUIRED: true to enforce a client cert" do
    result = MtlsConfig.build(true, "/path/to/ca.pem", true)
    assert result[:transport_options][:fail_if_no_peer_cert] == true
  end

  test "honours MTLS_REQUIRED: false explicitly" do
    result = MtlsConfig.build(true, "/path/to/ca.pem", false)
    assert result[:transport_options][:fail_if_no_peer_cert] == false
  end
end
