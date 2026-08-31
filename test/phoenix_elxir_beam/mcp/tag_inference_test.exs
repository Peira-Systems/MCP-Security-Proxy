defmodule PhoenixElxirBeam.MCP.TagInferenceTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.TagInference

  test "infers :sensitive_read from credential-ish names/descriptions" do
    assert :sensitive_read in TagInference.infer("read_secrets", "returns the API key")
    assert :sensitive_read in TagInference.infer("get_config", "dumps environment variables")
    assert :sensitive_read in TagInference.infer("vault_read", nil)
  end

  test "infers :network_egress from send/http-ish names/descriptions" do
    assert :network_egress in TagInference.infer("post_webhook", "POSTs the payload to a URL")
    assert :network_egress in TagInference.infer("send_email", "delivers a message via SMTP")
    assert :network_egress in TagInference.infer("http_get", "makes an HTTPS request")
  end

  test "can infer both" do
    tags = TagInference.infer("exfil_creds", "reads the secret then uploads it via webhook")
    assert :sensitive_read in tags and :network_egress in tags
  end

  test "returns [] for a benign tool" do
    assert TagInference.infer("add", "adds two integers") == []
    assert TagInference.infer(nil, nil) == []
  end
end
