defmodule PhoenixElxirBeam.MCP.CallFingerprintTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.CallFingerprint

  describe "compute/1" do
    test "same arguments produce the same fingerprint regardless of key order" do
      a = CallFingerprint.compute(%{"path" => "/tmp/x", "mode" => "write"})
      b = CallFingerprint.compute(%{"mode" => "write", "path" => "/tmp/x"})
      assert a == b
    end

    test "different arguments produce different fingerprints" do
      a = CallFingerprint.compute(%{"path" => "/tmp/x"})
      b = CallFingerprint.compute(%{"path" => "/tmp/y"})
      refute a == b
    end

    test "nested maps are canonicalized recursively" do
      a = CallFingerprint.compute(%{"opts" => %{"b" => 1, "a" => 2}})
      b = CallFingerprint.compute(%{"opts" => %{"a" => 2, "b" => 1}})
      assert a == b
    end

    test "nil and empty map both fingerprint deterministically, and to the same value as each other" do
      assert CallFingerprint.compute(nil) == CallFingerprint.compute(%{})
      assert CallFingerprint.compute(nil) == CallFingerprint.compute(nil)
    end

    test "returns a sha256: prefixed hex digest" do
      assert "sha256:" <> hex = CallFingerprint.compute(%{"a" => 1})
      assert String.length(hex) == 64
      assert hex =~ ~r/^[0-9a-f]+$/
    end

    test "raw argument values never appear in the output" do
      fp = CallFingerprint.compute(%{"secret" => "AKIAVERYSECRETVALUE"})
      refute fp =~ "AKIAVERYSECRETVALUE"
    end
  end
end
