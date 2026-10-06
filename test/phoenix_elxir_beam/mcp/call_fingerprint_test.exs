defmodule PhoenixElxirBeam.MCP.CallFingerprintTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.CallFingerprint

  describe "compute/2" do
    test "same arguments produce the same fingerprint for the same session" do
      a = CallFingerprint.compute("session-a", %{"path" => "/tmp/x", "mode" => "write"})
      b = CallFingerprint.compute("session-a", %{"mode" => "write", "path" => "/tmp/x"})
      assert a == b
    end

    test "atom-keyed and string-keyed equivalents fingerprint identically" do
      # Elixir map equality is already key-order-independent for literals with
      # the same keys — the real risk this canonicalization guards against is
      # mixed key representations (e.g. a map built from `%{atom: 1}` vs. one
      # decoded from JSON as `%{"atom" => 1}`), which a naive `Jason.encode!`
      # on the raw map would NOT treat as equivalent, since Jason would emit
      # `"atom"` for both keys only coincidentally (atoms encode to their
      # string form) — this test pins that coincidence as a guarantee.
      a = CallFingerprint.compute("session-a", %{atom_key: 1})
      b = CallFingerprint.compute("session-a", %{"atom_key" => 1})
      assert a == b
    end

    test "different arguments produce different fingerprints" do
      a = CallFingerprint.compute("session-a", %{"path" => "/tmp/x"})
      b = CallFingerprint.compute("session-a", %{"path" => "/tmp/y"})
      refute a == b
    end

    test "nested maps are canonicalized recursively regardless of insertion order" do
      a = CallFingerprint.compute("session-a", %{"opts" => %{"b" => 1, "a" => 2}})
      b = CallFingerprint.compute("session-a", %{"opts" => Map.new([{"a", 2}, {"b", 1}])})
      assert a == b
    end

    test "nil and empty map both fingerprint deterministically, and to the same value as each other" do
      assert CallFingerprint.compute("session-a", nil) ==
               CallFingerprint.compute("session-a", %{})

      assert CallFingerprint.compute("session-a", nil) ==
               CallFingerprint.compute("session-a", nil)
    end

    test "returns a sha256: prefixed hex digest" do
      assert "sha256:" <> hex = CallFingerprint.compute("session-a", %{"a" => 1})
      assert String.length(hex) == 64
      assert hex =~ ~r/^[0-9a-f]+$/
    end

    test "raw argument values never appear in the output" do
      fp = CallFingerprint.compute("session-a", %{"secret" => "AKIAVERYSECRETVALUE"})
      refute fp =~ "AKIAVERYSECRETVALUE"
    end

    test "the same arguments fingerprint differently across sessions" do
      a = CallFingerprint.compute("session-a", %{"path" => "/tmp/x"})
      b = CallFingerprint.compute("session-b", %{"path" => "/tmp/x"})
      refute a == b
    end

    test "cannot be reproduced without the server key, so it is not a bare unsalted hash" do
      args = %{"secret" => "a-known-low-entropy-value"}
      fp = CallFingerprint.compute("session-a", args)

      # A bare SHA-256 of the canonical JSON (no key) would let anyone who
      # can read the persisted fingerprint brute-force a guessed argument
      # value offline. Confirm the real fingerprint is NOT that.
      canonical_json =
        Jason.encode!(Jason.OrderedObject.new([{"secret", "a-known-low-entropy-value"}]))

      naive_unsalted =
        "sha256:" <> Base.encode16(:crypto.hash(:sha256, canonical_json), case: :lower)

      refute fp == naive_unsalted
    end

    test "never raises, even on a value Jason cannot encode" do
      # Arguments are attacker/agent-controlled input reaching the single
      # PolicyEngine GenServer on its hot path — a struct with no
      # Jason.Encoder impl (e.g. a stray DateTime nested in arguments)
      # must not crash the process and wipe every in-memory session.
      args = %{"when" => DateTime.utc_now(), "ref" => make_ref()}

      assert "sha256:" <> hex = CallFingerprint.compute("session-a", args)
      assert String.length(hex) == 64
    end
  end
end
