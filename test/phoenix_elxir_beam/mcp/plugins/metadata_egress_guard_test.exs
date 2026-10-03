defmodule PhoenixElxirBeam.MCP.Plugins.MetadataEgressGuardTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.CallContext
  alias PhoenixElxirBeam.MCP.Plugins.MetadataEgressGuard

  defp ctx(arguments) do
    CallContext.new(%{
      phase: :pre_call,
      call: %{
        session_id: "s",
        server_id: "net",
        tool_name: "fetch_url",
        tags: [:network_egress],
        arguments: arguments
      },
      session: %{seen_tags: []}
    })
  end

  test "denies a call whose argument targets the cloud metadata address" do
    ctx = ctx(%{"url" => "http://169.254.169.254/latest/meta-data/"})

    assert %{verdict: :deny, severity: :high, reason: reason} =
             MetadataEgressGuard.evaluate(:pre_call, ctx)

    assert reason =~ "169.254.169.254"
  end

  test "allows a call to an ordinary public URL" do
    ctx = ctx(%{"url" => "https://api.example.com/v1/widgets"})
    assert %{verdict: :allow} = MetadataEgressGuard.evaluate(:pre_call, ctx)
  end

  test "denies a call whose argument targets a loopback address" do
    ctx = ctx(%{"url" => "http://127.0.0.1:8080/admin"})

    assert %{verdict: :deny, severity: :high, reason: reason} =
             MetadataEgressGuard.evaluate(:pre_call, ctx)

    assert reason =~ "127.0.0.1"
  end

  test "denies a call whose argument targets an RFC1918 private address" do
    ctx = ctx(%{"url" => "http://10.0.0.5/internal"})

    assert %{verdict: :deny, severity: :high} = MetadataEgressGuard.evaluate(:pre_call, ctx)
  end

  test "denies a call whose argument targets a link-local address (not just the metadata IP)" do
    ctx = ctx(%{"url" => "http://169.254.1.1/"})

    assert %{verdict: :deny, severity: :high} = MetadataEgressGuard.evaluate(:pre_call, ctx)
  end

  test "allows a URL whose path merely contains private-looking digits, not a private host" do
    ctx = ctx(%{"url" => "https://api.example.com/orders/10.0.0.5/receipt"})
    assert %{verdict: :allow} = MetadataEgressGuard.evaluate(:pre_call, ctx)
  end

  test "denies a hostname that resolves to loopback (DNS rebinding toward a forbidden range)" do
    ctx = ctx(%{"url" => "http://localhost:9999/"})

    assert %{verdict: :deny, severity: :high, reason: reason} =
             MetadataEgressGuard.evaluate(:pre_call, ctx)

    assert reason =~ "localhost"
    assert reason =~ "127.0.0.1"
  end

  test "allows a hostname that fails to resolve (left to fail upstream, not this guard's job)" do
    Application.put_env(:phoenix_elxir_beam, :metadata_egress_resolver, fn _ -> :error end)
    on_exit(fn -> Application.delete_env(:phoenix_elxir_beam, :metadata_egress_resolver) end)

    ctx = ctx(%{"url" => "http://this-host-does-not-exist.invalid/"})
    assert %{verdict: :allow} = MetadataEgressGuard.evaluate(:pre_call, ctx)
  end

  test "allows a hostname with only an AAAA record (IPv6-only is not checked, by design)" do
    Application.put_env(:phoenix_elxir_beam, :metadata_egress_resolver, fn _ -> :error end)
    on_exit(fn -> Application.delete_env(:phoenix_elxir_beam, :metadata_egress_resolver) end)

    # An :a-only resolver (this plugin's default_resolver/1 queries :in, :a)
    # sees no answer for an AAAA-only host and falls through to :error, same
    # as any other unresolvable host -- allowed, same as today. This test
    # exists to make that an intentional, documented behavior rather than a
    # gap someone discovers later.
    ctx = ctx(%{"url" => "http://ipv6-only.test/"})
    assert %{verdict: :allow} = MetadataEgressGuard.evaluate(:pre_call, ctx)
  end

  test "finds a forbidden target nested inside the arguments map" do
    ctx = ctx(%{"request" => %{"headers" => %{}, "url" => "http://169.254.169.254/"}})
    assert %{verdict: :deny} = MetadataEgressGuard.evaluate(:pre_call, ctx)
  end

  test "manifest declares a fail_closed pre_call policy scoped to :network_egress" do
    manifest = MetadataEgressGuard.manifest()

    assert manifest.plugin.name == "metadata-egress-guard"
    assert %{policy: policy} = manifest.capabilities
    assert policy.phases == [:pre_call]
    assert policy.tool_tags == [:network_egress]
    assert policy.fail_mode == :fail_closed
    assert "call.arguments" in policy.data_needs
  end

  test "resolve_all/2 returns every address and TTL from an injected resolver" do
    fake_resolver = fn
      ~c"multi.test" -> {:ok, [{{93, 184, 216, 34}, 300}, {{169, 254, 169, 254}, 30}]}
      _ -> :error
    end

    assert {:ok, [{{93, 184, 216, 34}, 300}, {{169, 254, 169, 254}, 30}]} =
             MetadataEgressGuard.resolve_all("multi.test", fake_resolver)
  end

  test "resolve_all/2 returns :error when the injected resolver fails" do
    fake_resolver = fn _ -> :error end
    assert :error = MetadataEgressGuard.resolve_all("nowhere.test", fake_resolver)
  end

  test "resolve_all/2 parses an IP-literal host without calling the resolver" do
    fake_resolver = fn _ -> raise "resolver should not be called for an IP literal" end

    assert {:ok, [{{127, 0, 0, 1}, 0}]} =
             MetadataEgressGuard.resolve_all("127.0.0.1", fake_resolver)
  end

  describe "multi-answer and TTL handling" do
    setup do
      on_exit(fn -> Application.delete_env(:phoenix_elxir_beam, :metadata_egress_resolver) end)
    end

    test "denies a call when a forbidden address appears as a non-first DNS answer" do
      Application.put_env(:phoenix_elxir_beam, :metadata_egress_resolver, fn
        ~c"sneaky.test" -> {:ok, [{{93, 184, 216, 34}, 300}, {{169, 254, 169, 254}, 300}]}
        _ -> :error
      end)

      ctx = ctx(%{"url" => "http://sneaky.test/"})

      assert %{verdict: :deny, reason: reason} = MetadataEgressGuard.evaluate(:pre_call, ctx)
      assert reason =~ "169.254.169.254"
    end

    test "escalates severity to :critical when the forbidden answer's TTL is under 60s" do
      Application.put_env(:phoenix_elxir_beam, :metadata_egress_resolver, fn
        ~c"rebinder.test" -> {:ok, [{{169, 254, 169, 254}, 15}]}
        _ -> :error
      end)

      ctx = ctx(%{"url" => "http://rebinder.test/"})

      assert %{verdict: :deny, severity: :critical, reason: reason} =
               MetadataEgressGuard.evaluate(:pre_call, ctx)

      assert reason =~ "short TTL"
    end

    test "keeps :high severity when the forbidden answer's TTL is not suspiciously short" do
      Application.put_env(:phoenix_elxir_beam, :metadata_egress_resolver, fn
        ~c"normal.test" -> {:ok, [{{169, 254, 169, 254}, 3600}]}
        _ -> :error
      end)

      ctx = ctx(%{"url" => "http://normal.test/"})

      assert %{verdict: :deny, severity: :high} = MetadataEgressGuard.evaluate(:pre_call, ctx)
    end

    test "an IP-literal host (synthetic TTL of 0) is never treated as a short-TTL rebinding signal" do
      ctx = ctx(%{"url" => "http://169.254.169.254/"})

      assert %{verdict: :deny, severity: :high, reason: reason} =
               MetadataEgressGuard.evaluate(:pre_call, ctx)

      refute reason =~ "short TTL"
    end
  end
end
