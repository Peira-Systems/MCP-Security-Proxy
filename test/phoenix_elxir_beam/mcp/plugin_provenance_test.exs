defmodule PhoenixElxirBeam.MCP.Plugin.ProvenanceTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias PhoenixElxirBeam.MCP.Plugin.{Manifest, Provenance, SidecarRunner}

  @fixture Path.expand("../../support/fixtures/sidecar_scanner.js", __DIR__)

  defp manifest do
    Manifest.normalize(%Manifest{
      plugin: %{name: "p", version: "1"},
      capabilities: %{}
    })
  end

  describe "digests" do
    test "code_digest is stable and file-content sensitive" do
      d1 = Provenance.code_digest("node", [@fixture])
      assert d1 == Provenance.code_digest("node", [@fixture])
      assert String.starts_with?(d1, "sha256:")

      tmp = Path.join(System.tmp_dir!(), "prov_#{System.unique_integer([:positive])}.js")
      File.write!(tmp, File.read!(@fixture) <> "\n// tweak\n")
      on_exit(fn -> File.rm(tmp) end)

      refute Provenance.code_digest("node", [tmp]) == d1
    end

    test "manifest_digest is stable" do
      assert Provenance.manifest_digest(manifest()) == Provenance.manifest_digest(manifest())
    end
  end

  describe "verify/2" do
    test "unpinned → {:ok, digests} and logs the pin snippet" do
      spec = %{name: "p", cmd: "node", resolved_args: [@fixture], pin: nil}

      log =
        capture_log(fn ->
          assert {:ok, %{code: c, manifest: m}} = Provenance.verify(spec, manifest())
          assert String.starts_with?(c, "sha256:")
          assert String.starts_with?(m, "sha256:")
        end)

      assert log =~ "unpinned"
      assert log =~ "pin: [code:"
    end

    test "matching pin → ok, mismatched pin → error" do
      base = %{name: "p", cmd: "node", resolved_args: [@fixture], pin: nil}
      {:ok, digests} = Provenance.verify(base, manifest())

      ok = %{base | pin: [code: digests.code, manifest: digests.manifest]}
      assert {:ok, _} = Provenance.verify(ok, manifest())

      bad = %{base | pin: [code: "sha256:deadbeef", manifest: digests.manifest]}
      assert {:error, detail} = Provenance.verify(bad, manifest())
      assert detail =~ "code digest mismatch"
    end
  end

  describe "SidecarRunner integration" do
    test "a wrong code pin refuses to start" do
      node = System.find_executable("node") || raise "node not found on PATH"
      name = :"prov_sc_#{System.unique_integer([:positive])}"

      log =
        capture_log(fn ->
          assert {:error, _} =
                   start_supervised(
                     {SidecarRunner,
                      name: name,
                      plugin_name: "pinned-scanner",
                      cmd: node,
                      cmd_string: "node",
                      args: [@fixture],
                      pin: [code: "sha256:not-the-real-hash"]},
                     id: name
                   )
        end)

      assert log =~ "code digest mismatch"
      assert log =~ "sidecar_provenance"
    end

    test "a correct pin starts normally" do
      node = System.find_executable("node") || raise "node not found on PATH"
      code = Provenance.code_digest("node", [@fixture])
      name = :"prov_ok_#{System.unique_integer([:positive])}"

      pid =
        start_supervised!(
          {SidecarRunner,
           name: name,
           plugin_name: "pinned-scanner",
           cmd: node,
           cmd_string: "node",
           args: [@fixture],
           pin: [code: code]},
          id: name
        )

      assert Process.alive?(pid)
      assert %Manifest{} = SidecarRunner.manifest(name)
    end
  end
end
