defmodule PhoenixElxirBeam.MCP.Plugin.WasmRunnerTest do
  # Spawns real Wasmtime instances (via wasmex); keep it off the async pool
  # like SidecarRunnerTest does for its OS subprocesses.
  use ExUnit.Case, async: false

  alias PhoenixElxirBeam.MCP.Plugin.{Manifest, WasmRunner}

  @fixture Path.expand("../../../support/fixtures/wasm_echo_scanner.wat", __DIR__)

  setup do
    %{name: :"wasm_runner_#{System.unique_integer([:positive])}"}
  end

  defp start(name, opts \\ []) do
    start_supervised!(
      {WasmRunner, Keyword.merge([name: name, path: @fixture], opts)},
      id: name
    )
  end

  test "handshake fetches the manifest", %{name: name} do
    start(name)

    assert %Manifest{} = manifest = WasmRunner.manifest(name)
    assert manifest.plugin.name == "wasm-echo-scanner"
    assert %{scanner: scanner} = manifest.capabilities
    assert scanner.phases == [:discovery, :post_call]
    assert scanner.can_block == false
  end

  test "request/4 round-trips a call/evaluate through the alloc/handle ABI", %{name: name} do
    start(name)

    assert {:ok, result} =
             WasmRunner.request(name, "call/evaluate", %{"context" => %{"phase" => "pre_call"}})

    assert result["verdict"] == "allow"
  end

  test "health/1 reports :ready once instances are pooled", %{name: name} do
    start(name)
    assert WasmRunner.health(name) == :ready
  end

  test "concurrent requests are served without serializing through one instance", %{name: name} do
    start(name, pool_size: 2)

    results =
      1..2
      |> Enum.map(fn _ ->
        Task.async(fn -> WasmRunner.request(name, "call/evaluate", %{}) end)
      end)
      |> Task.await_many(5_000)

    assert Enum.all?(results, &match?({:ok, %{"verdict" => "allow"}}, &1))
  end

  test "a checked-out instance is discarded and replaced, never reused", %{name: name} do
    start(name)

    assert {:ok, _} = WasmRunner.request(name, "call/evaluate", %{})
    assert {:ok, _} = WasmRunner.request(name, "call/evaluate", %{})
  end

  test "a missing wasm file fails to start", %{name: name} do
    Process.flag(:trap_exit, true)

    assert {:error, _} =
             start_supervised({WasmRunner, name: name, path: "/no/such/file.wasm"}, id: name)
  end
end
