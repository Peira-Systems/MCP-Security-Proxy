defmodule PhoenixElxirBeam.MCP.Plugins.RugPullTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.CallContext
  alias PhoenixElxirBeam.MCP.Plugins.RugPull

  defp ctx(tools, previous_hashes) do
    CallContext.new(%{
      phase: :discovery,
      discovery: %{
        server: %{id: "real-x", name: "x", transport: :http},
        tools: tools,
        previous_hashes: previous_hashes
      }
    })
  end

  defp tool(name, hash, description \\ "d") do
    %{name: name, description: description, input_schema: %{}, description_hash: hash}
  end

  test "flags a tool whose hash changed since it was pinned" do
    tools = [tool("read_secrets", "sha256:new", "poisoned <IMPORTANT>…</IMPORTANT>")]

    assert {:ok, [finding], [update]} =
             RugPull.scan(:discovery, ctx(tools, %{"read_secrets" => "sha256:old"}))

    assert finding.type == "rug_pull"
    assert finding.severity == :high

    assert update == %{
             name: "read_secrets",
             quarantine: true,
             reason: "tool definition changed since registration (possible rug pull)"
           }
  end

  test "ignores a tool whose hash is unchanged" do
    tools = [tool("read_secrets", "sha256:same")]

    assert {:ok, [], []} =
             RugPull.scan(:discovery, ctx(tools, %{"read_secrets" => "sha256:same"}))
  end

  test "ignores a tool with no previous hash (new tool, not drift)" do
    tools = [tool("brand_new", "sha256:whatever")]
    assert {:ok, [], []} = RugPull.scan(:discovery, ctx(tools, %{}))
  end

  test "manifest declares a discovery scanner that can block" do
    manifest = RugPull.manifest()

    assert manifest.plugin.name == "rug-pull"
    assert %{scanner: scanner} = manifest.capabilities
    assert scanner.phases == [:discovery]
    assert scanner.can_block == true
    assert scanner.fail_mode == :fail_open
  end
end
