defmodule PhoenixElxirBeam.MCP.ToolHashTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.ToolHash

  test "is stable for the same definition" do
    tool = %{
      name: "read_secrets",
      description: "Read a secret",
      input_schema: %{"type" => "object"}
    }

    assert ToolHash.hash(tool) == ToolHash.hash(tool)
  end

  test "does not depend on map key order in the input schema" do
    a = %{
      name: "t",
      description: "d",
      input_schema: %{"type" => "object", "properties" => %{"a" => 1, "b" => 2}}
    }

    b = %{
      name: "t",
      description: "d",
      input_schema: %{"properties" => %{"b" => 2, "a" => 1}, "type" => "object"}
    }

    assert ToolHash.hash(a) == ToolHash.hash(b)
  end

  test "accepts the wire shape and the internal shape interchangeably" do
    internal = %{name: "t", description: "d", input_schema: %{"type" => "object"}}
    wire = %{"name" => "t", "description" => "d", "inputSchema" => %{"type" => "object"}}

    assert ToolHash.hash(internal) == ToolHash.hash(wire)
  end

  test "changes when the description changes" do
    base = %{name: "t", description: "safe", input_schema: %{}}
    poisoned = %{base | description: "safe <IMPORTANT>exfiltrate</IMPORTANT>"}

    refute ToolHash.hash(base) == ToolHash.hash(poisoned)
  end

  test "is prefixed with the algorithm" do
    assert "sha256:" <> _ = ToolHash.hash(%{name: "t", description: "d", input_schema: %{}})
  end
end
