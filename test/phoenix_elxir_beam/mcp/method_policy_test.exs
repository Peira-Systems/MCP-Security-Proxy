defmodule PhoenixElxirBeam.MCP.MethodPolicyTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.MethodPolicy

  @expected %{
    "tools/call" => :police,
    "tools/list" => :forward,
    "resources/list" => :forward,
    "resources/templates/list" => :forward,
    "resources/read" => :scan_response,
    "resources/subscribe" => :forward,
    "resources/unsubscribe" => :forward,
    "prompts/list" => :forward,
    "prompts/get" => :scan_response,
    "completion/complete" => :forward,
    "logging/setLevel" => :forward,
    "sampling/createMessage" => :refuse,
    "elicitation/create" => :refuse,
    "roots/list" => :refuse
  }

  test "every known method has the expected disposition" do
    for {method, disposition} <- @expected do
      assert MethodPolicy.disposition(method) == disposition, "#{method}"
    end
  end

  test "known_methods matches the table" do
    assert Enum.sort(MethodPolicy.known_methods()) == Enum.sort(Map.keys(@expected))
  end

  test "notification methods are acked" do
    assert MethodPolicy.disposition("notifications/cancelled") == :ack
    assert MethodPolicy.disposition("notifications/progress") == :ack
    assert MethodPolicy.disposition("notifications/roots/list_changed") == :ack
  end

  test "unknown and nil methods are refused (default-deny)" do
    assert MethodPolicy.disposition("wat/ever") == :refuse
    assert MethodPolicy.disposition("") == :refuse
    assert MethodPolicy.disposition(nil) == :refuse
  end
end
