defmodule PhoenixElxirBeam.MCP.Plugin.ConfigSchemaTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.Plugin.ConfigSchema

  describe "schema/1" do
    test "every field carries the keys the dashboard form needs" do
      for name <- ~w(approval-gate baseline-guard response-size-guard stream-guard
                     unclassified-guard rule-engine-wasm) do
        for field <- ConfigSchema.schema(name) do
          assert is_binary(field.key)
          assert is_binary(field.label)
          assert is_binary(field.help)
          assert field.type in [:integer, :string, :string_list, :boolean, :select, :json]
          assert Map.has_key?(field, :default)
          if field.type == :select, do: assert(is_list(field.options))
        end
      end
    end

    test "plugins with no field form return an empty schema" do
      assert ConfigSchema.schema("chain-exfil") == []
      assert ConfigSchema.schema("event-log") == []
      assert ConfigSchema.schema("does-not-exist") == []
      # rule-engine has config, but it is edited through the visual rules editor.
      assert ConfigSchema.schema("rule-engine") == []
      assert ConfigSchema.custom_editor?("rule-engine")
      refute ConfigSchema.custom_editor?("baseline-guard")
    end

    test "rule-engine-wasm gets a generic :json rules field, not the bespoke editor" do
      # It takes the identical config shape as rule-engine (docs/wasm-plugin-plan.md W4)
      # but doesn't share rule-engine's single, unkeyed @rules_draft editor state.
      assert [%{key: "rules", type: :json}] = ConfigSchema.schema("rule-engine-wasm")
      refute ConfigSchema.custom_editor?("rule-engine-wasm")
    end
  end

  describe "build/3 coercion" do
    test "integer fields parse and range-check" do
      assert {:ok, %{"max_bytes" => 8000}} =
               ConfigSchema.build("response-size-guard", %{}, %{"max_bytes" => "8000"})

      assert {:error, msg} =
               ConfigSchema.build("response-size-guard", %{}, %{"max_bytes" => "-1"})

      assert msg =~ "at least 0"

      assert {:error, msg} =
               ConfigSchema.build("response-size-guard", %{}, %{"max_bytes" => "big"})

      assert msg =~ "whole number"
    end

    test "a blank integer drops the key so the plugin default applies" do
      assert {:ok, config} =
               ConfigSchema.build("response-size-guard", %{"max_bytes" => 1}, %{"max_bytes" => ""})

      refute Map.has_key?(config, "max_bytes")
    end

    test "string_list splits on commas and trims" do
      assert {:ok, %{"watch_tags" => ["sensitive_read", "network_egress"]}} =
               ConfigSchema.build("baseline-guard", %{}, %{
                 "watch_tags" => " sensitive_read , network_egress "
               })
    end

    test "select only accepts declared options" do
      assert {:ok, %{"mode" => "deny"}} =
               ConfigSchema.build("unclassified-guard", %{}, %{"mode" => "deny"})

      assert {:ok, config} =
               ConfigSchema.build("unclassified-guard", %{}, %{"mode" => "bogus"})

      refute Map.has_key?(config, "mode")
    end

    test "a :json field round-trips valid JSON and rejects invalid JSON" do
      assert {:ok, %{"rules" => [%{"action" => "deny"}]}} =
               ConfigSchema.build("rule-engine-wasm", %{}, %{"rules" => ~s([{"action":"deny"}])})

      assert {:error, msg} =
               ConfigSchema.build("rule-engine-wasm", %{}, %{"rules" => "not json"})

      assert msg =~ "valid JSON"
    end

    test "keys outside the schema are preserved" do
      assert {:ok, %{"max_bytes" => 10, "custom" => "kept"}} =
               ConfigSchema.build(
                 "response-size-guard",
                 %{"custom" => "kept"},
                 %{"max_bytes" => "10"}
               )
    end
  end

  describe "value_for/2 and display/1" do
    test "value_for prefers the live config, falls back to the default" do
      [field] = ConfigSchema.schema("approval-gate")
      assert ConfigSchema.value_for(field, %{"timeout_ms" => 5000}) == 5000
      assert ConfigSchema.value_for(field, %{}) == field.default
    end

    test "display renders lists, ints, and strings" do
      assert ConfigSchema.display(["a", "b"]) == "a, b"
      assert ConfigSchema.display([]) == "(none)"
      assert ConfigSchema.display(4000) == "4000"
      assert ConfigSchema.display("off") == "off"
    end
  end
end
