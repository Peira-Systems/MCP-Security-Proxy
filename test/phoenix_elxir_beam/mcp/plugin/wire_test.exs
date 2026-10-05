defmodule PhoenixElxirBeam.MCP.Plugin.WireTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.{CallContext, Decision}
  alias PhoenixElxirBeam.MCP.Plugin.Wire

  defp entry(data_needs), do: %{data_needs: data_needs, config: %{"k" => "v"}}

  defp pre_call_ctx do
    CallContext.new(%{
      phase: :pre_call,
      call: %{
        id: "c-1",
        session_id: "s-1",
        server_id: "net",
        tool_name: "post_webhook",
        tags: [:network_egress],
        arguments: %{"url" => "https://evil.example"}
      },
      session: %{seen_tags: [:sensitive_read]},
      tool: %{name: "post_webhook", description: "Post data", input_schema: %{}}
    })
  end

  test "encode_context uses camelCase, string tags, and always sends routing + seenTags" do
    wire = Wire.encode_context(pre_call_ctx(), entry([]))

    assert wire["phase"] == "pre_call"
    assert wire["pluginConfig"] == %{"k" => "v"}
    assert wire["call"]["sessionId"] == "s-1"
    assert wire["call"]["toolName"] == "post_webhook"
    assert wire["call"]["tags"] == ["network_egress"]
    assert wire["session"]["seenTags"] == ["sensitive_read"]
  end

  test "encode_context withholds arguments / tool fields unless dataNeeds asks" do
    without = Wire.encode_context(pre_call_ctx(), entry([]))
    refute Map.has_key?(without["call"], "arguments")
    refute Map.has_key?(without, "tool")

    with_needs =
      Wire.encode_context(pre_call_ctx(), entry(["call.arguments", "tool.description"]))

    assert with_needs["call"]["arguments"] == %{"url" => "https://evil.example"}
    assert with_needs["tool"]["description"] == "Post data"
    refute Map.has_key?(with_needs["tool"], "inputSchema")
  end

  test "encode_context sends session.recentCalls only when dataNeeds asks" do
    at = ~U[2026-08-29 12:00:00Z]

    ctx =
      CallContext.new(%{
        phase: :pre_call,
        call: %{id: "c", session_id: "s", server_id: "files", tool_name: "read_secrets"},
        session: %{
          seen_tags: [],
          recent_calls: [
            %{
              tool_name: "read_secrets",
              tags: [:sensitive_read],
              arg_fingerprint: "sha256:abc",
              at: at
            }
          ]
        }
      })

    refute Map.has_key?(Wire.encode_context(ctx, entry([]))["session"], "recentCalls")

    wire = Wire.encode_context(ctx, entry(["session.recentCalls"]))

    assert wire["session"]["recentCalls"] == [
             %{
               "toolName" => "read_secrets",
               "tags" => ["sensitive_read"],
               "argFingerprint" => "sha256:abc",
               "at" => "2026-08-29T12:00:00Z"
             }
           ]
  end

  test "encode_discovery matches the §9.1 params shape" do
    ctx =
      CallContext.new(%{
        phase: :discovery,
        discovery: %{
          server: %{id: "real-x", name: "x", transport: :http},
          tools: [
            %{
              name: "note",
              description: "Save a note",
              input_schema: %{"type" => "object"},
              tags: [:sensitive_read],
              description_hash: "sha256:abc"
            }
          ],
          previous_hashes: %{"note" => "sha256:old"}
        }
      })

    wire = Wire.encode_discovery(ctx)
    assert wire["server"]["transport"] == "http"
    assert [tool] = wire["tools"]
    assert tool["descriptionHash"] == "sha256:abc"
    assert tool["tags"] == ["sensitive_read"]
    assert wire["previousHashes"] == %{"note" => "sha256:old"}
  end

  test "decode_decision maps verdict/severity strings and addTags" do
    decision =
      Wire.decode_decision(%{
        "verdict" => "deny",
        "severity" => "high",
        "reason" => "nope",
        "mutations" => %{"addTags" => ["sensitive_read"]}
      })

    assert %Decision{verdict: :deny, severity: :high, reason: "nope"} = decision
    assert decision.mutations == %{add_tags: [:sensitive_read]}
  end

  test "decode_decision defaults an unknown verdict to :allow" do
    assert %Decision{verdict: :allow} = Wire.decode_decision(%{})
  end

  test "decode_discovery_result turns block into quarantine and addTags into atoms" do
    {findings, updates} =
      Wire.decode_discovery_result(%{
        "findings" => [%{"type" => "prompt_injection", "severity" => "high", "title" => "hit"}],
        "toolUpdates" => [
          %{"name" => "note", "block" => true, "addTags" => ["network_egress"], "reason" => "bad"}
        ]
      })

    assert [%{type: "prompt_injection"}] = findings

    assert [%{name: "note", quarantine: true, add_tags: [:network_egress], reason: "bad"}] =
             updates
  end

  test "decode_finding drops an unknown proposed tag rather than creating an atom" do
    {_findings, [update]} =
      Wire.decode_discovery_result(%{
        "toolUpdates" => [%{"name" => "n", "addTags" => ["totally_new_tag"]}]
      })

    assert update.add_tags == []
  end
end
