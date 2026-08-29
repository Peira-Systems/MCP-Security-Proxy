defmodule PhoenixElxirBeam.MCP.Plugin.Wire do
  @moduledoc """
  Translates between the proxy's in-process structs and the JSON-RPC wire
  shapes a sidecar plugin speaks (`docs/plugin-protocol.md` §7 / §9).

  Two rules the sidecar binding follows that the in-process binding does not:

    * **camelCase + strings** on the wire — `seenTags`, `descriptionHash`,
      tags as `"network_egress"` strings (internally they are atoms).
    * **data minimization** (§6) — `encode_context/2` only includes the
      `call.arguments` / `tool.*` / `response.*` fields the plugin's manifest
      `dataNeeds` actually asks for. Routing metadata, `session.seenTags`, and
      `session.callsSoFar` are always sent; `session.taint` /
      `session.recentCalls` are `dataNeeds`-gated.
  """

  require Logger

  alias PhoenixElxirBeam.MCP.{CallContext, Decision, Finding}

  @protocol_version "0.1"

  # -- encode: proxy -> sidecar ---------------------------------------------

  @doc "A `CallContext` as the §7.1 `context` object, filtered by `entry.data_needs`."
  @spec encode_context(CallContext.t(), map()) :: map()
  def encode_context(%CallContext{} = ctx, entry) do
    needs = Map.get(entry, :data_needs, [])
    call = ctx.call

    base = %{
      "protocolVersion" => @protocol_version,
      "phase" => to_string(ctx.phase),
      "pluginConfig" => Map.get(entry, :config, %{}),
      "call" => %{
        "id" => call[:id],
        "sessionId" => call[:session_id],
        "agentId" => call[:agent_id],
        "serverId" => call[:server_id],
        "toolName" => call[:tool_name],
        "method" => call[:method] || "tools/call",
        "tags" => encode_tags(call[:tags] || [])
      },
      "session" => %{
        "seenTags" => encode_tags(get_in(ctx.session, [:seen_tags]) || []),
        "callsSoFar" => Map.get(ctx.session, :calls_so_far, 0)
      }
    }

    base
    |> maybe_put("call", "arguments", needs, "call.arguments", fn -> call[:arguments] end)
    |> maybe_put_session_taint(ctx.session, needs)
    |> maybe_put_session_recent_calls(ctx.session, needs)
    |> maybe_put_tool(ctx.tool, needs)
    |> maybe_put_response(ctx.response, needs)
  end

  @doc "A discovery `CallContext` as the §9.1 `discovery/inspect` params."
  @spec encode_discovery(CallContext.t()) :: map()
  def encode_discovery(%CallContext{phase: :discovery, discovery: d}) do
    %{
      "server" => %{
        "id" => d.server.id,
        "name" => d.server.name,
        "transport" => to_string(d.server.transport)
      },
      "tools" =>
        Enum.map(d.tools, fn t ->
          %{
            "name" => t.name,
            "description" => t.description,
            "inputSchema" => t.input_schema,
            "tags" => encode_tags(t.tags),
            "descriptionHash" => t.description_hash
          }
        end),
      "previousHashes" => d.previous_hashes
    }
  end

  # -- decode: sidecar -> proxy -------------------------------------------

  @doc "A §7.2 `Decision` result object as a `%Decision{}`."
  @spec decode_decision(map()) :: Decision.t()
  def decode_decision(map) when is_map(map) do
    %Decision{
      verdict: decode_verdict(map["verdict"]),
      reason: map["reason"],
      severity: decode_severity(map["severity"]),
      findings: Enum.map(map["findings"] || [], &decode_finding/1),
      mutations: decode_mutations(map["mutations"]),
      hold: decode_hold(map["hold"])
    }
  end

  @doc "A §9.1 `discovery/inspect` result as `{findings, tool_updates}`."
  @spec decode_discovery_result(map()) :: {[Finding.t()], [map()]}
  def decode_discovery_result(map) when is_map(map) do
    findings = Enum.map(map["findings"] || [], &decode_finding/1)

    updates =
      Enum.map(map["toolUpdates"] || [], fn u ->
        %{
          name: u["name"],
          quarantine: u["block"] == true,
          add_tags: decode_tags(u["addTags"] || []),
          reason: u["reason"]
        }
      end)

    {findings, updates}
  end

  @doc "A §7.3 `Finding` object as a `%Finding{}`."
  @spec decode_finding(map()) :: Finding.t()
  def decode_finding(map) when is_map(map) do
    Finding.new(%{
      id: map["id"],
      type: map["type"] || "finding",
      severity: decode_severity(map["severity"]) || :info,
      title: map["title"] || "(untitled finding)",
      detail: map["detail"],
      confidence: map["confidence"],
      locator: map["locator"],
      evidence: map["evidence"],
      plugin: decode_plugin(map["plugin"])
    })
  end

  # -- helpers ------------------------------------------------------------

  defp maybe_put(acc, section, key, needs, need_path, fun) do
    if need_path in needs and not is_nil(fun.()) do
      put_in(acc, [section, key], fun.())
    else
      acc
    end
  end

  defp maybe_put_session_taint(acc, session, needs) do
    if "session.taint" in needs do
      sources =
        session
        |> Map.get(:taint, %{})
        |> Map.get(:sources, [])
        |> Enum.map(fn s ->
          # `secret` (the raw match) is deliberately never sent over the wire —
          # only the redacted `hint`.
          %{
            "originTool" => Map.get(s, :origin_tool),
            "findingType" => Map.get(s, :finding_type),
            "hint" => Map.get(s, :hint),
            "at" => encode_time(Map.get(s, :at))
          }
        end)

      put_in(acc, ["session", "taint"], %{"sources" => sources})
    else
      acc
    end
  end

  defp maybe_put_session_recent_calls(acc, session, needs) do
    if "session.recentCalls" in needs do
      calls =
        session
        |> Map.get(:recent_calls, [])
        |> Enum.map(fn c ->
          %{
            "tags" => encode_tags(Map.get(c, :tags, [])),
            "at" => encode_time(Map.get(c, :at))
          }
        end)

      put_in(acc, ["session", "recentCalls"], calls)
    else
      acc
    end
  end

  defp encode_time(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp encode_time(other), do: other

  defp maybe_put_tool(acc, nil, _needs), do: acc

  defp maybe_put_tool(acc, tool, needs) do
    fields =
      %{}
      |> put_if("description", needs, "tool.description", Map.get(tool, :description))
      |> put_if("inputSchema", needs, "tool.inputSchema", Map.get(tool, :input_schema))
      |> put_if(
        "descriptionHash",
        needs,
        "tool.descriptionHash",
        Map.get(tool, :description_hash)
      )
      |> put_if("tags", needs, "tool.tags", encode_tags(Map.get(tool, :tags, [])))

    if fields == %{},
      do: acc,
      else: Map.put(acc, "tool", Map.put(fields, "name", Map.get(tool, :name)))
  end

  defp maybe_put_response(acc, nil, _needs), do: acc

  defp maybe_put_response(acc, response, needs) do
    fields =
      %{}
      |> put_if("content", needs, "response.content", Map.get(response, :content))
      |> put_if("raw", needs, "response.raw", Map.get(response, :raw))

    if fields == %{}, do: acc, else: Map.put(acc, "response", fields)
  end

  defp put_if(map, _key, _needs, _path, nil), do: map

  defp put_if(map, key, needs, path, value) do
    if path in needs, do: Map.put(map, key, value), else: map
  end

  defp encode_tags(tags), do: Enum.map(tags, &to_string/1)

  defp decode_tags(tags) do
    Enum.flat_map(tags, fn tag ->
      try do
        [String.to_existing_atom(to_string(tag))]
      rescue
        ArgumentError ->
          Logger.warning("Wire: sidecar proposed unknown tag #{inspect(tag)}; dropped")
          []
      end
    end)
  end

  defp decode_verdict("deny"), do: :deny
  defp decode_verdict("hold"), do: :hold
  defp decode_verdict("annotate"), do: :annotate
  defp decode_verdict(_), do: :allow

  defp decode_hold(%{"prompt" => prompt} = h) do
    %{
      prompt: prompt,
      timeout_ms: h["timeoutMs"] || 120_000,
      on_timeout: if(h["onTimeout"] == "allow", do: :allow, else: :deny)
    }
  end

  defp decode_hold(_), do: nil

  defp decode_severity(s) when s in ~w(info low medium high critical),
    do: String.to_existing_atom(s)

  defp decode_severity(_), do: nil

  defp decode_mutations(nil), do: %{}

  defp decode_mutations(map) when is_map(map) do
    %{}
    |> put_mutation(:add_tags, decode_tags(map["addTags"] || []))
    |> put_mutation(:redact_response, map["redactResponse"])
    |> put_mutation(:add_taint_sources, decode_taint_sources(map["addTaintSources"]))
  end

  defp decode_taint_sources(nil), do: []

  defp decode_taint_sources(list) when is_list(list) do
    Enum.map(list, fn s ->
      %{
        origin_tool: s["originTool"] || s["origin_tool"],
        finding_type: s["findingType"] || s["finding_type"] || "unknown",
        at: decode_time(s["at"])
      }
    end)
  end

  defp decode_time(s) when is_binary(s) do
    case DateTime.from_iso8601(s) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  defp decode_time(_), do: nil

  defp put_mutation(acc, _key, nil), do: acc
  defp put_mutation(acc, _key, []), do: acc
  defp put_mutation(acc, key, value), do: Map.put(acc, key, value)

  defp decode_plugin(%{"name" => name} = p), do: %{name: name, version: p["version"] || "0.0.0"}
  defp decode_plugin(_), do: nil
end
