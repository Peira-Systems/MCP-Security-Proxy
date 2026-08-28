defmodule PhoenixElxirBeam.MCP.ToolCatalog do
  @moduledoc """
  Static catalog of the mock MCP servers, their tools, tags, and canned
  responses used throughout the demo. Nothing here performs a real file
  read or a real network call — every response is a hardcoded string.
  """

  @tools %{
    "files" => [
      %{
        name: "list_files",
        description: "List files in the demo workspace",
        tags: [],
        input_schema: %{"type" => "object", "properties" => %{}},
        response: "README.md\nnotes.txt\nsecrets.env\n(simulated directory listing)"
      },
      %{
        name: "read_secrets",
        description: "Read the contents of a sensitive secrets file",
        tags: [:sensitive_read],
        input_schema: %{"type" => "object", "properties" => %{}},
        response: "API_KEY=sk-demo-FAKE1234 (simulated content, not a real secret)"
      },
      %{
        name: "read_config",
        description: "Read the app config file",
        # Deliberately untagged: the operator never marked this sensitive, so
        # tag-based rules (ChainExfil / ApprovalGate) never fire on it. The
        # `post_call` secret scanner still catches the leak in its response
        # and taints the session, so TaintGuard blocks a later egress.
        tags: [],
        input_schema: %{"type" => "object", "properties" => %{}},
        response:
          "region=us-east-1\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIfake7MDENGbPxRfiCYEXAMPLE (simulated, not a real secret)"
      }
    ],
    "net" => [
      %{
        name: "check_status",
        description: "Check the status of an external service",
        tags: [],
        input_schema: %{"type" => "object", "properties" => %{}},
        response: "status: ok (simulated)"
      },
      %{
        name: "post_webhook",
        description: "Post data to an external webhook URL",
        tags: [:network_egress],
        input_schema: %{
          "type" => "object",
          "properties" => %{
            "url" => %{"type" => "string"},
            "body" => %{"type" => "string"}
          }
        },
        response: "webhook delivered (simulated, no real network call made)"
      }
    ]
  }

  @doc "Returns the list of known server ids."
  def servers, do: Map.keys(@tools)

  @doc "Returns the tool definitions for a server id, or [] if unknown."
  def tools(server_id), do: Map.get(@tools, server_id, [])

  @doc "Looks up a single tool definition by server id and tool name."
  def tool(server_id, tool_name) do
    Enum.find(tools(server_id), &(&1.name == tool_name))
  end

  @doc "Builds the `tools/list` JSON-RPC result payload for a server id."
  def list_tools_json(server_id) do
    Enum.map(tools(server_id), fn tool ->
      %{
        "name" => tool.name,
        "description" => tool.description,
        "inputSchema" => tool.input_schema
      }
    end)
  end
end
