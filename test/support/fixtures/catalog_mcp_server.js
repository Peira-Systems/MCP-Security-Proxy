// Minimal MCP stdio server with a fixed tool catalog, used to exercise the
// proxy's policy pipeline end to end without a live third-party server.
// Speaks newline-delimited JSON-RPC, same framing as a real MCP server.
//
// Tools are deliberately shaped to trip specific plugins:
//   read_secrets  -> response carries a fake API key (SecretLeak redacts it)
//   read_config   -> response carries a fake AWS key, tool is left untagged
//   export_all    -> response > 4 KB (ResponseSizeGuard withholds it)
//   post_webhook  -> benign egress target (tagged :network_egress by the test)

const bigExport =
  Array.from(
    { length: 120 },
    (_, i) =>
      `user_${i + 1},user${i + 1}@example.test,role=member,created=2026-0${(i % 8) + 1}-${(i % 27) + 1}`
  ).join("\n") + "\n(simulated full export)"

const RESOURCES = [
  {
    uri: "file:///readme.md",
    name: "readme",
    mimeType: "text/markdown",
    text: "# Demo workspace\n\nNothing sensitive here."
  },
  {
    uri: "config://app",
    name: "app-config",
    mimeType: "text/plain",
    // carries a fake credential — SecretLeak redacts it and taints the session
    text: "region=us-east-1\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIfake7MDENGbPxRfiCYEXAMPLE (simulated)"
  }
]

const PROMPTS = [
  {
    name: "greeting",
    description: "A friendly greeting",
    // message text carries a fake credential too
    messageText: "Say hello. Context: API_KEY=sk-demo-FAKE1234 (simulated, not a real secret)"
  }
]

const TOOLS = [
  {
    name: "list_files",
    description: "List files in the workspace",
    inputSchema: { type: "object", properties: {} },
    response: "README.md\nnotes.txt\nsecrets.env\n(simulated directory listing)"
  },
  {
    name: "read_secrets",
    description: "Read the contents of a sensitive secrets file",
    inputSchema: { type: "object", properties: {} },
    response: "API_KEY=sk-demo-FAKE1234 (simulated content, not a real secret)"
  },
  {
    name: "read_config",
    description: "Read the app config file",
    inputSchema: { type: "object", properties: {} },
    response:
      "region=us-east-1\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIfake7MDENGbPxRfiCYEXAMPLE (simulated, not a real secret)"
  },
  {
    name: "export_all",
    description: "Export every user record",
    inputSchema: { type: "object", properties: {} },
    response: bigExport
  },
  {
    name: "post_webhook",
    description: "Post data to an external webhook URL",
    inputSchema: {
      type: "object",
      properties: { url: { type: "string" }, body: { type: "string" } }
    },
    response: "webhook delivered (simulated, no real network call made)"
  }
]

process.stdin.setEncoding("utf8")

let buffer = ""

process.stdin.on("data", (chunk) => {
  buffer += chunk
  let index

  while ((index = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, index)
    buffer = buffer.slice(index + 1)
    if (line.trim() !== "") {
      handle(JSON.parse(line))
    }
  }
})

function handle(msg) {
  switch (msg.method) {
    case "initialize":
      respond(msg.id, {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {}, resources: {}, prompts: {} },
        serverInfo: { name: "catalog", version: "0.0.1" }
      })
      break
    case "tools/list":
      respond(msg.id, {
        tools: TOOLS.map(({ name, description, inputSchema }) => ({
          name,
          description,
          inputSchema
        }))
      })
      break
    case "tools/call": {
      const tool = TOOLS.find((t) => t.name === (msg.params && msg.params.name))
      if (!tool) {
        fail(msg.id, "unknown tool")
      } else {
        respond(msg.id, {
          content: [{ type: "text", text: tool.response }],
          isError: false
        })
      }
      break
    }
    case "resources/list":
      respond(msg.id, {
        resources: RESOURCES.map(({ uri, name, mimeType }) => ({ uri, name, mimeType }))
      })
      break
    case "resources/read": {
      const res = RESOURCES.find((r) => r.uri === (msg.params && msg.params.uri))
      if (!res) {
        fail(msg.id, "unknown resource")
      } else {
        respond(msg.id, {
          contents: [{ uri: res.uri, mimeType: res.mimeType, text: res.text }]
        })
      }
      break
    }
    case "prompts/list":
      respond(msg.id, {
        prompts: PROMPTS.map(({ name, description }) => ({ name, description }))
      })
      break
    case "prompts/get": {
      const prompt = PROMPTS.find((p) => p.name === (msg.params && msg.params.name))
      if (!prompt) {
        fail(msg.id, "unknown prompt")
      } else {
        respond(msg.id, {
          description: prompt.description,
          messages: [
            { role: "user", content: { type: "text", text: prompt.messageText } }
          ]
        })
      }
      break
    }
  }
}

function respond(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n")
}

function fail(id, message) {
  process.stdout.write(
    JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32000, message } }) + "\n"
  )
}
