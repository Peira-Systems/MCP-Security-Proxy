// Minimal MCP stdio server used to test StdioServer/ServerRegistry's real
// process-handling logic without depending on npm/pip network installs.
// Speaks the same newline-delimited JSON-RPC framing as real MCP servers.

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
        capabilities: { tools: {} },
        serverInfo: { name: "echo", version: "0.0.1" }
      })
      break
    case "tools/list":
      respond(msg.id, {
        tools: [
          {
            name: "echo",
            description: "Echoes its arguments back",
            inputSchema: { type: "object", properties: {} }
          }
        ]
      })
      break
    case "tools/call":
      respond(msg.id, {
        content: [{ type: "text", text: JSON.stringify(msg.params) }],
        isError: false
      })
      break
    case "fail":
      fail(msg.id, "boom")
      break
  }
}

function respond(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n")
}

function fail(id, message) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32000, message } }) + "\n")
}
