// Minimal out-of-process plugin (sidecar) used to test SidecarRunner /
// Pipeline sidecar dispatch without a Python dependency. Speaks the
// newline-delimited JSON-RPC 2.0 Plugin Protocol (docs/plugin-protocol.md).

const MANIFEST = {
  protocolVersion: "0.1",
  plugin: { name: "test-sidecar-scanner", version: "0.1.0" },
  capabilities: {
    scanner: {
      phases: ["discovery"],
      dataNeeds: ["tool.description"],
      timeoutMs: 1000,
      failMode: "fail_open",
      canBlock: true
    }
  }
}

function scanText(text) {
  return (text || "").includes("<IMPORTANT>")
}

function handle(msg) {
  switch (msg.method) {
    case "initialize":
      return MANIFEST
    case "ping":
      return {}
    case "discovery/inspect": {
      const findings = []
      const toolUpdates = []
      for (const t of msg.params.tools) {
        if (scanText(t.description)) {
          findings.push({
            id: "f-sidecar",
            type: "prompt_injection",
            severity: "high",
            title: `Suspicious phrase in ${t.name}`,
            evidence: "<IMPORTANT>",
            plugin: MANIFEST.plugin
          })
          toolUpdates.push({ name: t.name, block: true, reason: "prompt injection in description" })
        }
      }
      return { findings, toolUpdates }
    }
    case "call/evaluate":
      return { verdict: "allow" }
    default:
      throw new LookupError(msg.method)
  }
}

class LookupError extends Error {}

process.stdin.setEncoding("utf8")
let buffer = ""

process.stdin.on("data", (chunk) => {
  buffer += chunk
  let index
  while ((index = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, index).trim()
    buffer = buffer.slice(index + 1)
    if (line === "") continue
    const req = JSON.parse(line)
    if (req.id === undefined) continue // notification: initialized / shutdown
    let out
    try {
      out = { jsonrpc: "2.0", id: req.id, result: handle(req) }
    } catch (e) {
      out = { jsonrpc: "2.0", id: req.id, error: { code: -32601, message: String(e.message || e) } }
    }
    process.stdout.write(JSON.stringify(out) + "\n")
  }
})
