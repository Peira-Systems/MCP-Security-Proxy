#!/usr/bin/env python3
"""
Prompt-injection / tool-poisoning scanner for the MCP Security Proxy,
running out of process as a *sidecar* plugin.

Speaks the newline-delimited JSON-RPC 2.0 Plugin Protocol
(docs/plugin-protocol.md). This is the reference polyglot plugin: the proxy
treats it identically to an in-process Elixir plugin.

It inspects tool descriptions during the `discovery` phase and, on a hit,
emits a `prompt_injection` finding and (with the operator's `block` grant) a
tool-quarantine update.
"""

import sys
import json

MANIFEST = {
    "protocolVersion": "0.1",
    "plugin": {
        "name": "prompt-injection-scanner",
        "version": "0.1.0",
        "vendor": "mcp-security-proxy examples",
        "description": "Flags hidden instructions in MCP tool descriptions.",
    },
    "capabilities": {
        "scanner": {
            "phases": ["discovery"],
            "dataNeeds": ["tool.description"],
            "timeoutMs": 800,
            "failMode": "fail_open",
            "canBlock": True,
        }
    },
}

SUSPICIOUS = (
    "<important>",
    "ignore previous",
    "ignore the above",
    "do not tell the user",
    "do not mention",
    "read ~/.ssh",
    "read secrets",
)


def scan_text(text):
    lowered = (text or "").lower()
    return [p for p in SUSPICIOUS if p in lowered]


def truncate(text, limit=200):
    text = text or ""
    return text if len(text) <= limit else text[:limit] + "…"


def handle_discovery(params):
    findings = []
    tool_updates = []
    for tool in params.get("tools", []):
        hits = scan_text(tool.get("description"))
        if not hits:
            continue
        findings.append({
            "id": f"pi-{tool['name']}",
            "type": "prompt_injection",
            "severity": "critical" if "<important>" in hits else "high",
            "confidence": 0.9,
            "title": f"Hidden instruction in '{tool['name']}' description",
            "detail": f"Description contains suspicious phrase(s): {', '.join(hits)}",
            "locator": {"path": f"tools.{tool['name']}.description"},
            "evidence": truncate(tool.get("description")),
            "plugin": MANIFEST["plugin"],
        })
        tool_updates.append({
            "name": tool["name"],
            "block": True,
            "reason": "prompt injection in tool description",
        })
    return {"findings": findings, "toolUpdates": tool_updates}


def handle(msg):
    method = msg.get("method")
    if method == "initialize":
        return MANIFEST
    if method == "ping":
        return {}
    if method == "discovery/inspect":
        return handle_discovery(msg.get("params", {}))
    if method == "call/evaluate":
        return {"verdict": "allow"}
    raise LookupError(method)


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        if "id" not in req:  # notification: initialized / shutdown
            if req.get("method") == "shutdown":
                return
            continue
        try:
            out = {"jsonrpc": "2.0", "id": req["id"], "result": handle(req)}
        except LookupError as exc:
            out = {
                "jsonrpc": "2.0",
                "id": req["id"],
                "error": {"code": -32601, "message": f"method not found: {exc}"},
            }
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
