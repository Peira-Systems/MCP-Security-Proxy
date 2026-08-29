#!/usr/bin/env python3
"""
Prompt-injection / tool-poisoning scanner for the MCP Security Proxy,
running out of process as a *sidecar* plugin.

Speaks the newline-delimited JSON-RPC 2.0 Plugin Protocol
(docs/plugin-protocol.md). This is the reference polyglot plugin: the proxy
treats it identically to an in-process Elixir plugin.

Two phases:

  * `discovery` — inspects tool *descriptions* at server registration /
    re-handshake. On a hit it emits a `prompt_injection` finding and (with
    the operator's `block` grant) a tool-quarantine update.
  * `post_call` — inspects tool *responses* before the agent sees them.
    A hidden instruction that arrives inside otherwise-normal tool output
    (the classic "the web page told the agent to exfiltrate secrets"
    attack) is reported as a finding and stripped from the response via a
    `redactResponse` mutation. Advisory: the response is still delivered,
    just neutralised.
"""

import re
import sys
import json

MANIFEST = {
    "protocolVersion": "0.1",
    "plugin": {
        "name": "prompt-injection-scanner",
        "version": "0.2.0",
        "vendor": "mcp-security-proxy examples",
        "description": "Flags hidden instructions in MCP tool descriptions and responses.",
    },
    "capabilities": {
        "scanner": {
            "phases": ["discovery", "post_call"],
            "dataNeeds": ["tool.description", "response.content"],
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

# Matches a hidden-instruction block in a tool response so it can be redacted
# out before the agent sees it. Case-insensitive, spans newlines.
IMPORTANT_BLOCK = r"(?is)<important>.*?</important>"


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


def handle_inspect_response(params):
    # `params["context"]` is the §7.1 CallContext object directly.
    context = params.get("context", {})
    call = context.get("call", {})
    content = (context.get("response") or {}).get("content") or []

    findings = []
    redactions = []
    for index, part in enumerate(content):
        text = part.get("text") if isinstance(part, dict) else None
        hits = scan_text(text)
        if not hits:
            continue
        findings.append({
            "id": f"pi-resp-{call.get('id') or index}",
            "type": "prompt_injection",
            "severity": "high",
            "confidence": 0.85,
            "title": f"Hidden instruction in '{call.get('toolName') or 'tool'}' response",
            "detail": f"Response text contains suspicious phrase(s): {', '.join(hits)}",
            "locator": {"path": f"content[{index}].text"},
            "evidence": truncate(text),
            "plugin": MANIFEST["plugin"],
        })
        if re.search(IMPORTANT_BLOCK, text):
            redactions.append({
                "path": f"content[{index}].text",
                "match": "/" + IMPORTANT_BLOCK + "/",
                "replacement": "‹hidden instruction removed by prompt-injection-scanner›",
            })

    if not findings:
        return {"verdict": "allow"}

    result = {"verdict": "annotate", "severity": "high", "findings": findings}
    if redactions:
        result["mutations"] = {"redactResponse": redactions}
    return result


def handle(msg):
    method = msg.get("method")
    if method == "initialize":
        return MANIFEST
    if method == "ping":
        return {}
    if method == "discovery/inspect":
        return handle_discovery(msg.get("params", {}))
    if method == "call/inspectResponse":
        return handle_inspect_response(msg.get("params", {}))
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
