#!/usr/bin/env python3
"""
Prompt-injection / tool-poisoning scanner for the MCP Security Proxy,
running out of process as a *sidecar* plugin.

Speaks the newline-delimited JSON-RPC 2.0 Plugin Protocol
(docs/plugin-protocol.md). This is the reference polyglot plugin: the proxy
treats it identically to an in-process Elixir plugin.

Detection is a **maintained ruleset** (`injection_rules.json`, M4.3) — labelled
regex rules across instruction-override, secrecy, exfiltration and
tool-poisoning categories. Precision/recall against the labelled corpus in
`corpus/` is measured by `score_injection.py`, gated in CI. Extend the ruleset,
not this file.

Two phases:

  * `discovery` — inspects tool *descriptions* at server registration /
    re-handshake. On a hit it emits a `prompt_injection` finding and (with
    the operator's `block` grant) a tool-quarantine update.
  * `post_call` — inspects tool *responses* before the agent sees them.
    A hidden instruction that arrives inside otherwise-normal tool output
    is reported as a finding and stripped via a `redactResponse` mutation.
"""

import re
import sys
import json
import os

# The ruleset path may be passed as argv[1] (so it is covered by the sidecar's
# provenance pin, M3.5); otherwise it sits next to this file.
RULES_PATH = (
    sys.argv[1]
    if len(sys.argv) > 1 and sys.argv[1].endswith(".json")
    else os.path.join(os.path.dirname(os.path.abspath(__file__)), "injection_rules.json")
)

MANIFEST = {
    "protocolVersion": "0.1",
    "plugin": {
        "name": "prompt-injection-scanner",
        "version": "0.3.0",
        "vendor": "mcp-security-proxy",
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

# A hidden-instruction block in a tool response, redacted before the agent
# sees it. Case-insensitive, spans newlines.
IMPORTANT_BLOCK = r"(?is)<\s*important\s*>.*?<\s*/\s*important\s*>"

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


# Zero-width codepoints with no visible rendering, used to split a trigger
# phrase's letters apart so a word-boundary-based regex never sees them
# adjacent. NFKC does not strip these (they have no compatibility
# decomposition). Distinct from the `poison-zero-width` RULE in
# injection_rules.json, which flags a dense run of 3+ as its own signature
# -- this strips scattered SINGLE occurrences so the underlying trigger
# phrase becomes visible to the existing rules, a different obfuscation
# shape than the rule's dense-block pattern.
_ZERO_WIDTH_CODEPOINTS = "​‌‍‎‏﻿"
_ZERO_WIDTH_RE = re.compile(f"[{_ZERO_WIDTH_CODEPOINTS}]")


def strip_zero_width(text):
    return _ZERO_WIDTH_RE.sub("", text or "")


# Cross-script look-alike characters that NFKC does not fold (NFKC only
# unifies compatibility-equivalent forms *within* a script, e.g. fullwidth
# Latin to ordinary Latin -- it has no concept of "this Cyrillic letter
# looks like that Latin letter"). Scoped to the look-alikes relevant to
# defeating THIS ruleset's existing Latin-script trigger phrases, not a
# general-purpose transliteration of Cyrillic/Greek text -- see the
# confusables table maintained by the Unicode Consortium
# (unicode.org/Public/security/latest/confusables.txt) for the much larger
# full set this intentionally does not replicate.
#
# Folds confusables using a *local-context* gate: a confusable character is
# folded only when it sits inside a contiguous run of word-characters
# (letters/digits/confusables) that also contains at least one genuine ASCII
# Latin letter. This catches homoglyph-disguised Latin phrases wherever they
# appear (even embedded in otherwise non-Latin documents) while never
# touching runs that are genuinely all non-Latin.
_CONFUSABLES = {
    "а": "a", "А": "A",  # Cyrillic a
    "е": "e", "Е": "E",  # Cyrillic ye
    "о": "o", "О": "O",  # Cyrillic o
    "р": "p", "Р": "P",  # Cyrillic er
    "с": "c", "С": "C",  # Cyrillic es
    "х": "x", "Х": "X",  # Cyrillic ha
    "у": "y", "У": "Y",  # Cyrillic u
    "і": "i", "І": "I",  # Cyrillic/Ukrainian i
    "ѕ": "s", "Ѕ": "S",  # Cyrillic dze
    "ј": "j", "Ј": "J",  # Cyrillic je
    "ԛ": "q",            # Cyrillic qa
    "ԝ": "w",            # Cyrillic we
    "α": "a", "Α": "A",  # Greek alpha
    "β": "b", "Β": "B",  # Greek beta
    "ο": "o", "Ο": "O",  # Greek omicron
    "ρ": "p", "Ρ": "P",  # Greek rho
    "τ": "t", "Τ": "T",  # Greek tau
    "υ": "u", "Υ": "Y",  # Greek upsilon
}


def fold_confusables(text):
    if not text:
        return text or ""

    def is_wordish(c):
        return c.isalnum() or c in _CONFUSABLES

    out = []
    i = 0
    n = len(text)
    while i < n:
        if is_wordish(text[i]):
            j = i
            while j < n and is_wordish(text[j]):
                j += 1
            run = text[i:j]
            has_ascii_latin = any(c.isascii() and c.isalpha() for c in run)
            if has_ascii_latin:
                run = "".join(_CONFUSABLES.get(c, c) for c in run)
            out.append(run)
            i = j
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def load_rules(path=RULES_PATH):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    compiled = []
    for rule in data.get("rules", []):
        compiled.append({
            "id": rule["id"],
            "category": rule.get("category", "uncategorised"),
            "severity": rule.get("severity", "high"),
            "confidence": rule.get("confidence", 0.8),
            "re": re.compile(rule["pattern"], re.IGNORECASE | re.DOTALL),
        })
    return compiled, data.get("version", "unknown")


RULES, RULESET_VERSION = load_rules()


def scan_text(text):
    """Returns a list of {id, category, severity, confidence, evidence} hits."""
    # NFKC-normalize before matching: folds Unicode *compatibility* variants
    # (fullwidth/halfwidth forms, certain ligatures) down to their ordinary
    # ASCII/Latin equivalents, so e.g. fullwidth "ｉｇｎｏｒｅ" matches the
    # same rule as "ignore" without every pattern needing a fullwidth
    # alternative. It does NOT fold cross-script homoglyphs (Cyrillic "о" has
    # no compatibility decomposition to Latin "o") or reverse other encodings
    # (base64, reversed text) -- those remain a documented ruleset limit.
    text = unicodedata.normalize("NFKC", text or "")
    hits = []
    for rule in RULES:
        m = rule["re"].search(text)
        if not m:
            continue
        hits.append({
            "id": rule["id"],
            "category": rule["category"],
            "severity": rule["severity"],
            "confidence": rule["confidence"],
            "evidence": _snippet(text, m.start(), m.end()),
        })
    return hits


def is_injection(text):
    return bool(scan_text(text))


def _snippet(text, start, end, pad=40):
    lo = max(0, start - pad)
    hi = min(len(text), end + pad)
    return ("…" if lo else "") + text[lo:hi] + ("…" if hi < len(text) else "")


def _worst(hits):
    return max(hits, key=lambda h: (_SEVERITY_RANK.get(h["severity"], 2), h["confidence"]))


def truncate(text, limit=200):
    text = text or ""
    return text if len(text) <= limit else text[:limit] + "…"


def handle_discovery(params):
    findings, tool_updates = [], []
    for tool in params.get("tools", []):
        hits = scan_text(tool.get("description"))
        if not hits:
            continue
        worst = _worst(hits)
        cats = sorted({h["category"] for h in hits})
        findings.append({
            "id": f"pi-{tool['name']}",
            "type": "prompt_injection",
            "severity": worst["severity"],
            "confidence": worst["confidence"],
            "title": f"Hidden instruction in '{tool['name']}' description",
            "detail": f"matched rule(s) {', '.join(h['id'] for h in hits)} ({', '.join(cats)})",
            "locator": {"path": f"tools.{tool['name']}.description"},
            "evidence": truncate(worst["evidence"]),
            "plugin": MANIFEST["plugin"],
        })
        tool_updates.append({
            "name": tool["name"],
            "block": True,
            "reason": f"prompt injection in tool description ({cats[0]})",
        })
    return {"findings": findings, "toolUpdates": tool_updates}


def handle_inspect_response(params):
    context = params.get("context", {})
    call = context.get("call", {})
    content = (context.get("response") or {}).get("content") or []

    findings, redactions = [], []
    for index, part in enumerate(content):
        text = part.get("text") if isinstance(part, dict) else None
        hits = scan_text(text)
        if not hits:
            continue
        worst = _worst(hits)
        findings.append({
            "id": f"pi-resp-{call.get('id') or index}",
            "type": "prompt_injection",
            "severity": worst["severity"],
            "confidence": worst["confidence"],
            "title": f"Hidden instruction in '{call.get('toolName') or 'tool'}' response",
            "detail": f"matched rule(s) {', '.join(h['id'] for h in hits)}",
            "locator": {"path": f"content[{index}].text"},
            "evidence": truncate(worst["evidence"]),
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

    top = max(findings, key=lambda f: _SEVERITY_RANK.get(f["severity"], 2))
    result = {"verdict": "annotate", "severity": top["severity"], "findings": findings}
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
        if "id" not in req:
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
