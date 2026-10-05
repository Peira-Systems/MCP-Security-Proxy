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
import unicodedata

from similarity_layer import load_similarity_model, encode

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


# A single-character-separated spelled-out word (I-g-n-o-r-e) defeats any
# regex relying on word boundaries, since every "word" is one character.
# Only collapse a run this long -- 6+ single-char tokens sharing the same
# separator -- so this never touches ordinary short hyphenation ("a-b
# test") or an initialism ("U.S.").
_SPACING_RUN_RE = re.compile(r"\b(?:\w[-.]){3,}\w\b")


def strip_artificial_spacing(text):
    if not text:
        return text or ""

    def collapse(match):
        run = match.group(0)
        return re.sub(r"[-.\s]", "", run)

    return _SPACING_RUN_RE.sub(collapse, text)


# Minimum length before attempting a base64 decode -- below this, too many
# short, coincidental substrings would match the base64 alphabet and cost
# decode attempts for no real signal.
_BASE64_MIN_LEN = 16
_BASE64_SEGMENT_RE = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % _BASE64_MIN_LEN)


def try_base64_segments(text):
    import base64
    import binascii

    decoded = []
    for match in _BASE64_SEGMENT_RE.finditer(text or ""):
        segment = match.group(0)
        try:
            raw = base64.b64decode(segment, validate=False)
            as_text = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        decoded.append(as_text)
    return decoded


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

# The similarity layer's model/tokenizer paths follow the same
# argv-or-fallback convention as RULES_PATH above: argv[2]/argv[3] when
# the sidecar is launched with them (covered by the provenance pin),
# falling back to script-relative paths when run standalone (e.g. from
# score_injection.py or a unit test, neither of which pass sidecar-style
# argv).
SIMILARITY_MODEL_PATH = (
    sys.argv[2]
    if len(sys.argv) > 2 and sys.argv[2].endswith(".onnx")
    else os.path.join(os.path.dirname(os.path.abspath(__file__)), "model", "model.onnx")
)
SIMILARITY_TOKENIZER_PATH = (
    sys.argv[3]
    if len(sys.argv) > 3 and sys.argv[3].endswith(".json")
    else os.path.join(os.path.dirname(os.path.abspath(__file__)), "model", "tokenizer.json")
)


def load_similarity_references(corpus_path):
    """Returns the 54 in-scope malicious examples from the main labelled
    corpus as similarity-check reference texts -- no separate reference
    file is needed (unlike the abandoned TF-IDF design): the embedding
    model is already multilingual, and catches multilingual target rows
    using only these English references (verified during spec research:
    10/23 target rows caught, including non-English ones, using only
    this corpus's existing malicious examples)."""
    references = []
    with open(corpus_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("label") == "malicious" and row.get("scope") != "out_of_scope":
                references.append({"text": row["text"], "category": row["category"]})
    return references


def build_similarity_index(model_path, tokenizer_path, corpus_path):
    """Loads the ONNX model/tokenizer and encodes the reference examples
    once. Called once at module load time, the same pattern as
    `RULES, RULESET_VERSION = load_rules()` above. Any failure here
    (missing/corrupt model files, missing corpus) propagates as an
    unhandled exception, so the sidecar process exits non-zero and never
    reaches its stdio read loop -- fail loudly, not a graceful degrade to
    rule-only detection."""
    session, tokenizer = load_similarity_model(model_path, tokenizer_path)
    references = load_similarity_references(corpus_path)
    reference_matrix = encode([r["text"] for r in references], session, tokenizer)
    return session, tokenizer, reference_matrix, references


_SIMILARITY_CORPUS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "corpus", "injection_corpus.jsonl"
)
(
    SIMILARITY_SESSION,
    SIMILARITY_TOKENIZER,
    SIMILARITY_MATRIX,
    SIMILARITY_REFERENCES,
) = build_similarity_index(SIMILARITY_MODEL_PATH, SIMILARITY_TOKENIZER_PATH, _SIMILARITY_CORPUS_PATH)

# Measured against the current corpus during spec research: at this
# threshold, catches 10/23 target out-of-scope rows with 0/70 false
# positives on the benign corpus. Do not change without re-running the
# full calibration sweep in docs/superpowers/specs/2026-10-04-injection-detection-similarity-layer-design.md.
SIMILARITY_THRESHOLD = 0.605


def check_similarity(text, session, tokenizer, reference_matrix, references, threshold):
    """Returns {"reference_text", "category", "score"} for the
    best-matching reference if its cosine similarity to `text` meets
    `threshold`, else None."""
    query_emb = encode([text], session, tokenizer)
    scores = query_emb @ reference_matrix.T
    best_idx = int(scores[0].argmax())
    best_score = float(scores[0][best_idx])
    if best_score < threshold:
        return None
    return {
        "reference_text": references[best_idx]["text"],
        "category": references[best_idx]["category"],
        "score": best_score,
    }


def _similarity_severity(score):
    if score >= 0.75:
        return "high"
    if score >= 0.65:
        return "medium"
    return "low"


def _similarity_finding(hit):
    return [{
        "id": "similarity-match",
        "category": hit["category"],
        "severity": _similarity_severity(hit["score"]),
        "confidence": hit["score"],
        "evidence": (
            f"similar to known attack ({hit['category']}, score {hit['score']:.2f}): "
            f"{hit['reference_text'][:60]}"
        ),
    }]


def _match_rules(text):
    """The per-candidate matching loop, unchanged in substance from the
    original scan_text body -- extracted so multiple candidates can share it."""
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


def _tag_transform(hits, transform_name):
    if transform_name == "direct":
        return hits
    for hit in hits:
        hit["evidence"] = f"[via {transform_name}] {hit['evidence']}"
    return hits


def scan_text(text):
    """Returns a list of {id, category, severity, confidence, evidence} hits.

    Checks the input directly first (NFKC-normalized, as before), then --
    only if that finds nothing -- a small set of reversible transforms
    (confusables folding, zero-width stripping, artificial-spacing
    stripping, whole-string reversal, and any base64-decoded substrings)
    against the same, unchanged ruleset. See
    docs/superpowers/specs/2026-10-04-injection-detection-normalization-closure-design.md.

    NFKC still runs first on every candidate's base text: it folds Unicode
    *compatibility* variants (fullwidth/halfwidth forms, certain ligatures)
    that none of the newer transforms touch, so e.g. a fullwidth-encoded
    trigger phrase that is ALSO reversed still gets NFKC-folded before the
    reversal check runs.
    """
    text = unicodedata.normalize("NFKC", text or "")

    candidates = [("direct", text)]
    candidates.append(("confusables_folded", fold_confusables(text)))
    candidates.append(("zero_width_stripped", strip_zero_width(text)))
    candidates.append(("spacing_stripped", strip_artificial_spacing(text)))
    candidates.append(("reversed", text[::-1]))
    for decoded in try_base64_segments(text):
        candidates.append(("base64_decoded", decoded))

    for transform_name, candidate in candidates:
        hits = _match_rules(candidate)
        if hits:
            return _tag_transform(hits, transform_name)

    similarity_hit = check_similarity(
        text, SIMILARITY_SESSION, SIMILARITY_TOKENIZER, SIMILARITY_MATRIX,
        SIMILARITY_REFERENCES, SIMILARITY_THRESHOLD,
    )
    if similarity_hit:
        return _similarity_finding(similarity_hit)
    return []


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
