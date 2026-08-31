# Prompt-injection detection

**Status:** Active · **Implements:** [productionization-plan.md](productionization-plan.md) M4.3

## Approach

A **maintained regex ruleset**, not an ML model or an external service. At this
system's scale (first-party, single-node, a small operator team) a curated
ruleset with a measured corpus is the right trade: no model weights or inference
deps in the image, no network dependency on the request path, and every decision
is explainable ("matched rule `override-ignore-previous`").

| File | Role |
|---|---|
| [`priv/plugins/injection_rules.json`](../priv/plugins/injection_rules.json) | the ruleset — `{id, category, pattern, severity, confidence}` per rule. **Edit this**, not the scanner. |
| [`priv/plugins/prompt_injection_scanner.py`](../priv/plugins/prompt_injection_scanner.py) | the sidecar — loads the ruleset, runs it over tool descriptions (`discovery`) and responses (`post_call`). Ruleset path is `argv[1]` so it's covered by the M3.5 provenance pin. |
| [`priv/plugins/corpus/injection_corpus.jsonl`](../priv/plugins/corpus/injection_corpus.jsonl) | labelled samples — `{text, label: malicious\|benign, category}`. |
| [`priv/plugins/score_injection.py`](../priv/plugins/score_injection.py) | scores the ruleset against the corpus; enforces the budget. |

Categories: `instruction_override` (ignore-previous, jailbreak, role reassignment,
"disable safety"), `secrecy` ("do not tell the user"), `exfiltration` (send/email
credentials, read `~/.ssh` / `.env`, "print your system prompt"), `tool_poisoning`
(`<important>` / model-turn markers / instruction-bearing HTML comments /
zero-width runs / "decode and execute").

## Budget

`score_injection.py` fails CI (`.github/workflows/ci.yml`) if, against the
corpus:

| metric | budget |
|---|---|
| recall (known injections caught) | ≥ 0.85 |
| precision (flags that are real) | ≥ 0.90 |
| false-positive rate (benign misflagged) | ≤ 0.05 |

Current: recall 1.00, precision 1.00, FP 0.00 on 95 samples. The perfect score
partly reflects that the corpus and ruleset were authored together — treat the
budget headroom (not the current numbers) as the real safety margin, and grow
the corpus with adversarial and borderline cases over time.

## Maintaining it

1. Add samples to the corpus first (both a new attack *and* a benign near-miss).
2. Run `python3 priv/plugins/score_injection.py` — see what's missed / false-alarmed.
3. Add or tighten a rule in `injection_rules.json`.
4. Re-run until the budget passes; keep FP rate low — a noisy scanner gets ignored.
5. Recompute the sidecar provenance pin in `config/prod.exs` (the ruleset is part
   of the pinned digest) — command is in the comment there.

## Limits (feeds the threat model, M4.4)

- Regexes miss paraphrase and novel phrasings the corpus doesn't cover.
- Detection is advisory on `post_call` (finding + redaction, response still
  delivered) and blocking on `discovery` (with the `block` grant).
- Multi-lingual and heavily-obfuscated payloads are largely out of scope.
- It does not see agent↔model traffic, only tool descriptions and tool responses.
