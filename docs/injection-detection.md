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
| [`priv/plugins/corpus/injection_corpus.jsonl`](../priv/plugins/corpus/injection_corpus.jsonl) | labelled samples — `{text, label: malicious\|benign, category, scope?: "out_of_scope"}`. The optional `scope` tag excludes a row from the CI-gated budget while keeping it measured (see Budget). |
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

Current (M4.3 corpus-growth follow-up): recall 1.00, precision 1.00, FP 0.00 on
115 **in-scope** samples (49 malicious, 66 benign). The corpus now also carries
28 samples explicitly tagged `"scope": "out_of_scope"` — paraphrase,
multilingual, and heavily-obfuscated variants of the same attacks (see Limits
below) — which `score_injection.py` measures and prints separately but does
not gate CI on. Measured, that out-of-scope set catches **1/28 (0.036
recall)**: this is the honest number the original "corpus and ruleset were
authored together" 1.00 was hiding. Two gaps found this way were genuinely
closable and got fixed in the ruleset/scanner rather than left as accepted
misses: Unicode NFKC normalization (closes the fullwidth-character evasion
class) and newline-tolerant middle clauses on `override-ignore-previous`
(closes a regex design gap that let a single embedded newline split a trigger
phrase past `[^.\n]`). Everything still in the out-of-scope set is a case the
"Limits" section below already, independently disclaims — treat that 3.6% as
a floor on generalization, not a bug to chase with narrower and narrower
per-sample rules (see step 3 below).

## Maintaining it

1. Add samples to the corpus first (both a new attack *and* a benign near-miss).
2. Run `python3 priv/plugins/score_injection.py` — see what's missed / false-alarmed.
3. Add or tighten a rule in `injection_rules.json` **only if the fix generalizes**
   (a broader synonym in an existing alternation, a genuine regex-design gap like
   the newline one above, Unicode normalization). Don't chase an individual missed
   sentence with a rule shaped to match that sentence — that just recreates the
   "corpus and ruleset authored together" problem this follow-up exists to avoid.
   If a miss is a case the Limits section already disclaims (paraphrase,
   multilingual, heavy obfuscation) and no generalizable fix presents itself, tag
   the row `"scope": "out_of_scope"` instead of forcing the budget to pass — it
   stays measured and visible in the scorer's informational section, just not
   CI-gating.
4. Re-run until the in-scope budget passes; keep FP rate low — a noisy scanner
   gets ignored.
5. Recompute the sidecar provenance pin in `config/prod.exs` (the ruleset is part
   of the pinned digest) — command is in the comment there.

## Limits (feeds the threat model, M4.4)

- Regexes miss paraphrase and novel phrasings the corpus doesn't cover —
  measured, not just asserted: 0/15 paraphrased malicious samples across all
  four categories were caught (see the corpus's `*_paraphrase` rows).
- Detection is advisory on `post_call` (finding + redaction, response still
  delivered) and blocking on `discovery` (with the `block` grant).
- Multi-lingual and heavily-obfuscated payloads are largely out of scope —
  measured: 0/8 multilingual and 1/5 heavily-obfuscated malicious samples were caught
  (the one catch, a homoglyph sample, fired on an unrelated unobfuscated
  trigger phrase elsewhere in the same sentence, not on defeating the
  homoglyph substitution itself). Two specific, narrow obfuscation classes
  *are* handled — Unicode-compatibility tricks (fullwidth/halfwidth forms, via
  NFKC normalization) and a single embedded newline splitting a trigger phrase
  — because both are closable regex/encoding-normalization fixes rather than
  open-ended language coverage. Cross-script homoglyphs, base64/rotated
  encodings, reversed text, and zero-width interleaving remain out of scope; a
  representative sample of each is kept in the corpus (tagged
  `"scope": "out_of_scope"`) as a tracked, non-gating regression check rather
  than silently dropped.
- It does not see agent↔model traffic, only tool descriptions and tool responses.
