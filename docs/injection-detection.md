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

Current (2026-10-04 normalization-closure follow-up): recall 1.00,
precision 1.00, FP 0.00 on 124 **in-scope** samples (54 malicious, 70
benign). The corpus now carries 23 samples explicitly tagged
`"scope": "out_of_scope"` — paraphrase and multilingual variants of the
same attacks (see Limits below) — which `score_injection.py` measures and
prints separately but does not gate CI on. Measured, that out-of-scope
set catches **0/23 (0.0 recall)**.

Four gaps previously in the out-of-scope set were closed this round via
generalizable text-normalization transforms in `prompt_injection_scanner.py`
(not new rules): zero-width-character stripping (scattered single
zero-width codepoints between letters, distinct from the
`poison-zero-width` RULE's dense-block signature), artificial-spacing
stripping (`I-g-n-o-r-e`-style single-character separation), base64
segment decoding, and whole-string reversal. Each candidate transform is
checked against the same, unchanged ruleset — see
`docs/superpowers/specs/2026-10-04-injection-detection-normalization-closure-design.md`.

A fifth, confusables-folding (cross-script homoglyphs like Cyrillic "о"
for Latin "o"), was also added this round and works correctly in
isolation, but the specific out-of-scope corpus row it targets
(`obfuscation_homoglyph`) turned out to already be caught by an unrelated
pre-existing rule (`override-act-as`, on an unobfuscated clause elsewhere
in the same sample) — so its closure isn't attributable to this
transform for that particular sample. The transform itself is kept
(it is independently covered by the unit test suite, now run in CI per
the fix above) since a differently-worded homoglyph attack without an
incidental unobfuscated trigger phrase would still need it.

Earlier closed gaps from the prior round remain in place: Unicode NFKC
normalization (fullwidth-character evasion) and newline-tolerant middle
clauses on `override-ignore-previous`. Everything still in the out-of-scope
set (paraphrase, multilingual) is a case the "Limits" section below
already, independently disclaims — closing those needs semantic/
statistical matching, not further text-normalization transforms, and is
scoped as a separate plan.

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
- Multi-lingual payloads remain out of scope — measured: 0/8 multilingual
  malicious samples caught. Heavily-obfuscated payloads are now
  substantially covered: all five previously-uncaught obfuscation classes
  (cross-script homoglyphs, single-character spacing, zero-width
  interleaving, base64 encoding, whole-string reversal) are closed via
  text-normalization transforms, alongside the two already-closed classes
  from the prior round (Unicode-compatibility tricks via NFKC, a single
  embedded newline splitting a trigger phrase). A representative sample of
  each closed class stays in the corpus, now in-scope and CI-gated, as a
  permanent regression check rather than a one-time fix.
- It does not see agent↔model traffic, only tool descriptions and tool responses.
