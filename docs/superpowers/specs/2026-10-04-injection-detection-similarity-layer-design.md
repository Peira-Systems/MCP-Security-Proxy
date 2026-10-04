# Injection detection: similarity layer — design spec

Date: 2026-10-04

## Problem

The regex-based injection scanner (`docs/injection-detection.md`) plus the
normalization-closure transforms (confusables-folding, zero-width-stripping,
spacing-stripping, base64-decoding, reversal — `2026-10-04-injection-detection-normalization-closure-design.md`)
together close 5 of 28 previously out-of-scope corpus rows. 23 remain
uncaught, all genuinely semantic/translation problems no text transform can
recover: 15 paraphrase rows (different English wording, same meaning) and
8 multilingual rows (same meaning, different language — Spanish, French,
German, Portuguese, Italian, Chinese, Japanese).

This spec adds a third detection stage — a statistical similarity check —
specifically targeting those 23 rows. It runs only after the existing
rule-matching and transform-expansion stages find nothing, preserving the
existing stages' explainability and zero false-positive track record
unchanged.

## Why not a trained classifier

The labelled corpus is 147 rows total (124 in-scope + 23 out-of-scope as of
this writing). This is far too small to train a classifier that
generalizes — a model fit on ~49 malicious examples would memorize this
specific corpus's phrasing, not learn a transferable notion of "injection
attack." The approach that is honest about this data size is **nearest-
neighbor similarity**: vectorize a fixed set of known-malicious reference
examples once, and for new text, check whether it is textually similar to
any of them. This is explicitly not a claim of learned semantic
understanding — it is nearest-neighbor retrieval against a small,
hand-authored reference set, and its coverage is bounded by what that
reference set contains.

## Approach

### Technique

`sklearn.feature_extraction.text.TfidfVectorizer(analyzer="char", ngram_range=(3, 5))`
fit once, at sidecar startup, against a reference set of malicious example
texts. Character n-grams (not word tokens) are used because:
- They require no per-language word-boundary logic — word-level
  tokenization assumes whitespace-delimited words, which doesn't hold for
  Chinese or Japanese.
- They are more tolerant of minor spelling/morphological variation than
  exact word matching.

For an input string that reached this stage (meaning no rule and no
transform-expanded candidate matched it), vectorize it with the same fitted
vectorizer and compute cosine similarity
(`sklearn.metrics.pairwise.cosine_similarity`) against every row of the
fitted reference matrix. The highest-scoring reference, if its score meets
the calibrated threshold (see Calibration below), produces a finding.

### Reference corpus

New file: `priv/plugins/corpus/similarity_references.jsonl`, containing
only the new, hand-authored translated reference examples described
below — not a copy of the 49 existing in-scope malicious examples.

`load_similarity_references` (see Scanner integration) builds its
in-memory reference set at import time by concatenating two sources:
1. Every row from `injection_corpus.jsonl` where `label == "malicious"`
   and `scope != "out_of_scope"` (the 49 existing in-scope malicious
   examples), read directly from that file at startup — never duplicated
   into a second file, so the two stay in sync automatically as the main
   corpus grows.
2. Every row from the new `similarity_references.jsonl` — 2–3 varied
   phrasings per language for each of the 7 languages represented in the
   existing multilingual corpus rows (Spanish, French, German, Portuguese,
   Italian, Chinese, Japanese), covering the same attack categories
   present in those rows (`instruction_override`, `secrecy`,
   `exfiltration`). This file holds only new content — translated
   phrasings that don't already exist anywhere else in the repo.

This means `build_similarity_index` takes both file paths and merges the
two lists before fitting the vectorizer — not just the new file alone.

Row shape: `{"text": "...", "category": "...", "language": "..."}` — the
`language` field is informational (helps a human auditing the reference
set), not used by the matching logic itself (cosine similarity doesn't
care what language a reference is in).

### Honest limit on multilingual coverage

Adding 2–3 translated references per language gives the similarity check
something to match against in that language, but it is still nearest-
neighbor similarity to specific phrasings, not translation or semantic
understanding. A new attack in, say, Spanish, phrased very differently
from all 2–3 Spanish references, will likely still be missed — the same
limitation paraphrase detection has in English, just with a much thinner
reference set per language. This is a measured improvement over zero
multilingual coverage, not comprehensive multilingual detection, and the
spec and docs must say so plainly rather than imply broader coverage than
this technique can deliver.

### Scanner integration

New functions in `priv/plugins/prompt_injection_scanner.py`:

- `load_similarity_references(corpus_path, references_path)` — reads
  `injection_corpus.jsonl` (`corpus_path`) and keeps only rows where
  `label == "malicious"` and `scope != "out_of_scope"`; reads
  `similarity_references.jsonl` (`references_path`) in full; returns the
  concatenation as a list of `{"text": ..., "category": ..., "language": ...}`
  dicts (rows sourced from the main corpus have `"language": "en"`, since
  that file has no `language` field of its own). Mirrors `load_rules`'s
  existing loading pattern.
- `build_similarity_index(references)` — fits
  `TfidfVectorizer(analyzer="char", ngram_range=(3, 5))` on the reference
  texts, returns `(vectorizer, reference_matrix, references)`. Called once
  at module load time, the same pattern as the existing
  `RULES, RULESET_VERSION = load_rules()` at module scope. If the
  `sklearn`/`scipy` import itself fails, this must propagate as an
  unhandled exception at import time — the sidecar process exits
  non-zero and never reaches its stdio read loop, which the supervising
  `SidecarRunner`/`Provenance` layer already treats as a startup failure
  (fail loudly, not a graceful degrade to rule-only detection).
- `check_similarity(text, vectorizer, reference_matrix, references, threshold)`
  — vectorizes `text` with the fitted vectorizer, computes cosine
  similarity against every reference row, returns
  `{"reference_text": ..., "category": ..., "score": ...}` for the
  best match if its score ≥ `threshold`, else `None`.

`scan_text`'s existing candidate-expansion loop (from the normalization-
closure plan) gets one more stage, tried only if the entire existing loop
(direct match + all 6 transform candidates) produces no hits:

```python
def scan_text(text):
    text = unicodedata.normalize("NFKC", text or "")
    candidates = [("direct", text)]
    # ... existing candidate list unchanged ...
    for transform_name, candidate in candidates:
        hits = _match_rules(candidate)
        if hits:
            return _tag_transform(hits, transform_name)

    similarity_hit = check_similarity(
        text, SIMILARITY_VECTORIZER, SIMILARITY_MATRIX, SIMILARITY_REFERENCES,
        SIMILARITY_THRESHOLD,
    )
    if similarity_hit:
        return [_similarity_finding(similarity_hit)]
    return []
```

(`SIMILARITY_VECTORIZER`/`SIMILARITY_MATRIX`/`SIMILARITY_REFERENCES` are
module-level globals built once via `build_similarity_index` at import
time, the same pattern as `RULES`. `SIMILARITY_THRESHOLD` is a module-level
constant set from the calibration exercise below.)

`_similarity_finding(hit)` builds a finding dict shaped like `_match_rules`'
output, but with:
- `"id": "similarity-match"`
- `"category": hit["category"]`
- `"severity"`: scaled from `hit["score"]` (see Severity below)
- `"confidence": hit["score"]` (the actual cosine similarity, not a fixed
  value — this stage's confidence is inherently continuous, unlike a
  regex match's fixed per-rule confidence)
- `"evidence"`: names which reference example matched and the score, e.g.
  `f"similar to known attack ({hit['category']}, score {hit['score']:.2f}): {hit['reference_text'][:60]}"`
  — an operator seeing this finding can tell why it fired, not just that
  it fired.

### Severity

Cosine similarity score maps to severity, never reaching `critical` (that
tier is reserved for deterministic rule matches):

| Score range | Severity |
|---|---|
| ≥ 0.90 | `high` |
| ≥ 0.80, < 0.90 | `medium` |
| ≥ `SIMILARITY_THRESHOLD`, < 0.80 | `low` |
| < `SIMILARITY_THRESHOLD` | no hit (not reported at all) |

The 0.90/0.80 boundaries and `SIMILARITY_THRESHOLD` itself are placeholders
here — the plan's calibration step (below) replaces them with real numbers
derived from measurement, not guessed.

### Calibration

A one-time script (run during implementation, its result becomes the
committed `SIMILARITY_THRESHOLD` constant — not a permanent CI artifact)
sweeps candidate threshold values against the full existing benign corpus
(70 rows) to find the highest threshold value that still produces zero
false positives on that benign set, then reports the resulting recall on
the 23 target out-of-scope rows at that threshold. This grounds the
threshold in the project's existing zero-FP track record rather than an
arbitrary guess.

### Dependency and deployment impact

This plan adds `scikit-learn` (and its transitive `numpy`/`scipy`
dependencies) to the Python sidecar — the first non-stdlib Python
dependency this project has ever had. Concretely:

- New file: `priv/plugins/requirements.txt` pinning exact versions (not
  loose ranges) for `scikit-learn`, matching this project's exact-pin
  philosophy elsewhere (`mix.lock`, the provenance digests).
- `Dockerfile`'s runtime stage (currently installs bare `python3`, no
  `pip`) needs `python3-pip` added to its `apt-get install` line, plus a
  new `RUN pip3 install --no-cache-dir -r priv/plugins/requirements.txt`
  step (or `pip install --break-system-packages`, depending on the base
  image's externally-managed-environment policy — the implementer must
  check the actual Debian/pip behavior on the pinned base image version
  and use whichever flag that version actually requires, verified by
  building the image, not assumed).
- This is a real, visible change to the deployment footprint, explicitly
  accepted for this plan (per discussion) despite the alternative
  (pure-stdlib char-n-gram similarity, zero new dependencies) being
  available and consistent with the project's existing zero-dependency
  sidecar design. Noted here so a future reader understands this was a
  deliberate tradeoff, not an oversight.

### Provenance pinning

The similarity reference file is security-relevant: if swapped, an
attacker could make the similarity layer stop matching anything, silently
disabling this entire detection layer. Per project convention
(`docs/plugin-supply-chain.md`), it is added as a third pinned `args`
entry — covered by the same `code:` provenance digest as the script and
ruleset, not loaded as a plain unpinned path from inside the script:

```elixir
args: [
  {:priv, "plugins/prompt_injection_scanner.py"},
  {:priv, "plugins/injection_rules.json"},
  {:priv, "plugins/corpus/similarity_references.jsonl"}
],
```

in both `config/dev.exs` (unpinned, as today) and `config/prod.exs`
(pinned — the existing `pin: [code: "sha256:..."]` digest must be
recomputed once all four `args` entries below are final, since it will
cover four files' bytes instead of two). The scanner script's own
`RULES_PATH`-style argv resolution needs a matching convention for both
new file paths — see below.

**`injection_corpus.jsonl` is a new runtime dependency the sidecar did not
previously have** (today, only `score_injection.py` — a separate, offline
scoring script — reads it; the sidecar itself has never opened it before
this plan). Per the same reasoning, this file is equally swappable and
equally capable of silently defeating the similarity layer (an attacker
could replace it with an empty or defanged corpus), so it must ALSO be
added as a fourth pinned `args` entry, not read via the script's own
`os.path.dirname(__file__)`-relative fallback the way `RULES_PATH`'s
default path works today:

```elixir
args: [
  {:priv, "plugins/prompt_injection_scanner.py"},
  {:priv, "plugins/injection_rules.json"},
  {:priv, "plugins/corpus/similarity_references.jsonl"},
  {:priv, "plugins/corpus/injection_corpus.jsonl"}
],
```

`load_similarity_references`'s two path parameters must both be taken
from argv (positions 2 and 3, following the ruleset's existing
`argv[1]` convention) when provided, falling back to script-relative
paths only when run standalone outside the sidecar (e.g. from
`score_injection.py` or a unit test) — matching `RULES_PATH`'s existing
fallback pattern exactly, applied to two paths instead of one.

## Non-goals

- No true multilingual understanding or translation capability — this is
  nearest-neighbor similarity to a small, hand-authored reference set (see
  "Honest limit on multilingual coverage" above).
- No coverage guarantee for attack phrasings, languages, or categories not
  represented in the reference set.
- No attempt to address the base image's broader dependency-management
  surface beyond pinning the two files `code_digest` already covers plus
  the two new files this plan adds (the similarity reference corpus and
  the main labelled corpus) — introducing `pip` itself is an accepted,
  bounded cost of this plan, not a broader supply-chain hardening effort.
- No replacement of the existing regex/transform stages — this is strictly
  additive, tried last, and never overrides or weakens an existing finding.

## Testing strategy

1. Extend the existing scoring script (`score_injection.py` or a close,
   explicitly-named sibling) to report, for each out-of-scope row, which
   stage caught it (rule, transform, similarity, or none) — giving a clear
   measured before/after picture specific to this plan's contribution, not
   just an aggregate pass/fail.
2. The one-time threshold-calibration script described above.
3. Unit tests for `load_similarity_references`/`build_similarity_index`/
   `check_similarity` in isolation, following the same plain-assert-script
   convention as `test_normalization_transforms.py`.
4. Elixir end-to-end regression tests through the real plugin protocol
   (same pattern as the normalization-closure plan's final task),
   including at least one genuine paraphrase case and one genuine
   multilingual case from the target corpus rows.
5. A test that the sidecar actually refuses to start (not just logs a
   warning) when the `sklearn` import is made to fail — verifying the
   fail-loudly behavior is real, not just documented intent.
6. A benign-corpus regression check confirming the new stage introduces
   zero false positives on the existing 70-row benign set, at the
   calibrated threshold.

## Review Focus

- A benign tool response that happens to share vocabulary with a
  malicious reference example (e.g. discussing "ignoring previous
  guidance" in a legitimate documentation context) must not cross the
  calibrated threshold — covered by the calibration sweep and the benign
  regression check.
- The sidecar must fail to start, not silently run with reduced coverage,
  if `scikit-learn` is missing or fails to import — covered by the
  import-failure test.
- A similarity-only finding's `evidence` must name the specific reference
  example and score it matched, not just a bare "similarity match"
  message with no explanation of why — covered by the finding-shape
  requirement above.
- The provenance pin in `config/prod.exs` must be recomputed to cover all
  four files (script, ruleset, similarity reference corpus, main labelled
  corpus) — a stale pin here would be invisible to `mix test`'s dev-config
  run, the same class of gap found and fixed twice during the
  normalization-closure plan's execution.
- `requirements.txt`'s pinned `scikit-learn` version must actually install
  cleanly on the pinned Debian base image version in a real Docker build
  — not just assumed to work from the package name alone, since this is
  the project's first time adding a pip dependency to this image.
