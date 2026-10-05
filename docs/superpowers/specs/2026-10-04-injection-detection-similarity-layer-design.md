# Injection detection: similarity layer — design spec

Date: 2026-10-04 (revised 2026-10-05 after calibration invalidated the
original TF-IDF approach — see "Why not TF-IDF" below)

## Problem

The regex-based injection scanner (`docs/injection-detection.md`) plus the
normalization-closure transforms (confusables-folding, zero-width-stripping,
spacing-stripping, base64-decoding, reversal — `2026-10-04-injection-detection-normalization-closure-design.md`)
together close 5 of 28 previously out-of-scope corpus rows. 23 remain
uncaught, all genuinely semantic/translation problems no text transform can
recover: 15 paraphrase rows (different English wording, same meaning) and
8 multilingual rows (same meaning, different language — Spanish, French,
German, Portuguese, Italian, Chinese, Japanese).

This spec adds a third detection stage — a semantic similarity check —
specifically targeting those 23 rows. It runs only after the existing
rule-matching and transform-expansion stages find nothing, preserving the
existing stages' explainability and zero false-positive track record
unchanged.

## Why not TF-IDF

The original version of this spec proposed character-n-gram TF-IDF cosine
similarity (pure lexical matching) against the corpus's own 54 in-scope
malicious examples. Before writing any task against that design, it was
measured directly against the real corpus using the project's actual
labelled data (`priv/plugins/corpus/injection_corpus.jsonl`, 54 in-scope
malicious rows as references, 23 target out-of-scope rows, 70 benign rows):

- At the only threshold producing zero false positives (0.41), it caught
  **0 of 23** target rows.
- The single highest-scoring benign row ("Lists environment variables
  that start with the given prefix...", score 0.403) scored *higher*
  than 21 of the 23 actual attack rows (scores ranged 0.16–0.39).
- Four other TF-IDF parameter variants (different character-n-gram
  ranges, word-level unigrams/bigrams) were also measured; none caught
  more than 2/23 at zero false positives.

This is not a threshold-tuning problem. The project's 70-row benign corpus
deliberately includes security-adjacent technical text ("environment
variables," "developer mode," "API key," "system prompt") as near-misses,
and that is exactly the vocabulary genuine attacks also use — lexical
(word- or character-based) similarity cannot separate the two on this
corpus at any threshold. TF-IDF is abandoned; see "Why real embeddings"
below for the approach that replaced it, verified against the same
real data before being written into this spec.

## Why real embeddings (and why ONNX, not the full PyTorch stack)

A semantic sentence-embedding model — `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2`,
a small (118M-parameter) multilingual model purpose-built for cross-
lingual paraphrase similarity — was measured against the identical
corpus, references, and procedure as the TF-IDF test above:

- At threshold **0.605**, it catches **10 of 23** target rows with
  **zero false positives** (max benign score 0.604, just under the
  threshold).
- This includes multilingual rows TF-IDF could never reach in principle
  (lexical similarity to English-only references cannot match non-English
  text; semantic embeddings place translations of the same meaning close
  together in vector space regardless of surface form).
- Per-call latency: ~8–13ms, trivial against the sidecar's 800ms budget.

This is a real, measured result, not a projection — but the full
`sentence-transformers` library pulls in PyTorch as a transitive
dependency, which measured **1.2GB** on disk for `torch` alone, plus
~116MB for `transformers`. This is far outside what was scoped earlier in
this project's discussion ("lightweight only... no model weights to
download... no transformer runtime").

Before accepting that cost, a **verified** lighter alternative was built
and cross-checked: the same model, already published in ONNX format on
the HuggingFace Hub (`sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2/onnx/model.onnx`),
run through `onnxruntime` with a small hand-written tokenization +
mean-pooling + L2-normalization routine replacing the
`sentence-transformers` library's internals. This was verified, not
assumed:

- Cosine agreement between the ONNX-path embeddings and the original
  `sentence-transformers`-path embeddings: **1.00000** (bit-identical,
  to 5 decimal places) across English and German test sentences.
- Re-running the full corpus calibration through the ONNX path reproduced
  the **exact same result**: 10/23 caught at threshold 0.605, 0/70 false
  positives.
- Runtime dependency footprint: `onnxruntime` + `tokenizers` + `numpy` =
  **~122MB measured on disk**, zero PyTorch.
- Latency with the ONNX path: ~12.7ms/call — comparable to the PyTorch
  path, still trivial against budget.

The model weights themselves are unavoidable either way — the ONNX
export is ~470MB, essentially the same as the native format — only the
*runtime* around them shrinks. Total new footprint: **~590MB** (122MB
runtime + ~470MB model files), versus ~1.8GB for the full PyTorch-based
stack. This is still the single largest dependency this project has ever
taken on, and is accepted here as the real, measured cost of the only
approach that actually works on this corpus — explicitly not "lightweight"
in the sense originally scoped, and that framing should not be revived
for this plan.

## Approach

### Technique

1. At sidecar startup, load `model.onnx` into an `onnxruntime.InferenceSession`
   and `tokenizer.json` into a `tokenizers.Tokenizer`.
2. Encode the 54 in-scope malicious reference texts once, producing a
   fixed `(54, 384)` reference embedding matrix (384 is this model's
   output dimension).
3. For an input string that reached this stage (meaning no rule and no
   transform-expanded candidate matched it — see Scanner integration),
   encode it the same way and compute cosine similarity (dot product,
   since embeddings are L2-normalized) against every row of the
   reference matrix. The highest-scoring reference, if its score meets
   `SIMILARITY_THRESHOLD = 0.605`, produces a finding.

### Encoding routine (must reproduce `sentence-transformers` exactly)

This is the part most likely to be gotten subtly wrong — the model's
published usage examples all go through the full `sentence-transformers`
library, which hides the tokenization/pooling details this plan must
reimplement by hand. The exact, verified routine:

```python
def mean_pooling(token_embeddings, attention_mask):
    mask = attention_mask[..., None].astype(np.float32)
    summed = (token_embeddings * mask).sum(axis=1)
    counts = np.clip(mask.sum(axis=1), a_min=1e-9, a_max=None)
    return summed / counts

def encode(texts, session, tokenizer):
    encoded = tokenizer.encode_batch(texts)
    max_len = max(len(e.ids) for e in encoded)
    input_ids = np.array(
        [e.ids + [0] * (max_len - len(e.ids)) for e in encoded], dtype=np.int64
    )
    attention_mask = np.array(
        [e.attention_mask + [0] * (max_len - len(e.attention_mask)) for e in encoded],
        dtype=np.int64,
    )
    token_type_ids = np.zeros_like(input_ids)
    outputs = session.run(
        None,
        {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "token_type_ids": token_type_ids,
        },
    )
    pooled = mean_pooling(outputs[0], attention_mask)
    norms = np.linalg.norm(pooled, axis=1, keepdims=True)
    return pooled / np.clip(norms, a_min=1e-9, a_max=None)
```

The `tokenizer` must be configured with `enable_padding()` and
`enable_truncation(max_length=128)` before use (128 matches this model's
trained sequence length; longer inputs are truncated, which is
acceptable here since this stage only ever receives already-NFKC-
normalized tool descriptions/responses, the same inputs the existing
rule stage already handles at full length via regex, not something newly
exposed to length limits).

### Model and tokenizer files

Two new binary/large files, **not committed to git** (470MB and 9MB are
both far too large for a repo that has never carried large binaries) —
fetched at Docker build time instead, the same way `mix deps.get`/`curl`
already fetch other build-time artifacts in this project's existing
`Dockerfile`:

- `model.onnx` — fetched from
  `https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2/resolve/main/onnx/model.onnx`.
  Verified size: 470,301,610 bytes. Verified checksum:
  `sha256:10f7a088420252b26caf819236ca2c9d2987afd0fc06fec7553b542a5655a05a`.
- `tokenizer.json` — fetched from
  `https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2/resolve/main/tokenizer.json`.
  Verified size: 9,081,518 bytes. Verified checksum:
  `sha256:2c3387be76557bd40970cec13153b3bbf80407865484b209e655e5e4729076b8`.

Both checksums were computed directly against a real download during
this spec's own verification, not copied from a third-party source —
re-verify them once more during implementation in case the upstream file
changes before this plan lands, and update the pinned hashes here if so
(do not silently proceed if the downloaded file's hash doesn't match
what's pinned — that is exactly the tampered/stale-mirror scenario this
check exists to catch).

The Dockerfile step downloads both files to `priv/plugins/model/` (a new
directory) during the build, verifies each against its pinned SHA256
immediately after download, and fails the build on mismatch — the same
integrity principle as this project's existing provenance pins, applied
to a build-time fetch instead of a runtime-loaded file. Local development
(`config/dev.exs`) needs the same two files present on disk; the plan's
tasks must include a one-time local setup step (a small shell script or
documented `curl` command) so a developer isn't blocked trying to run
`mix test` without first fetching ~480MB of model files — this should be
gitignored, not committed, matching how `deps/`/`_build/` are already
gitignored build artifacts.

### Reference examples

No new reference-text file is needed (unlike the abandoned TF-IDF
design, which added hand-authored translated phrasings). The embedding
model is already multilingual and was measured catching multilingual
target rows using only the existing 54 in-scope **English** malicious
examples as references — translations aren't needed for the model to
recognize semantic similarity across languages. `load_similarity_references`
reads only `injection_corpus.jsonl`, keeping rows where
`label == "malicious"` and `scope != "out_of_scope"`:

```python
def load_similarity_references(corpus_path):
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
```

### Scanner integration

New functions in `priv/plugins/prompt_injection_scanner.py`:

- `load_similarity_references(corpus_path)` — above.
- `build_similarity_index(model_path, tokenizer_path, references)` —
  loads the ONNX session and tokenizer, encodes the reference texts
  once via `encode()` (above), returns
  `(session, tokenizer, reference_matrix, references)`. Called once at
  module load time, the same pattern as the existing
  `RULES, RULESET_VERSION = load_rules()`. If `onnxruntime`/`tokenizers`/
  `numpy` fail to import, or the model/tokenizer files are missing or
  fail their checksum (checked again at load time, not only at Docker
  build time, so a corrupted or swapped file is caught even if the
  Docker build step was somehow bypassed), this must propagate as an
  unhandled exception at import time — the sidecar process exits
  non-zero and never reaches its stdio read loop, which the supervising
  `SidecarRunner`/`Provenance` layer already treats as a startup failure
  (fail loudly, not a graceful degrade to rule-only detection).
- `check_similarity(text, session, tokenizer, reference_matrix, references, threshold)`
  — encodes `text` with `encode()`, computes cosine similarity (dot
  product against the L2-normalized reference matrix) against every
  reference row, returns `{"reference_text": ..., "category": ..., "score": ...}`
  for the best match if its score ≥ `threshold`, else `None`.

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
        text, SIMILARITY_SESSION, SIMILARITY_TOKENIZER, SIMILARITY_MATRIX,
        SIMILARITY_REFERENCES, SIMILARITY_THRESHOLD,
    )
    if similarity_hit:
        return [_similarity_finding(similarity_hit)]
    return []
```

(`SIMILARITY_SESSION`/`SIMILARITY_TOKENIZER`/`SIMILARITY_MATRIX`/
`SIMILARITY_REFERENCES` are module-level globals built once via
`build_similarity_index` at import time, the same pattern as `RULES`.
`SIMILARITY_THRESHOLD = 0.605` is a module-level constant — already
measured, not a placeholder.)

`_similarity_finding(hit)` builds a finding dict shaped like
`_match_rules`' output, but with:
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
tier is reserved for deterministic rule matches). The measured target
score range is 0.605 (threshold) to 0.856 (the highest-scoring target
row); bands are placed to spread that real range across three tiers
rather than clustering everything into one:

| Score range | Severity |
|---|---|
| ≥ 0.75 | `high` |
| ≥ 0.65, < 0.75 | `medium` |
| ≥ 0.605 (`SIMILARITY_THRESHOLD`), < 0.65 | `low` |
| < 0.605 | no hit (not reported at all) |

### File layout and model-loading paths

```
priv/plugins/
  prompt_injection_scanner.py
  injection_rules.json
  corpus/
    injection_corpus.jsonl
  model/                              # new, gitignored
    model.onnx
    tokenizer.json
```

`build_similarity_index`'s `model_path`/`tokenizer_path` parameters
follow the same argv-or-fallback convention as `RULES_PATH`: taken from
`sys.argv[2]`/`sys.argv[3]` when the sidecar is launched with them
(covered by the provenance pin, see below), falling back to
`priv/plugins/model/model.onnx` / `priv/plugins/model/tokenizer.json`
(script-relative) when run standalone — e.g. from `score_injection.py`
or a unit test, neither of which pass sidecar-style argv.

### Dependency and deployment impact

New Python dependencies: `onnxruntime`, `tokenizers`, `numpy` — ~122MB
measured on disk, the first non-stdlib Python dependencies this project
has ever had. Concretely:

- New file: `priv/plugins/requirements.txt` pinning exact versions (not
  loose ranges), matching this project's exact-pin philosophy elsewhere
  (`mix.lock`, the provenance digests).
- `Dockerfile`'s runtime stage (currently installs bare `python3`, no
  `pip`) needs `python3-pip` added to its `apt-get install` line, a new
  `RUN pip3 install --no-cache-dir -r priv/plugins/requirements.txt`
  step (or `pip install --break-system-packages`, depending on the
  pinned base image's externally-managed-environment policy — verified
  by building the image during implementation, not assumed), and a new
  step downloading and checksum-verifying `model.onnx`/`tokenizer.json`
  into `priv/plugins/model/`.
- CI (`.github/workflows/ci.yml`) also needs these Python packages
  installed and the model files fetched before any step that imports
  `prompt_injection_scanner` runs `scan_text` — today's CI runner has
  no pip-install step at all for the sidecar's Python code; this plan
  adds the first one. Concretely, two new steps must run in the `test`
  job, placed before the existing "Injection ruleset score" step (which
  already imports and calls `scan_text` indirectly via `is_injection`,
  and will start failing the moment this plan's code lands if these
  steps aren't added first):
  ```yaml
      - name: Install sidecar Python dependencies
        run: pip3 install --break-system-packages --no-cache-dir -r priv/plugins/requirements.txt

      - name: Fetch and verify similarity model files
        run: |
          mkdir -p priv/plugins/model
          curl -sL -o priv/plugins/model/model.onnx \
            https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2/resolve/main/onnx/model.onnx
          curl -sL -o priv/plugins/model/tokenizer.json \
            https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2/resolve/main/tokenizer.json
          echo "10f7a088420252b26caf819236ca2c9d2987afd0fc06fec7553b542a5655a05a  priv/plugins/model/model.onnx" | sha256sum -c -
          echo "2c3387be76557bd40970cec13153b3bbf80407865484b209e655e5e4729076b8  priv/plugins/model/tokenizer.json" | sha256sum -c -
  ```
  (The `--break-system-packages` flag matches whatever the Dockerfile's
  own pip-install step above ends up using once verified against the
  real base image — keep the two in sync, or note explicitly if CI's
  runner and the Docker base image need different flags.) This CI job
  downloads ~480MB on every run; if this becomes a real time/bandwidth
  problem, caching the model files via `actions/cache@v4` keyed on the
  pinned checksums (the same cache action already used for `deps`/
  `_build` just above in this same file) is the natural follow-up, but
  is not required for this plan to land — note it as a possible later
  optimization, not a blocking requirement.
- This ~590MB total footprint is explicitly accepted for this plan, per
  the measured results above — the pure-stdlib and TF-IDF alternatives
  were both tried first and don't work on this corpus at any acceptable
  false-positive rate.

### Provenance pinning

`model.onnx` and `tokenizer.json` are security-relevant: if either is
swapped (or simply absent, with the sidecar somehow still starting), an
attacker could make the similarity layer stop matching anything, or
match arbitrarily, silently disabling or corrupting this detection
layer. Per project convention (`docs/plugin-supply-chain.md`), both are
added as pinned `args` entries — covered by the same `code:` provenance
digest as the script and ruleset, not loaded as plain unpinned paths:

```elixir
args: [
  {:priv, "plugins/prompt_injection_scanner.py"},
  {:priv, "plugins/injection_rules.json"},
  {:priv, "plugins/model/model.onnx"},
  {:priv, "plugins/model/tokenizer.json"}
],
```

in both `config/dev.exs` (unpinned, as today) and `config/prod.exs`
(pinned — the existing `pin: [code: "sha256:..."]` digest must be
recomputed once these `args` entries are final, since it will cover
four files' bytes instead of two; recomputing a digest over a 470MB
file is slower than the existing two-file digest, but still a one-time
build-time operation, not a per-request cost).

`injection_corpus.jsonl` (used as the reference-embedding source) is
**not** added as a pinned argv entry — unlike the abandoned TF-IDF
design, this file is read only once at startup to build
`SIMILARITY_REFERENCES`/`SIMILARITY_MATRIX` from already-public,
already-committed-to-git example texts (the same corpus `score_injection.py`
already reads unpinned). Swapping it would at most degrade which known
attacks the layer recognizes, not defeat the model itself the way a
swapped model file would — a materially smaller risk than the model/
tokenizer files, and already covered by this file being under version
control and subject to the same PR review as any other code change.

## Non-goals

- No coverage guarantee for attack phrasings, languages, or categories
  the model wasn't trained to represent well — 13 of the 23 target rows
  remain uncaught even with this layer (see the measured 10/23 result);
  this is a real, bounded improvement, not comprehensive coverage.
- No attempt to shrink the ~470MB model file itself — quantization,
  distillation, or a smaller model are out of scope for this plan; the
  model and threshold used here are the ones actually measured against
  this corpus, and swapping either without re-measuring would invalidate
  the accepted false-positive guarantee.
- No attempt to address the base image's broader dependency-management
  surface beyond this plan's own two new files (model, tokenizer) and
  three new Python packages — introducing `pip` itself, and a ~590MB
  footprint, are accepted, bounded costs of this plan, not a broader
  supply-chain hardening effort.
- No replacement of the existing regex/transform stages — this is
  strictly additive, tried last, and never overrides or weakens an
  existing finding.

## Testing strategy

1. Extend the existing scoring script (`score_injection.py` or a close,
   explicitly-named sibling) to report, for each out-of-scope row, which
   stage caught it (rule, transform, similarity, or none) — giving a
   clear measured picture of this plan's actual contribution (10 more
   rows caught), not just an aggregate pass/fail.
2. A regression test pinning the exact measured numbers from this spec
   (threshold 0.605, 10/23 caught, 0/70 false positives) against the
   real corpus — if this plan's implementation doesn't reproduce these
   exact figures, that's a signal something in the encoding routine (the
   part most likely to drift from the verified reference implementation
   above) doesn't match what was actually measured.
3. Unit tests for `load_similarity_references`/`build_similarity_index`/
   `check_similarity`/`encode` in isolation, following the same
   plain-assert-script convention as `test_normalization_transforms.py`.
   Must include a test asserting the ONNX-path embedding for a fixed
   test sentence matches a pinned expected vector (or a pinned
   similarity score against a fixed reference) to a tight tolerance —
   this is the test that would catch a future accidental change to the
   encoding routine silently drifting from the verified implementation.
4. Elixir end-to-end regression tests through the real plugin protocol
   (same pattern as the normalization-closure plan's final task),
   including at least one of the 10 genuinely-caught paraphrase/
   multilingual rows and confirming at least one of the 13 genuinely-
   uncaught rows is correctly still not flagged (so this layer's honest
   limit is pinned by a test, not just asserted in prose).
5. A test that the sidecar actually refuses to start (not just logs a
   warning) when the model/tokenizer files are missing, corrupted, or
   fail checksum verification — verifying the fail-loudly behavior is
   real, not just documented intent.
6. A benign-corpus regression check confirming the new stage introduces
   zero false positives on the existing 70-row benign set, at the
   committed threshold (0.605) — this is a direct re-run of the
   calibration exercise from this spec, not a new one.

## Review Focus

- A benign tool response that happens to be semantically close to a
  known attack phrase (not just lexically — the point of using
  embeddings) must not cross the 0.605 threshold — covered by the
  benign regression check (item 6 above), using the exact same corpus
  and threshold this spec's own calibration was measured against.
- The sidecar must fail to start, not silently run with reduced
  coverage, if the ONNX runtime, model file, or tokenizer file is
  missing, corrupted, or fails checksum verification — covered by the
  import/load-failure test (item 5 above).
- A similarity-only finding's `evidence` must name the specific
  reference example and score it matched, not just a bare "similarity
  match" message with no explanation of why — covered by the
  finding-shape requirement above.
- The provenance pin in `config/prod.exs` must be recomputed to cover
  all four pinned files (script, ruleset, model, tokenizer) — a stale
  pin here would be invisible to `mix test`'s dev-config run, the same
  class of gap found and fixed twice during the normalization-closure
  plan's execution.
- The hand-written encoding routine (tokenization + mean-pooling +
  normalization) must exactly reproduce `sentence-transformers`'
  output, not merely "look reasonable" — covered by the pinned-vector/
  pinned-score unit test (item 3 above), since a subtly wrong pooling
  implementation would silently produce different (and unmeasured,
  unvalidated) similarity scores than everything calibrated in this
  spec.
