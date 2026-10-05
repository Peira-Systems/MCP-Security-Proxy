#!/usr/bin/env python3
"""
Semantic similarity encoding for the prompt-injection scanner's
similarity-layer detection stage (2026-10-05 plan). Wraps a pre-exported
ONNX model (paraphrase-multilingual-MiniLM-L12-v2) with a hand-written
tokenization + mean-pooling + L2-normalization routine, reproducing
sentence-transformers' own output exactly (verified bit-identical
during spec research: cosine agreement 1.00000) without requiring
PyTorch or the sentence-transformers/transformers libraries.

See docs/superpowers/specs/2026-10-04-injection-detection-similarity-layer-design.md
for the full design rationale, including why TF-IDF (tried first) does
not work on this project's corpus.
"""

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer


def load_similarity_model(model_path, tokenizer_path):
    """Loads the ONNX session and tokenizer. Raises if either file is
    missing or malformed -- this must propagate as an unhandled
    exception at sidecar import time, not be caught here, so the
    sidecar fails loudly rather than silently degrading to rule-only
    detection (see this plan's Global Constraints)."""
    session = ort.InferenceSession(model_path)
    tokenizer = Tokenizer.from_file(tokenizer_path)
    tokenizer.enable_padding()
    tokenizer.enable_truncation(max_length=128)
    return session, tokenizer


def mean_pooling(token_embeddings, attention_mask):
    mask = attention_mask[..., None].astype(np.float32)
    summed = (token_embeddings * mask).sum(axis=1)
    counts = np.clip(mask.sum(axis=1), a_min=1e-9, a_max=None)
    return summed / counts


def encode(texts, session, tokenizer):
    """Returns an L2-normalized (N, 384) embedding matrix for the given
    texts. Cosine similarity between two outputs reduces to a plain dot
    product, since both are already unit vectors."""
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
