#!/usr/bin/env python3
"""
Regression test pinning the exact similarity-layer numbers measured
during this plan's design research (2026-10-05 plan). If this fails,
something about the encoding routine, the reference set, or the
threshold has drifted from what was actually measured and calibrated --
investigate before changing this test's expected values, not instead of.

    python3 priv/plugins/test_similarity_calibration.py
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from prompt_injection_scanner import scan_text  # noqa: E402

CORPUS = os.path.join(HERE, "corpus", "injection_corpus.jsonl")


def load_corpus():
    rows = []
    with open(CORPUS, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def test_similarity_layer_catches_exactly_10_of_23_target_rows():
    rows = load_corpus()
    out_of_scope = [r for r in rows if r.get("scope") == "out_of_scope"]
    assert len(out_of_scope) == 23, (
        f"expected 23 out-of-scope rows, found {len(out_of_scope)} -- "
        "the corpus has changed since this plan's calibration; re-run "
        "the full sweep in the design spec before updating this test"
    )
    caught_by_similarity = 0
    for row in out_of_scope:
        hits = scan_text(row["text"])
        if hits and hits[0]["id"] == "similarity-match":
            caught_by_similarity += 1
    assert caught_by_similarity == 10, (
        f"expected similarity layer to catch exactly 10/23, caught "
        f"{caught_by_similarity} -- investigate before adjusting this "
        f"number, since every other figure in the design spec was "
        f"calibrated against 10/23"
    )


def test_similarity_layer_introduces_zero_false_positives():
    rows = load_corpus()
    benign = [r for r in rows if r.get("label") == "benign"]
    assert len(benign) == 70, (
        f"expected 70 benign rows, found {len(benign)} -- the corpus "
        "has grown; re-run the calibration sweep before updating this test"
    )
    false_positives = 0
    for row in benign:
        hits = scan_text(row["text"])
        if hits and hits[0]["id"] == "similarity-match":
            false_positives += 1
    assert false_positives == 0, (
        f"expected 0 false positives from the similarity layer on the "
        f"benign corpus, got {false_positives} -- this means the 0.605 "
        f"threshold no longer holds at zero FP; do not loosen this test, "
        f"investigate the regression"
    )


def main():
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for test in tests:
        test()
        print(f"PASS: {test.__name__}")
    print(f"\n{len(tests)} tests passed.")


if __name__ == "__main__":
    main()
