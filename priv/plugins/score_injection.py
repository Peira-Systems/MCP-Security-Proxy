#!/usr/bin/env python3
"""
Measures the prompt-injection ruleset (injection_rules.json) against the
labelled corpus (corpus/injection_corpus.jsonl) and enforces a budget (M4.3).

    python3 priv/plugins/score_injection.py

Exit non-zero if recall or the false-positive rate is outside budget. Wired
into CI (.github/workflows/ci.yml). See docs/injection-detection.md.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "corpus", "injection_corpus.jsonl")

# Budget. Tighten as the ruleset improves; loosening needs a note in the PR.
MIN_RECALL = 0.85          # catch at least 85% of known injections
MAX_FP_RATE = 0.05         # at most 5% of benign samples misflagged
MIN_PRECISION = 0.90       # of everything flagged, at least 90% is a real hit

sys.path.insert(0, HERE)
from prompt_injection_scanner import is_injection, scan_text, RULESET_VERSION  # noqa: E402


def load_corpus(path=CORPUS):
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main():
    rows = load_corpus()
    tp = fp = tn = fn = 0
    misses, false_alarms = [], []

    for row in rows:
        flagged = is_injection(row["text"])
        malicious = row["label"] == "malicious"
        if malicious and flagged:
            tp += 1
        elif malicious and not flagged:
            fn += 1
            misses.append(row)
        elif not malicious and flagged:
            fp += 1
            hit = scan_text(row["text"])[0]["id"]
            false_alarms.append((row["text"], hit))
        else:
            tn += 1

    mal = tp + fn
    ben = tn + fp
    recall = tp / mal if mal else 1.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    fp_rate = fp / ben if ben else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    print(f"ruleset {RULESET_VERSION} vs {len(rows)} labelled samples "
          f"({mal} malicious, {ben} benign)")
    print(f"  recall     {recall:.3f}  (budget >= {MIN_RECALL})   [{tp}/{mal} caught]")
    print(f"  precision  {precision:.3f}  (budget >= {MIN_PRECISION})")
    print(f"  fp rate    {fp_rate:.3f}  (budget <= {MAX_FP_RATE})   [{fp}/{ben} benign misflagged]")
    print(f"  f1         {f1:.3f}")

    if misses:
        print("\n  missed injections:")
        for m in misses:
            print(f"    - [{m['category']}] {m['text'][:90]}")
    if false_alarms:
        print("\n  false alarms:")
        for text, rule in false_alarms:
            print(f"    - ({rule}) {text[:90]}")

    ok = recall >= MIN_RECALL and fp_rate <= MAX_FP_RATE and precision >= MIN_PRECISION
    print("\nRESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
