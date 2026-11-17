#!/usr/bin/env python3
"""Score a jsonl with a packaged ensemble on CPU, as the engine does (runs on 77).

The input is prepare_ft_data.py output (id, text, label, group), e.g. the
red-team export, which stays on 77. Each member is scored with ONNX Runtime
(intent_parity_cases.Member: same prefix and head+tail truncation as the
engine); the score is the equal-weight mean of dev-standardised logits from
ensemble.json. Reports AUC, and recall/FPR at the packaged dev threshold and
at the benign FPR 1%/5% cuts of this set (descriptive only: choosing a
threshold on an evaluation set is not an independent estimate). Writes only
ids, labels and scores, never text.
"""

import argparse
from concurrent.futures import ProcessPoolExecutor
import json
from pathlib import Path

import numpy as np

from intent_parity_cases import Member

MEMBERS = {}


def init(package, threads):
    spec = json.loads((Path(package) / "ensemble.json").read_text())
    for m in spec["members"]:
        MEMBERS[m["name"]] = (Member(Path(package) / m["dir"], threads), m["dev_mean"], m["dev_std"])


def score(text):
    return sum((member.logit(text) - mean) / std for member, mean, std in MEMBERS.values()) / len(MEMBERS)


def auc(scores, labels):
    order = np.argsort(scores, kind="mergesort")
    ranks = np.empty(len(scores))
    ranks[order] = np.arange(1, len(scores) + 1)
    for value in np.unique(scores):  # average ranks of ties
        tied = scores == value
        if tied.sum() > 1:
            ranks[tied] = ranks[tied].mean()
    pos = labels == 1
    return float((ranks[pos].sum() - pos.sum() * (pos.sum() + 1) / 2) / (pos.sum() * (~pos).sum()))


def at(scores, labels, tau):
    flagged = scores > tau
    return {"threshold": round(float(tau), 4), "recall": round(float(flagged[labels == 1].mean()), 4),
            "fpr": round(float(flagged[labels == 0].mean()), 4),
            "accuracy": round(float((flagged == (labels == 1)).mean()), 4)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--eval", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--threads", type=int, default=2, help="intra-op threads per member per worker")
    args = parser.parse_args()
    spec = json.loads((args.package / "ensemble.json").read_text())
    rows = [json.loads(line) for line in open(args.eval, encoding="utf-8") if line.strip()]
    rows = [r for r in rows if r["label"] in (0, 1)]
    with ProcessPoolExecutor(args.workers, initializer=init, initargs=(str(args.package), args.threads)) as pool:
        scores = np.array(list(pool.map(score, [r["text"] for r in rows], chunksize=8)))
    labels = np.array([r["label"] for r in rows])
    benign = np.sort(scores[labels == 0])
    report = {"package": spec["model_version"], "eval": args.eval.name, "n": len(rows),
              "malicious": int(labels.sum()), "auc": round(auc(scores, labels), 4),
              "at_package_threshold": at(scores, labels, spec["threshold"]),
              "at_set_fpr1": at(scores, labels, benign[int(np.ceil(len(benign) * 0.99)) - 1]),
              "at_set_fpr5": at(scores, labels, benign[int(np.ceil(len(benign) * 0.95)) - 1]),
              "score_quantiles": {q: round(float(np.quantile(scores, q / 100)), 3) for q in (5, 25, 50, 75, 95)},
              "scores": [{"id": r["id"], "label": r["label"], "score": round(float(s), 5)} for r, s in zip(rows, scores)]}
    args.output.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "scores"}, ensure_ascii=False))


if __name__ == "__main__":
    main()
