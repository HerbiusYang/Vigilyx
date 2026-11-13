#!/usr/bin/env python3
"""Out-of-fold accuracy over all data from k fold runs (training server).

Each fold run must have accuracy_scores.npz from report_accuracy.py. Every
record is scored by the one fold model that held it out, at that fold's dev
1%-FPR threshold, so the pooled result covers the whole dataset with no record
scored by a model that trained on it. Reports overall, per source/language
group, per synthetic notice type and per commercial-mail round below 98%.
"""

import argparse
import collections
import json
from pathlib import Path

import numpy as np


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", required=True, nargs="+", type=Path, help="fold runs, in fold order")
    parser.add_argument("--folds-data", required=True, type=Path, help="build_kfold.py output")
    parser.add_argument("--notice-types", type=Path)
    parser.add_argument("--spam-variants", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    notice = json.loads(args.notice_types.read_text()) if args.notice_types else {}
    variants = json.loads(args.spam_variants.read_text()) if args.spam_variants else {}
    rows = []
    for fold, run in enumerate(args.runs):
        tau = json.loads((run / "classifier_config.json").read_text())["dev_threshold_fpr1"]
        scores = np.load(run / "accuracy_scores.npz")
        by_id = dict(zip(scores["test_ids"].tolist(), scores["test_scores"].tolist()))
        for line in open(args.folds_data / f"fold{fold}" / "test.jsonl", encoding="utf-8"):
            r = json.loads(line)
            rows.append((r["id"], r["label"], r["group"], by_id[r["id"]] > tau))
    ids = [r[0] for r in rows]
    if len(set(ids)) != len(ids):
        raise SystemExit("a record is in more than one test fold")
    stats = collections.defaultdict(lambda: [0, 0])
    tp = tn = pos = neg = 0
    for row_id, label, group, flagged in rows:
        correct = flagged == (label == 1)
        pos += label == 1
        neg += label == 0
        tp += flagged and label == 1
        tn += (not flagged) and label == 0
        keys = [group]
        if row_id in notice:
            keys.append("type:" + notice[row_id])
        if row_id in variants:
            keys.append("commercial:" + variants[row_id])
        for key in keys:
            stats[key][0] += 1
            stats[key][1] += int(correct)
    report = {"n": len(rows), "accuracy": round((tp + tn) / (pos + neg), 4),
              "balanced_accuracy": round((tp / pos + tn / neg) / 2, 4), "recall": round(tp / pos, 4),
              "fpr": round(1 - tn / neg, 4),
              "groups": {k: {"n": n, "accuracy": round(ok / n, 4)} for k, (n, ok) in sorted(stats.items())}}
    if args.output:
        args.output.write_text(json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"out-of-fold n={report['n']} acc={100 * report['accuracy']:.2f}% bal={100 * report['balanced_accuracy']:.2f}% "
          f"recall={100 * report['recall']:.2f}% fpr={100 * report['fpr']:.2f}%")
    for key, value in report["groups"].items():
        if not key.startswith("type:") or value["accuracy"] < 0.98:
            print(f"   {key:32} n={value['n']:5} acc={100 * value['accuracy']:.2f}%")


if __name__ == "__main__":
    main()
