#!/usr/bin/env python3
"""Out-of-fold accuracy for threshold rules and model ensembles (training server).

Inputs are k-fold groups that share the same fold dev/test sets (each run has
accuracy_scores.npz from report_accuracy.py). For every fold, all choices are
made on that fold's dev set only and then applied unchanged to its test set:

* threshold rule `fpr1`: dev benign false-positive rate 1% (the run's own);
  `acc`: the dev threshold with the highest dev accuracy.
* ensemble: each model's logits are standardised with dev mean/std, combined
  as a weighted mean; weights come from a grid searched on dev accuracy.
  `NAME=PREFIX_A+PREFIX_B` averages several seeds of one model (each
  standardised on dev) into a single member before ensembling.

Pooled test-fold predictions cover every record once, scored by models that
never trained on it.
"""

import argparse
import collections
import itertools
import json
import math
from pathlib import Path

import numpy as np


def fold_scores(run, fold_dir):
    z = np.load(run / "accuracy_scores.npz")
    out = {}
    for name in ("dev", "test"):
        by_id = dict(zip(z[f"{name}_ids"].tolist(), z[f"{name}_scores"].tolist()))
        rows = [json.loads(line) for line in open(fold_dir / f"{name}.jsonl", encoding="utf-8")]
        out[name] = (np.array([by_id[r["id"]] for r in rows]), rows)
    return out


def member_scores(prefix, fold, fold_dir):
    """One ensemble member: a single run, or seeds joined by '+' averaged after dev standardisation."""
    runs = [fold_scores(Path(p + str(fold)), fold_dir) for p in prefix.split("+")]
    if len(runs) == 1:
        return runs[0]
    for run in runs[1:]:
        assert [r["id"] for r in run["test"][1]] == [r["id"] for r in runs[0]["test"][1]]
    stats = [(run["dev"][0].mean(), run["dev"][0].std() + 1e-9) for run in runs]
    return {name: (sum((run[name][0] - m) / sd for run, (m, sd) in zip(runs, stats)) / len(runs), runs[0][name][1])
            for name in ("dev", "test")}


def threshold_fpr(scores, labels, fpr=0.01):
    benign = np.sort(scores[labels == 0])
    return float(benign[max(int(math.ceil(len(benign) * (1 - fpr))) - 1, 0)])


def threshold_acc(scores, labels):
    order = np.argsort(scores)
    s, y = scores[order], labels[order]
    # Flag everything above a cut between s[i-1] and s[i]: benign below the cut are right, malicious above are right.
    benign_below = np.concatenate([[0], np.cumsum(y == 0)])
    malicious_above = (y == 1).sum() - np.concatenate([[0], np.cumsum(y == 1)])
    correct = benign_below + malicious_above
    best = np.flatnonzero(correct == correct.max())
    i = int(best[len(best) // 2])
    if i == 0:
        return float(s[0] - 1)
    if i == len(s):
        return float(s[-1] + 1)
    return float((s[i - 1] + s[i]) / 2)


def accuracy(scores, labels, tau):
    return float(((scores > tau) == (labels == 1)).mean())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", action="append", required=True, metavar="NAME=RUN_PREFIX",
                        help="runs RUN_PREFIX0..RUN_PREFIX{k-1}; repeat for each model")
    parser.add_argument("--folds-data", required=True, type=Path)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--notice-types", type=Path)
    parser.add_argument("--spam-variants", type=Path)
    parser.add_argument("--grid", type=float, default=0.1, help="ensemble weight step")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    groups = [g.split("=", 1) for g in args.group]
    notice = json.loads(args.notice_types.read_text()) if args.notice_types else {}
    variants = json.loads(args.spam_variants.read_text()) if args.spam_variants else {}
    steps = int(round(1 / args.grid))
    weights = [w for w in itertools.product(range(steps + 1), repeat=len(groups)) if sum(w) == steps] if len(groups) > 1 else []
    methods = collections.defaultdict(list)  # method -> [(row, flagged)]
    chosen = collections.defaultdict(list)
    for fold in range(args.folds):
        fold_dir = args.folds_data / f"fold{fold}"
        data = {name: member_scores(prefix, fold, fold_dir) for name, prefix in groups}
        rows_dev, rows_test = data[groups[0][0]]["dev"][1], data[groups[0][0]]["test"][1]
        y_dev = np.array([r["label"] for r in rows_dev])
        std_dev, std_test = [], []
        for name, prefix in groups:
            dev, test = data[name]["dev"][0], data[name]["test"][0]
            if "+" in prefix:
                tau_fpr = threshold_fpr(dev, y_dev)
            else:
                tau_fpr = json.loads((Path(prefix + str(fold)) / "classifier_config.json").read_text())["dev_threshold_fpr1"]
            methods[f"{name}/fpr1"] += list(zip(rows_test, test > tau_fpr))
            methods[f"{name}/acc"] += list(zip(rows_test, test > threshold_acc(dev, y_dev)))
            mean, sd = dev.mean(), dev.std() + 1e-9
            std_dev.append((dev - mean) / sd)
            std_test.append((test - mean) / sd)
        if weights:
            best = None
            for w in weights:
                combo = sum(wi * s for wi, s in zip(w, std_dev)) / steps
                tau = threshold_acc(combo, y_dev)
                score = accuracy(combo, y_dev, tau)
                if best is None or score > best[0]:
                    best = (score, w, tau)
            _, w, tau = best
            combo_test = sum(wi * s for wi, s in zip(w, std_test)) / steps
            methods["ensemble/acc"] += list(zip(rows_test, combo_test > tau))
            combo_dev = sum(wi * s for wi, s in zip(w, std_dev)) / steps
            methods["ensemble/fpr1"] += list(zip(rows_test, combo_test > threshold_fpr(combo_dev, y_dev)))
            chosen["ensemble_weights"].append([round(x / steps, 3) for x in w])
            equal = sum(std_dev) / len(std_dev)
            methods["mean/acc"] += list(zip(rows_test, sum(std_test) / len(std_test) > threshold_acc(equal, y_dev)))

    report = {"chosen": dict(chosen), "methods": {}}
    for method, items in methods.items():
        ids = [r["id"] for r, _ in items]
        assert len(ids) == len(set(ids))
        stats = collections.defaultdict(lambda: [0, 0])
        tp = tn = pos = neg = 0
        for r, flagged in items:
            label, correct = r["label"], bool(flagged) == (r["label"] == 1)
            pos += label == 1; neg += label == 0
            tp += bool(flagged) and label == 1; tn += (not flagged) and label == 0
            keys = [r["group"]] + (["type:" + notice[r["id"]]] if r["id"] in notice else []) \
                + (["commercial:" + variants[r["id"]]] if r["id"] in variants else [])
            for key in keys:
                stats[key][0] += 1; stats[key][1] += int(correct)
        report["methods"][method] = {
            "n": len(items), "errors": int(len(items) - tp - tn), "accuracy": round((tp + tn) / len(items), 5),
            "recall": round(tp / pos, 5), "fpr": round(1 - tn / neg, 5),
            "groups": {k: {"n": n, "accuracy": round(ok / n, 4)} for k, (n, ok) in sorted(stats.items())},
            # ids only (no text), for error review against the fold files
            "error_ids": sorted(r["id"] for r, flagged in items if bool(flagged) != (r["label"] == 1))}
    if args.output:
        args.output.write_text(json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")
    if chosen:
        print("ensemble weights per fold (dev-chosen):", chosen["ensemble_weights"], [g[0] for g in groups])
    for method, r in sorted(report["methods"].items(), key=lambda kv: -kv[1]["accuracy"]):
        low = {k: v["accuracy"] for k, v in r["groups"].items() if v["n"] >= 50 and v["accuracy"] < 0.98}
        print(f"{method:22} n={r['n']} errors={r['errors']:4} acc={100 * r['accuracy']:.2f}% "
              f"recall={100 * r['recall']:.2f}% fpr={100 * r['fpr']:.2f}%  below98(n>=50)={low}")


if __name__ == "__main__":
    main()
