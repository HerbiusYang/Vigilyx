#!/usr/bin/env python3
"""Accuracy of a fine-tuned run on train/dev/test (training server).

Loads model.pt from a train_classifier.py run, scores the three splits, and
reports accuracy, balanced accuracy, recall and false-positive rate at the dev
1%-FPR threshold saved with the run, overall and per source/language group.
Per-email logits are saved to accuracy_scores.npz for error analysis.
Commercial spam (label -1) is excluded from accuracy and reported separately.
"""

import argparse
import json
from pathlib import Path

import numpy as np
import torch
from tokenizers import Tokenizer

from train_classifier import Classifier, load, predict


def metrics(scores, items, tau):
    labels = np.array([c[1] for c in items])
    flagged = scores > tau
    keep = labels >= 0
    y, f = labels[keep], flagged[keep]
    tp, tn = int((f & (y == 1)).sum()), int((~f & (y == 0)).sum())
    pos, neg = int((y == 1).sum()), int((y == 0).sum())
    out = {"n": int(keep.sum()), "accuracy": round((tp + tn) / max(pos + neg, 1), 4),
           "balanced_accuracy": round(((tp / pos if pos else 1) + (tn / neg if neg else 1)) / 2, 4),
           "recall": round(tp / pos, 4) if pos else None, "fpr": round(1 - tn / neg, 4) if neg else None}
    if (labels == -1).any():
        out["spam_flag_rate"] = round(float(flagged[labels == -1].mean()), 4)
    groups = {}
    for (_, label, group, _), flag in zip(items, flagged):
        if label < 0:
            continue
        n, ok = groups.get(group, (0, 0))
        groups[group] = (n + 1, ok + int(flag == (label == 1)))
    out["groups"] = {g: {"n": n, "accuracy": round(ok / n, 4)} for g, (n, ok) in sorted(groups.items())}
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--data", required=True, type=Path)
    args = parser.parse_args()
    config = json.load(open(args.run / "classifier_config.json"))
    tokenizer = Tokenizer.from_file(str(args.run / "tokenizer.json"))
    tokenizer.no_truncation()
    tokenizer.no_padding()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = Classifier(args.model_dir, config["pooling"]).to(device)
    model.load_state_dict(torch.load(args.run / "model.pt", map_location="cpu"))
    tau = config["dev_threshold_fpr1"]
    report = {"run": args.run.name, "threshold": tau}
    dump = {}
    for name in ("train", "dev", "test"):
        items = load(args.data / f"{name}.jsonl", tokenizer, config["prefix"], config["max_len"], config["head_tokens"])
        scores = predict(model, items, config["pad_id"], device)
        report[name] = metrics(scores, items, tau)
        dump[f"{name}_scores"], dump[f"{name}_ids"] = scores, np.array([c[3] for c in items])
    # Per-email logits for error analysis (ids only, no text).
    np.savez(args.run / "accuracy_scores.npz", **dump)
    with open(args.run / "accuracy_report.json", "w") as stream:
        json.dump(report, stream, indent=1, ensure_ascii=False)
    for name in ("train", "dev", "test"):
        r = report[name]
        print(f"{args.run.name} {name:5} n={r['n']:5} acc={100 * r['accuracy']:.2f}% bal={100 * r['balanced_accuracy']:.2f}% "
              f"recall={100 * r['recall']:.2f}% fpr={100 * r['fpr']:.2f}%"
              + (f" spam_flag={100 * r['spam_flag_rate']:.1f}%" if "spam_flag_rate" in r else ""))
        low = {g: v for g, v in r["groups"].items() if v["n"] >= 20 and v["accuracy"] < 0.98}
        if low:
            print("   groups below 98%:", json.dumps(low, ensure_ascii=False))


if __name__ == "__main__":
    main()
