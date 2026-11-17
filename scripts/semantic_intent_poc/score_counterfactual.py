#!/usr/bin/env python3
"""Name-swap counterfactual check for k-fold runs (training server).

--rows is add_vigilyx_corpus.py --rows-out output: the same records rendered
with people the training text never named and real institutions swapped for
others of the same type. Each record is scored by the fold model that held it
out (its id is in fold k's test.jsonl), and its decision is compared with the
original rendering's out-of-fold decision. A flip means names, not content,
decided the result. Scores go to RUN/cf_scores.npz, or RUN/--scores-name for
other probe sets such as make_probes.py output (accuracy_scores.npz is left
alone). Reported per member at the run's dev 1%-FPR threshold and for the
equal-weight ensemble at the dev accuracy-max threshold (`mean/acc` in
kfold_ensemble.py), overall and for records that name a real institution.
"""

import argparse
import json
from pathlib import Path

import numpy as np
import torch
from tokenizers import Tokenizer

from kfold_ensemble import threshold_acc
from train_classifier import Classifier, load, predict


def score_run(run, model_dir, rows_path, ids, scores_name):
    config = json.load(open(run / "classifier_config.json"))
    tokenizer = Tokenizer.from_file(str(run / "tokenizer.json"))
    tokenizer.no_truncation()
    tokenizer.no_padding()
    items = [c for c in load(rows_path, tokenizer, config["prefix"], config["max_len"], config["head_tokens"])
             if c[3] in ids]
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = Classifier(model_dir, config["pooling"]).to(device)
    model.load_state_dict(torch.load(run / "model.pt", map_location="cpu"))
    scores = predict(model, items, config["pad_id"], device)
    np.savez(run / scores_name, cf_ids=np.array([c[3] for c in items]), cf_scores=scores)


def summarise(pairs, labels, institution_ids):
    out = {}
    for name, keep in (("all", lambda i: True), ("names_real_institution", lambda i: i in institution_ids)):
        chosen = [(i, a, b) for i, (a, b) in pairs.items() if keep(i)]
        if not chosen:
            continue
        flips = [i for i, a, b in chosen if a != b]
        out[name] = {"n": len(chosen), "flips": len(flips), "flip_rate": round(len(flips) / len(chosen), 5),
                     "accuracy_original": round(sum(a == (labels[i] == 1) for i, a, _ in chosen) / len(chosen), 5),
                     "accuracy_swapped": round(sum(b == (labels[i] == 1) for i, _, b in chosen) / len(chosen), 5),
                     "flipped_ids": sorted(flips)}
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", action="append", required=True, metavar="NAME=RUN_PREFIX")
    parser.add_argument("--model-dir", action="append", required=True, metavar="NAME=BASE_MODEL_DIR")
    parser.add_argument("--rows", required=True, type=Path)
    parser.add_argument("--folds-data", required=True, type=Path)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--institution-ids", type=Path, help="JSON list of corpus ids naming a real institution")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--scores-name", default="cf_scores.npz", help="per-run score file for this probe set")
    args = parser.parse_args()
    groups = [g.split("=", 1) for g in args.group]
    model_dirs = dict(m.split("=", 1) for m in args.model_dir)
    cf_ids = {json.loads(line)["id"] for line in open(args.rows, encoding="utf-8") if line.strip()}
    institution_ids = set(json.loads(args.institution_ids.read_text())) if args.institution_ids else set()
    labels, member_pairs, ensemble_pairs = {}, {name: {} for name, _ in groups}, {}
    for fold in range(args.folds):
        fold_dir = args.folds_data / f"fold{fold}"
        test_rows = [json.loads(line) for line in open(fold_dir / "test.jsonl", encoding="utf-8")]
        ids = {r["id"] for r in test_rows} & cf_ids
        labels.update({r["id"]: r["label"] for r in test_rows if r["id"] in ids})
        dev_rows = [json.loads(line) for line in open(fold_dir / "dev.jsonl", encoding="utf-8")]
        y_dev = np.array([r["label"] for r in dev_rows])
        std_orig, std_cf, std_dev = [], [], []
        for name, prefix in groups:
            run = Path(prefix + str(fold))
            if not (run / args.scores_name).exists():
                score_run(run, model_dirs[name], args.rows, ids, args.scores_name)
            z, cf = np.load(run / "accuracy_scores.npz"), np.load(run / args.scores_name)
            orig = dict(zip(z["test_ids"].tolist(), z["test_scores"].tolist()))
            swapped = dict(zip(cf["cf_ids"].tolist(), cf["cf_scores"].tolist()))
            dev_by_id = dict(zip(z["dev_ids"].tolist(), z["dev_scores"].tolist()))
            dev = np.array([dev_by_id[r["id"]] for r in dev_rows])
            tau = json.loads((run / "classifier_config.json").read_text())["dev_threshold_fpr1"]
            order = sorted(ids)
            for i in order:
                member_pairs[name][i] = (orig[i] > tau, swapped[i] > tau)
            mean, sd = dev.mean(), dev.std() + 1e-9
            std_dev.append((dev - mean) / sd)
            std_orig.append((np.array([orig[i] for i in order]) - mean) / sd)
            std_cf.append((np.array([swapped[i] for i in order]) - mean) / sd)
        tau = threshold_acc(sum(std_dev) / len(std_dev), y_dev)
        for i, a, b in zip(order, sum(std_orig) / len(groups), sum(std_cf) / len(groups)):
            ensemble_pairs[i] = (bool(a > tau), bool(b > tau))
    report = {name: summarise(pairs, labels, institution_ids) for name, pairs in member_pairs.items()}
    report["ensemble_mean_acc"] = summarise(ensemble_pairs, labels, institution_ids)
    args.output.write_text(json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")
    for name, parts in report.items():
        for part, r in parts.items():
            print(f"{name:18} {part:24} n={r['n']:5} flips={r['flips']:4} ({100 * r['flip_rate']:.2f}%) "
                  f"acc orig={100 * r['accuracy_original']:.2f}% swapped={100 * r['accuracy_swapped']:.2f}%")


if __name__ == "__main__":
    main()
