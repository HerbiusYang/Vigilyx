#!/usr/bin/env python3
"""Score a jsonl with a packaged ensemble's member runs (training server).

Each member is a train_classifier.py run directory (model.pt, tokenizer.json,
classifier_config.json). Logits are standardised with the dev mean/std in
ensemble.json and their equal-weight mean is compared with its threshold:
the decision rule the engine applies. Reports accuracy, recall and FPR overall
and per group, and writes nothing into the run directories. Used to score an
earlier package on data it never saw (e.g. v2 on a newly added corpus).
"""

import argparse
import collections
import json
from pathlib import Path

import numpy as np
import torch
from tokenizers import Tokenizer

from train_classifier import Classifier, load, predict


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--member", action="append", required=True, metavar="NAME=RUN_DIR")
    parser.add_argument("--model-dir", action="append", required=True, metavar="NAME=BASE_MODEL_DIR")
    parser.add_argument("--ensemble", required=True, type=Path, help="ensemble.json of the package")
    parser.add_argument("--rows", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    ensemble = json.loads(args.ensemble.read_text())
    stats = {m["name"]: (m["dev_mean"], m["dev_std"]) for m in ensemble["members"]}
    model_dirs = dict(m.split("=", 1) for m in args.model_dir)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    standardised, rows = [], None
    for spec in args.member:
        name, run = spec.split("=", 1)
        run = Path(run)
        config = json.load(open(run / "classifier_config.json"))
        tokenizer = Tokenizer.from_file(str(run / "tokenizer.json"))
        tokenizer.no_truncation()
        tokenizer.no_padding()
        items = load(args.rows, tokenizer, config["prefix"], config["max_len"], config["head_tokens"])
        rows = rows or items
        model = Classifier(model_dirs[name], config["pooling"]).to(device)
        model.load_state_dict(torch.load(run / "model.pt", map_location="cpu"))
        mean, std = stats[name]
        standardised.append((predict(model, items, config["pad_id"], device) - mean) / std)
        del model
    flagged = sum(standardised) / len(standardised) > ensemble["threshold"]
    labels = np.array([c[1] for c in rows])
    groups = collections.defaultdict(lambda: [0, 0])
    for (_, label, group, _), flag in zip(rows, flagged):
        groups[group][0] += 1
        groups[group][1] += int(flag == (label == 1))
    report = {"package": ensemble["model_version"], "n": len(rows),
              "accuracy": round(float((flagged == (labels == 1)).mean()), 5),
              "recall": round(float(flagged[labels == 1].mean()), 5) if (labels == 1).any() else None,
              "fpr": round(float(flagged[labels == 0].mean()), 5) if (labels == 0).any() else None,
              "groups": {g: {"n": n, "accuracy": round(ok / n, 4)} for g, (n, ok) in sorted(groups.items())}}
    args.output.write_text(json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
