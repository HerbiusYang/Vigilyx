#!/usr/bin/env python3
"""Package the final semantic intent ensemble for the engine (training server).

Inputs are the final member runs (train_classifier.py output, each scored by
report_accuracy.py on the final data so accuracy_scores.npz holds dev logits).
For every member the dev mean and standard deviation of its logits are
recorded; the equal-weight mean of standardised logits is the ensemble score,
and the threshold is the dev cut with the highest dev accuracy (the `mean/acc`
rule evaluated out-of-fold by kfold_ensemble.py).

Writes DEST/ensemble.json, one directory per member with model.onnx,
tokenizer.json and classifier_config.json, SHA256SUMS over every file, and
MODEL_CARD.md. The engine reads ensemble.json (vigilyx-semantic-intent-ensemble/v1).
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil

import numpy as np

from kfold_ensemble import threshold_acc

SCHEMA = "vigilyx-semantic-intent-ensemble/v1"


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--member", action="append", required=True, metavar="NAME=RUN_DIR")
    parser.add_argument("--data", required=True, type=Path, help="final data directory (dev.jsonl)")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--evaluation", type=Path, help="kfold_ensemble.py report to quote in the model card")
    parser.add_argument("--data-note", action="append", default=[], help="extra training-data paragraph for the card")
    args = parser.parse_args()
    dev_rows = [json.loads(line) for line in open(args.data / "dev.jsonl", encoding="utf-8") if line.strip()]
    dev_ids = [r["id"] for r in dev_rows]
    labels = np.array([r["label"] for r in dev_rows])
    args.output.mkdir(parents=True)
    members, standardised = [], []
    for spec in args.member:
        name, run = spec.split("=", 1)
        run = Path(run)
        scores = np.load(run / "accuracy_scores.npz")
        by_id = dict(zip(scores["dev_ids"].tolist(), scores["dev_scores"].tolist()))
        dev = np.array([by_id[i] for i in dev_ids], dtype=np.float64)
        mean, std = float(dev.mean()), float(dev.std())
        standardised.append((dev - mean) / std)
        target = args.output / name
        target.mkdir()
        for file in ("model.onnx", "tokenizer.json", "classifier_config.json"):
            shutil.copy2(run / file, target / file)
        if (run / "model.onnx.data").exists():  # external weights of members over 2 GB
            shutil.copy2(run / "model.onnx.data", target / "model.onnx.data")
        config = json.loads((run / "classifier_config.json").read_text())
        report = json.loads((run / "training_report.json").read_text())
        members.append({"name": name, "dir": name, "dev_mean": mean, "dev_std": std,
                        "source_model": config.get("source_model"), "lowercase": config.get("lowercase", False),
                        "training_args": {k: report["args"][k] for k in ("epochs", "lr", "batch", "seed", "pooling")}})
    combined = sum(standardised) / len(standardised)
    tau = threshold_acc(combined, labels)
    flagged = combined > tau
    dev_metrics = {"n": len(labels), "accuracy": round(float((flagged == (labels == 1)).mean()), 5),
                   "recall": round(float(flagged[labels == 1].mean()), 5),
                   "fpr": round(float(flagged[labels == 0].mean()), 5)}
    ensemble = {"schema": SCHEMA, "model_version": args.version, "threshold": tau,
                "threshold_rule": "dev accuracy maximum of the equal-weight mean of dev-standardised logits",
                "members": members, "final_dev": dev_metrics}
    (args.output / "ensemble.json").write_text(json.dumps(ensemble, indent=1) + "\n", encoding="utf-8")

    evaluation = json.loads(args.evaluation.read_text()) if args.evaluation else None
    lines = [f"# Semantic intent ensemble {args.version}", "",
             "Fine-tuned encoders scored on CPU inside the Vigilyx engine (semantic_scan). Shadow mode records",
             "the score in details only; scored mode (SEMANTIC_INTENT_SCORE_THRESHOLD) turns a hit into a",
             "review-level Low module result that enters verdict fusion.", "",
             "## Members", ""]
    for m in members:
        lines.append(f"- `{m['name']}`: {m['source_model']} (lowercase={m['lowercase']}, {m['training_args']})")
    lines += ["", "## Decision rule", "",
              "Each member logit is standardised with its dev mean and standard deviation; the equal-weight",
              f"mean is compared with threshold {tau:.6f} (dev accuracy maximum). Final dev {dev_metrics} is the",
              "set that chose the threshold, so it is not an independent estimate; see Evaluation.", "",
              "## Training data", "",
              "E-PhishLLM (ACM AISec 2025) and Fraud-R1 (Findings of ACL 2025), plus synthetic benign notices",
              "(generator versions 1 and 2) and a translated English anti-fraud supplement. Fraud-R1 commercial",
              "mail is labelled by round: raw/generated/round2 benign, round3/round4 malicious. Identities are",
              "masked before training and inference. No real user mail was used.", ""]
    for note in args.data_note:
        lines += [note, ""]
    lines += ["**Licence restriction:** E-PhishLLM and Fraud-R1 ship no licence; both are for (defensive)",
              "research use and must not be redistributed. Do not publish these weights without the dataset",
              "authors' consent.",
              # bge-small-zh-v1.5, bge-m3 and multilingual-e5-base are all MIT
              f"Base models are MIT ({', '.join(m['source_model'].split()[0] for m in members)}).", ""]
    if evaluation:
        lines += ["## Evaluation", "", "5-fold group cross-validation, out-of-fold over all records:", ""]
        for method, r in sorted(evaluation["methods"].items(), key=lambda kv: -kv[1]["accuracy"])[:4]:
            lines.append(f"- {method}: accuracy {r['accuracy']:.4%}, recall {r['recall']:.4%}, "
                         f"FPR {r['fpr']:.4%}, errors {r['errors']} of {r['n']}")
        lines.append("")
    lines += ["## Limits", "",
              "- Public and synthetic data only; red-team AUC about 0.55. Not validated on real traffic.",
              "- Some remaining out-of-fold errors are not decidable from the body text (malicious links or",
              "  attachments behind ordinary wording, round-2 marketing pressure).", ""]
    (args.output / "MODEL_CARD.md").write_text("\n".join(lines), encoding="utf-8")
    files = sorted(p for p in args.output.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    (args.output / "SHA256SUMS").write_text(
        "".join(f"{sha256(p)}  {p.relative_to(args.output)}\n" for p in files), encoding="utf-8")
    print(json.dumps({"threshold": tau, "final_dev": dev_metrics, "members": [(m["name"], m["dev_mean"], m["dev_std"]) for m in members]}))


if __name__ == "__main__":
    main()
