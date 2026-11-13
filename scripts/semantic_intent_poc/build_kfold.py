#!/usr/bin/env python3
"""Build per-fold fine-tuning files from kfold_assign.py output (training server).

Input is a prepare_ft_data.py output (train/dev/test.jsonl, train may carry
train-only supplements) plus the fold assignment. For fold k: test = records
whose test fold is k, dev = inner-dev records of the other folds, train = the
rest plus every unassigned (train-only) record. A tied train-only record
([[folds], 0, 1]) is left out of those folds and trains the others.

`--final` also writes final/: the deployment training set. dev = every
inner-dev record (threshold and ensemble calibration), train = everything
else including all train-only records; test.jsonl is a copy of dev only so
train_classifier.py runs unchanged (it is not an independent test).
"""

import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--assign", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--final", action="store_true", help="also write final/ (all data, inner dev only)")
    args = parser.parse_args()
    assignment = json.loads(args.assign.read_text(encoding="utf-8"))
    rows = [line for name in ("train", "dev", "test")
            for line in open(args.data / f"{name}.jsonl", encoding="utf-8") if line.strip()]
    ids = [json.loads(line)["id"] for line in rows]
    if len(set(ids)) != len(ids):
        raise SystemExit("duplicate ids across splits")
    extra = sum(1 for i in ids if i not in assignment or len(assignment[i]) == 3)
    summary = {"rows": len(rows), "train_only": extra}
    for fold in range(args.folds):
        out = args.output / f"fold{fold}"
        out.mkdir(parents=True)
        streams = {name: open(out / f"{name}.jsonl", "x", encoding="utf-8") for name in ("train", "dev", "test")}
        for row_id, line in zip(ids, rows):
            test_fold, inner_dev, train_only = (assignment.get(row_id, [None, 0]) + [0])[:3]
            if train_only:
                if fold in (test_fold if isinstance(test_fold, list) else [test_fold]):
                    continue
                name = "train"
            else:
                name = "test" if test_fold == fold else "dev" if test_fold is not None and inner_dev else "train"
            streams[name].write(line if line.endswith("\n") else line + "\n")
        for stream in streams.values():
            stream.close()
        summary[f"fold{fold}"] = {name: sum(1 for _ in open(out / f"{name}.jsonl", encoding="utf-8"))
                                  for name in ("train", "dev", "test")}
    if args.final:
        out = args.output / "final"
        out.mkdir(parents=True)
        with open(out / "train.jsonl", "x", encoding="utf-8") as train, open(out / "dev.jsonl", "x", encoding="utf-8") as dev:
            for row_id, line in zip(ids, rows):
                _, inner_dev, train_only = (assignment.get(row_id, [None, 0]) + [0])[:3]
                (dev if inner_dev and not train_only else train).write(line if line.endswith("\n") else line + "\n")
        (out / "test.jsonl").write_bytes((out / "dev.jsonl").read_bytes())
        summary["final"] = {name: sum(1 for _ in open(out / f"{name}.jsonl", encoding="utf-8")) for name in ("train", "dev")}
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
