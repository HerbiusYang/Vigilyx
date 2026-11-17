#!/usr/bin/env python3
"""Group k-fold assignment over the whole split (runs on 77, stdlib only).

Every record of train/dev/test gets a test fold, so the k fold models together
train on all data and every record is scored once by a model that never saw
it. Groups follow prepare_semantic_classifier_split.py (Fraud-R1 record id
across rounds and languages, E-PhishLLM record, synthetic notice type; exact
duplicates joined), so a group never straddles a fold. Within the non-test
folds, a hash-chosen eighth of the groups is that fold's dev set (epoch choice
and the 1%-FPR threshold); nothing is tuned on the test fold.

Writes {content_id: [test_fold, inner_dev]} only; texts stay where they are.
Train-only supplements are not listed and go to every fold's train, unless
`--train-only FILE TIE` ties them to the groups they resemble. TIE is a group
key (every record of FILE) or `@tie-map.json` (notice type -> group keys, from
supplement_v2_types.py). Tied records are listed as [[excluded folds], 0, 1]
and left out of the folds that test those groups (the English anti-fraud
supplement translates zh/anti_fraud, so it must not train that fold).
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


def load_split_module(path):
    spec = importlib.util.spec_from_file_location("classifier_split", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bucket(seed, salt, group, modulo):
    return int(hashlib.sha256(("%s\x1f%s\x1f%s" % (seed, salt, group)).encode()).hexdigest()[:8], 16) % modulo


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split-script", required=True, type=Path, help="prepare_semantic_classifier_split.py")
    parser.add_argument("--split", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", default="vigilyx-semantic-kfold-v1")
    parser.add_argument("--train-only", nargs=2, action="append", default=[], metavar=("FILE", "TIE"),
                        help="train-only records and a group key or @tie-map.json")
    args = parser.parse_args()
    split = load_split_module(args.split_script)
    records = [json.loads(line) for name in ("train", "dev", "test")
               for line in open(args.split / f"{name}.jsonl", encoding="utf-8") if line.strip()]
    parent = {}

    def find(key):
        parent.setdefault(key, key)
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    for record in records:
        keys = [split.group_key(source) for source in record["sources"]]
        find(keys[0])
        for key in keys[1:]:
            parent[find(key)] = find(keys[0])
    representative = {}
    for key in list(parent):
        root = find(key)
        representative[root] = min(representative.get(root, key), key)
    assignment, counts = {}, {}
    for record in records:
        group = representative[find(split.group_key(record["sources"][0]))]
        fold = bucket(args.seed, "fold", group, args.folds)
        inner_dev = int(bucket(args.seed, "dev", group, 8) == 0)
        assignment[record["content_id"]] = [fold, inner_dev]
        label = record["sources"][0]["label"]
        key = "fold%d/%s" % (fold, label)
        counts[key] = counts.get(key, 0) + 1
    def fold_of(group):
        root = find(group)
        if root not in representative:
            raise SystemExit("unknown tie group %s" % group)
        return bucket(args.seed, "fold", representative[root], args.folds)

    for path, tie in args.train_only:
        tie_map = json.loads(Path(tie[1:]).read_text(encoding="utf-8")) if tie.startswith("@") else None
        for line in open(path, encoding="utf-8"):
            if not line.strip():
                continue
            record = json.loads(line)
            if record["content_id"] in assignment:
                raise SystemExit("train-only record collides with the split: %s" % record["content_id"])
            groups = tie_map.get(record["sources"][0]["notice_type"], []) if tie_map is not None else [tie]
            excluded = sorted({fold_of(group) for group in groups})
            assignment[record["content_id"]] = [excluded, 0, 1]
            key = "train_only/excluded_from_%d_folds" % len(excluded)
            counts[key] = counts.get(key, 0) + 1
    args.output.write_text(json.dumps(assignment), encoding="utf-8")
    print(json.dumps({"records": len(assignment), "groups": len(representative), "counts": dict(sorted(counts.items()))}))


if __name__ == "__main__":
    main()
