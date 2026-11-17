#!/usr/bin/env python3
"""Train-only benign mail from the generator's version-2 notice types (runs on 77).

The frozen split uses generator version 1 (34 zh / 27 en notice types). Held
out notice types are the largest false-positive source, so more benign
variety helps. Version 2 adds procedural (institution how-to) and business
correspondence types; this keeps only those new types, drops any content id
already in the split, and writes them as train-only records.

To keep held-out evaluation honest, each new type is tied to every version-1
type whose distinctive text it shares (character 8-grams for Chinese, 5-word
shingles for English, ignoring shingles found in three or more version-1
types, i.e. salutations, closings and disclaimers). `tie-map.json` maps the
new type to those version-1 groups; kfold_assign.py leaves the record out of
the folds that test them. Only benign mail is produced. Stdlib only.
"""

import argparse
import collections
import importlib.util
import json
from pathlib import Path
import re
import tempfile


def shingles(text, language):
    if language == "zh":
        compact = re.sub(r"\s+", "", text)
        return {compact[i:i + 8] for i in range(len(compact) - 7)}
    words = re.findall(r"[a-z']+", text.lower())
    return {" ".join(words[i:i + 5]) for i in range(len(words) - 4)}


def by_type(records):
    out = collections.defaultdict(set)
    for record in records:
        notice = record["sources"][0]["notice_type"]
        out[notice] |= shingles((record.get("subject") or "") + "\n" + (record.get("body") or ""), notice.split("/")[0])
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generator", required=True, type=Path)
    parser.add_argument("--v1", required=True, type=Path, help="version-1 synthetic-benign directory used by the split")
    parser.add_argument("--split", required=True, type=Path, help="split directory (ids to avoid)")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--seed", default="vigilyx-synthetic-benign-v2-supplement")
    parser.add_argument("--per-language", type=int, default=3520, help="about 40 zh / 54 en per v2 type")
    parser.add_argument("--tie-threshold", type=float, default=0.01)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("synthetic_benign_generator", args.generator)
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    v1_records = [json.loads(line) for line in open(args.v1 / "cases.jsonl", encoding="utf-8") if line.strip()]
    v1_types = {r["sources"][0]["notice_type"] for r in v1_records}
    known = {json.loads(line)["content_id"] for name in ("train", "dev", "test")
             for line in open(args.split / f"{name}.jsonl", encoding="utf-8") if line.strip()}
    with tempfile.TemporaryDirectory() as tmp:
        generator.generate(Path(tmp) / "v2", args.seed, args.per_language, 2)
        generated = [json.loads(line) for line in open(Path(tmp) / "v2" / "cases.jsonl", encoding="utf-8") if line.strip()]
    records = [r for r in generated if r["sources"][0]["notice_type"] not in v1_types and r["content_id"] not in known]
    for record in records:
        record["sources"][0]["variant"] = "supplement-v2"

    old, new = by_type(v1_records), by_type(records)
    tie_map, overlap = {}, {}
    for language in ("zh", "en"):
        old_types = sorted(t for t in old if t.startswith(language + "/"))
        common = collections.Counter(s for t in old_types for s in old[t])
        boiler = {s for s, n in common.items() if n >= 3}
        for notice in sorted(t for t in new if t.startswith(language + "/")):
            mine = new[notice] - boiler
            ties = []
            for other in old_types:
                theirs = old[other] - boiler
                shared = len(mine & theirs)
                share = max(shared / max(len(theirs), 1), shared / max(len(mine), 1))
                if share >= args.tie_threshold:
                    ties.append("synthetic:" + other)
                    overlap["%s|%s" % (notice, other)] = round(share, 4)
            tie_map[notice] = ties

    args.output.mkdir(parents=True)
    path = args.output / "cases.jsonl"
    with path.open("xb") as stream:
        for record in records:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    (args.output / "tie-map.json").write_text(json.dumps(tie_map, ensure_ascii=False, indent=1), encoding="utf-8")
    counts = collections.Counter(r["sources"][0]["notice_type"].split("/")[0] for r in records)
    manifest = {"schema_version": 1, "dataset": generator.DATASET, "seed": args.seed, "generator_version": 2,
                "per_language": args.per_language, "split": "train-only", "records": len(records),
                "by_language": dict(counts), "new_types": len(new), "tie_threshold": args.tie_threshold,
                "tied_types": sum(1 for v in tie_map.values() if v), "overlap": overlap,
                "cases_sha256": generator.digest(path.read_bytes())}
    with (args.output / "manifest.json").open("x") as stream:
        json.dump(manifest, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({k: manifest[k] for k in ("records", "by_language", "new_types", "tied_types", "cases_sha256")}))


if __name__ == "__main__":
    main()
