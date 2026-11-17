#!/usr/bin/env python3
"""Compare two complete offline semantic replays on exactly the same input."""

import argparse
from collections import Counter, defaultdict
from itertools import zip_longest
import hashlib
import json
from pathlib import Path


def lines(path):
    with path.open() as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def compare(cases_path, baseline, candidate, output):
    expected_hash = hashlib.sha256(cases_path.read_bytes()).hexdigest()
    for directory in (baseline, candidate):
        summary = json.loads((directory / "summary.json").read_text())
        if summary["limited_run"] or summary["input_sha256"] != expected_hash:
            raise ValueError(f"incomplete or mismatched replay: {directory}")
    cases = {case["content_id"]: case for case in lines(cases_path)}
    groups = defaultdict(Counter)
    seen = set()
    fields = ("scenario_observed", "review_required", "elevated_threat", "coverage_limited")
    new_benign_threats = []
    output.mkdir(exist_ok=False)
    with (output / "case_deltas.jsonl").open("x") as stream:
        for before, after in zip_longest(lines(baseline / "results.jsonl"), lines(candidate / "results.jsonl")):
            if before is None or after is None or before["content_id"] != after["content_id"]:
                raise ValueError("replay identities or order differ")
            identity = before["content_id"]
            if identity in seen or identity not in cases:
                raise ValueError("duplicate or unknown content")
            seen.add(identity)
            case = cases[identity]
            flags_before = {field: before.get(field) is True for field in fields}
            flags_after = {field: after.get(field) is True for field in fields}
            flags_before["current_request"] = before.get("current_request_count", 0) > 0
            flags_after["current_request"] = after.get("current_request_count", 0) > 0
            changed = flags_before != flags_after
            if changed:
                stream.write(json.dumps({"content_id": identity, "sources": case["sources"],
                                         "before": flags_before, "after": flags_after}, ensure_ascii=False) + "\n")
            keys = {(s["dataset"], s["language"], s["data_type"], s["variant"], s["label"])
                    for s in case["sources"]}
            for key in keys:
                tally = groups[key]
                tally["contents"] += 1
                for field in flags_before:
                    tally[f"baseline_{field}"] += flags_before[field]
                    tally[f"candidate_{field}"] += flags_after[field]
                    tally[f"gained_{field}"] += not flags_before[field] and flags_after[field]
                    tally[f"lost_{field}"] += flags_before[field] and not flags_after[field]
                tally["baseline_errors"] += before["status"] != "ok"
                tally["candidate_errors"] += after["status"] != "ok"
            if flags_after["elevated_threat"] and not flags_before["elevated_threat"]:
                if any(s["label"] == "benign" for s in case["sources"]):
                    new_benign_threats.append(identity)
    if len(seen) != len(cases):
        raise ValueError("not every frozen content was replayed")
    result = {
        "input_sha256": expected_hash, "unique_contents": len(seen),
        "new_benign_threat_count": len(new_benign_threats),
        "new_benign_threat_ids": new_benign_threats,
        "strata": [dict(zip(("dataset", "language", "data_type", "variant", "label"), key), **value)
                   for key, value in sorted(groups.items())],
        "interpretation": "request/scenario observations are separate from module threat; losses require case review; labels are inherited dataset labels",
    }
    with (output / "comparison.json").open("x") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({key: result[key] for key in ("unique_contents", "new_benign_threat_count")}, indent=2))
    return bool(new_benign_threats)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    raise SystemExit(compare(args.cases, args.baseline, args.candidate, args.output))
