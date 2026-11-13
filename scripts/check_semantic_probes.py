#!/usr/bin/env python3
"""Check frozen basic-intent expectations against offline Rust probe output."""

import argparse
import hashlib
import json
from pathlib import Path


def check(cases_path, report_dir):
    cases_bytes = cases_path.read_bytes()
    cases = {row["content_id"]: row for row in map(json.loads, cases_bytes.splitlines())}
    summary = json.loads((report_dir / "summary.json").read_text())
    if summary["limited_run"] or summary["input_sha256"] != hashlib.sha256(cases_bytes).hexdigest():
        raise ValueError("probe output does not match the complete frozen input")
    results = {}
    for line in (report_dir / "results.jsonl").read_text().splitlines():
        result = json.loads(line)
        identity = result["content_id"]
        if identity in results:
            raise ValueError("duplicate probe result")
        results[identity] = result
    if set(results) != set(cases):
        raise ValueError("missing or unknown probes")
    comparisons = []
    for identity, case in cases.items():
        result = results[identity]
        expected = case["expected_current_request"]
        if not isinstance(expected, bool):
            raise ValueError("probe expectation must be boolean")
        actual = result.get("current_request_count", 0) > 0
        comparisons.append({
            "id": case["sources"][0]["sample_id"], "content_id": identity,
            "expected_current_request": expected, "actual_current_request": actual,
            "passed": result["status"] == "ok" and actual == expected,
            "scenario_observed": result.get("scenario_observed"),
            "elevated_threat": result.get("elevated_threat"),
            "claims": result.get("details", {}).get("semantic_context", {}).get("claims", []),
        })
    failures = [row["id"] for row in comparisons if not row["passed"]]
    output = {
        "input_sha256": summary["input_sha256"],
        "effective_policy_sha256": summary["effective_policy_sha256"],
        "total": len(comparisons), "passed": len(comparisons) - len(failures),
        "failed": len(failures), "failed_ids": failures, "comparisons": comparisons,
    }
    with (report_dir / "expectations.json").open("x") as stream:
        json.dump(output, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({key: output[key] for key in ("total", "passed", "failed", "failed_ids")}, indent=2))
    return bool(failures)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    raise SystemExit(check(args.cases, args.report))
