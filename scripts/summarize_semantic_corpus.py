#!/usr/bin/env python3
"""Join offline Rust semantic results to imported research-corpus provenance."""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path


def load_lines(path):
    with path.open() as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def summarize(corpus, report):
    manifest = json.loads((corpus / "manifest.json").read_text())
    digest = hashlib.sha256((corpus / "cases.jsonl").read_bytes()).hexdigest()
    if digest != manifest["corpus_sha256"]:
        raise ValueError("prepared corpus no longer matches manifest")
    summary = json.loads((report / "summary.json").read_text())
    if not summary["limited_run"] and summary["input_sha256"] != digest:
        raise ValueError("Rust replay did not consume the frozen corpus")
    if hashlib.sha256((report / "effective_policy.json").read_bytes()).hexdigest() != summary["effective_policy_sha256"]:
        raise ValueError("effective policy no longer matches replay")
    cases = {case["content_id"]: case for case in load_lines(corpus / "cases.jsonl")}
    seen = set()
    tags = Counter()
    elapsed = []
    examples = Counter()
    rows = []
    aggregates = defaultdict(Counter)
    with (report / "issue_candidates.jsonl").open("x") as issues:
        for result in load_lines(report / "results.jsonl"):
            identity = result["content_id"]
            if identity in seen or identity not in cases:
                raise ValueError(f"duplicate or unknown result: {identity}")
            seen.add(identity)
            case = cases[identity]
            elapsed.append(result["elapsed_us"] / 1000)
            keys = {(s["dataset"], s["language"], s["data_type"], s["variant"], s["label"])
                    for s in case["sources"]}
            for key in keys:
                tally = aggregates[key]
                tally["contents"] += 1
                for field in ("scenario_observed", "review_required", "actionable_extortion",
                              "elevated_threat", "coverage_limited"):
                    tally[field] += result.get(field) is True
                tally["current_request"] += result.get("current_request_count", 0) > 0
                tally["module_errors"] += result["status"] != "ok"
            for tag in result["issue_tags"]:
                tags[tag] += 1
                # Bounded review index: full facts remain in results.jsonl and
                # original text in cases.jsonl. Never copy corpus text into Git.
                if examples[tag] < 20:
                    issues.write(json.dumps({
                        "content_id": identity, "issue": tag,
                        "sources": case["sources"], "status": "needs_manual_review",
                    }, ensure_ascii=False) + "\n")
                    examples[tag] += 1
    if len(seen) != summary["unique_contents"]["contents"]:
        raise ValueError("result count does not match Rust summary")
    if not summary["limited_run"] and len(seen) != len(cases):
        raise ValueError("full corpus replay is incomplete")

    for name, tally in summary["strata"].items():
        total = tally["contents"]
        rows.append({
            "stratum": name, **tally,
            "scenario_observation_percent": round(tally["scenario_observed"] / total * 100, 3),
            "elevated_module_threat_percent": round(tally["elevated_threat"] / total * 100, 3),
            "coverage_limited_percent": round(tally["coverage_limited"] / total * 100, 3),
        })
    elapsed.sort()
    percentile = lambda q: elapsed[max(0, math.ceil(len(elapsed) * q) - 1)]
    measurements = {
        "corpus_sha256": digest, "evaluated_unique_contents": len(seen),
        "effective_policy_sha256": summary["effective_policy_sha256"],
        "available_unique_contents": len(cases), "limited_run": summary["limited_run"],
        "timing_ms": {"p50": percentile(.50), "p95": percentile(.95),
                      "p99": percentile(.99), "max": elapsed[-1]},
        "strata": rows, "issue_candidate_counts": dict(tags),
        "aggregate_strata": [dict(zip(("dataset", "language", "data_type", "variant", "label"), key), **value)
                             for key, value in sorted(aggregates.items())],
        "interpretation": [
            "scenario observations are not attack decisions or false positives",
            "elevated threat is a local semantic-module result, not the fused platform verdict",
            "Fraud-R1 commercial spam is a separate label, not a benign control",
            "raw reports/dialogues, messages, job postings and independent rounds are separate diagnostic strata",
            "dataset labels are not independent annotations of actor, intent, negation or link ownership",
            "strata overlap on exact duplicate content; do not sum strata to estimate unique corpus size",
        ],
    }
    with (report / "measurements.json").open("x") as stream:
        json.dump(measurements, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({key: measurements[key] for key in (
        "evaluated_unique_contents", "available_unique_contents", "limited_run", "timing_ms",
    )}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    summarize(args.corpus, args.report)
