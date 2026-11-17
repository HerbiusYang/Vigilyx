#!/usr/bin/env python3
"""Score a semantic_external_harness replay of one classifier split.

Positive prediction: semantic module ThreatLevel above Safe (rules or the text
classifier). Primary metric, fixed before the test split was read:

    balanced accuracy = (recall over all malicious rows + specificity over
    E-PhishLLM benign rows) / 2, target >= 0.90 with FPR <= 0.02.

Commercial spam is neither class and is reported separately. Synthetic
benign mail (split v3 and later) is not part of the primary metric; its
false-positive rate is reported on its own. Python 3.9.
"""

import argparse
from collections import Counter, defaultdict
import json

CHINESE = {"Chinese", "zh-cn", "zh"}
SYNTHETIC = "vigilyx-synthetic-benign"


def rows(path):
    with open(path) as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def rate(numerator, denominator):
    return round(numerator / denominator, 4) if denominator else None


def binary(positives, negatives, key="flagged"):
    tp = sum(row[key] for row in positives)
    fp = sum(row[key] for row in negatives)
    recall = rate(tp, len(positives))
    fpr = rate(fp, len(negatives))
    result = {"malicious": len(positives), "benign": len(negatives), "tp": tp, "fp": fp,
              "recall": recall, "fpr": fpr}
    if recall is not None and fpr is not None:
        result["balanced_accuracy"] = round((recall + 1 - fpr) / 2, 4)
        result["precision"] = rate(tp, tp + fp)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    cases = {case["content_id"]: case for case in rows(args.cases)}
    evaluated = []
    for result in rows(args.results):
        case = cases.pop(result["content_id"])
        source = case["sources"][0]
        details = result.get("details") or {}
        classifier = details.get("semantic_text_classifier") or {}
        decision = details.get("semantic_scoring_decision") or {}
        flagged = result["status"] == "ok" and result["threat_level"] != "safe"
        evaluated.append({
            "label": source["label"],
            "dataset": source["dataset"],
            "language": "zh" if any(s["language"] in CHINESE for s in case["sources"]) else source["language"],
            "flagged": flagged,
            "classifier_fired": classifier.get("fired") is True,
            "rules_flagged": flagged and decision.get("text_classifier_drives_score") is not True,
            "route": classifier.get("route"),
            "status": classifier.get("status"),
            "error": result["status"] != "ok",
        })
    if cases:
        raise ValueError("replay is missing %d cases" % len(cases))

    malicious = [row for row in evaluated if row["label"] == "malicious"]
    benign = [row for row in evaluated if row["label"] == "benign" and row["dataset"] != SYNTHETIC]
    synthetic = [row for row in evaluated if row["label"] == "benign" and row["dataset"] == SYNTHETIC]
    spam = [row for row in evaluated if row["label"] == "spam"]
    subset = lambda items, **match: [r for r in items if all(r[k] == v for k, v in match.items())]
    primary = binary(malicious, benign)
    report = {
        "positive_definition": "semantic ThreatLevel > Safe (rules or text classifier)",
        "primary_all_malicious_vs_ephish_benign": primary,
        "target_met": primary["balanced_accuracy"] >= 0.90 and primary["fpr"] <= 0.02,
        "rules_only_same_rows": binary(malicious, benign, "rules_flagged"),
        "non_chinese": binary([r for r in malicious if r["language"] != "zh"], benign),
        "ephish_only": binary(subset(malicious, dataset="E-PhishLLM"), benign),
        "recall_by_subset": {},
        "benign_fpr_by_language": {},
        "spam_flag_rate": {"n": len(spam), "flagged": sum(r["flagged"] for r in spam)},
        "synthetic_benign_fpr_by_language": {
            language: {"n": len(items), "fp": sum(r["flagged"] for r in items),
                       "fpr": rate(sum(r["flagged"] for r in items), len(items))}
            for language, items in sorted(
                ((language, [r for r in synthetic if r["language"] == language])
                 for language in {r["language"] for r in synthetic}))
        },
        "classifier_status": dict(Counter(r["status"] for r in evaluated)),
        "route_by_language": {},
        "module_errors": sum(r["error"] for r in evaluated),
    }
    groups = defaultdict(list)
    for row in malicious:
        groups["%s/%s" % (row["dataset"], row["language"])].append(row)
    for key, items in sorted(groups.items()):
        report["recall_by_subset"][key] = {
            "n": len(items), "flagged": sum(r["flagged"] for r in items),
            "recall": rate(sum(r["flagged"] for r in items), len(items)),
            "rules_only": sum(r["rules_flagged"] for r in items),
        }
    for language in sorted({r["language"] for r in benign}):
        items = [r for r in benign if r["language"] == language]
        report["benign_fpr_by_language"][language] = {
            "n": len(items), "fp": sum(r["flagged"] for r in items)}
    for language in sorted({r["language"] for r in evaluated}):
        report["route_by_language"][language] = dict(
            Counter(str(r["route"]) for r in evaluated if r["language"] == language))
    with open(args.output, "x") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
