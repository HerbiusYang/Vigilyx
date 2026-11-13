#!/usr/bin/env python3
"""Freeze public synthetic DS regression metadata without exposing mail contents.

This is an inventory tool, not an evaluator. It never updates existing labels or
the external capability manifest and never claims blind-corpus acceptance.
Execute evaluation and verification on the remote builder per AGENTS.md.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys


BASELINE_MANIFEST_SHA256 = (
    "sha256:ae834c67345faccbc546f68dbf786433e8a8f6e1b93da315276a0f951cd3c94b"
)


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def canonical_hash(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def build_inventory(repo: Path, baseline_manifest: Path | None = None) -> dict:
    relative_root = Path("crates/vigilyx-engine/tests/redteam_cases")
    cases_root = repo / relative_root
    manifest = load_json(cases_root / "capability_manifest.json")
    labels = load_json(cases_root / "labels.json")
    manifest_hash = canonical_hash(manifest)
    if manifest_hash != BASELINE_MANIFEST_SHA256:
        raise ValueError("established capability manifest changed; separate governance is required")
    if baseline_manifest is not None and load_json(baseline_manifest) != manifest:
        raise ValueError("manifest differs from the baseline release manifest")

    records = labels["cases"]
    if len(records) != 105 or len(manifest["capabilities"]) != 20:
        raise ValueError("this frozen audit expects all 105 cases and all 20 capabilities")
    if len({record["case_id"] for record in records}) != len(records):
        raise ValueError("duplicate case IDs in source labels")
    if len({record["file"] for record in records}) != len(records):
        raise ValueError("duplicate fixture paths in source labels")

    cases = []
    for record in sorted(records, key=lambda item: item["case_id"]):
        relative = Path(record["file"])
        if relative.is_absolute() or ".." in relative.parts or relative.suffix != ".eml":
            raise ValueError("fixture must be a relative .eml path inside the case bank")
        fixture = cases_root / relative
        if fixture.is_symlink() or not fixture.is_file():
            raise ValueError("fixture missing or symlink: " + relative.as_posix())
        if record["expected"] not in {"block", "deliver", "regression_contract"}:
            raise ValueError("unknown expected outcome: " + record["case_id"])
        metadata = {
            key: record[key]
            for key in ("case_id", "file", "family", "label", "expected", "group", "language")
        }
        metadata["fixture_sha256"] = file_hash(fixture)
        metadata["required_assertion_axes"] = [
            "threat", "classification", "authentication", "coverage", "data_security", "disposition"
        ]
        cases.append(metadata)

    capabilities = []
    for capability in manifest["capabilities"]:
        selected = [row for row in cases if row["family"] == capability["id"]]
        case_ids = sorted(row["case_id"] for row in selected)
        if canonical_hash(case_ids) != capability["case_set_sha256"]:
            raise ValueError("case-set hash mismatch: " + capability["id"])
        if len(case_ids) != capability["minimum_cases"]:
            raise ValueError("case count differs from frozen manifest: " + capability["id"])
        capabilities.append({**capability, "case_ids": case_ids})
    if {row["family"] for row in cases} != {row["id"] for row in capabilities}:
        raise ValueError("case family and capability membership differ")

    selection = sorted(row["file"] for row in cases)
    payload = {
        "schema_version": 1,
        "document_type": "ds_capability_replay_inventory",
        "milestone": "hypothesis_only",
        "selection": "all",
        "manifest_path": (relative_root / "capability_manifest.json").as_posix(),
        "manifest_version": manifest["manifest_version"],
        "manifest_sha256": manifest_hash,
        "labels_sha256": canonical_hash(labels),
        "case_content_binding_sha256": canonical_hash(cases),
        "capability_count": len(capabilities),
        "case_count": len(cases),
        "expected_counts": dict(sorted(Counter(row["expected"] for row in cases).items())),
        "source_label_counts": dict(sorted(Counter(row["label"] for row in cases).items())),
        "capabilities": capabilities,
        "cases": cases,
        "harness_environment": {
            "VIGILYX_REDTEAM_INCLUDE_SYNTH": "1",
            "VIGILYX_REDTEAM_CASES": ",".join(selection),
        },
        "selection_paths": selection,
        "limitations": [
            "Existing manifest hashes bind case IDs; this inventory additionally binds fixture bytes.",
            "This known development bank is evaluation-only and cannot train DS reliability or calibrate thresholds.",
            "The 92 block, 12 deliver and 1 coverage-contract expectations are separate denominators.",
            "No baseline or candidate pass sets are inferred from historical engine_status labels.",
            "A final severity match alone does not establish the six-layer or semantic-context contracts.",
            "Include nested traversal and the exact selection together; neither the default 93-case run nor unfiltered synth traversal is the full frozen bank.",
        ],
    }
    payload["inventory_sha256"] = canonical_hash(payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--baseline-manifest", type=Path)
    parser.add_argument("--baseline-inventory", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--selection-output", type=Path)
    args = parser.parse_args()
    try:
        inventory = build_inventory(args.repo.resolve(), args.baseline_manifest)
        if args.baseline_inventory is not None:
            baseline = load_json(args.baseline_inventory)
            for key in ("manifest_sha256", "labels_sha256", "case_content_binding_sha256"):
                if baseline.get(key) != inventory[key]:
                    raise ValueError("baseline/candidate inventory differs: " + key)
        rendered = json.dumps(inventory, ensure_ascii=False, indent=2) + "\n"
        if args.output is None:
            sys.stdout.write(rendered)
        else:
            # Never silently overwrite an already frozen inventory.
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(rendered)
        if args.selection_output is not None:
            with args.selection_output.open("x", encoding="utf-8") as stream:
                stream.write(inventory["harness_environment"]["VIGILYX_REDTEAM_CASES"] + "\n")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("inventory error: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
