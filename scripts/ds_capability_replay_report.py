#!/usr/bin/env python3
"""Compare complete frozen DS capability replays, without emitting mail contents.

Expected outcomes come from the immutable inventory, never historical engine
status. Legacy stdout supports disposition and level/class telemetry; it cannot
prove structured coverage. Optional DS_REPLAY_OUTCOME JSON records supply that
missing telemetry without changing model semantics.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

from ds_capability_inventory import BASELINE_MANIFEST_SHA256, canonical_hash


LEVELS = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
LEGACY = re.compile(
    r"\[(?P<file>[^\]\r\n]+\.eml)\] FINAL=(?P<level>\w+) "
    r"class=(?P<class>Some\(\w+\)|None) conf=(?P<confidence>[0-9.]+) modules="
)
FAILURE = re.compile(r"\[([^\]\r\n]+\.eml)\] (?:PARSE FAILED|module ([\w-]+) ERROR:)")
STRUCTURED_MARKER = "DS_REPLAY_OUTCOME "


def snake_case(value: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", value).lower()


def verify_inventory(path: Path) -> dict:
    inventory = json.loads(path.read_text(encoding="utf-8"))
    payload = dict(inventory)
    recorded_hash = payload.pop("inventory_sha256", None)
    if canonical_hash(payload) != recorded_hash:
        raise ValueError("inventory canonical hash mismatch")
    if inventory.get("manifest_sha256") != BASELINE_MANIFEST_SHA256:
        raise ValueError("inventory does not bind the established baseline manifest")
    if inventory.get("case_count") != 105 or inventory.get("capability_count") != 20:
        raise ValueError("the full 105 cases and 20 capabilities are required")
    cases = inventory["cases"]
    if canonical_hash(cases) != inventory["case_content_binding_sha256"]:
        raise ValueError("inventory case-content binding mismatch")
    if len(cases) != 105 or len({row["case_id"] for row in cases}) != 105:
        raise ValueError("inventory case IDs are missing or duplicated")
    # Legacy stdout uses basenames. Reject ambiguity rather than guessing.
    if len({Path(row["file"]).name for row in cases}) != 105:
        raise ValueError("legacy stdout cannot resolve duplicate fixture basenames")
    for capability in inventory["capabilities"]:
        ids = sorted(row["case_id"] for row in cases if row["family"] == capability["id"])
        if canonical_hash(ids) != capability["case_set_sha256"]:
            raise ValueError("capability membership differs from frozen hash")
    return inventory


def verify_severity_contract(path: Path, inventory: dict) -> dict:
    contract = json.loads(path.read_text(encoding="utf-8"))
    payload = dict(contract)
    recorded_hash = payload.pop("contract_sha256", None)
    if canonical_hash(payload) != recorded_hash:
        raise ValueError("severity contract canonical hash mismatch")
    if contract.get("document_type") != "ds_severity_restoration_contract":
        raise ValueError("unsupported severity contract type")
    for key in ("manifest_sha256", "inventory_sha256", "case_content_binding_sha256"):
        if contract.get(key) != inventory[key]:
            raise ValueError("severity contract inventory binding mismatch: " + key)
    targets = contract.get("severity_floors")
    if not isinstance(targets, list) or len(targets) != contract.get("case_count"):
        raise ValueError("severity contract target count mismatch")
    if not targets or len({row["case_id"] for row in targets}) != len(targets):
        raise ValueError("severity contract targets empty or duplicated")
    cases = {row["case_id"]: row for row in inventory["cases"]}
    for target in targets:
        original = cases.get(target["case_id"])
        if original is None or original["file"] != target.get("file"):
            raise ValueError("severity contract target is not in frozen inventory")
        if original["expected"] != "block":
            raise ValueError("severity target must not override a deliver/coverage label")
        if target.get("minimum_threat_level") not in LEVELS:
            raise ValueError("invalid minimum threat level in severity contract")
    invariants = contract.get("invariants", {})
    for key in ("all_105_expected_contracts_pass", "preserve_native_medium_plus_set", "all_12_ham_deliver", "classification_unchanged_for_all_105", "structured_coverage_unchanged_for_all_105"):
        if invariants.get(key) is not True:
            raise ValueError("severity contract cannot disable preservation invariant: " + key)
    return contract


def read_replay(path: Path, inventory: dict, exit_code: int | None, structured_path: Path | None = None) -> dict:
    encoded = path.read_bytes()
    cases_by_name = {Path(row["file"]).name: row for row in inventory["cases"]}
    cases_by_path = {row["file"]: row for row in inventory["cases"]}
    legacy = {}
    structured = {}
    errors = []
    failures = []
    counts = {"legacy": Counter(), "structured": Counter()}
    lines = encoded.decode("utf-8", errors="replace").splitlines()
    structured_bytes = structured_path.read_bytes() if structured_path else None
    if structured_bytes is not None:
        lines.extend(STRUCTURED_MARKER + line for line in structured_bytes.decode("utf-8").splitlines() if line.strip())
    for raw_line in lines:
        line = ANSI.sub("", raw_line)
        failure = FAILURE.search(line)
        if failure:
            failures.append({"file": failure.group(1), "kind": "module_error" if failure.group(2) else "parse_failure", "module": failure.group(2)})
        marker_index = line.find(STRUCTURED_MARKER)
        if marker_index >= 0:
            try:
                item = json.loads(line[marker_index + len(STRUCTURED_MARKER):])
                row = cases_by_path.get(item.get("file"))
                if row is None:
                    raise ValueError("unknown or non-relative structured fixture path")
                case_id = row["case_id"]
                counts["structured"][case_id] += 1
                level = item["threat_level"]
                coverage = item["inspection_coverage"]
                if level not in LEVELS or coverage not in {"complete", "limited", "unknown"}:
                    raise ValueError("invalid structured threat or coverage enum")
                if type(item["would_deliver"]) is not bool:
                    raise ValueError("would_deliver must be boolean")
                classification = item.get("classification")
                if classification is not None and not isinstance(classification, str):
                    raise ValueError("classification must be string or null")
                reasons = item.get("coverage_reasons", [])
                if not isinstance(reasons, list) or not all(isinstance(reason, str) for reason in reasons):
                    raise ValueError("coverage_reasons must be an array of strings")
                # Keep only defined telemetry, never summary/body/evidence snippets.
                structured[case_id] = {
                    "threat_level": level,
                    "classification": classification,
                    "inspection_coverage": coverage,
                    "coverage_reason_count": len(reasons),
                    "would_deliver": item["would_deliver"],
                    "telemetry_source": "structured",
                }
            except (ValueError, KeyError, TypeError) as exc:
                errors.append("invalid structured outcome: " + str(exc))
            continue
        match = LEGACY.search(line)
        if match is None:
            continue
        row = cases_by_name.get(match["file"])
        if row is None:
            errors.append("unexpected legacy fixture: " + match["file"])
            continue
        case_id = row["case_id"]
        counts["legacy"][case_id] += 1
        level = match["level"].lower()
        if level not in LEVELS:
            errors.append("invalid legacy threat enum: " + case_id)
            continue
        classification = None if match["class"] == "None" else snake_case(match["class"][5:-1])
        summary = line.split("] summary=", 1)[-1] if "] summary=" in line else ""
        legacy[case_id] = {
            "threat_level": level,
            "classification": classification,
            "inspection_coverage": None,
            "coverage_reason_count": None,
            "legacy_summary_reports_incomplete": any(marker in summary for marker in ("Inspection incomplete", "inspection coverage incomplete", "Quarantine required: inspection coverage")),
            "would_deliver": line.rstrip().endswith("==> DELIVERED (below quarantine)"),
            "telemetry_source": "legacy_stdout_coverage_unreported",
        }
    for kind, found in counts.items():
        errors.extend("duplicate " + kind + " outcome: " + case_id for case_id, count in found.items() if count != 1)
    for case_id in set(legacy) & set(structured):
        for key in ("threat_level", "classification", "would_deliver"):
            if legacy[case_id][key] != structured[case_id][key]:
                errors.append("legacy/structured disagreement: " + case_id + ":" + key)
    outcomes = {**legacy, **structured}
    expected_ids = {row["case_id"] for row in inventory["cases"]}
    missing = sorted(expected_ids - outcomes.keys())
    errors.extend("missing outcome: " + case_id for case_id in missing)
    if exit_code is None:
        errors.append("harness process exit code was not supplied")
    elif exit_code != 0:
        errors.append("harness process failed with exit code " + str(exit_code))
    if failures:
        errors.append("harness reported parse/module failures")
    evaluated = {}
    for row in inventory["cases"]:
        case_id = row["case_id"]
        observed = outcomes.get(case_id)
        if observed is None:
            state, reason = "unverified", "missing_outcome"
        elif row["expected"] == "block":
            state = "pass" if not observed["would_deliver"] else "fail"
            reason = "expected_inline_block"
        elif row["expected"] == "deliver":
            state = "pass" if observed["would_deliver"] else "fail"
            reason = "expected_inline_deliver"
        elif row["expected"] == "regression_contract":
            if observed["would_deliver"]:
                state, reason = "fail", "coverage_contract_delivered"
            elif observed["inspection_coverage"] is None:
                state, reason = "unverified", "legacy_stdout_does_not_report_structured_coverage"
            else:
                state = "pass" if observed["inspection_coverage"] == "limited" and observed["coverage_reason_count"] > 0 else "fail"
                reason = "expected_limited_coverage_with_reasons_and_non_delivery"
        else:
            state, reason = "unverified", "unknown_expected_contract"
        if observed is not None and observed["telemetry_source"] == "structured":
            expected_delivery = LEVELS[observed["threat_level"]] < LEVELS["medium"] and observed["inspection_coverage"] != "limited"
            if observed["would_deliver"] != expected_delivery:
                errors.append("level/coverage/disposition disagreement: " + case_id)
        evaluated[case_id] = {
            "file": row["file"], "family": row["family"], "expected": row["expected"],
            "contract_state": state, "contract_basis": reason,
            "native_threat_detected": bool(observed and LEVELS[observed["threat_level"]] >= LEVELS["medium"]) if row["expected"] == "block" else None,
            "observed": observed,
        }
    return {
        "log_sha256": "sha256:" + hashlib.sha256(encoded).hexdigest(),
        "structured_export_sha256": "sha256:" + hashlib.sha256(structured_bytes).hexdigest() if structured_bytes is not None else None,
        "process_exit_code": exit_code,
        "exact_case_set_and_execution_valid": not errors,
        "errors": sorted(set(errors)), "execution_failures": failures,
        "outcome_count": len(outcomes), "missing_case_ids": missing,
        "legacy_record_count": sum(counts["legacy"].values()),
        "structured_record_count": sum(counts["structured"].values()),
        "all_coverage_structurally_reported": len(structured) == 105,
        "expected_contract_counts": dict(sorted(Counter(row["contract_state"] for row in evaluated.values()).items())),
        "native_block_case_detection_count": sum(row["native_threat_detected"] is True for row in evaluated.values()),
        "native_block_case_denominator": 92,
        "cases": evaluated,
    }


def report(inventory: dict, baseline: dict, candidate: dict | None, require_native_threat_preservation: bool = False, severity_contract: dict | None = None) -> dict:
    capabilities = {}
    all_lost = []
    all_lost_native = []
    all_candidate_failures = []
    for capability in inventory["capabilities"]:
        ids = capability["case_ids"]
        def selected(replay: dict | None, state: str) -> list[str]:
            return sorted(case_id for case_id in ids if replay and replay["cases"][case_id]["contract_state"] == state)
        baseline_pass = selected(baseline, "pass")
        candidate_pass = selected(candidate, "pass") if candidate else None
        lost = sorted(set(baseline_pass) - set(candidate_pass)) if candidate else None
        gained = sorted(set(candidate_pass) - set(baseline_pass)) if candidate else None
        unchanged_failures = sorted(set(selected(baseline, "fail")) & set(selected(candidate, "fail"))) if candidate else None
        baseline_native = sorted(case_id for case_id in ids if baseline["cases"][case_id]["expected"] == "block" and baseline["cases"][case_id]["native_threat_detected"])
        candidate_native = sorted(case_id for case_id in ids if candidate["cases"][case_id]["expected"] == "block" and candidate["cases"][case_id]["native_threat_detected"]) if candidate else None
        lost_native = sorted(set(baseline_native) - set(candidate_native)) if candidate else None
        if lost:
            all_lost.extend(lost)
        if lost_native:
            all_lost_native.extend(lost_native)
        all_candidate_failures.extend(selected(candidate, "fail"))
        capabilities[capability["id"]] = {
            "case_set_sha256": capability["case_set_sha256"], "n": len(ids),
            "baseline_pass_case_ids": baseline_pass,
            "candidate_pass_case_ids": candidate_pass,
            "baseline_existing_contract_failures": selected(baseline, "fail"),
            "baseline_unverified_case_ids": selected(baseline, "unverified"),
            "candidate_contract_failures": selected(candidate, "fail") if candidate else None,
            "candidate_unverified_case_ids": selected(candidate, "unverified") if candidate else None,
            "lost_case_ids": lost, "gained_case_ids": gained,
            "both_fail_case_ids": unchanged_failures,
            "baseline_pass_set_preserved": not lost if candidate else None,
            "baseline_threat_supported_ids": baseline_native,
            "candidate_threat_supported_ids": candidate_native,
            "lost_native_threat_ids": lost_native,
            "native_threat_set_preserved": not lost_native if candidate else None,
        }
    comparison_valid = bool(candidate and baseline["exact_case_set_and_execution_valid"] and candidate["exact_case_set_and_execution_valid"])
    telemetry_changes = []
    if candidate:
        for case_id in baseline["cases"]:
            old = baseline["cases"][case_id]["observed"]
            new = candidate["cases"][case_id]["observed"]
            if old and new:
                changes = {key: {"baseline": old[key], "candidate": new[key]} for key in ("threat_level", "classification", "inspection_coverage", "would_deliver") if old[key] != new[key]}
                if changes:
                    telemetry_changes.append({"case_id": case_id, "changes": changes})
    classification_changes = [{"case_id": row["case_id"], **row["changes"]["classification"]} for row in telemetry_changes if "classification" in row["changes"]]
    coverage_differences = [{"case_id": row["case_id"], **row["changes"]["inspection_coverage"]} for row in telemetry_changes if "inspection_coverage" in row["changes"]]
    coverage_changes = [row for row in coverage_differences if row["baseline"] is not None and row["candidate"] is not None]
    coverage_availability_changes = [row for row in coverage_differences if row["baseline"] is None or row["candidate"] is None]
    severity_evaluation = None
    severity_gate_pass = True
    if severity_contract is not None:
        require_native_threat_preservation = True
        baseline_bound = baseline["structured_export_sha256"] == severity_contract["baseline"]["structured_export_sha256"]
        severity_cases = []
        for target in severity_contract["severity_floors"]:
            case_id = target["case_id"]
            old = baseline["cases"][case_id]["observed"]
            new = candidate["cases"][case_id]["observed"] if candidate else None
            minimum = target["minimum_threat_level"]
            severity_cases.append({
                "case_id": case_id, "file": target["file"], "minimum_threat_level": minimum,
                "baseline_threat_level": old["threat_level"] if old else None,
                "candidate_threat_level": new["threat_level"] if new else None,
                "baseline_meets_minimum": old is not None and LEVELS[old["threat_level"]] >= LEVELS[minimum],
                "candidate_meets_minimum": new is not None and LEVELS[new["threat_level"]] >= LEVELS[minimum] if candidate else None,
            })
        failing = [row["case_id"] for row in severity_cases if row["candidate_meets_minimum"] is False]
        unverified = [row["case_id"] for row in severity_cases if row["candidate_threat_level"] is None] if candidate else []
        ham = [row for row in candidate["cases"].values() if row["expected"] == "deliver"] if candidate else []
        invariant_results = {
            "exact_all_105_execution_valid": comparison_valid,
            "all_105_expected_contracts_pass": bool(candidate and candidate["expected_contract_counts"].get("pass", 0) == 105),
            "native_medium_plus_preserved": comparison_valid and not all_lost_native,
            "all_12_ham_deliver": len(ham) == 12 and all(row["contract_state"] == "pass" for row in ham),
            "classification_unchanged_for_all_105": comparison_valid and not classification_changes,
            "structured_coverage_unchanged_for_all_105": bool(candidate and baseline["all_coverage_structurally_reported"] and candidate["all_coverage_structurally_reported"] and not coverage_changes and not coverage_availability_changes),
        }
        severity_gate_pass = baseline_bound and not failing and not unverified and all(invariant_results.values()) if candidate else False
        severity_evaluation = {
            "contract_id": severity_contract["contract_id"], "contract_sha256": severity_contract["contract_sha256"],
            "baseline_export_binding_valid": baseline_bound, "target_count": len(severity_cases),
            "candidate_pass_count": sum(row["candidate_meets_minimum"] is True for row in severity_cases) if candidate else None,
            "failed_case_ids": failing if candidate else None, "unverified_case_ids": unverified if candidate else None,
            "invariant_results": invariant_results, "combined_gate_pass": severity_gate_pass if candidate else None,
            "cases": severity_cases,
        }
    if candidate is None:
        status = "baseline_only" if baseline["exact_case_set_and_execution_valid"] else "execution_invalid"
    elif not comparison_valid:
        status = "execution_invalid"
    elif all_lost:
        status = "disposition_contract_regression"
    elif all_lost_native:
        status = "native_threat_regression"
    elif severity_contract is not None and not severity_gate_pass:
        status = "severity_restoration_contract_failed"
    elif candidate["expected_contract_counts"].get("pass", 0) != 105:
        status = "expected_contract_gaps_remain"
    else:
        status = "expected_contracts_pass"
    return {
        "schema_version": 1, "document_type": "ds_capability_replay_comparison",
        "milestone": "hypothesis_only",
        "inventory_sha256": inventory["inventory_sha256"],
        "manifest_sha256": inventory["manifest_sha256"], "manifest_version": inventory["manifest_version"],
        "comparison_execution_valid": comparison_valid,
        "comparison_status": status,
        "baseline_passing_disposition_contracts_preserved": comparison_valid and not all_lost if candidate else None,
        "baseline_native_threat_set_preserved": comparison_valid and not all_lost_native if candidate else None,
        "native_threat_preservation_required": require_native_threat_preservation,
        "required_preservation_gates_pass": comparison_valid and not all_lost and (not require_native_threat_preservation or not all_lost_native) and severity_gate_pass if candidate else None,
        "severity_contract_evaluation": severity_evaluation,
        "candidate_all_105_expected_contracts_pass": bool(candidate and candidate["exact_case_set_and_execution_valid"] and candidate["expected_contract_counts"].get("pass", 0) == 105) if candidate else None,
        "full_six_layer_semantic_acceptance_supported": False,
        "baseline": baseline, "candidate": candidate, "capabilities": capabilities,
        "lost_case_ids": sorted(all_lost) if candidate else None,
        "lost_native_threat_ids": sorted(all_lost_native) if candidate else None,
        "candidate_contract_failure_case_ids": sorted(all_candidate_failures) if candidate else None,
        "telemetry_changes": telemetry_changes,
        "classification_changes": classification_changes,
        "coverage_changes": coverage_changes,
        "coverage_telemetry_availability_changes": coverage_availability_changes,
        "limitations": [
            "Frozen labels define disposition and one coverage contract, not complete classification/authentication/DLP/semantic expectations.",
            "Block success means would_deliver=false; native Medium+ detection is a separately reported 92-case metric.",
            "Native threat preservation independently compares expected-block cases that were Medium+ on the baseline, even when both versions quarantine.",
            "A baseline-passing subset check does not excuse cases where both baseline and candidate violate expected behavior.",
            "Legacy stdout does not report structured inspection_coverage; a summary marker is not promoted to verified coverage.",
            "This development-bank replay is not a blind estimate of production FPR/recall and does not validate learned reliability.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--baseline-log", required=True, type=Path)
    parser.add_argument("--baseline-exit-code", type=int)
    parser.add_argument("--baseline-jsonl", type=Path)
    parser.add_argument("--candidate-log", type=Path)
    parser.add_argument("--candidate-exit-code", type=int)
    parser.add_argument("--candidate-jsonl", type=Path)
    parser.add_argument("--require-native-threat-preservation", action="store_true")
    parser.add_argument("--severity-contract", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        inventory = verify_inventory(args.inventory)
        severity_contract = verify_severity_contract(args.severity_contract, inventory) if args.severity_contract else None
        baseline = read_replay(args.baseline_log, inventory, args.baseline_exit_code, args.baseline_jsonl)
        candidate = read_replay(args.candidate_log, inventory, args.candidate_exit_code, args.candidate_jsonl) if args.candidate_log else None
        result = report(inventory, baseline, candidate, args.require_native_threat_preservation, severity_contract)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        print(json.dumps({
            "output": str(args.output),
            "baseline": baseline["expected_contract_counts"],
            "candidate": candidate["expected_contract_counts"] if candidate else None,
            "baseline_execution_valid": baseline["exact_case_set_and_execution_valid"],
            "comparison_execution_valid": result["comparison_execution_valid"],
            "comparison_status": result["comparison_status"],
            "lost_case_ids": result["lost_case_ids"],
            "baseline_native_medium_plus": baseline["native_block_case_detection_count"],
            "candidate_native_medium_plus": candidate["native_block_case_detection_count"] if candidate else None,
            "native_block_denominator": 92,
            "lost_native_threat_ids": result["lost_native_threat_ids"],
            "native_threat_preservation_required": result["native_threat_preservation_required"],
            "required_preservation_gates_pass": result["required_preservation_gates_pass"],
            "classification_change_count": len(result["classification_changes"]),
            "coverage_change_count": len(result["coverage_changes"]),
            "coverage_telemetry_availability_change_count": len(result["coverage_telemetry_availability_changes"]),
            "severity_targets_passed": result["severity_contract_evaluation"]["candidate_pass_count"] if result["severity_contract_evaluation"] else None,
            "severity_targets_required": result["severity_contract_evaluation"]["target_count"] if result["severity_contract_evaluation"] else None,
            "severity_failed_case_ids": result["severity_contract_evaluation"]["failed_case_ids"] if result["severity_contract_evaluation"] else None,
            "full_six_layer_semantic_acceptance_supported": False,
        }, ensure_ascii=False))
        if not baseline["exact_case_set_and_execution_valid"] or (candidate is not None and not candidate["exact_case_set_and_execution_valid"]):
            return 2
        # An explicitly selected supplementary severity contract is a hard
        # opt-in gate. Default reporting retains its integrity-only exit code.
        if severity_contract is not None and candidate is not None and not result["required_preservation_gates_pass"]:
            return 3
        return 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print("replay report error: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
