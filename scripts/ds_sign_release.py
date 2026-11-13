#!/usr/bin/env python3
"""Sign an externally validated DS release; no bypass, activation, or key creation.

DS_MODEL_RELEASE_KEY_FILE must identify a protected regular file containing at
least 32 raw key bytes. A candidate training report is not a governance report.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

from ds_learned_model import (ContractError, integer, number, parameter_content_sha256,
                              read_json, validate_parameters, wilson)


REPOSITORY = Path(__file__).resolve().parents[1]
VALIDATOR = REPOSITORY / "scripts/governance/validate_acceptance.py"
HEX = re.compile(r"[0-9a-f]{64}\Z")
METRIC_FIELDS = ("holdout_negatives", "holdout_positives", "decision_threshold", "false_positive_budget",
                 "false_positive_upper_bound", "recall_lower_bound", "baseline_recall_lower_bound",
                 "brier", "baseline_brier", "review_cost", "baseline_review_cost",
                 "baseline_passing_case_ids", "candidate_passing_case_ids")


def _canonical_hash(value):
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def release_payload(parameter_hash, report_hash, manifest_hash):
    for digest in (parameter_hash, report_hash, manifest_hash):
        if not isinstance(digest, str) or not HEX.fullmatch(digest):
            raise ContractError("release hashes must be 64 lowercase hexadecimal characters")
    return ("vigilyx-ds-release-v1\n" + parameter_hash + "\n" + report_hash + "\n" + manifest_hash).encode("utf-8")


def _read_key(path):
    if not path:
        raise ContractError("DS_MODEL_RELEASE_KEY_FILE is required; no key is generated")
    key_path = Path(path)
    if key_path.is_symlink():
        raise ContractError("release key must not be a symbolic link")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(key_path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            raise ContractError("release key must be a regular file with no group/other access")
        if hasattr(os, "geteuid") and os.geteuid() not in (0, metadata.st_uid):
            raise ContractError("release key must belong to the signing user")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            key = handle.read(4097)
        if not 32 <= len(key) <= 4096:
            raise ContractError("release key must contain 32 to 4096 raw bytes")
        return key
    finally:
        os.close(fd)


def _nested(value, *keys):
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _matrix(raw, name):
    if not isinstance(raw, dict) or set(raw) != {"tp", "fp", "tn", "fn"}:
        raise ContractError(f"{name} must contain raw tp/fp/tn/fn counts")
    return {k: integer(v, name + "." + k) for k, v in raw.items()}


def _pass_ids(raw, name):
    if (not isinstance(raw, list) or any(not isinstance(v, str) or not v.strip() for v in raw)
            or len(set(raw)) != len(raw)):
        raise ContractError(f"{name} requires unique explicit case IDs")
    return set(raw)


def verified_metrics(plan, results):
    """Derive/check install metrics from the signed report, never training loss.

    The report producer remains responsible for honest human labels and raw
    prediction/cost provenance. Counts and confidence limits are recomputed here;
    whole-bank passing sets are independently checked by the governance process.
    """
    metrics = results.get("ds_learning_acceptance") if isinstance(results, dict) else None
    if not isinstance(metrics, dict) or not set(METRIC_FIELDS).issubset(metrics):
        raise ContractError("measured results.ds_learning_acceptance metrics are required")
    negatives = integer(metrics["holdout_negatives"], "holdout_negatives", 1)
    positives = integer(metrics["holdout_positives"], "holdout_positives", 1)
    threshold = number(metrics["decision_threshold"], "decision_threshold")
    planned_threshold = number(_nested(plan, "ds_learning_release_policy", "decision_threshold"),
                               "preregistered decision_threshold")
    if threshold != .40 or planned_threshold != .40:
        raise ContractError("release confusion matrices must use the live Medium threshold 0.40")
    if (metrics.get("decision_score") != "final_threat_risk"
            or metrics.get("policy_constraints_applied") is not True
            or metrics.get("coverage_or_disposition_used_as_threat_label") is not False):
        raise ContractError("release metrics must use final threat risk with policy, and independent threat labels")
    budget = number(metrics["false_positive_budget"], "false_positive_budget", 0, .01)
    planned_budget = _nested(plan, "ds_learning_release_policy", "false_positive_budget")
    if budget <= 0 or number(planned_budget, "preregistered false_positive_budget", 0, .01) != budget:
        raise ContractError("false-positive budget must match the preregistered DS policy")
    candidate = _matrix(_nested(results, "quality", "holdout", "confusion_matrix"), "candidate holdout")
    baseline = _matrix(metrics.get("baseline_confusion_matrix"), "baseline holdout")
    total = integer(_nested(results, "windows", "holdout", "n"), "holdout n", 1)
    for matrix in (candidate, baseline):
        if (matrix["fp"] + matrix["tn"] != negatives or matrix["tp"] + matrix["fn"] != positives
                or sum(matrix.values()) != total):
            raise ContractError("DS holdout class counts must match both raw matrices and the governed window")
    expected = {
        "false_positive_upper_bound": wilson(candidate["fp"], negatives)[1],
        "recall_lower_bound": wilson(candidate["tp"], positives)[0],
        "baseline_recall_lower_bound": wilson(baseline["tp"], positives)[0],
    }
    for field, computed in expected.items():
        reported = number(metrics[field], field)
        if not math.isclose(reported, computed, rel_tol=0, abs_tol=1e-12):
            raise ContractError(f"{field} differs from recomputed two-sided Wilson 95% bound")
    if expected["false_positive_upper_bound"] > budget:
        raise ContractError("holdout cannot establish the false-positive budget at 95% confidence")
    if expected["recall_lower_bound"] < expected["baseline_recall_lower_bound"]:
        raise ContractError("holdout recall lower bound regresses")
    brier = number(metrics["brier"], "brier")
    baseline_brier = number(metrics["baseline_brier"], "baseline_brier")
    cost = number(metrics["review_cost"], "review_cost", 0, math.inf)
    baseline_cost = number(metrics["baseline_review_cost"], "baseline_review_cost", 0, math.inf)
    if brier > baseline_brier or cost > baseline_cost:
        raise ContractError("measured Brier or review cost regresses")
    capabilities = _nested(results, "capability_preservation", "capabilities")
    if not isinstance(capabilities, dict) or not capabilities:
        raise ContractError("complete capability preservation results are required")
    sets = {}
    for role in ("baseline", "candidate"):
        complete = set()
        for capability_id, result in capabilities.items():
            if not isinstance(result, dict):
                raise ContractError("malformed capability result")
            ids = _pass_ids(result.get(role + "_pass_case_ids"), capability_id + "." + role)
            complete.update(capability_id + ":" + case_id for case_id in ids)
        reported = _pass_ids(metrics[role + "_passing_case_ids"], role + "_passing_case_ids")
        if reported != complete:
            raise ContractError(f"{role} passing IDs must equal the complete qualified capability passing set")
        sets[role] = complete
    if not sets["baseline"] or not sets["baseline"].issubset(sets["candidate"]):
        raise ContractError("complete baseline capabilities must be preserved")
    # Return precisely the Rust Acceptance metric fields, not matrix/metadata extras.
    output = {key: metrics[key] for key in METRIC_FIELDS}
    for role in sets:
        output[role + "_passing_case_ids"] = sorted(sets[role])
    return output


def sign_release(model_path, plan_path, results_path, capability_path, baseline_capability_path,
                 key_path=None):
    """Always execute the pinned governance validator before touching the key.

    Inputs are snapshotted byte-for-byte into a private directory so validation
    and the certificate bind the same bytes despite concurrent source edits.
    """
    paths = {"model": Path(model_path), "plan": Path(plan_path), "results": Path(results_path),
             "capabilities": Path(capability_path), "baseline_capabilities": Path(baseline_capability_path)}
    if not VALIDATOR.is_file():
        raise ContractError("required governance acceptance validator is missing")
    with tempfile.TemporaryDirectory(prefix="vigilyx-ds-release-") as temporary:
        snapshots, documents, digests = {}, {}, {}
        for name, path in paths.items():
            snapshot = Path(temporary) / (name + ".json")
            snapshot.write_bytes(path.read_bytes())
            documents[name], digests[name] = read_json(snapshot)
            snapshots[name] = snapshot
        model = validate_parameters(documents["model"])
        if model["training_status"] != "validated" or model["calibration"] is None:
            raise ContractError("a staged validated model with fitted calibration is required")
        content_hash = parameter_content_sha256(model)
        identity = "sha256:" + content_hash
        bindings = {
            "plan.environment.candidate_artifact_id": _nested(documents["plan"], "environment", "candidate_artifact_id"),
            "results.capability_preservation.candidate_artifact_id": _nested(documents["results"], "capability_preservation", "candidate_artifact_id"),
            "results.release.artifact_id": _nested(documents["results"], "release", "artifact_id"),
        }
        for field, value in bindings.items():
            if value != identity:
                raise ContractError(f"{field} must bind the exact staged parameter content hash")
        manifest_hash = _canonical_hash(documents["capabilities"])
        for name in ("plan", "results"):
            if _nested(documents[name], "capability_preservation", "manifest_sha256") != "sha256:" + manifest_hash:
                raise ContractError(f"{name} capability manifest hash mismatch")
        command = [sys.executable, str(VALIDATOR), str(snapshots["plan"]), str(snapshots["results"]),
                   "--capability-manifest", str(snapshots["capabilities"]),
                   "--baseline-capability-manifest", str(snapshots["baseline_capabilities"]),
                   "--require-milestone", "release_ready", "--json"]
        checked = subprocess.run(command, capture_output=True, text=True, check=False, timeout=60)
        if checked.returncode != 0:
            # Do not echo full reports or protected corpus details to shell logs.
            raise ContractError(f"governance release validation failed (exit {checked.returncode}); no certificate issued")
        try:
            validation = json.loads(checked.stdout)
        except json.JSONDecodeError as exc:
            raise ContractError("governance validator returned invalid JSON") from exc
        if (not isinstance(validation, dict) or validation.get("milestone") != "release_ready"
                or validation.get("schema_errors") != [] or validation.get("gate_failures") != []
                or validation.get("release_gaps") != []):
            raise ContractError("governance validator did not confirm all release gates")
        acceptance_metrics = verified_metrics(documents["plan"], documents["results"])
        key = _read_key(key_path if key_path is not None else os.environ.get("DS_MODEL_RELEASE_KEY_FILE"))
        payload = release_payload(content_hash, digests["results"], manifest_hash)
        signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
        signed_fields = {"parameter_sha256": content_hash, "report_sha256": digests["results"],
                         "capability_manifest_sha256": manifest_hash, "release_signature": signature}
        return {"schema_version": 1, **signed_fields,
                "parameter_artifact_sha256": digests["model"],
                "signature_algorithm": "hmac-sha256",
                "signature_protocol": "vigilyx-ds-release-v1",
                "governance_milestone": "release_ready", "automatic_activation": False,
                "acceptance": {**acceptance_metrics, **signed_fields},
                "validator_sha256": hashlib.sha256(VALIDATOR.read_bytes()).hexdigest()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--capability-manifest", required=True)
    parser.add_argument("--baseline-capability-manifest", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        inputs = [args.model, args.plan, args.results, args.capability_manifest, args.baseline_capability_manifest]
        output = Path(args.output).resolve()
        key_path = os.environ.get("DS_MODEL_RELEASE_KEY_FILE")
        if key_path:
            inputs.append(key_path)
        if output in (Path(path).resolve() for path in inputs):
            raise ContractError("certificate must not overwrite an input or signing key")
        certificate = sign_release(args.model, args.plan, args.results, args.capability_manifest,
                                   args.baseline_capability_manifest)
        # Exclusive creation prevents accidentally replacing an existing release.
        raw = (json.dumps(certificate, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
        print(json.dumps({"certificate_written": str(output),
                          "parameter_sha256": certificate["parameter_sha256"], "automatic_activation": False}))
    except (ContractError, OSError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
