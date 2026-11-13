#!/usr/bin/env python3
"""Compare measured shadow results with a preregistered governance plan."""

from __future__ import annotations

import argparse
import json
import math
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from validate_shadow_plan import (
    REQUIRED_STRATA,
    WINDOWS,
    canonical_plan_sha256,
    immutable_identifier,
    load_json,
    parse_time,
    validate_capability_manifest_binding,
    validate_capability_manifest_unchanged,
    validate_git_binding,
    validate_plan,
)


MILESTONE_ORDER = {
    "hypothesis_only": 0,
    "implemented": 1,
    "shadow_validated": 2,
    "release_ready": 3,
}
ACCEPTANCE_WINDOWS = ("validation", "holdout")
REQUIRED_EXECUTION_FLAGS = {
    "shadow_only": True,
    "production_disposition_mutation": False,
    "global_thresholds_unchanged": True,
    "six_layer_outcomes": True,
    "per_bucket_metrics": True,
    "separate_stage_deltas": True,
}
CONFUSION_KEYS = {"tp", "fp", "tn", "fn"}
WEIGHT_BUCKETS = {"safe", "low", "medium", "high_critical"}
SIX_LAYER_VALUES = {
    "threat": {"unknown", "safe", "low", "medium", "high", "critical"},
    "classification": {
        "undetermined",
        "business",
        "transactional",
        "marketing",
        "spam",
        "scam",
        "phishing",
        "impersonation",
        "social_engineering",
        "bec",
        "malware",
    },
    "authentication": {
        "local_pass",
        "trusted_gateway_pass",
        "local_fail_original_bytes",
        "trusted_gateway_fail",
        "unknown_modified",
        "unknown_untrusted_claim",
        "not_present",
    },
    "coverage": {"complete", "limited", "insufficient", "blocked"},
    "data_security": {"none", "audit_hit", "policy_hit", "blocked"},
    "disposition": {"accept", "tag", "review", "tempfail", "quarantine", "reject", "mirror_audit"},
}


def positive_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def nonnegative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def finite_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def window_sample_targets(plan: dict[str, Any], window: str) -> dict[str, int]:
    corpus = plan.get("corpus", {})
    cohort = corpus.get(window, {}) if isinstance(corpus, dict) else {}
    strata = cohort.get("strata", {}) if isinstance(cohort, dict) else {}
    return {name: value for name, value in strata.items() if isinstance(value, int) and not isinstance(value, bool)}


def validate_result_windows(
    plan: dict[str, Any],
    results: dict[str, Any],
    schema_errors: list[str],
    gate_failures: list[str],
) -> dict[str, int]:
    windows = results.get("windows")
    if not isinstance(windows, dict) or set(windows) != set(WINDOWS):
        schema_errors.append("results.windows must provide development, validation, and holdout")
        return {}
    totals: dict[str, int] = {}
    for window in WINDOWS:
        prefix = f"results.windows.{window}"
        value = windows[window]
        if not isinstance(value, dict):
            schema_errors.append(f"{prefix} must be an object")
            continue
        n = value.get("n")
        if not positive_integer(n):
            schema_errors.append(f"{prefix}.n must be a positive integer")
        strata = value.get("strata")
        if not isinstance(strata, dict) or set(strata) != REQUIRED_STRATA:
            schema_errors.append(f"{prefix}.strata must contain exactly the five required strata")
            continue
        if not all(positive_integer(item) for item in strata.values()):
            schema_errors.append(f"{prefix}.strata values must be positive integers")
            continue
        if n != sum(strata.values()):
            schema_errors.append(f"{prefix}.n must equal the sum of its strata")
        if positive_integer(n) and n == sum(strata.values()):
            totals[window] = n
        for name, minimum in window_sample_targets(plan, window).items():
            if strata[name] < minimum:
                gate_failures.append(
                    f"{prefix}.strata.{name}={strata[name]} is below the preregistered minimum {minimum}"
                )
        sealed = value.get("sealed")
        if window == "holdout" and sealed is not True:
            gate_failures.append("results.windows.holdout.sealed must be true")
        if window != "holdout" and sealed is True:
            gate_failures.append(f"results.windows.{window}.sealed must be false")
    return totals


def validate_result_labeling(
    plan: dict[str, Any],
    results: dict[str, Any],
    totals: dict[str, int],
    schema_errors: list[str],
    gate_failures: list[str],
) -> None:
    labeling = results.get("labeling")
    if not isinstance(labeling, dict) or set(labeling) != set(WINDOWS):
        schema_errors.append("results.labeling must provide development, validation, and holdout")
        return
    plan_labeling = plan.get("labeling", {})
    planned_review = plan_labeling.get("second_review_n", {}) if isinstance(plan_labeling, dict) else {}
    for window in WINDOWS:
        prefix = f"results.labeling.{window}"
        item = labeling[window]
        if not isinstance(item, dict):
            schema_errors.append(f"{prefix} must be an object")
            continue
        kappa = item.get("kappa")
        if not finite_number(kappa):
            schema_errors.append(f"{prefix}.kappa must be a finite number")
        minimum_kappa = plan_labeling.get("minimum_kappa", 0.75)
        if not finite_number(minimum_kappa):
            minimum_kappa = 0.75
        elif finite_number(kappa) and kappa < minimum_kappa:
            gate_failures.append(
                f"{prefix}.kappa={kappa} is below the preregistered minimum {minimum_kappa}"
            )
        review_n = item.get("second_review_n")
        if not positive_integer(review_n):
            schema_errors.append(f"{prefix}.second_review_n must be a positive integer")
        else:
            planned = planned_review.get(window) if isinstance(planned_review, dict) else None
            minimum = max(80, math.ceil(totals.get(window, 0) * 0.20))
            if not positive_integer(planned):
                schema_errors.append(f"plan.labeling.second_review_n.{window} is missing")
            elif review_n < planned:
                gate_failures.append(f"{prefix}.second_review_n={review_n} is below the planned {planned}")
            if review_n < minimum:
                gate_failures.append(f"{prefix}.second_review_n={review_n} is below the 20%/80 minimum {minimum}")
            if review_n > totals.get(window, 0):
                schema_errors.append(f"{prefix}.second_review_n cannot exceed that window cohort")


def validate_confusion_matrix(
    value: Any,
    prefix: str,
    expected_n: int | None,
    schema_errors: list[str],
) -> dict[str, int] | None:
    if not isinstance(value, dict) or set(value) != CONFUSION_KEYS:
        schema_errors.append(f"{prefix} must contain exactly tp, fp, tn, and fn")
        return None
    if not all(nonnegative_integer(item) for item in value.values()):
        schema_errors.append(f"{prefix} values must be non-negative integers")
        return None
    matrix = {name: value[name] for name in CONFUSION_KEYS}
    if expected_n is not None and sum(matrix.values()) != expected_n:
        schema_errors.append(f"{prefix} must sum to the window or stratum n={expected_n}")
    return matrix


def validate_six_layer_counts(
    value: Any,
    prefix: str,
    expected_n: int,
    schema_errors: list[str],
) -> None:
    if not isinstance(value, dict) or set(value) != set(SIX_LAYER_VALUES):
        schema_errors.append(f"{prefix} must provide all six outcome dimensions")
        return
    for dimension, allowed_values in SIX_LAYER_VALUES.items():
        counts = value.get(dimension)
        dimension_prefix = f"{prefix}.{dimension}"
        if not isinstance(counts, dict) or not counts:
            schema_errors.append(f"{dimension_prefix} must be a non-empty count object")
            continue
        unknown = sorted(set(counts) - allowed_values)
        if unknown:
            schema_errors.append(f"{dimension_prefix} has unknown labels: {', '.join(unknown)}")
        if not all(nonnegative_integer(count) for count in counts.values()):
            schema_errors.append(f"{dimension_prefix} values must be non-negative integers")
        elif sum(counts.values()) != expected_n:
            schema_errors.append(f"{dimension_prefix} must sum to window n={expected_n}")


def validate_disagreement_matrices(
    value: Any,
    prefix: str,
    expected_review_n: int,
    schema_errors: list[str],
) -> None:
    if not isinstance(value, dict) or set(value) != set(SIX_LAYER_VALUES):
        schema_errors.append(f"{prefix} must provide a matrix for all six outcome dimensions")
        return
    for dimension, allowed_values in SIX_LAYER_VALUES.items():
        matrix = value.get(dimension)
        matrix_prefix = f"{prefix}.{dimension}"
        if not isinstance(matrix, dict) or not matrix:
            schema_errors.append(f"{matrix_prefix} must be a non-empty reviewer-label matrix")
            continue
        total = 0
        valid = True
        for first_label, row in matrix.items():
            if first_label not in allowed_values or not isinstance(row, dict) or not row:
                valid = False
                continue
            for second_label, count in row.items():
                if second_label not in allowed_values or not nonnegative_integer(count):
                    valid = False
                    continue
                total += count
        if not valid:
            schema_errors.append(f"{matrix_prefix} contains an invalid label, row, or count")
        elif total != expected_review_n:
            schema_errors.append(
                f"{matrix_prefix} must sum to second_review_n={expected_review_n}"
            )


def validate_quality_artifacts(
    results: dict[str, Any],
    totals: dict[str, int],
    schema_errors: list[str],
) -> None:
    quality = results.get("quality")
    if not isinstance(quality, dict) or set(quality) != set(WINDOWS):
        schema_errors.append("results.quality must provide development, validation, and holdout")
        return
    labeling = results.get("labeling")
    windows = results.get("windows")
    if not isinstance(labeling, dict) or not isinstance(windows, dict):
        return
    for window in WINDOWS:
        item = quality.get(window)
        prefix = f"results.quality.{window}"
        expected_n = totals.get(window)
        if not isinstance(item, dict) or expected_n is None:
            schema_errors.append(f"{prefix} must be an object")
            continue
        overall = validate_confusion_matrix(
            item.get("confusion_matrix"), f"{prefix}.confusion_matrix", expected_n, schema_errors
        )
        per_bucket = item.get("per_bucket_confusion_matrices")
        strata = windows.get(window, {}).get("strata") if isinstance(windows.get(window), dict) else None
        bucket_matrices: dict[str, dict[str, int]] = {}
        if not isinstance(per_bucket, dict) or set(per_bucket) != REQUIRED_STRATA:
            schema_errors.append(
                f"{prefix}.per_bucket_confusion_matrices must contain exactly the five required strata"
            )
        elif isinstance(strata, dict):
            for bucket in sorted(REQUIRED_STRATA):
                matrix = validate_confusion_matrix(
                    per_bucket[bucket],
                    f"{prefix}.per_bucket_confusion_matrices.{bucket}",
                    strata.get(bucket),
                    schema_errors,
                )
                if matrix is not None:
                    bucket_matrices[bucket] = matrix
        if overall is not None and len(bucket_matrices) == len(REQUIRED_STRATA):
            for key in CONFUSION_KEYS:
                bucket_total = sum(matrix[key] for matrix in bucket_matrices.values())
                if bucket_total != overall[key]:
                    schema_errors.append(
                        f"{prefix}: per-bucket {key} total {bucket_total} does not match overall {overall[key]}"
                    )

        weights = item.get("traffic_weights")
        if not isinstance(weights, dict) or set(weights) != WEIGHT_BUCKETS:
            schema_errors.append(f"{prefix}.traffic_weights must provide safe, low, medium, and high_critical")
        elif not all(finite_number(weight) and 0.0 <= weight <= 1.0 for weight in weights.values()):
            schema_errors.append(f"{prefix}.traffic_weights values must be finite proportions")
        elif not math.isclose(sum(weights.values()), 1.0, rel_tol=0.0, abs_tol=1e-9):
            schema_errors.append(f"{prefix}.traffic_weights must sum to 1.0")

        validate_six_layer_counts(
            item.get("six_layer_counts"), f"{prefix}.six_layer_counts", expected_n, schema_errors
        )
        review_item = labeling.get(window)
        review_n = review_item.get("second_review_n") if isinstance(review_item, dict) else None
        if positive_integer(review_n):
            validate_disagreement_matrices(
                item.get("disagreement_matrices"),
                f"{prefix}.disagreement_matrices",
                review_n,
                schema_errors,
            )


def validate_cohort_audit(results: dict[str, Any], schema_errors: list[str]) -> None:
    audit = results.get("cohort_audit")
    if not isinstance(audit, dict):
        schema_errors.append("results.cohort_audit must be an object")
        return
    for field in (
        "sampling_seed_verified",
        "deduplication_method_verified",
        "campaign_copies_removed",
    ):
        if audit.get(field) is not True:
            schema_errors.append(f"results.cohort_audit.{field} must be true")
    overlap = audit.get("cross_window_overlap")
    if not nonnegative_integer(overlap) or overlap != 0:
        schema_errors.append("results.cohort_audit.cross_window_overlap must be integer 0")


def validate_capability_preservation(
    plan: dict[str, Any],
    results: dict[str, Any],
    schema_errors: list[str],
    gate_failures: list[str],
) -> None:
    plan_contract = plan.get("capability_preservation")
    result_contract = results.get("capability_preservation")
    if not isinstance(plan_contract, dict):
        return
    if not isinstance(result_contract, dict):
        schema_errors.append("results.capability_preservation must be an object")
        return
    if result_contract.get("manifest_version") != plan_contract.get("manifest_version"):
        schema_errors.append(
            "results.capability_preservation.manifest_version must match the plan"
        )
    if result_contract.get("manifest_sha256") != plan_contract.get("manifest_sha256"):
        schema_errors.append(
            "results.capability_preservation.manifest_sha256 must match the plan"
        )
    environment = plan.get("environment")
    if not isinstance(environment, dict):
        environment = {}
    for field in ("baseline_artifact_id", "candidate_artifact_id"):
        if result_contract.get(field) != environment.get(field):
            schema_errors.append(
                f"results.capability_preservation.{field} must match plan.environment.{field}"
            )

    expected_items = plan_contract.get("required_capabilities")
    expected: dict[str, dict[str, Any]] = {}
    if isinstance(expected_items, list):
        for item in expected_items:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                expected[item["id"]] = item
    actual = result_contract.get("capabilities")
    if not isinstance(actual, dict) or set(actual) != set(expected):
        schema_errors.append(
            "results.capability_preservation.capabilities must exactly match all required capability ids"
        )
        return
    for capability_id, planned in expected.items():
        value = actual[capability_id]
        prefix = f"results.capability_preservation.capabilities.{capability_id}"
        if not isinstance(value, dict):
            schema_errors.append(f"{prefix} must be an object")
            continue
        if value.get("case_set_sha256") != planned.get("case_set_sha256"):
            schema_errors.append(f"{prefix}.case_set_sha256 must match the frozen plan case set")
        n = value.get("n")
        minimum_cases = planned.get("minimum_cases")
        if not positive_integer(n):
            schema_errors.append(f"{prefix}.n must be a positive integer")
        elif positive_integer(minimum_cases) and n < minimum_cases:
            gate_failures.append(
                f"{prefix}.n={n} is below minimum_cases={minimum_cases}"
            )
        pass_sets: dict[str, set[str]] = {}
        for field in ("baseline_pass_case_ids", "candidate_pass_case_ids"):
            case_ids = value.get(field)
            if (
                not isinstance(case_ids, list)
                or not case_ids
                or not all(isinstance(case_id, str) and case_id.strip() for case_id in case_ids)
            ):
                schema_errors.append(f"{prefix}.{field} must be a non-empty string array")
                continue
            if len(set(case_ids)) != len(case_ids):
                schema_errors.append(f"{prefix}.{field} must contain unique case ids")
                continue
            if positive_integer(n) and len(case_ids) > n:
                schema_errors.append(f"{prefix}.{field} cannot contain more than n cases")
                continue
            pass_sets[field] = set(case_ids)
        baseline = pass_sets.get("baseline_pass_case_ids")
        candidate = pass_sets.get("candidate_pass_case_ids")
        if baseline is not None and candidate is not None:
            lost = sorted(baseline - candidate)
            if lost:
                gate_failures.append(
                    f"capability regression {capability_id}: candidate lost baseline-passing cases: "
                    + ", ".join(lost)
                )


def expected_hypotheses(plan: dict[str, Any], schema_errors: list[str]) -> dict[tuple[str, str], dict[str, Any]]:
    output: dict[tuple[str, str], dict[str, Any]] = {}
    stages = plan.get("stages", [])
    if not isinstance(stages, list):
        return output
    for stage_index, stage in enumerate(stages):
        if not isinstance(stage, dict):
            continue
        stage_id = stage.get("id")
        hypotheses = stage.get("hypotheses", [])
        if not isinstance(stage_id, str) or not isinstance(hypotheses, list):
            continue
        for hypothesis_index, hypothesis in enumerate(hypotheses):
            if not isinstance(hypothesis, dict):
                continue
            metric = hypothesis.get("metric")
            if not isinstance(metric, str):
                continue
            key = (stage_id, metric)
            if key in output:
                schema_errors.append(
                    f"plan.stages[{stage_index}].hypotheses[{hypothesis_index}] duplicates metric {metric!r}"
                )
            output[key] = hypothesis
    return output


def validate_measurements(
    plan: dict[str, Any],
    results: dict[str, Any],
    totals: dict[str, int],
    schema_errors: list[str],
    gate_failures: list[str],
) -> bool:
    measurements = results.get("measurements")
    if not isinstance(measurements, list) or not measurements:
        schema_errors.append("results.measurements must be a non-empty array")
        return False
    actual: dict[tuple[str, str, str], dict[str, Any]] = {}
    for index, measurement in enumerate(measurements):
        prefix = f"results.measurements[{index}]"
        if not isinstance(measurement, dict):
            schema_errors.append(f"{prefix} must be an object")
            continue
        stage_id = measurement.get("stage_id")
        window = measurement.get("window")
        metric = measurement.get("metric")
        if not isinstance(stage_id, str) or not isinstance(window, str) or not isinstance(metric, str):
            schema_errors.append(f"{prefix} requires string stage_id, window, and metric")
            continue
        if window not in ACCEPTANCE_WINDOWS:
            schema_errors.append(f"{prefix}.window must be validation or holdout")
            continue
        if not positive_integer(measurement.get("n")):
            schema_errors.append(f"{prefix}.n must be a positive integer")
        elif window in totals and measurement["n"] > totals[window]:
            schema_errors.append(f"{prefix}.n cannot exceed results.windows.{window}.n")
        if not finite_number(measurement.get("value")):
            schema_errors.append(f"{prefix}.value must be a finite number")
        key = (stage_id, window, metric)
        if key in actual:
            schema_errors.append(f"{prefix} duplicates stage/window/metric {key!r}")
        actual[key] = measurement

    hypotheses = expected_hypotheses(plan, schema_errors)
    for stage_id, window, metric in actual:
        if (stage_id, metric) not in hypotheses:
            schema_errors.append(
                f"results.measurements contains an unregistered stage/metric: {stage_id}/{metric}"
            )
    all_passed = True
    for (stage_id, metric), hypothesis in hypotheses.items():
        expected = hypothesis.get("expected", {})
        for window in ACCEPTANCE_WINDOWS:
            measurement = actual.get((stage_id, window, metric))
            prefix = f"{stage_id}/{window}/{metric}"
            if measurement is None:
                gate_failures.append(f"missing preregistered measurement: {prefix}")
                all_passed = False
                continue
            minimum_n = hypothesis.get("minimum_n")
            if positive_integer(minimum_n) and measurement.get("n", 0) < minimum_n:
                gate_failures.append(
                    f"{prefix}: n={measurement['n']} is below preregistered minimum_n={minimum_n}"
                )
                all_passed = False
            if hypothesis.get("unit") == "proportion":
                numerator_count = measurement.get("numerator_count")
                denominator_count = measurement.get("denominator_count")
                if not nonnegative_integer(numerator_count):
                    schema_errors.append(f"{prefix}: numerator_count must be a non-negative integer")
                    all_passed = False
                if not positive_integer(denominator_count):
                    schema_errors.append(f"{prefix}: denominator_count must be a positive integer")
                    all_passed = False
                elif positive_integer(measurement.get("n")) and measurement["n"] != denominator_count:
                    schema_errors.append(f"{prefix}: n must equal denominator_count")
                    all_passed = False
                if (
                    nonnegative_integer(numerator_count)
                    and positive_integer(denominator_count)
                    and numerator_count > denominator_count
                ):
                    schema_errors.append(f"{prefix}: numerator_count cannot exceed denominator_count")
                    all_passed = False
                value = measurement.get("value")
                if (
                    nonnegative_integer(numerator_count)
                    and positive_integer(denominator_count)
                    and finite_number(value)
                    and not math.isclose(
                        value,
                        numerator_count / denominator_count,
                        rel_tol=0.0,
                        abs_tol=1e-12,
                    )
                ):
                    schema_errors.append(f"{prefix}: value must equal numerator_count / denominator_count")
                    all_passed = False
            if isinstance(expected, dict) and finite_number(expected.get("min")) and finite_number(expected.get("max")):
                value = measurement.get("value")
                if finite_number(value) and not expected["min"] <= value <= expected["max"]:
                    gate_failures.append(
                        f"{prefix}: value={value} is outside preregistered range "
                        f"[{expected['min']}, {expected['max']}]"
                    )
                    all_passed = False
    return all_passed


def uncertainty_half_width(n: int) -> float:
    """Worst-case normal 95% half-width for a proportion at p=0.5."""
    return 0.98 / math.sqrt(n)


def evaluate(plan: Any, results: Any, *, as_of: datetime | None = None) -> dict[str, Any]:
    schema_errors: list[str] = []
    gate_failures: list[str] = []
    release_gaps: list[str] = []
    if not isinstance(plan, dict):
        return {"schema_errors": ["plan root must be an object"], "gate_failures": [], "milestone": "hypothesis_only"}
    plan_errors = validate_plan(plan, as_of=as_of)
    if plan_errors:
        schema_errors.extend(f"plan: {error}" for error in plan_errors)
    if plan.get("version") != 2:
        schema_errors.append("acceptance validation requires a v2 plan")
    if not isinstance(results, dict):
        schema_errors.append("results root must be an object")
        return {"schema_errors": schema_errors, "gate_failures": gate_failures, "milestone": "hypothesis_only"}

    try:
        expected_hash = canonical_plan_sha256(plan)
    except (TypeError, ValueError) as exc:
        expected_hash = None
        schema_errors.append(f"plan cannot be canonically hashed: {exc}")
    if results.get("plan_sha256") != expected_hash:
        schema_errors.append("results.plan_sha256 must match the canonical preregistered plan hash")
    observed_at = results.get("observed_at")
    observed_errors: list[str] = []
    observed_time = parse_time(observed_at, "results.observed_at", observed_errors)
    schema_errors.extend(observed_errors)
    corpus = plan.get("corpus", {})
    holdout = corpus.get("holdout", {}) if isinstance(corpus, dict) else {}
    holdout_end_errors: list[str] = []
    holdout_end = parse_time(holdout.get("end"), "holdout.end", holdout_end_errors) if isinstance(holdout, dict) else None
    if observed_time is not None and holdout_end is not None and observed_time < holdout_end:
        gate_failures.append("results.observed_at must be at or after holdout.end")
    if as_of is not None and observed_time is not None and observed_time > as_of:
        gate_failures.append("results.observed_at must not be later than --as-of")

    execution = results.get("execution")
    if not isinstance(execution, dict):
        schema_errors.append("results.execution must be an object")
    else:
        for name, expected in REQUIRED_EXECUTION_FLAGS.items():
            if execution.get(name) is not expected:
                gate_failures.append(f"results.execution.{name} must be {str(expected).lower()}")
        if execution.get("rollback_triggered") is not False:
            gate_failures.append("results.execution.rollback_triggered must be false")

    totals = validate_result_windows(plan, results, schema_errors, gate_failures)
    validate_result_labeling(plan, results, totals, schema_errors, gate_failures)
    validate_cohort_audit(results, schema_errors)
    validate_capability_preservation(plan, results, schema_errors, gate_failures)
    validate_quality_artifacts(results, totals, schema_errors)
    measurements_passed = validate_measurements(plan, results, totals, schema_errors, gate_failures)
    if not measurements_passed:
        gate_failures.append("one or more preregistered validation/holdout hypotheses did not pass")

    if schema_errors:
        milestone = "hypothesis_only"
    elif not gate_failures:
        milestone = "shadow_validated"
    else:
        milestone = "implemented"

    release = results.get("release")
    if not isinstance(release, dict):
        release_gaps.append("results.release is missing")
    else:
        artifact_id = release.get("artifact_id")
        if not immutable_identifier(artifact_id):
            release_gaps.append("results.release.artifact_id must be an immutable identifier")
        if release.get("rollback_verified") is not True:
            release_gaps.append("results.release.rollback_verified must be true")
        if not immutable_identifier(release.get("rollback_evidence_id")):
            release_gaps.append("results.release.rollback_evidence_id must be an immutable identifier")
        if release.get("deployment_verified") is not True:
            release_gaps.append("results.release.deployment_verified must be true")
        if not immutable_identifier(release.get("deployment_evidence_id")):
            release_gaps.append("results.release.deployment_evidence_id must be an immutable identifier")
        owner = plan.get("rollback", {}).get("owner") if isinstance(plan.get("rollback"), dict) else None
        if release.get("rollback_owner") != owner:
            release_gaps.append("results.release.rollback_owner must match plan.rollback.owner")
        mode = plan.get("environment", {}).get("deployment_mode") if isinstance(plan.get("environment"), dict) else None
        if release.get("deployment_mode") != mode:
            release_gaps.append("results.release.deployment_mode must match plan.environment.deployment_mode")
        if release.get("disposition_reviewed") is not True:
            release_gaps.append("results.release.disposition_reviewed must be true")
        if not immutable_identifier(release.get("disposition_evidence_id")):
            release_gaps.append("results.release.disposition_evidence_id must be an immutable identifier")
        if not immutable_identifier(release.get("registry_validation_evidence_id")):
            release_gaps.append(
                "results.release.registry_validation_evidence_id must be an immutable identifier"
            )
        if not immutable_identifier(release.get("capability_evidence_id")):
            release_gaps.append(
                "results.release.capability_evidence_id must be an immutable identifier"
            )
        if release.get("owner") != owner:
            release_gaps.append("results.release.owner must match plan.rollback.owner")
    if milestone == "shadow_validated" and not release_gaps:
        milestone = "release_ready"

    resolutions = {
        window: {
            "n": totals[window],
            "worst_case_95pct_proportion_half_width": uncertainty_half_width(totals[window]),
        }
        for window in WINDOWS
        if window in totals
    }
    return {
        "schema_errors": schema_errors,
        "gate_failures": gate_failures,
        "release_gaps": release_gaps,
        "milestone": milestone,
        "resolutions": resolutions,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("results", type=Path)
    parser.add_argument("--as-of", type=str)
    parser.add_argument("--require-milestone", choices=sorted(MILESTONE_ORDER), default="shadow_validated")
    parser.add_argument("--git-repo", type=Path)
    parser.add_argument("--git-commit", type=str)
    parser.add_argument("--git-path", type=str)
    parser.add_argument(
        "--capability-manifest",
        type=Path,
        help="complete external capability manifest required for v2 acceptance",
    )
    parser.add_argument(
        "--baseline-capability-manifest",
        type=Path,
        help="capability manifest from the baseline release; must match during detector changes",
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()
    try:
        plan = load_json(args.plan)
        results = load_json(args.results)
        capability_manifest = (
            load_json(args.capability_manifest)
            if args.capability_manifest is not None
            else None
        )
        baseline_capability_manifest = (
            load_json(args.baseline_capability_manifest)
            if args.baseline_capability_manifest is not None
            else None
        )
    except ValueError as exc:
        print(f"schema_error: {exc}", file=sys.stderr)
        return 2

    as_of: datetime | None = None
    if args.as_of:
        errors: list[str] = []
        as_of = parse_time(args.as_of, "--as-of", errors)
        if errors:
            for error in errors:
                print(f"schema_error: {error}", file=sys.stderr)
            return 2
    try:
        report = evaluate(plan, results, as_of=as_of)
    except Exception as exc:  # acceptance tooling must never turn an internal crash into a pass
        print(f"schema_error: validator failure: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    if isinstance(plan, dict) and plan.get("version") == 2:
        external_errors: list[str] = []
        if capability_manifest is None:
            external_errors.append("--capability-manifest is required for v2 acceptance")
        else:
            validate_capability_manifest_binding(plan, capability_manifest, external_errors)
        if baseline_capability_manifest is None:
            external_errors.append(
                "--baseline-capability-manifest is required for v2 acceptance"
            )
        elif capability_manifest is not None:
            validate_capability_manifest_unchanged(
                capability_manifest, baseline_capability_manifest, external_errors
            )
        validate_git_binding(
            args.plan,
            plan,
            args.git_repo,
            args.git_commit,
            args.git_path,
            as_of,
            external_errors,
        )
        report["schema_errors"].extend(f"plan: {error}" for error in external_errors)
        if report["schema_errors"]:
            report["milestone"] = "hypothesis_only"
    if args.as_json:
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(f"allowed_milestone: {report['milestone']}")
        for window, values in report.get("resolutions", {}).items():
            print(
                f"resolution[{window}]: n={values['n']}, "
                f"worst_case_95pct_proportion_half_width="
                f"{values['worst_case_95pct_proportion_half_width']:.4f}"
            )
        for error in report["schema_errors"]:
            print(f"schema_error: {error}", file=sys.stderr)
        for error in report["gate_failures"]:
            print(f"gate_failure: {error}", file=sys.stderr)
        for error in report["release_gaps"]:
            print(f"release_gap: {error}", file=sys.stderr)
    if report["schema_errors"]:
        return 2
    if MILESTONE_ORDER[report["milestone"]] < MILESTONE_ORDER[args.require_milestone]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
