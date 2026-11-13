#!/usr/bin/env python3
"""Validate a preregistered Vigilyx email-security shadow plan."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


REQUIRED_STRATA = {"safe", "low", "medium", "high_critical", "random"}
REQUIRED_REPORT_DIMENSIONS = {
    "threat",
    "classification",
    "authentication",
    "coverage",
    "data_security",
    "disposition",
}
ALLOWED_MODES = {"mirror", "mta"}
SUPPORTED_VERSIONS = {1, 2}
WINDOWS = ("development", "validation", "holdout")
SAMPLE_PROFILES = {
    "full": {"safe": 400, "low": 200, "medium": 250, "high_critical": 150, "random": 300},
    "small_team": {"safe": 120, "low": 70, "medium": 100, "high_critical": 70, "random": 120},
}
STAGE_ROLE_REQUIREMENTS = {
    "A": {"false_positive_reduction", "malicious_recall_guardrail"},
    "B": {"missed_attack_recovery", "new_false_positive_guardrail"},
}
IMMUTABLE_IDENTIFIER = re.compile(
    r"^(?:sha256:[0-9a-f]{64}|[a-z][a-z0-9_-]{0,63}@[0-9a-f]{40})$"
)
PLAN_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
CAPABILITY_ID = re.compile(r"^[a-z][a-z0-9_]{0,95}$")


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON {path}: {exc}") from exc


def parse_time(value: Any, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"{field} must be an ISO-8601 string")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{field} is not valid ISO-8601")
        return None
    if parsed.utcoffset() is None:
        errors.append(f"{field} must include a timezone")
        return None
    return parsed


def finite_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def immutable_identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(IMMUTABLE_IDENTIFIER.fullmatch(value.strip()))


def canonical_plan_sha256(plan: dict[str, Any]) -> str:
    """Hash the plan while excluding only the self-referential hash field."""
    payload = copy.deepcopy(plan)
    preregistration = payload.get("preregistration")
    if isinstance(preregistration, dict):
        preregistration.pop("plan_sha256", None)
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def canonical_json_sha256(document: Any) -> str:
    """Return a stable SHA-256 for a standalone JSON document."""
    encoded = json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def validate_preregistration(plan: dict[str, Any], errors: list[str]) -> None:
    preregistration = plan.get("preregistration")
    if not isinstance(preregistration, dict):
        errors.append("preregistration must be an object")
        return
    timestamp = parse_time(
        preregistration.get("preregistered_at"), "preregistration.preregistered_at", errors
    )
    plan_hash = preregistration.get("plan_sha256")
    if not isinstance(plan_hash, str) or not PLAN_HASH.fullmatch(plan_hash):
        errors.append("preregistration.plan_sha256 must use sha256:<64 lowercase hex>")
    else:
        try:
            canonical_hash = canonical_plan_sha256(plan)
        except (TypeError, ValueError) as exc:
            errors.append(f"plan cannot be canonically hashed: {exc}")
            canonical_hash = None
        if canonical_hash is not None and plan_hash != canonical_hash:
            errors.append("preregistration.plan_sha256 does not match the canonical plan content")
    if timestamp is not None:
        corpus = plan.get("corpus")
        holdout = corpus.get("holdout") if isinstance(corpus, dict) else None
        holdout_start = holdout.get("start") if isinstance(holdout, dict) else None
        holdout_errors: list[str] = []
        parsed_holdout_start = parse_time(holdout_start, "holdout.start", holdout_errors)
        if parsed_holdout_start is not None and timestamp >= parsed_holdout_start:
            errors.append("preregistration.preregistered_at must precede holdout.start")


def validate_git_binding(
    plan_path: Path,
    plan: dict[str, Any],
    repo: Path | None,
    commit: str | None,
    git_path: str | None,
    as_of: datetime | None,
    errors: list[str],
) -> None:
    if commit is None and repo is None and git_path is None:
        return
    if not repo or not commit:
        errors.append("--git-repo and --git-commit must be supplied together")
        return
    if not non_empty_string(commit) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        errors.append("--git-commit must be a 40-character lowercase hexadecimal commit")
        return
    try:
        relative_path = git_path
        if not relative_path:
            relative_path = str(plan_path.resolve().relative_to(repo.resolve()))
        commit_time_result = subprocess.run(
            ["git", "-C", str(repo), "show", "-s", "--format=%cI", commit],
            check=False,
            capture_output=True,
            text=True,
        )
        blob_result = subprocess.run(
            ["git", "-C", str(repo), "show", f"{commit}:{relative_path}"],
            check=False,
            capture_output=True,
        )
    except (OSError, ValueError) as exc:
        errors.append(f"cannot inspect Git preregistration binding: {exc}")
        return
    if commit_time_result.returncode != 0 or blob_result.returncode != 0:
        errors.append("Git preregistration binding must reference an existing committed plan path")
        return
    commit_time_errors: list[str] = []
    commit_time = parse_time(commit_time_result.stdout.strip(), "git.commit_time", commit_time_errors)
    if commit_time is None:
        errors.extend(commit_time_errors)
    elif as_of is not None and commit_time > as_of:
        errors.append("Git preregistration commit is later than --as-of")
    corpus = plan.get("corpus")
    holdout = corpus.get("holdout") if isinstance(corpus, dict) else None
    holdout_errors: list[str] = []
    holdout_start = parse_time(
        holdout.get("start") if isinstance(holdout, dict) else None,
        "holdout.start",
        holdout_errors,
    )
    if holdout_start is not None and commit_time is not None and commit_time > holdout_start:
        errors.append("Git preregistration commit must precede holdout.start")
    try:
        committed_plan = json.loads(blob_result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.append(f"committed preregistration plan is not valid JSON: {exc}")
        return
    if not isinstance(committed_plan, dict):
        errors.append("committed preregistration plan must be an object")
    else:
        try:
            committed_hash = canonical_plan_sha256(committed_plan)
        except (TypeError, ValueError) as exc:
            errors.append(f"committed plan cannot be canonically hashed: {exc}")
            committed_hash = None
        if committed_hash is not None and committed_hash != plan.get("preregistration", {}).get("plan_sha256"):
            errors.append("committed plan content does not match preregistration.plan_sha256")


def validate_strata(cohort: dict[str, Any], field: str, errors: list[str]) -> int | None:
    strata = cohort.get("strata")
    if not isinstance(strata, dict):
        errors.append(f"{field}.strata must be an object")
        return None
    missing = sorted(REQUIRED_STRATA - strata.keys())
    extra = sorted(strata.keys() - REQUIRED_STRATA)
    if missing:
        errors.append(f"{field}.strata missing: {', '.join(missing)}")
    if extra:
        errors.append(f"{field}.strata has unknown keys: {', '.join(extra)}")
    for name in REQUIRED_STRATA & strata.keys():
        value = strata[name]
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            errors.append(f"{field}.strata.{name} must be a positive integer")
    if set(strata) != REQUIRED_STRATA or not all(
        isinstance(strata[name], int)
        and not isinstance(strata[name], bool)
        and strata[name] > 0
        for name in REQUIRED_STRATA
    ):
        return None
    return sum(strata.values())


def validate_cohort(
    corpus: dict[str, Any],
    name: str,
    errors: list[str],
    *,
    require_strata: bool,
) -> tuple[datetime | None, datetime | None, int | None]:
    cohort = corpus.get(name)
    if not isinstance(cohort, dict):
        errors.append(f"corpus.{name} must be an object")
        return None, None, None
    start = parse_time(cohort.get("start"), f"{name}.start", errors)
    end = parse_time(cohort.get("end"), f"{name}.end", errors)
    if start and end and start >= end:
        errors.append(f"{name} window must have start < end")
    total = validate_strata(cohort, f"corpus.{name}", errors) if require_strata else None
    return start, end, total


def validate_sampling_profile(
    corpus: dict[str, Any],
    cohort_totals: dict[str, int | None],
    errors: list[str],
) -> None:
    profile = corpus.get("sampling_profile")
    if profile not in SAMPLE_PROFILES:
        errors.append(
            "corpus.sampling_profile must be one of: " + ", ".join(sorted(SAMPLE_PROFILES))
        )
        return
    targets = SAMPLE_PROFILES[profile]
    for window in WINDOWS:
        cohort = corpus.get(window)
        if not isinstance(cohort, dict):
            continue
        strata = cohort.get("strata")
        if not isinstance(strata, dict):
            continue
        for stratum, minimum in targets.items():
            value = strata.get(stratum)
            if isinstance(value, int) and not isinstance(value, bool) and value < minimum:
                errors.append(
                    f"corpus.{window}.strata.{stratum} must be at least {minimum} "
                    f"for sampling_profile={profile}"
                )


def validate_preregistration_window(
    plan: dict[str, Any], as_of: datetime | None, errors: list[str]
) -> None:
    preregistration = plan.get("preregistration")
    if not isinstance(preregistration, dict):
        return
    timestamp_errors: list[str] = []
    timestamp = parse_time(
        preregistration.get("preregistered_at"),
        "preregistration.preregistered_at",
        timestamp_errors,
    )
    if timestamp is None:
        return
    if as_of is not None and timestamp > as_of:
        errors.append("preregistration.preregistered_at must not be later than --as-of")
    corpus = plan.get("corpus")
    holdout = corpus.get("holdout") if isinstance(corpus, dict) else None
    end_errors: list[str] = []
    holdout_end = parse_time(
        holdout.get("end") if isinstance(holdout, dict) else None,
        "holdout.end",
        end_errors,
    )
    if holdout_end is not None and holdout_end <= timestamp:
        errors.append("holdout.end must be later than preregistration.preregistered_at")


def validate_environment(plan: dict[str, Any], version: int, errors: list[str]) -> None:
    environment = plan.get("environment")
    if not isinstance(environment, dict):
        errors.append("environment must be an object")
        return
    if not isinstance(environment.get("ai_enabled"), bool):
        errors.append("environment.ai_enabled must be boolean")
    if not isinstance(environment.get("deployment_mode"), str) or environment.get("deployment_mode") not in ALLOWED_MODES:
        errors.append("environment.deployment_mode must be mirror or mta")
    if version >= 2:
        for field in (
            "baseline_artifact_id",
            "candidate_artifact_id",
            "module_data_version",
            "policy_version",
            "category_registry_version",
        ):
            if not immutable_identifier(environment.get(field)):
                errors.append(f"environment.{field} must be a non-empty immutable identifier")
        if environment.get("baseline_artifact_id") == environment.get("candidate_artifact_id"):
            errors.append("environment baseline and candidate artifacts must differ")
        if environment.get("ai_enabled") is True and not immutable_identifier(
            environment.get("ai_artifact_id")
        ):
            errors.append("environment.ai_artifact_id is required when AI is enabled")


def validate_labeling(
    plan: dict[str, Any], evaluation_total: int | None, version: int, errors: list[str]
) -> None:
    labeling = plan.get("labeling")
    if not isinstance(labeling, dict):
        errors.append("labeling must be an object")
        return
    if labeling.get("blind") is not True:
        errors.append("labeling.blind must be true")
    if labeling.get("adjudication") is not True:
        errors.append("labeling.adjudication must be true")
    review_n = labeling.get("second_review_n")
    if version >= 2:
        if not isinstance(review_n, dict) or set(review_n) != set(WINDOWS):
            errors.append("labeling.second_review_n must provide development, validation, and holdout counts")
        else:
            for window in WINDOWS:
                count = review_n[window]
                total = plan.get("corpus", {}).get(window, {}).get("strata")
                window_total = sum(total.values()) if isinstance(total, dict) else None
                minimum = max(80, math.ceil(window_total * 0.20)) if window_total else 80
                if not isinstance(count, int) or isinstance(count, bool) or count < minimum:
                    errors.append(
                        f"labeling.second_review_n.{window} must be at least {minimum} "
                        "(80 or 20% of that window, whichever is greater)"
                    )
                elif window_total is not None and count > window_total:
                    errors.append(f"labeling.second_review_n.{window} cannot exceed that window cohort")
    else:
        minimum = (
            min(evaluation_total, max(80, math.ceil(evaluation_total * 0.20)))
            if evaluation_total
            else 80
        )
        if not isinstance(review_n, int) or isinstance(review_n, bool) or review_n < minimum:
            errors.append(
                f"labeling.second_review_n must be at least {minimum} "
                "(all messages when the cohort is under 80, otherwise 80 or 20%, whichever is greater)"
            )
        elif evaluation_total is not None and review_n > evaluation_total:
            errors.append("labeling.second_review_n cannot exceed the complete evaluation cohort")
    kappa = labeling.get("minimum_kappa")
    if not finite_number(kappa) or not 0.75 <= kappa <= 1.0:
        errors.append("labeling.minimum_kappa must be between 0.75 and 1.0")
    if version >= 2:
        if not non_empty_string(labeling.get("rubric_version")):
            errors.append("labeling.rubric_version must be a non-empty string")
        if labeling.get("report_class_disagreement") is not True:
            errors.append("labeling.report_class_disagreement must be true")


def validate_hypothesis(
    hypothesis: Any, prefix: str, version: int, errors: list[str]
) -> None:
    if not isinstance(hypothesis, dict):
        errors.append(f"{prefix} must be an object")
        return
    if not non_empty_string(hypothesis.get("metric")):
        errors.append(f"{prefix}.metric must be a non-empty string")
    if not finite_number(hypothesis.get("baseline")):
        errors.append(f"{prefix}.baseline must be a finite number")
    expected = hypothesis.get("expected")
    if not isinstance(expected, dict) or not finite_number(expected.get("min")) or not finite_number(
        expected.get("max")
    ):
        errors.append(f"{prefix}.expected must contain finite min and max")
    elif expected["min"] > expected["max"]:
        errors.append(f"{prefix}.expected.min must be <= expected.max")
    if not non_empty_string(hypothesis.get("failure_action")):
        errors.append(f"{prefix}.failure_action must be a non-empty string")
    if version >= 2:
        role = hypothesis.get("role")
        if not non_empty_string(role):
            errors.append(f"{prefix}.role must be a non-empty string")
        if not non_empty_string(hypothesis.get("unit")):
            errors.append(f"{prefix}.unit must be a non-empty string")
        elif role in set().union(*STAGE_ROLE_REQUIREMENTS.values()) and hypothesis.get("unit") != "proportion":
            errors.append(f"{prefix}.unit must be proportion for required quality roles")
        if not non_empty_string(hypothesis.get("baseline_source")):
            errors.append(f"{prefix}.baseline_source must be a non-empty string")
        if not non_empty_string(hypothesis.get("numerator")):
            errors.append(f"{prefix}.numerator must define the measured numerator")
        if not non_empty_string(hypothesis.get("denominator")):
            errors.append(f"{prefix}.denominator must define the measured population")
        minimum_n = hypothesis.get("minimum_n")
        if not isinstance(minimum_n, int) or isinstance(minimum_n, bool) or minimum_n <= 0:
            errors.append(f"{prefix}.minimum_n must be a positive integer")


def validate_stages(plan: dict[str, Any], version: int, errors: list[str]) -> None:
    stages = plan.get("stages")
    valid_length = (
        isinstance(stages, list)
        and (len(stages) == 2 if version == 1 else 1 <= len(stages) <= 2)
    )
    if not valid_length:
        if version == 1:
            errors.append("v1 stages must contain exactly Stage A and Stage B")
        else:
            errors.append("v2 stages must contain one or two governed stages")
        return

    if version >= 2:
        sequences = {
            1: {("A", "subtract"), ("B", "add")},
            2: {("A", "subtract", "B", "add")},
        }
        actual_sequence = tuple(
            value
            for stage in stages
            if isinstance(stage, dict)
            for value in (stage.get("id"), stage.get("kind"))
        )
        if actual_sequence not in sequences[len(stages)]:
            errors.append(
                "v2 stages must be A/subtract only, B/add only, or A/subtract followed by B/add"
            )

    seen_ids: set[str] = set()
    for index, stage in enumerate(stages):
        prefix = f"stages[{index}]"
        if not isinstance(stage, dict):
            errors.append(f"{prefix} must be an object")
            continue
        stage_id = stage.get("id")
        if not non_empty_string(stage_id) or stage_id in seen_ids:
            errors.append(f"{prefix}.id must be non-empty and unique")
        else:
            seen_ids.add(stage_id)
        expected_kind = {"A": "subtract", "B": "add"}.get(stage_id)
        if version >= 2 and expected_kind is not None and stage.get("kind") != expected_kind:
            errors.append(f"{prefix}.kind must be {expected_kind} for Stage {stage_id}")
        if version == 1:
            legacy_id, legacy_kind = (("A", "subtract"), ("B", "add"))[index]
            if stage_id != legacy_id:
                errors.append(f"{prefix}.id must be {legacy_id}")
            if stage.get("kind") != legacy_kind:
                errors.append(f"{prefix}.kind must be {legacy_kind}")
        if version >= 2 and stage_id == "B" and not non_empty_string(
            stage.get("feature_flag")
        ):
            errors.append(f"{prefix}.feature_flag is required for additive Stage B")
        changes = stage.get("changes")
        if not isinstance(changes, list) or not changes or not all(
            non_empty_string(change) for change in changes
        ):
            errors.append(f"{prefix}.changes must be a non-empty string array")
        hypotheses = stage.get("hypotheses")
        if not isinstance(hypotheses, list) or not hypotheses:
            errors.append(f"{prefix}.hypotheses must be a non-empty array")
            continue
        for hypothesis_index, hypothesis in enumerate(hypotheses):
            validate_hypothesis(
                hypothesis,
                f"{prefix}.hypotheses[{hypothesis_index}]",
                version,
                errors,
            )
        if version >= 2 and stage_id in STAGE_ROLE_REQUIREMENTS:
            roles = {
                hypothesis.get("role")
                for hypothesis in hypotheses
                if isinstance(hypothesis, dict) and isinstance(hypothesis.get("role"), str)
            }
            missing_roles = sorted(STAGE_ROLE_REQUIREMENTS[stage_id] - roles)
            if missing_roles:
                errors.append(
                    f"{prefix}.hypotheses missing required roles: {', '.join(missing_roles)}"
                )


def validate_capability_preservation(plan: dict[str, Any], errors: list[str]) -> None:
    contract = plan.get("capability_preservation")
    if not isinstance(contract, dict):
        errors.append("capability_preservation must be an object")
        return
    if not immutable_identifier(contract.get("manifest_version")):
        errors.append("capability_preservation.manifest_version must be an immutable identifier")
    manifest_sha256 = contract.get("manifest_sha256")
    if not isinstance(manifest_sha256, str) or not PLAN_HASH.fullmatch(manifest_sha256):
        errors.append(
            "capability_preservation.manifest_sha256 must use sha256:<64 lowercase hex>"
        )
    if contract.get("selection") != "all":
        errors.append("capability_preservation.selection must be all")
    deprecated = contract.get("deprecated_capabilities")
    if deprecated != []:
        errors.append(
            "capability_preservation.deprecated_capabilities must be empty; deprecations require a separate authorized manifest change"
        )
    capabilities = contract.get("required_capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        errors.append("capability_preservation.required_capabilities must be a non-empty array")
        return
    seen: set[str] = set()
    for index, capability in enumerate(capabilities):
        prefix = f"capability_preservation.required_capabilities[{index}]"
        if not isinstance(capability, dict):
            errors.append(f"{prefix} must be an object")
            continue
        capability_id = capability.get("id")
        if not isinstance(capability_id, str) or not CAPABILITY_ID.fullmatch(capability_id):
            errors.append(f"{prefix}.id must be a lowercase capability id")
        elif capability_id in seen:
            errors.append(f"{prefix}.id is duplicated: {capability_id}")
        else:
            seen.add(capability_id)
        case_set_sha256 = capability.get("case_set_sha256")
        if not isinstance(case_set_sha256, str) or not PLAN_HASH.fullmatch(case_set_sha256):
            errors.append(f"{prefix}.case_set_sha256 must use sha256:<64 lowercase hex>")
        minimum_cases = capability.get("minimum_cases")
        if (
            not isinstance(minimum_cases, int)
            or isinstance(minimum_cases, bool)
            or minimum_cases <= 0
        ):
            errors.append(f"{prefix}.minimum_cases must be a positive integer")


def validate_capability_manifest_binding(
    plan: dict[str, Any], manifest: Any, errors: list[str]
) -> None:
    """Bind a plan to the complete external capability manifest, not a hand-picked subset."""
    contract = plan.get("capability_preservation")
    if not isinstance(contract, dict):
        return
    if not isinstance(manifest, dict):
        errors.append("capability manifest root must be an object")
        return
    allowed_fields = {"schema_version", "manifest_version", "capabilities"}
    extra_fields = sorted(set(manifest) - allowed_fields)
    missing_fields = sorted(allowed_fields - set(manifest))
    if missing_fields:
        errors.append(f"capability manifest missing fields: {', '.join(missing_fields)}")
    if extra_fields:
        errors.append(f"capability manifest has unknown fields: {', '.join(extra_fields)}")
    if manifest.get("schema_version") != 1:
        errors.append("capability manifest schema_version must be 1")
    if not immutable_identifier(manifest.get("manifest_version")):
        errors.append("capability manifest manifest_version must be an immutable identifier")
    if manifest.get("manifest_version") != contract.get("manifest_version"):
        errors.append(
            "capability manifest manifest_version must match capability_preservation.manifest_version"
        )

    manifest_capabilities = manifest.get("capabilities")
    manifest_proxy = {
        "capability_preservation": {
            "manifest_version": manifest.get("manifest_version"),
            "manifest_sha256": contract.get("manifest_sha256"),
            "selection": "all",
            "required_capabilities": manifest_capabilities,
            "deprecated_capabilities": [],
        }
    }
    manifest_errors: list[str] = []
    validate_capability_preservation(manifest_proxy, manifest_errors)
    for error in manifest_errors:
        if "manifest_sha256" not in error:
            errors.append(f"capability manifest: {error}")

    try:
        actual_sha256 = canonical_json_sha256(manifest)
    except (TypeError, ValueError) as exc:
        errors.append(f"capability manifest cannot be canonically hashed: {exc}")
        actual_sha256 = None
    if actual_sha256 is not None and contract.get("manifest_sha256") != actual_sha256:
        errors.append(
            "capability_preservation.manifest_sha256 does not match the external capability manifest"
        )
    if contract.get("required_capabilities") != manifest_capabilities:
        errors.append(
            "capability_preservation.required_capabilities must exactly match the complete external capability manifest"
        )


def validate_capability_manifest_unchanged(
    manifest: Any, baseline_manifest: Any, errors: list[str]
) -> None:
    """Forbid detector changes from rewriting the established capability bank."""
    try:
        manifest_sha256 = canonical_json_sha256(manifest)
        baseline_sha256 = canonical_json_sha256(baseline_manifest)
    except (TypeError, ValueError) as exc:
        errors.append(f"capability manifests cannot be canonically compared: {exc}")
        return
    if manifest_sha256 != baseline_sha256:
        errors.append(
            "capability manifest must be unchanged from the baseline release during a detector change; add new capabilities later in a separate manifest-only governance change"
        )


def validate_v2_release_contract(plan: dict[str, Any], errors: list[str]) -> None:
    validate_preregistration(plan, errors)
    validate_capability_preservation(plan, errors)

    if plan.get("shadow_only") is not True:
        errors.append("shadow_only must be true")
    if plan.get("production_disposition_mutation") is not False:
        errors.append("production_disposition_mutation must be false")

    rollback = plan.get("rollback")
    if not isinstance(rollback, dict):
        errors.append("rollback must be an object")
    else:
        if not non_empty_string(rollback.get("owner")):
            errors.append("rollback.owner must be a non-empty string")
        conditions = rollback.get("conditions")
        if not isinstance(conditions, list) or not conditions or not all(
            non_empty_string(condition) for condition in conditions
        ):
            errors.append("rollback.conditions must be a non-empty string array")

    reporting = plan.get("reporting")
    if not isinstance(reporting, dict):
        errors.append("reporting must be an object")
        return
    dimensions = reporting.get("required_dimensions")
    if not isinstance(dimensions, list) or not all(non_empty_string(item) for item in dimensions):
        errors.append("reporting.required_dimensions must be a string array")
    else:
        missing = sorted(REQUIRED_REPORT_DIMENSIONS - set(dimensions))
        if missing:
            errors.append(f"reporting.required_dimensions missing: {', '.join(missing)}")
    if reporting.get("per_bucket_metrics") is not True:
        errors.append("reporting.per_bucket_metrics must be true")
    if reporting.get("separate_stage_deltas") is not True:
        errors.append("reporting.separate_stage_deltas must be true")
    if reporting.get("sample_size_uncertainty") is not True:
        errors.append("reporting.sample_size_uncertainty must be true")


def validate_plan(plan: Any, *, as_of: datetime | None = None) -> list[str]:
    errors: list[str] = []
    if not isinstance(plan, dict):
        return ["plan root must be an object"]
    version = plan.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version not in SUPPORTED_VERSIONS:
        return ["version must be 1 or 2"]
    if not non_empty_string(plan.get("change_id")):
        errors.append("change_id must be a non-empty string")
    validate_environment(plan, version, errors)

    corpus = plan.get("corpus")
    if not isinstance(corpus, dict):
        return errors + ["corpus must be an object"]
    if corpus.get("repository_location") != "external_restricted":
        errors.append("real corpus must use repository_location=external_restricted")
    if version >= 2:
        if corpus.get("raw_data_in_repository") is not False:
            errors.append("corpus.raw_data_in_repository must be false")
        seed = corpus.get("sampling_seed")
        if isinstance(seed, bool) or not (
            isinstance(seed, int) or non_empty_string(seed)
        ):
            errors.append("corpus.sampling_seed must be a non-empty string or integer")

    development_start, development_end, development_total = validate_cohort(
        corpus, "development", errors, require_strata=True
    )
    if version == 1:
        holdout_start, holdout_end, _ = validate_cohort(
            corpus, "holdout", errors, require_strata=False
        )
        if development_end and holdout_start and holdout_start <= development_end:
            errors.append("holdout must start after the development window ends")
        holdout = corpus.get("holdout")
        if isinstance(holdout, dict) and holdout.get("sealed") is not True:
            errors.append("holdout.sealed must be true")
        evaluation_total = development_total
    else:
        validation_start, validation_end, validation_total = validate_cohort(
            corpus, "validation", errors, require_strata=True
        )
        holdout_start, holdout_end, holdout_total = validate_cohort(
            corpus, "holdout", errors, require_strata=True
        )
        if development_end and validation_start and validation_start <= development_end:
            errors.append("validation must start after the development window ends")
        if validation_end and holdout_start and holdout_start <= validation_end:
            errors.append("holdout must start after the validation window ends")
        holdout = corpus.get("holdout")
        if isinstance(holdout, dict) and holdout.get("sealed") is not True:
            errors.append("holdout.sealed must be true")
        totals = (development_total, validation_total, holdout_total)
        evaluation_total = sum(totals) if all(total is not None for total in totals) else None
        validate_sampling_profile(
            corpus,
            {
                "development": development_total,
                "validation": validation_total,
                "holdout": holdout_total,
            },
            errors,
        )

    validate_labeling(plan, evaluation_total, version, errors)
    if plan.get("global_thresholds_unchanged") is not True:
        errors.append("global_thresholds_unchanged must be true for the initial staged plan")
    validate_stages(plan, version, errors)
    if version >= 2:
        validate_v2_release_contract(plan, errors)
        validate_preregistration_window(plan, as_of, errors)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument(
        "--as-of",
        type=str,
        help="reject plans preregistered after this ISO-8601 instant",
    )
    parser.add_argument("--allow-legacy", action="store_true", help="allow v1 compatibility validation to exit 0")
    parser.add_argument("--git-repo", type=Path, help="repository containing the committed preregistration")
    parser.add_argument("--git-commit", type=str, help="40-hex commit that contains the preregistered plan")
    parser.add_argument("--git-path", type=str, help="plan path inside --git-repo; defaults to the plan path")
    parser.add_argument(
        "--capability-manifest",
        type=Path,
        help="complete external capability manifest required for v2 plans",
    )
    parser.add_argument(
        "--baseline-capability-manifest",
        type=Path,
        help="capability manifest from the baseline release; must match during detector changes",
    )
    args = parser.parse_args()
    as_of: datetime | None = None
    if args.as_of:
        as_of_errors: list[str] = []
        as_of = parse_time(args.as_of, "--as-of", as_of_errors)
        if as_of_errors:
            for error in as_of_errors:
                print(f"schema_error: {error}", file=sys.stderr)
            return 2
    try:
        plan = load_json(args.plan)
        errors = validate_plan(plan, as_of=as_of)
        if isinstance(plan, dict) and plan.get("version") == 1 and args.as_of:
            errors.append("--as-of requires a v2 plan with preregistration attestation")
        if isinstance(plan, dict) and plan.get("version") == 2:
            if args.capability_manifest is None:
                errors.append("--capability-manifest is required for v2 plans")
            else:
                capability_manifest = load_json(args.capability_manifest)
                validate_capability_manifest_binding(plan, capability_manifest, errors)
            if args.baseline_capability_manifest is None:
                errors.append("--baseline-capability-manifest is required for v2 plans")
            else:
                baseline_capability_manifest = load_json(args.baseline_capability_manifest)
                if args.capability_manifest is not None:
                    validate_capability_manifest_unchanged(
                        capability_manifest, baseline_capability_manifest, errors
                    )
            validate_git_binding(
                args.plan,
                plan,
                args.git_repo,
                args.git_commit,
                args.git_path,
                as_of,
                errors,
            )
    except ValueError as exc:
        print(f"schema_error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # fail closed and distinguish validator failure from a policy rejection
        print(f"schema_error: validator failure: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    version = plan.get("version") if isinstance(plan, dict) else "unknown"
    if version == 1 and not args.allow_legacy:
        print(
            "legacy_error: v1 plans are compatibility-only; rerun with --allow-legacy "
            "for historical replay",
            file=sys.stderr,
        )
        return 1
    suffix = " (legacy compatibility)" if version == 1 else ""
    print(f"valid: preregistered shadow plan v{version}{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
