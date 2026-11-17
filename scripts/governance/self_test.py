#!/usr/bin/env python3
"""Deterministic self-tests for the email-security governance validators."""

from __future__ import annotations

import copy
import json
import math
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import validate_acceptance
import validate_evidence_registry
import validate_shadow_plan


STRATA = {
    "safe": 120,
    "low": 70,
    "medium": 100,
    "high_critical": 70,
    "random": 120,
}


WINDOWS = ("development", "validation", "holdout")


def hypothesis(role: str = "false_positive_reduction") -> dict:
    return {
        "role": role,
        "metric": f"synthetic_{role}_rate",
        "unit": "proportion",
        "baseline": 0.25,
        "baseline_source": "external:synthetic-baseline",
        "numerator": f"synthetic numerator for {role}",
        "denominator": f"synthetic denominator for {role}",
        "minimum_n": 20,
        "expected": {"min": 0.10, "max": 0.20},
        "failure_action": "stop_and_restore",
    }


def capability_manifest(plan: dict) -> dict:
    contract = plan["capability_preservation"]
    return {
        "schema_version": 1,
        "manifest_version": contract["manifest_version"],
        "capabilities": copy.deepcopy(contract["required_capabilities"]),
    }


def shadow_v2() -> dict:
    plan = {
        "version": 2,
        "change_id": "synthetic-stage-a",
        "environment": {
            "ai_enabled": False,
            "deployment_mode": "mirror",
            "baseline_artifact_id": "vigilyx-engine@" + "1" * 40,
            "candidate_artifact_id": "vigilyx-engine@" + "2" * 40,
            "module_data_version": "sha256:" + "c" * 64,
            "policy_version": "sha256:" + "a" * 64,
            "category_registry_version": "registry@" + "b" * 40,
        },
        "corpus": {
            "repository_location": "external_restricted",
            "sampling_profile": "small_team",
            "raw_data_in_repository": False,
            "sampling_seed": "synthetic-seed",
            "development": {
                "start": "2026-01-01T00:00:00Z",
                "end": "2026-01-02T00:00:00Z",
                "strata": copy.deepcopy(STRATA),
            },
            "validation": {
                "start": "2026-01-03T00:00:00Z",
                "end": "2026-01-04T00:00:00Z",
                "strata": copy.deepcopy(STRATA),
            },
            "holdout": {
                "start": "2026-01-05T00:00:00Z",
                "end": "2026-01-06T00:00:00Z",
                "sealed": True,
                "strata": copy.deepcopy(STRATA),
            },
        },
        "labeling": {
            "blind": True,
            "second_review_n": {"development": 96, "validation": 96, "holdout": 96},
            "adjudication": True,
            "minimum_kappa": 0.75,
            "rubric_version": "six-layer-v1",
            "report_class_disagreement": True,
        },
        "shadow_only": True,
        "production_disposition_mutation": False,
        "global_thresholds_unchanged": True,
        "stages": [
            {
                "id": "A",
                "kind": "subtract",
                "changes": ["demote a synthetic weak observation"],
                "hypotheses": [
                    hypothesis("false_positive_reduction"),
                    hypothesis("malicious_recall_guardrail"),
                ],
            }
        ],
        "capability_preservation": {
            "manifest_version": "sha256:" + "d" * 64,
            "manifest_sha256": "",
            "selection": "all",
            "required_capabilities": [
                {
                    "id": "credential_phishing_detection",
                    "case_set_sha256": "sha256:" + "e" * 64,
                    "minimum_cases": 3,
                },
                {
                    "id": "malicious_attachment_detection",
                    "case_set_sha256": "sha256:" + "f" * 64,
                    "minimum_cases": 3,
                },
                {
                    "id": "benign_business_safe",
                    "case_set_sha256": "sha256:" + "0" * 64,
                    "minimum_cases": 3,
                },
            ],
            "deprecated_capabilities": [],
        },
        "rollback": {
            "owner": "synthetic-oncall",
            "conditions": ["recall falls below the preregistered bound"],
        },
        "reporting": {
            "required_dimensions": sorted(validate_shadow_plan.REQUIRED_REPORT_DIMENSIONS),
            "per_bucket_metrics": True,
            "separate_stage_deltas": True,
            "sample_size_uncertainty": True,
        },
    }
    plan["capability_preservation"]["manifest_sha256"] = (
        validate_shadow_plan.canonical_json_sha256(capability_manifest(plan))
    )
    plan["preregistration"] = {
        "preregistered_at": "2025-12-31T00:00:00Z",
        "plan_sha256": "",
    }
    plan["preregistration"]["plan_sha256"] = validate_shadow_plan.canonical_plan_sha256(plan)
    return plan


def shadow_v1() -> dict:
    plan = shadow_v2()
    plan["version"] = 1
    plan["environment"] = {"ai_enabled": False, "deployment_mode": "mirror"}
    plan["corpus"] = {
        "repository_location": "external_restricted",
        "development": plan["corpus"]["development"],
        "holdout": {
            "start": "2026-01-05T00:00:00Z",
            "end": "2026-01-06T00:00:00Z",
            "sealed": True,
        },
    }
    plan["labeling"] = {
        "blind": True,
        "second_review_n": 96,
        "adjudication": True,
        "minimum_kappa": 0.75,
    }
    plan["stages"].append(
        {
            "id": "B",
            "kind": "add",
            "changes": ["add a synthetic scenario"],
            "hypotheses": [
                {
                    "metric": "synthetic_recall",
                    "baseline": 0.50,
                    "expected": {"min": 0.60, "max": 0.80},
                    "failure_action": "disable",
                }
            ],
        }
    )
    for hypothesis_item in plan["stages"][0]["hypotheses"]:
        for key in ("role", "unit", "baseline_source", "numerator", "denominator", "minimum_n"):
            hypothesis_item.pop(key)
    for key in (
        "shadow_only",
        "production_disposition_mutation",
        "rollback",
        "reporting",
        "preregistration",
    ):
        plan.pop(key)
    return plan


def category(
    evidence_class: str,
    *,
    direct_fusion: bool,
    breaker_eligible: bool = False,
    promotion_authority: bool = False,
    auth_provenance: str | None = None,
    causal_family: str | None = None,
) -> dict:
    family = causal_family or f"synthetic_{evidence_class}_family"
    item = {
        "evidence_class": evidence_class,
        "cluster": "synthetic_cluster",
        "causal_family": family,
            "causal_key_template": f"synthetic:{family}:{{message_hash}}",
        "direct_fusion": direct_fusion,
        "breaker_eligible": breaker_eligible,
        "promotion_authority": promotion_authority,
        "ui": {"zh": "合成证据", "en": "Synthetic evidence"},
    }
    if breaker_eligible:
        item["breaker_basis"] = {
            "category_ids": ["synthetic_observation", "synthetic_auth_fail"],
            "rationale": "synthetic independently actionable control",
        }
    if auth_provenance is not None:
        item["auth_provenance"] = auth_provenance
    return item


def registry_v2() -> dict:
    return {
        "version": 2,
        "categories": {
            "synthetic_observation": category("observation", direct_fusion=False),
            "synthetic_auth_fail": category(
                "auth",
                direct_fusion=False,
                promotion_authority=True,
                auth_provenance="local_fail_original_bytes",
            ),
            "synthetic_promoted_attack": category(
                "native_actionable",
                direct_fusion=True,
                breaker_eligible=True,
                causal_family="synthetic_promoted_family",
            ),
            "synthetic_payload_attack": category(
                "native_actionable",
                direct_fusion=True,
                causal_family="synthetic_payload_family",
            ),
        },
        "promotions": [
            {
                "id": "synthetic_identity_scenario",
                "observations": ["synthetic_observation"],
                "triggers": ["synthetic_auth_fail"],
                "causal_independence": "synthetic observation and authentication have distinct sources",
                "require_distinct_runtime_causal_keys": True,
                "result": "synthetic_promoted_attack",
            }
        ],
        "floors": [
            {
                "id": "synthetic_confirmed_floor",
                "trigger_categories": ["synthetic_promoted_attack", "synthetic_payload_attack"],
                "minimum_independent_causes": 2,
                "require_distinct_runtime_causal_keys": True,
                "basis": {
                    "category_ids": ["synthetic_promoted_attack", "synthetic_payload_attack"],
                    "rationale": "two independent native actionable synthetic causes",
                },
            }
        ],
    }


def refresh_hash(plan: dict) -> dict:
    plan["preregistration"]["plan_sha256"] = validate_shadow_plan.canonical_plan_sha256(plan)
    return plan


def confusion_matrix() -> dict:
    return {"tp": 60, "fp": 12, "tn": 398, "fn": 10}


def per_bucket_confusion_matrices() -> dict:
    return {
        "safe": {"tp": 10, "fp": 5, "tn": 100, "fn": 5},
        "low": {"tp": 10, "fp": 3, "tn": 55, "fn": 2},
        "medium": {"tp": 15, "fp": 2, "tn": 81, "fn": 2},
        "high_critical": {"tp": 20, "fp": 0, "tn": 50, "fn": 0},
        "random": {"tp": 5, "fp": 2, "tn": 112, "fn": 1},
    }


def six_layer_counts() -> dict:
    return {
        "threat": {"safe": 350, "low": 40, "medium": 50, "high": 30, "critical": 10},
        "classification": {
            "business": 300,
            "spam": 80,
            "scam": 30,
            "phishing": 30,
            "bec": 20,
            "malware": 20,
        },
        "authentication": {"not_present": 480},
        "coverage": {"complete": 480},
        "data_security": {"none": 480},
        "disposition": {"mirror_audit": 480},
    }


def disagreement_matrices(review_n: int = 96) -> dict:
    return {
        "threat": {"safe": {"safe": review_n}},
        "classification": {"business": {"business": review_n}},
        "authentication": {"not_present": {"not_present": review_n}},
        "coverage": {"complete": {"complete": review_n}},
        "data_security": {"none": {"none": review_n}},
        "disposition": {"mirror_audit": {"mirror_audit": review_n}},
    }


def quality_window() -> dict:
    return {
        "confusion_matrix": confusion_matrix(),
        "per_bucket_confusion_matrices": per_bucket_confusion_matrices(),
        "traffic_weights": {"safe": 0.55, "low": 0.15, "medium": 0.20, "high_critical": 0.10},
        "six_layer_counts": six_layer_counts(),
        "disagreement_matrices": disagreement_matrices(),
    }


def acceptance_results(plan: dict, *, kappa: float = 0.80, value: float = 0.12) -> dict:
    measurements = [
        {
            "stage_id": stage["id"],
            "window": window,
            "metric": item["metric"],
            "n": 100,
            "value": value,
            "numerator_count": int(value * 100),
            "denominator_count": 100,
        }
        for stage in plan["stages"]
        for item in stage["hypotheses"]
        for window in ("validation", "holdout")
    ]
    capability_results = {}
    for capability in plan["capability_preservation"]["required_capabilities"]:
        case_ids = [
            f"{capability['id']}_case_{index + 1}"
            for index in range(capability["minimum_cases"])
        ]
        capability_results[capability["id"]] = {
            "case_set_sha256": capability["case_set_sha256"],
            "n": capability["minimum_cases"],
            "baseline_pass_case_ids": case_ids,
            "candidate_pass_case_ids": list(case_ids),
        }
    return {
        "plan_sha256": plan["preregistration"]["plan_sha256"],
        "observed_at": "2026-01-07T00:00:00Z",
        "windows": {
            window: {"n": 480, "sealed": window == "holdout", "strata": copy.deepcopy(STRATA)}
            for window in WINDOWS
        },
        "labeling": {
            window: {"kappa": kappa, "second_review_n": 96} for window in WINDOWS
        },
        "cohort_audit": {
            "sampling_seed_verified": True,
            "deduplication_method_verified": True,
            "campaign_copies_removed": True,
            "cross_window_overlap": 0,
        },
        "capability_preservation": {
            "manifest_version": plan["capability_preservation"]["manifest_version"],
            "manifest_sha256": plan["capability_preservation"]["manifest_sha256"],
            "baseline_artifact_id": plan["environment"]["baseline_artifact_id"],
            "candidate_artifact_id": plan["environment"]["candidate_artifact_id"],
            "capabilities": capability_results,
        },
        "execution": {
            "shadow_only": True,
            "production_disposition_mutation": False,
            "global_thresholds_unchanged": True,
            "six_layer_outcomes": True,
            "per_bucket_metrics": True,
            "separate_stage_deltas": True,
            "rollback_triggered": False,
        },
        "quality": {window: quality_window() for window in WINDOWS},
        "measurements": measurements,
    }


class ShadowPlanTests(unittest.TestCase):
    def test_malformed_plan_root_is_rejected(self) -> None:
        self.assertEqual(
            validate_shadow_plan.validate_plan([]), ["plan root must be an object"]
        )

    def test_v2_stage_a_only_is_valid(self) -> None:
        self.assertEqual(validate_shadow_plan.validate_plan(shadow_v2()), [])

    def test_v2_stage_b_only_is_valid(self) -> None:
        plan = shadow_v2()
        plan["change_id"] = "synthetic-stage-b-only"
        plan["stages"] = [
            {
                "id": "B",
                "kind": "add",
                "feature_flag": "synthetic_stage_b",
                "changes": ["recover a synthetic missed attack"],
                "hypotheses": [
                    hypothesis("missed_attack_recovery"),
                    hypothesis("new_false_positive_guardrail"),
                ],
            }
        ]
        refresh_hash(plan)
        self.assertEqual(validate_shadow_plan.validate_plan(plan), [])

    def test_v2_rejects_stage_without_required_quality_roles(self) -> None:
        plan = shadow_v2()
        plan["stages"][0]["hypotheses"] = [hypothesis("false_positive_reduction")]
        refresh_hash(plan)
        self.assertTrue(
            any("malicious_recall_guardrail" in error for error in validate_shadow_plan.validate_plan(plan))
        )

    def test_v2_requires_complete_capability_manifest(self) -> None:
        plan = shadow_v2()
        plan["capability_preservation"]["required_capabilities"] = []
        refresh_hash(plan)
        self.assertTrue(
            any("required_capabilities" in error for error in validate_shadow_plan.validate_plan(plan))
        )

    def test_v2_binds_to_complete_external_capability_manifest(self) -> None:
        plan = shadow_v2()
        errors: list[str] = []
        validate_shadow_plan.validate_capability_manifest_binding(
            plan, capability_manifest(plan), errors
        )
        self.assertEqual(errors, [])

    def test_v2_rejects_capability_omitted_from_plan(self) -> None:
        plan = shadow_v2()
        manifest = capability_manifest(plan)
        plan["capability_preservation"]["required_capabilities"].pop()
        plan["capability_preservation"]["manifest_sha256"] = (
            validate_shadow_plan.canonical_json_sha256(manifest)
        )
        refresh_hash(plan)
        errors: list[str] = []
        validate_shadow_plan.validate_capability_manifest_binding(plan, manifest, errors)
        self.assertTrue(any("exactly match" in error for error in errors))

    def test_v2_rejects_rewriting_baseline_capability_manifest(self) -> None:
        plan = shadow_v2()
        baseline_manifest = capability_manifest(plan)
        candidate_manifest = copy.deepcopy(baseline_manifest)
        candidate_manifest["capabilities"].pop()
        errors: list[str] = []
        validate_shadow_plan.validate_capability_manifest_unchanged(
            candidate_manifest, baseline_manifest, errors
        )
        self.assertTrue(any("unchanged from the baseline release" in error for error in errors))

    def test_v2_cli_requires_external_capability_manifest(self) -> None:
        plan = shadow_v2()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            manifest_path = root / "capability-manifest.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            manifest_path.write_text(
                json.dumps(capability_manifest(plan)), encoding="utf-8"
            )
            command = [
                sys.executable,
                str(Path(__file__).with_name("validate_shadow_plan.py")),
                str(plan_path),
            ]
            rejected = subprocess.run(command, check=False, capture_output=True, text=True)
            accepted = subprocess.run(
                command
                + [
                    "--capability-manifest",
                    str(manifest_path),
                    "--baseline-capability-manifest",
                    str(manifest_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(rejected.returncode, 1)
        self.assertIn("--capability-manifest is required", rejected.stderr)
        self.assertEqual(accepted.returncode, 0)

    def test_v2_rejects_hidden_capability_deprecation(self) -> None:
        plan = shadow_v2()
        plan["capability_preservation"]["deprecated_capabilities"] = [
            "malicious_attachment_detection"
        ]
        refresh_hash(plan)
        self.assertTrue(
            any("separate authorized manifest change" in error for error in validate_shadow_plan.validate_plan(plan))
        )

    def test_v2_two_stage_plan_requires_and_accepts_feature_flag(self) -> None:
        plan = shadow_v2()
        plan["stages"].append(
            {
                "id": "B",
                "kind": "add",
                "feature_flag": "synthetic_stage_b",
                "changes": ["add a synthetic scenario"],
                "hypotheses": [
                    hypothesis("missed_attack_recovery"),
                    hypothesis("new_false_positive_guardrail"),
                ],
            }
        )
        refresh_hash(plan)
        self.assertEqual(validate_shadow_plan.validate_plan(plan), [])
        plan["stages"][1].pop("feature_flag")
        self.assertTrue(
            any("feature_flag" in error for error in validate_shadow_plan.validate_plan(plan))
        )

    def test_v2_rejects_holdout_without_cross_bucket_strata(self) -> None:
        plan = shadow_v2()
        plan["corpus"]["holdout"].pop("strata")
        self.assertIn(
            "corpus.holdout.strata must be an object",
            validate_shadow_plan.validate_plan(plan),
        )

    def test_v2_rejects_production_disposition_mutation(self) -> None:
        plan = shadow_v2()
        plan["production_disposition_mutation"] = True
        self.assertIn(
            "production_disposition_mutation must be false",
            validate_shadow_plan.validate_plan(plan),
        )

    def test_v2_rejects_mutable_policy_labels(self) -> None:
        plan = shadow_v2()
        plan["environment"]["policy_version"] = "latest"
        self.assertTrue(
            any(
                "immutable identifier" in error
                for error in validate_shadow_plan.validate_plan(plan)
            )
        )

    def test_v2_rejects_noncanonical_immutable_identifier_case(self) -> None:
        plan = shadow_v2()
        plan["environment"]["policy_version"] = "SHA256:" + "a" * 64
        self.assertTrue(
            any(
                "immutable identifier" in error
                for error in validate_shadow_plan.validate_plan(plan)
            )
        )

    def test_v1_remains_valid(self) -> None:
        self.assertEqual(validate_shadow_plan.validate_plan(shadow_v1()), [])

    def test_v2_rejects_changed_content_after_preregistration(self) -> None:
        plan = shadow_v2()
        plan["stages"][0]["changes"][0] = "changed after preregistration"
        self.assertTrue(any("canonical plan content" in error for error in validate_shadow_plan.validate_plan(plan)))

    def test_v2_requires_per_window_review_counts(self) -> None:
        plan = shadow_v2()
        plan["labeling"]["second_review_n"] = 288
        self.assertTrue(any("must provide" in error for error in validate_shadow_plan.validate_plan(plan)))

    def test_git_binding_checks_committed_plan_hash_and_time(self) -> None:
        plan = shadow_v2()
        plan["preregistration"]["preregistered_at"] = "2098-12-31T00:00:00Z"
        plan["corpus"]["development"]["start"] = "2099-01-01T00:00:00Z"
        plan["corpus"]["development"]["end"] = "2099-01-02T00:00:00Z"
        plan["corpus"]["validation"]["start"] = "2099-01-03T00:00:00Z"
        plan["corpus"]["validation"]["end"] = "2099-01-04T00:00:00Z"
        plan["corpus"]["holdout"]["start"] = "2099-01-05T00:00:00Z"
        plan["corpus"]["holdout"]["end"] = "2099-01-06T00:00:00Z"
        refresh_hash(plan)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "plan.json"
            path.write_text(json.dumps(plan), encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.name", "Synthetic Test"], check=True)
            subprocess.run(["git", "-C", str(root), "add", "plan.json"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-qm", "preregister synthetic plan"], check=True)
            commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
            errors: list[str] = []
            validate_shadow_plan.validate_git_binding(path, plan, root, commit, "plan.json", None, errors)
        self.assertEqual(errors, [])

    def test_v1_cli_requires_explicit_legacy_flag(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy-plan.json"
            path.write_text(json.dumps(shadow_v1()), encoding="utf-8")
            command = [sys.executable, str(Path(__file__).with_name("validate_shadow_plan.py")), str(path)]
            rejected = subprocess.run(command, check=False, capture_output=True, text=True)
            accepted = subprocess.run(command + ["--allow-legacy"], check=False, capture_output=True, text=True)
        self.assertEqual(rejected.returncode, 1)
        self.assertIn("legacy_error", rejected.stderr)
        self.assertEqual(accepted.returncode, 0)


class AcceptanceTests(unittest.TestCase):
    def test_acceptance_cli_requires_external_capability_manifest(self) -> None:
        plan = shadow_v2()
        results = acceptance_results(plan)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            results_path = root / "results.json"
            manifest_path = root / "capability-manifest.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            results_path.write_text(json.dumps(results), encoding="utf-8")
            manifest_path.write_text(
                json.dumps(capability_manifest(plan)), encoding="utf-8"
            )
            command = [
                sys.executable,
                str(Path(__file__).with_name("validate_acceptance.py")),
                str(plan_path),
                str(results_path),
                "--json",
            ]
            rejected = subprocess.run(command, check=False, capture_output=True, text=True)
            accepted = subprocess.run(
                command
                + [
                    "--capability-manifest",
                    str(manifest_path),
                    "--baseline-capability-manifest",
                    str(manifest_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(json.loads(rejected.stdout)["milestone"], "hypothesis_only")
        self.assertEqual(accepted.returncode, 0)

    def test_acceptance_reaches_shadow_validated(self) -> None:
        plan = shadow_v2()
        report = validate_acceptance.evaluate(plan, acceptance_results(plan))
        self.assertEqual(report["schema_errors"], [])
        self.assertEqual(report["gate_failures"], [])
        self.assertEqual(report["milestone"], "shadow_validated")
        self.assertAlmostEqual(
            report["resolutions"]["holdout"]["worst_case_95pct_proportion_half_width"],
            0.98 / math.sqrt(480),
        )

    def test_acceptance_blocks_low_kappa(self) -> None:
        plan = shadow_v2()
        report = validate_acceptance.evaluate(plan, acceptance_results(plan, kappa=0.74))
        self.assertEqual(report["milestone"], "implemented")
        self.assertTrue(any("kappa" in error for error in report["gate_failures"]))

    def test_acceptance_blocks_out_of_range_measurement(self) -> None:
        plan = shadow_v2()
        report = validate_acceptance.evaluate(plan, acceptance_results(plan, value=0.90))
        self.assertEqual(report["milestone"], "implemented")
        self.assertTrue(any("outside preregistered range" in error for error in report["gate_failures"]))

    def test_acceptance_rejects_assertion_without_quality_artifacts(self) -> None:
        plan = shadow_v2()
        results = acceptance_results(plan)
        results.pop("quality")
        report = validate_acceptance.evaluate(plan, results)
        self.assertEqual(report["milestone"], "hypothesis_only")
        self.assertTrue(any("results.quality" in error for error in report["schema_errors"]))

    def test_acceptance_rejects_unreconciled_metric_value(self) -> None:
        plan = shadow_v2()
        results = acceptance_results(plan)
        results["measurements"][0]["numerator_count"] = 11
        report = validate_acceptance.evaluate(plan, results)
        self.assertEqual(report["milestone"], "hypothesis_only")
        self.assertTrue(any("numerator_count / denominator_count" in error for error in report["schema_errors"]))

    def test_acceptance_blocks_loss_of_existing_capability(self) -> None:
        plan = shadow_v2()
        results = acceptance_results(plan)
        capability = results["capability_preservation"]["capabilities"][
            "malicious_attachment_detection"
        ]
        capability["candidate_pass_case_ids"].remove(
            "malicious_attachment_detection_case_2"
        )
        report = validate_acceptance.evaluate(plan, results)
        self.assertEqual(report["milestone"], "implemented")
        self.assertTrue(
            any("capability regression malicious_attachment_detection" in error for error in report["gate_failures"])
        )

    def test_acceptance_rejects_missing_capability_result(self) -> None:
        plan = shadow_v2()
        results = acceptance_results(plan)
        results["capability_preservation"]["capabilities"].pop(
            "credential_phishing_detection"
        )
        report = validate_acceptance.evaluate(plan, results)
        self.assertEqual(report["milestone"], "hypothesis_only")
        self.assertTrue(
            any("exactly match all required capability ids" in error for error in report["schema_errors"])
        )

    def test_acceptance_reaches_release_ready_only_with_release_evidence(self) -> None:
        plan = shadow_v2()
        results = acceptance_results(plan)
        results["release"] = {
            "artifact_id": "vigilyx-email-security@" + "c" * 40,
            "rollback_verified": True,
            "rollback_evidence_id": "rollback@" + "d" * 40,
            "deployment_verified": True,
            "deployment_evidence_id": "deployment@" + "e" * 40,
            "rollback_owner": "synthetic-oncall",
            "deployment_mode": "mirror",
            "disposition_reviewed": True,
            "disposition_evidence_id": "disposition@" + "f" * 40,
            "registry_validation_evidence_id": "registry-validation@" + "a" * 40,
            "capability_evidence_id": "capability-regression@" + "b" * 40,
            "owner": "synthetic-oncall",
        }
        report = validate_acceptance.evaluate(plan, results)
        self.assertEqual(report["milestone"], "release_ready")


class EvidenceRegistryTests(unittest.TestCase):
    def test_malformed_registry_root_is_rejected(self) -> None:
        errors, _ = validate_evidence_registry.validate_registry([])
        self.assertEqual(errors, ["registry root must be an object"])

    def test_v2_registry_is_valid(self) -> None:
        errors, _ = validate_evidence_registry.validate_registry(registry_v2())
        self.assertEqual(errors, [])

    def test_v2_rejects_object_observation_reference_without_crashing(self) -> None:
        registry = registry_v2()
        registry["promotions"][0]["observations"] = [{"category": "synthetic_observation"}]
        errors, _ = validate_evidence_registry.validate_registry(registry)
        self.assertTrue(any("registered category id string" in error for error in errors))

    def test_v2_allows_shared_causal_template_for_runtime_deduplication(self) -> None:
        registry = registry_v2()
        registry["categories"]["synthetic_payload_attack"]["causal_key_template"] = registry["categories"][
            "synthetic_promoted_attack"
        ]["causal_key_template"]
        errors, _ = validate_evidence_registry.validate_registry(registry)
        self.assertEqual(errors, [])

    def test_v2_rejects_static_category_causal_key(self) -> None:
        registry = registry_v2()
        registry["categories"]["synthetic_payload_attack"]["causal_key_template"] = "payload:static"
        errors, _ = validate_evidence_registry.validate_registry(registry)
        self.assertTrue(any("runtime placeholder" in error for error in errors))

    def test_v2_rejects_unregistered_breaker_basis(self) -> None:
        registry = registry_v2()
        registry["categories"]["synthetic_promoted_attack"]["breaker_basis"]["category_ids"] = ["not_registered"]
        errors, _ = validate_evidence_registry.validate_registry(registry)
        self.assertTrue(any("unknown category" in error for error in errors))

    def test_v2_rejects_floor_without_independent_prerequisites(self) -> None:
        registry = registry_v2()
        registry["floors"][0]["trigger_categories"] = [
            "synthetic_promoted_attack",
            "synthetic_promoted_attack",
        ]
        errors, _ = validate_evidence_registry.validate_registry(registry)
        self.assertTrue(any("unique strings" in error or "independent" in error for error in errors))

    def test_v2_requires_runtime_causal_independence_guard(self) -> None:
        registry = registry_v2()
        registry["floors"][0].pop("require_distinct_runtime_causal_keys")
        registry["promotions"][0].pop("require_distinct_runtime_causal_keys")
        errors, _ = validate_evidence_registry.validate_registry(registry)
        self.assertGreaterEqual(
            sum("require_distinct_runtime_causal_keys" in error for error in errors), 2
        )

    def test_v2_rejects_emitted_manifest_with_dead_category(self) -> None:
        registry = registry_v2()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = root / "registry.json"
            emitted_path = root / "emitted.json"
            registry_path.write_text(json.dumps(registry), encoding="utf-8")
            emitted_path.write_text(json.dumps(["synthetic_observation"]), encoding="utf-8")
            command = [
                sys.executable,
                str(Path(__file__).with_name("validate_evidence_registry.py")),
                "--registry",
                str(registry_path),
                "--emitted",
                str(emitted_path),
            ]
            result = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("never emitted", result.stderr)

    def test_v1_registry_cli_requires_explicit_legacy_flag(self) -> None:
        registry = registry_v2()
        registry["version"] = 1
        for item in registry["categories"].values():
            for key in (
                "causal_key_template",
                "direct_fusion",
                "auth_provenance",
                "breaker_basis",
            ):
                item.pop(key, None)
        registry["promotions"][0].pop("causal_independence")
        registry["promotions"][0].pop("require_distinct_runtime_causal_keys")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy-registry.json"
            path.write_text(json.dumps(registry), encoding="utf-8")
            command = [
                sys.executable,
                str(Path(__file__).with_name("validate_evidence_registry.py")),
                "--registry",
                str(path),
            ]
            rejected = subprocess.run(command, check=False, capture_output=True, text=True)
            accepted = subprocess.run(command + ["--allow-legacy"], check=False, capture_output=True, text=True)
        self.assertEqual(rejected.returncode, 1)
        self.assertIn("legacy_error", rejected.stderr)
        self.assertEqual(accepted.returncode, 0)


class PublicValidatorContractTests(unittest.TestCase):
    def test_public_cli_help_without_private_skill(self) -> None:
        for name in ("validate_acceptance.py", "validate_shadow_plan.py", "validate_evidence_registry.py"):
            with self.subTest(name=name):
                result = subprocess.run([sys.executable, str(Path(__file__).with_name(name)), "--help"],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usage:", result.stdout)

    def test_v1_registry_remains_valid(self) -> None:
        registry = registry_v2()
        registry["version"] = 1
        for item in registry["categories"].values():
            for key in (
                "causal_key_template",
                "direct_fusion",
                "auth_provenance",
                "breaker_basis",
            ):
                item.pop(key, None)
        registry["promotions"][0].pop("causal_independence")
        registry["promotions"][0].pop("require_distinct_runtime_causal_keys")
        errors, _ = validate_evidence_registry.validate_registry(registry)
        self.assertEqual(errors, [])

    def test_v2_rejects_diagnostic_breaker(self) -> None:
        registry = registry_v2()
        registry["categories"]["synthetic_observation"] = category(
            "diagnostic", direct_fusion=False, breaker_eligible=True
        )
        errors, _ = validate_evidence_registry.validate_registry(registry)
        self.assertTrue(any("cannot be breaker_eligible" in error for error in errors))

    def test_v2_rejects_modified_auth_as_promotion_authority(self) -> None:
        registry = registry_v2()
        registry["categories"]["synthetic_auth_fail"][
            "auth_provenance"
        ] = "unknown_modified"
        errors, _ = validate_evidence_registry.validate_registry(registry)
        self.assertTrue(any("provenance-qualified" in error for error in errors))

    def test_v2_rejects_duplicate_inputs_and_multihop(self) -> None:
        registry = registry_v2()
        registry["promotions"][0]["observations"].append("synthetic_observation")
        registry["categories"]["synthetic_second_attack"] = category(
            "native_actionable", direct_fusion=True
        )
        registry["promotions"].append(
            {
                "id": "synthetic_second_scenario",
                "observations": ["synthetic_observation"],
                "triggers": ["synthetic_promoted_attack"],
                "causal_independence": "synthetic second source",
                "result": "synthetic_second_attack",
            }
        )
        errors, _ = validate_evidence_registry.validate_registry(registry)
        self.assertTrue(any("contains duplicates" in error for error in errors))
        self.assertTrue(any("cannot trigger another promotion" in error for error in errors))

    def test_v2_rejects_promotion_cycle_even_when_metadata_is_malformed(self) -> None:
        registry = registry_v2()
        first = registry["categories"]["synthetic_promoted_attack"]
        first.update(
            {
                "evidence_class": "observation",
                "direct_fusion": False,
                "breaker_eligible": False,
                "promotion_authority": False,
            }
        )
        first.pop("breaker_basis")
        registry["promotions"].append(
            {
                "id": "synthetic_cycle",
                "observations": ["synthetic_promoted_attack"],
                "triggers": ["synthetic_auth_fail"],
                "causal_independence": "synthetic independent cycle control",
                "result": "synthetic_observation",
            }
        )
        errors, _ = validate_evidence_registry.validate_registry(registry)
        self.assertTrue(any("promotion graph contains a cycle" in error for error in errors))


if __name__ == "__main__":
    unittest.main(verbosity=2)
