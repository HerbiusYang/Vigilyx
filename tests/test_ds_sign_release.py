"""Release-gate tests; all reports, keys and certificates are ephemeral fixtures.

Run on 77 only. No production key is loaded and no production certificate is
created. The successful-path fixture exercises the actual governance validator.
"""

import copy
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ds_learned_model as ds
import ds_sign_release as signing

GOVERNANCE_SCRIPTS = ROOT / "scripts/governance"
sys.path.insert(0, str(GOVERNANCE_SCRIPTS))
FIXTURE_SPEC = importlib.util.spec_from_file_location("governance_synthetic_fixtures", GOVERNANCE_SCRIPTS / "self_test.py")
fixtures = importlib.util.module_from_spec(FIXTURE_SPEC)
FIXTURE_SPEC.loader.exec_module(fixtures)


class SigningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.model = {"schema_version": 1, "parameter_version": "synthetic-signing-test",
                      "training_status": "validated", "sources": {}, "base_rate": .01,
                      "calibration": {"slope": 1., "intercept": 0.}, "training_sample_count": 2}
        self.plan = fixtures.shadow_v2()
        self.plan["environment"]["candidate_artifact_id"] = "sha256:" + ds.parameter_content_sha256(self.model)
        self.plan["ds_learning_release_policy"] = {"false_positive_budget": .01, "decision_threshold": .40}
        fixtures.refresh_hash(self.plan)
        self.results = fixtures.acceptance_results(self.plan)
        # Invented gate fixture: move each false positive into true negatives,
        # retaining 480 rows and 410 negatives. No real performance claim.
        quality = self.results["quality"]["holdout"]
        for matrix in [quality["confusion_matrix"], *quality["per_bucket_confusion_matrices"].values()]:
            matrix["tn"] += matrix["fp"]
            matrix["fp"] = 0
        matrix = quality["confusion_matrix"]
        negatives, positives = matrix["tn"] + matrix["fp"], matrix["tp"] + matrix["fn"]
        self.results["ds_learning_acceptance"] = {
            "holdout_negatives": negatives, "holdout_positives": positives,
            "decision_threshold": .40, "decision_score": "final_threat_risk",
            "policy_constraints_applied": True, "coverage_or_disposition_used_as_threat_label": False,
            "false_positive_budget": .01,
            "false_positive_upper_bound": ds.wilson(matrix["fp"], negatives)[1],
            "recall_lower_bound": ds.wilson(matrix["tp"], positives)[0],
            "baseline_recall_lower_bound": ds.wilson(matrix["tp"], positives)[0],
            "brier": .1, "baseline_brier": .2, "review_cost": .2, "baseline_review_cost": .3,
            "baseline_confusion_matrix": dict(matrix),
            **{role + "_passing_case_ids": sorted(capability_id + ":" + case_id
                for capability_id, values in self.results["capability_preservation"]["capabilities"].items()
                for case_id in values[role + "_pass_case_ids"])
                for role in ("baseline", "candidate")}}
        self.results["release"] = {
            "artifact_id": self.plan["environment"]["candidate_artifact_id"],
            "rollback_verified": True, "rollback_evidence_id": "rollback@" + "d" * 40,
            "deployment_verified": True, "deployment_evidence_id": "deployment@" + "e" * 40,
            "rollback_owner": "synthetic-oncall", "deployment_mode": "mirror",
            "disposition_reviewed": True, "disposition_evidence_id": "disposition@" + "f" * 40,
            "registry_validation_evidence_id": "registry-validation@" + "a" * 40,
            "capability_evidence_id": "capability-regression@" + "b" * 40,
            "owner": "synthetic-oncall"}
        self.manifest = fixtures.capability_manifest(self.plan)
        self.paths = {name: self.directory / (name + ".json")
                      for name in ("model", "plan", "results", "capabilities", "baseline")}
        self.key = self.directory / "test-only-key"
        self.key.write_bytes(b"ephemeral numerical signing fixture key only")
        self.key.chmod(0o600)
        self.save()

    def save(self):
        for name, value in (("model", self.model), ("plan", self.plan), ("results", self.results),
                            ("capabilities", self.manifest), ("baseline", self.manifest)):
            ds.write_json(self.paths[name], value)

    def sign(self, key=None):
        return signing.sign_release(self.paths["model"], self.paths["plan"], self.paths["results"],
            self.paths["capabilities"], self.paths["baseline"], self.key if key is None else key)

    def test_actual_governance_validator_then_exact_hmac_payload(self):
        certificate = self.sign()
        report_hash = hashlib.sha256(self.paths["results"].read_bytes()).hexdigest()
        self.assertEqual(certificate["report_sha256"], report_hash)
        payload = signing.release_payload(certificate["parameter_sha256"], report_hash,
                                          certificate["capability_manifest_sha256"])
        self.assertFalse(payload.endswith(b"\n"))
        self.assertEqual(certificate["release_signature"], hmac.new(self.key.read_bytes(), payload, hashlib.sha256).hexdigest())
        self.assertEqual(certificate["governance_milestone"], "release_ready")
        self.assertFalse(certificate["automatic_activation"])
        self.assertEqual(set(certificate["acceptance"]), set(signing.METRIC_FIELDS) | {
            "parameter_sha256", "report_sha256", "capability_manifest_sha256", "release_signature"})

    def test_missing_or_failed_governance_gate_never_reads_key(self):
        self.results["release"]["rollback_verified"] = False
        self.save()
        with patch.object(signing, "_read_key") as read_key:
            with self.assertRaisesRegex(ds.ContractError, "validation failed"):
                self.sign()
            read_key.assert_not_called()

    def test_training_report_cannot_be_used_as_release_report(self):
        self.results = {"training_status": "candidate", "release_ready": True,
                        "independent_evaluation": {"brier": 0.01}}
        self.save()
        with self.assertRaises(ds.ContractError):
            self.sign()

    def test_candidate_or_changed_model_cannot_borrow_validated_report(self):
        for change in ({"training_status": "candidate"}, {"base_rate": .5}):
            original = copy.deepcopy(self.model)
            self.model.update(change)
            self.save()
            with self.subTest(change=change), self.assertRaises(ds.ContractError):
                self.sign()
            self.model = original

    def test_missing_plan_and_modified_baseline_manifest_fail(self):
        self.paths["plan"].unlink()
        with self.assertRaises(OSError):
            self.sign()
        self.save()
        altered = copy.deepcopy(self.manifest)
        altered["capabilities"][0]["minimum_cases"] += 1
        ds.write_json(self.paths["baseline"], altered)
        with self.assertRaises(ds.ContractError):
            self.sign()

    def test_validator_success_exit_alone_is_not_a_pass(self):
        fake = subprocess.CompletedProcess([], 0, json.dumps({"milestone": "release_ready"}), "")
        with patch.object(signing.subprocess, "run", return_value=fake), patch.object(signing, "_read_key") as key:
            with self.assertRaises(ds.ContractError):
                self.sign()
            key.assert_not_called()

    def test_no_key_weak_key_public_key_and_symlink_are_rejected(self):
        with self.assertRaises(ds.ContractError):
            signing._read_key("")
        self.key.write_bytes(b"short")
        with self.assertRaises(ds.ContractError):
            signing._read_key(self.key)
        self.key.write_bytes(b"test-only-key-that-is-long-enough" * 2)
        self.key.chmod(0o644)
        with self.assertRaises(ds.ContractError):
            signing._read_key(self.key)
        self.key.chmod(0o600)
        link = self.directory / "key-link"
        link.symlink_to(self.key)
        with self.assertRaises(ds.ContractError):
            signing._read_key(link)

    def test_hashes_require_lowercase_hex_and_payload_is_exact(self):
        self.assertEqual(signing.release_payload("a" * 64, "b" * 64, "c" * 64),
                         ("vigilyx-ds-release-v1\n" + "a" * 64 + "\n" + "b" * 64 + "\n" + "c" * 64).encode())
        for digest in ("A" * 64, "sha256:" + "a" * 64, "x" * 64, "a" * 63):
            with self.assertRaises(ds.ContractError):
                signing.release_payload(digest, "b" * 64, "c" * 64)

    def test_validator_is_pinned_and_requires_release_ready(self):
        process = subprocess.CompletedProcess([], 1, "{}", "")
        with patch.object(signing.subprocess, "run", return_value=process) as run:
            with self.assertRaises(ds.ContractError):
                self.sign()
            command = run.call_args.args[0]
            self.assertEqual(command[1], str(signing.VALIDATOR))
            self.assertEqual(command[command.index("--require-milestone") + 1], "release_ready")
            self.assertIn("--capability-manifest", command)
            self.assertIn("--baseline-capability-manifest", command)

    def test_missing_or_invented_ds_metric_block_cannot_sign(self):
        del self.results["ds_learning_acceptance"]
        self.save()
        with patch.object(signing, "_read_key") as key:
            with self.assertRaisesRegex(ds.ContractError, "ds_learning_acceptance"):
                self.sign()
            key.assert_not_called()

    def test_fabricated_confidence_bound_and_wrong_counts_rejected(self):
        original = copy.deepcopy(self.results)
        for field, value in (("false_positive_upper_bound", 0.), ("holdout_negatives", 1),
                             ("recall_lower_bound", 1.), ("baseline_recall_lower_bound", 0.)):
            self.results = copy.deepcopy(original)
            self.results["ds_learning_acceptance"][field] = value
            with self.subTest(field=field), self.assertRaises(ds.ContractError):
                signing.verified_metrics(self.plan, self.results)

    def test_no_subset_or_unqualified_capability_ids(self):
        metrics = self.results["ds_learning_acceptance"]
        metrics["baseline_passing_case_ids"] = metrics["baseline_passing_case_ids"][:1]
        with self.assertRaisesRegex(ds.ContractError, "complete qualified"):
            signing.verified_metrics(self.plan, self.results)

    def test_zero_observed_fp_small_sample_cannot_prove_budget(self):
        matrix = {"tp": 5, "fn": 0, "fp": 0, "tn": 5}
        self.results["quality"]["holdout"]["confusion_matrix"] = matrix
        self.results["windows"]["holdout"]["n"] = 10
        self.results["ds_learning_acceptance"].update(
            holdout_negatives=5, holdout_positives=5, baseline_confusion_matrix=dict(matrix),
            false_positive_upper_bound=ds.wilson(0, 5)[1],
            recall_lower_bound=ds.wilson(5, 5)[0], baseline_recall_lower_bound=ds.wilson(5, 5)[0])
        with self.assertRaisesRegex(ds.ContractError, "95% confidence"):
            signing.verified_metrics(self.plan, self.results)

    def test_offline_selected_threshold_or_unapplied_policy_cannot_sign(self):
        original = copy.deepcopy(self.results)
        for field, value in (("decision_threshold", .9), ("decision_score", "raw_belief"),
                             ("policy_constraints_applied", False),
                             ("coverage_or_disposition_used_as_threat_label", True)):
            self.results = copy.deepcopy(original)
            self.results["ds_learning_acceptance"][field] = value
            with self.subTest(field=field), self.assertRaises(ds.ContractError):
                signing.verified_metrics(self.plan, self.results)

    def test_brier_and_cost_regression_rejected(self):
        for field in ("brier", "review_cost"):
            altered = copy.deepcopy(self.results)
            altered["ds_learning_acceptance"][field] = .8
            with self.subTest(field=field), self.assertRaises(ds.ContractError):
                signing.verified_metrics(self.plan, altered)


if __name__ == "__main__":
    unittest.main()
