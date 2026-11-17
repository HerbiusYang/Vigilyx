"""Numerical contract fixtures, NOT a real feedback corpus or performance benchmark.

Run only on 77: python3 -m unittest discover -s tests -p test_ds_learned_model.py
"""

import copy
import hashlib
import importlib.util
import itertools
import json
import math
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ds_learned_model.py"
SPEC = importlib.util.spec_from_file_location("ds_learned_model", SCRIPT)
ds = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ds
SPEC.loader.exec_module(ds)


def model(sources=None, base_rate=.01):
    return {"schema_version": 1, "parameter_version": "unit-fixture-v1", "training_status": "bootstrap",
            "sources": sources or {}, "base_rate": base_rate, "calibration": None,
            "training_sample_count": 0}


def item(source="content:request", key="body:one", score=.8, confidence=.9, legacy=.4, anchor=0., scored=True):
    return {"source_id": source, "causal_key": key, "cluster": "social_engineering_intent",
            "raw_score": score, "confidence": confidence, "item_scored": scored,
            "legacy_mass": legacy, "confirmed_anchor_mass": anchor}


def case(case_id="train-a", split="train", label=1, score=.8, group=None, day=1):
    # These provenance strings only exercise validation code. This fixture must
    # never be exported as human feedback or an independent real-world holdout.
    return {"case_id": case_id, "group_id": group, "split": split, "label": label,
            "label_source": "analyst_feedback", "data_origin": "analyst_feedback",
            "corrected_threat_level": "high" if label else "safe",
            "content_sha256": hashlib.sha256(("numerical-fixture:" + case_id).encode()).hexdigest(),
            "items": [item(score=score)], "adjudicated": True,
            "observed_at": f"2026-01-{day:02d}T01:00:00Z",
            "labeled_at": f"2026-01-{day:02d}T02:00:00Z"}


def feedback(rows=None):
    return {"schema_version": 1, "cases": rows or [case()]}


def independent_fixture():
    rows = []
    for day, split in enumerate(ds.SPLITS, 1):
        for label, score in ((0, .1), (1, .9)):
            name = f"{split}-{label}"
            rows.append(case(name, split, label, score, "campaign-" + name, day))
    return {"schema_version": 1, "cases": rows, "evaluation_protocol": {
        "holdout_frozen_before_fit": True, "holdout_frozen_at": "2025-12-31T00:00:00Z",
        "holdout_labels_hidden_during_fit": True}}


class InferenceTests(unittest.TestCase):
    def test_exact_mapping_and_projection(self):
        params = model({"content:request": {"slope": 4., "intercept": -2., "reliability": .8}})
        output = ds.predict([item()], params)
        b = .8 * .9 * ds.sigmoid(4 * .8 - 2)
        self.assertAlmostEqual(output["belief"], b)
        self.assertAlmostEqual(output["uncertainty"], 1 - b)
        self.assertAlmostEqual(output["probability"], b + .01 * (1 - b))
        self.assertEqual(output["disbelief"], 0)
        self.assertEqual(output["conflict"], 0)

    def test_zero_empty_missing_and_unknown_source(self):
        params = model({"content:request": dict(ds.SOURCE_DEFAULT)})
        self.assertEqual(ds.predict([], params)["belief"], 0)
        self.assertEqual(ds.predict([], params)["probability"], .01)
        self.assertEqual(ds.predict([item(score=0, anchor=.4)], params)["risk_constrained"], .01)
        self.assertEqual(ds.predict([item(confidence=0)], params)["belief"], 0)
        self.assertAlmostEqual(ds.predict([item(source="unknown:source")], params)["belief"], .4)
        self.assertAlmostEqual(ds.predict([item(scored=False)], params)["belief"], .4)
        with self.assertRaises(ds.ContractError):
            ds.predict([dict(item(), raw_score=None)], params)

    def test_anchors_do_not_change_belief_or_probability(self):
        params = model({"content:request": {"slope": 1., "intercept": -10., "reliability": .1}})
        left = ds.predict([item(anchor=0, legacy=.8)], params)
        right = ds.predict([item(anchor=.8, legacy=.8)], params)
        self.assertEqual(left["belief"], right["belief"])
        self.assertEqual(left["probability"], right["probability"])
        self.assertEqual(right["risk_constrained"], .8)
        with self.assertRaises(ds.ContractError):
            ds.predict([item(anchor=.5, legacy=.4)], params)

    def test_calibration_does_not_change_bpa_or_anchor(self):
        params = model()
        baseline = ds.predict([item()], params)
        params["calibration"] = {"slope": 2., "intercept": -1.}
        result = ds.predict([item()], params)
        self.assertEqual(result["belief"], baseline["belief"])
        self.assertAlmostEqual(result["probability"], ds.sigmoid(2 * ds.logit(baseline["probability"]) - 1))
        self.assertTrue(result["probability_calibration_applied"])

    def test_same_source_different_urls_do_not_accumulate(self):
        result = ds.predict([item(key="url:https://a.example/"), item(key="url:https://b.example/")], model())
        self.assertAlmostEqual(result["belief"], .4)
        self.assertEqual(len(result["components"]), 1)

    def test_different_sources_same_key_do_not_accumulate(self):
        self.assertAlmostEqual(ds.predict([item(), item(source="link:request")], model())["belief"], .4)

    def test_different_sources_and_keys_accumulate_under_declared_assumption(self):
        rows = [item(), item(source="payload:malware", key="attachment:a", legacy=.5)]
        self.assertAlmostEqual(ds.predict(rows, model())["belief"], .7)

    def test_transitive_dependency_is_permutation_and_duplicate_invariant(self):
        rows = [item(source="a:signal", key="key-1", legacy=.3),
                item(source="b:signal", key="key-1", legacy=.5),
                item(source="b:signal", key="key-2", legacy=.4),
                item(source="c:signal", key="key-2", legacy=.6)]
        for order in itertools.permutations(rows):
            result = ds.predict(list(order) + [rows[0]], model())
            self.assertAlmostEqual(result["belief"], .6)
            self.assertEqual(len(result["components"]), 1)
            self.assertEqual(result["components"][0]["causal_keys"], ["key-1", "key-2"])

    def test_null_is_unknown_overlap_not_independent_source(self):
        rows = [item(legacy=.3), item(source="other:signal", key=None, legacy=.6)]
        result = ds.predict(rows, model())
        self.assertAlmostEqual(result["belief"], .6)
        self.assertAlmostEqual(result["unbound_residual"], (.6 - .3) / .7)
        rows.append(item(source="another:signal", key=None, legacy=.5))
        self.assertAlmostEqual(ds.predict(rows, model())["belief"], .6)

    def test_zero_raw_does_not_bridge_but_zero_reliability_preserves_graph(self):
        rows = [item(source="a:x", key="one", legacy=.3),
                item(source="b:x", key="two", legacy=.4),
                item(source="bridge:x", key="one", score=.5),
                item(source="bridge:x", key="two", score=.5)]
        params = model({"bridge:x": {"slope": 4., "intercept": -2., "reliability": 0.}})
        self.assertAlmostEqual(ds.predict(rows, params)["belief"], .4)
        params["sources"]["bridge:x"]["reliability"] = 1e-10
        self.assertAlmostEqual(ds.predict(rows, params)["belief"], .4)
        rows[2]["raw_score"] = rows[3]["raw_score"] = 0
        self.assertAlmostEqual(ds.predict(rows, params)["belief"], .58)

    def test_finite_bounded_and_strict_model_schema(self):
        for value in (float("nan"), float("inf"), -1., 1.1, True, "0.5"):
            with self.subTest(value=value), self.assertRaises(ds.ContractError):
                ds.predict([dict(item(), raw_score=value)], model())
        for key, value in (("slope", -1), ("slope", 17), ("intercept", -17), ("reliability", 2)):
            params = model({"content:request": dict(ds.SOURCE_DEFAULT, **{key: value})})
            with self.assertRaises(ds.ContractError):
                ds.predict([item()], params)
        with self.assertRaises(ds.ContractError):
            ds.validate_parameters(dict(model(), silent_fallback=True))
        with self.assertRaises(ds.ContractError):
            ds.validate_parameters(dict(model(), training_sample_count=True))

    def test_gradient_matches_fixed_graph_finite_difference(self):
        params = model({"content:request": dict(ds.SOURCE_DEFAULT)})
        items = ds.parse_items([item(), item(source="payload:x", key="file", legacy=.2)])
        _, gradient = ds._predict(items, params, gradients=True)
        for key in ds.SOURCE_BOUNDS:
            plus, minus = copy.deepcopy(params), copy.deepcopy(params)
            plus["sources"]["content:request"][key] += 1e-6
            minus["sources"]["content:request"][key] -= 1e-6
            numerical = (ds._predict(items, plus)[0]["probability_uncalibrated"]
                         - ds._predict(items, minus)[0]["probability_uncalibrated"]) / 2e-6
            self.assertAlmostEqual(gradient["content:request"][key], numerical, places=7)


class FeedbackLearningTests(unittest.TestCase):
    def test_tiny_training_only_is_candidate_and_pending(self):
        trained, report = ds.train_candidate(feedback(), epochs=4)
        self.assertEqual(trained["training_status"], "candidate")
        self.assertEqual(trained["training_sample_count"], 1)
        self.assertFalse(report["automatic_activation"])
        self.assertFalse(report["release_ready"])
        self.assertIsNone(report["independent_evaluation"])
        self.assertIn("missing_holdout_split", report["pending_gates"])
        self.assertIn("missing_campaign_group_ids", report["pending_gates"])

    def test_real_optimization_and_deterministic_row_order(self):
        rows = [case("positive", label=1, score=.9), case("negative", label=0, score=.1)]
        trained, report = ds.train_candidate(feedback(rows), epochs=30)
        self.assertLess(report["training_diagnostics_not_validation"]["nll_after"],
                        report["training_diagnostics_not_validation"]["nll_before"])
        reverse, _ = ds.train_candidate(feedback(list(reversed(rows))), epochs=30)
        self.assertEqual(trained, reverse)

    def test_severity_original_verdict_and_anchor_do_not_train_probability(self):
        original = feedback([case("p", label=1), case("n", label=0, score=.2)])
        altered = copy.deepcopy(original)
        for row in altered["cases"]:
            row["corrected_threat_level"] = "critical"
            row["original_verdict"] = {"risk": .99, "threat_level": "critical"}
            row["items"][0]["confirmed_anchor_mass"] = .4
        left, _ = ds.train_candidate(original, epochs=6)
        right, _ = ds.train_candidate(altered, epochs=6)
        self.assertEqual(left, right)

    def test_unseen_calibration_holdout_source_is_not_added(self):
        data = independent_fixture()
        data["cases"][-1]["items"][0]["source_id"] = "holdout_only:signal"
        trained, _ = ds.train_candidate(data, epochs=4)
        self.assertNotIn("holdout_only:signal", trained["sources"])

    def test_existing_unobserved_source_continuity_and_stale_calibration_cleared(self):
        initial = model({"retained:source": {"slope": 2., "intercept": -3., "reliability": .7}})
        initial["calibration"] = {"slope": 2., "intercept": 1.}
        trained, _ = ds.train_candidate(feedback(), initial, epochs=3)
        self.assertEqual(initial["sources"]["retained:source"], trained["sources"]["retained:source"])
        self.assertIsNone(trained["calibration"])

    def test_model_or_synthetic_labels_cannot_train(self):
        for key, value in (("label_source", "original_verdict"), ("label_source", "llm"),
                           ("data_origin", "synthetic"), ("data_origin", "redteam"),
                           ("synthetic", True), ("automated_label", True), ("label", True)):
            data = feedback()
            data["cases"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ds.ContractError):
                ds.train_candidate(data, epochs=1)

    def test_group_and_hash_leakage_rejected(self):
        data = independent_fixture()
        data["cases"][-1]["group_id"] = data["cases"][0]["group_id"]
        with self.assertRaises(ds.ContractError):
            ds.parse_feedback(data)
        data = independent_fixture()
        data["cases"][-1]["content_sha256"] = data["cases"][0]["content_sha256"]
        with self.assertRaises(ds.ContractError):
            ds.parse_feedback(data)

    def test_time_overlap_future_freeze_and_naive_time_rejected(self):
        data = independent_fixture()
        data["cases"][-1]["observed_at"] = "2026-01-01T01:00:00Z"
        with self.assertRaises(ds.ContractError):
            ds.parse_feedback(data)
        data = independent_fixture()
        data["evaluation_protocol"]["holdout_frozen_at"] = "2026-01-04T00:00:00Z"
        with self.assertRaises(ds.ContractError):
            ds.train_candidate(data, epochs=1)
        data = feedback()
        data["cases"][0]["observed_at"] = "2026-01-01T01:00:00"
        with self.assertRaises(ds.ContractError):
            ds.parse_feedback(data)

    def test_complete_tiny_splits_report_uncertainty_and_never_promote(self):
        trained, report = ds.train_candidate(independent_fixture(), epochs=3)
        self.assertEqual(trained["training_status"], "candidate")
        evaluation = report["independent_evaluation"]
        self.assertIsNotNone(evaluation)
        self.assertFalse(evaluation["holdout_fpr_upper95_meets_target"])
        self.assertEqual(evaluation["threshold_fit_split"], "calibration")
        self.assertIn("external_complete_capability_preservation", report["pending_gates"])
        self.assertIn("holdout_fpr_precision_or_performance_insufficient", report["pending_gates"])
        self.assertFalse(report["release_ready"])

    def test_holdout_labels_do_not_affect_trained_parameters(self):
        data = independent_fixture()
        altered = copy.deepcopy(data)
        for row in altered["cases"]:
            if row["split"] == "holdout":
                row["label"] = 1 - row["label"]
        first, _ = ds.train_candidate(data, epochs=4)
        second, _ = ds.train_candidate(altered, epochs=4)
        self.assertEqual(first, second)

    def test_missing_provenance_prevents_validation_report(self):
        data = independent_fixture()
        data["cases"][0]["adjudicated"] = False
        _, report = ds.train_candidate(data, epochs=1)
        self.assertIsNone(report["independent_evaluation"])
        self.assertFalse(report["calibration_fitted"])
        self.assertIn("labels_not_independently_adjudicated", report["pending_gates"])

    def test_fixed_fpr_threshold_not_selected_on_holdout(self):
        rows = [(.1, 0), (.7, 0), (.6, 1), (.9, 1)]
        self.assertEqual(ds._fixed_fpr_threshold(rows, 0), .9)
        self.assertEqual(ds._fixed_fpr_threshold(rows, .5), .6)


class ArtifactTests(unittest.TestCase):
    def test_shared_parameter_hash_normalizes_numeric_types_and_signed_zero(self):
        first = model({"content:request": {"slope": 2, "intercept": 0, "reliability": 1}})
        second = model({"content:request": {"slope": 2., "intercept": -0., "reliability": 1.}})
        self.assertEqual(ds.parameter_content_sha256(first), ds.parameter_content_sha256(second))
        second["training_status"] = "validated"
        self.assertNotEqual(ds.parameter_content_sha256(first), ds.parameter_content_sha256(second))

    def test_public_parity_fixture(self):
        fixture, _ = ds.read_json(SCRIPT.parents[1] / "tests/fixtures/ds-learning-parity.json")
        for row in fixture["cases"]:
            with self.subTest(case=row["id"]):
                actual = ds.predict(row["items"], row["model"])
                for key, expected in row["expected"].items():
                    if key == "calibrated":
                        got = actual["probability"] if actual["probability_calibration_applied"] else None
                    else:
                        got = actual[key]
                    if expected is None:
                        self.assertIsNone(got)
                    else:
                        self.assertAlmostEqual(got, expected, places=12)
                if "parameter_content_sha256" in row:
                    self.assertEqual(ds.parameter_content_sha256(row["model"]), row["parameter_content_sha256"])

    def test_strict_json_nonfinite_duplicate_and_raw_bytes_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            for raw in ('{"a":NaN}', '{"a":1,"a":2}'):
                path.write_text(raw)
                with self.assertRaises(ds.ContractError):
                    ds.read_json(path)
            path.write_bytes(b'{"a": 1}\n')
            value, digest = ds.read_json(path)
            self.assertEqual(value, {"a": 1})
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_cli_candidate_artifact_hash_and_no_activation(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, output, report_path = [Path(tmp) / name for name in ("input.json", "model.json", "report.json")]
            ds.write_json(source, feedback())
            status = ds.main(["train", "--input", str(source), "--output", str(output),
                              "--report", str(report_path), "--epochs", "2"])
            self.assertEqual(status, 0)
            artifact = json.loads(output.read_text())
            report = json.loads(report_path.read_text())
            self.assertEqual(artifact["training_status"], "candidate")
            self.assertEqual(report["parameter_artifact_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
            self.assertFalse(report["automatic_activation"])


if __name__ == "__main__":
    unittest.main()
