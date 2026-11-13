"""Run remotely only: python3 -m unittest discover -s tests -p 'test_ds_*experiment.py'."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ds_fusion_experiment as ds
import ds_replay_to_experiment as bridge


def source(engine="social_engineering_intent", b=.4, d=0):
    return {"engine_id": engine, "engine_name": "test", "modules": ["module_a", "module_b"],
            "key_factors": ["PRIVATE FACTOR MUST NOT BE COPIED"],
            "bpa": {"b": b, "d": d, "u": 1 - b - d, "epsilon": 0}}


def record(sources=None, file="case.eml", version=3):
    sources = [source()] if sources is None else sources
    mass, diagnostics = ds.yager([bridge.closed_mass(s["bpa"]) for s in sources])
    return {"schema_version": 1, "record_type": "synthetic_capability_regression",
            "independent_holdout": False, "file": file, "threat_level": "medium",
            "classification": "phishing", "inspection_coverage": "complete", "would_deliver": False,
            "label": 1, "session": {"body": "PRIVATE EMAIL MUST NOT BE COPIED"},
            "module_results": {"secrets": "PRIVATE MODULE MUST NOT BE COPIED"},
            "verdict": {"fusion_details": {"primary_result": {
                "model": "clustered_ds_v2", "model_version": version,
                "fused_bpa": {**ds.asdict(mass), "epsilon": 0}, "risk_base": mass.b,
                "k_conflict": diagnostics["conjunctive_conflict"], "source_details": sources}}}}


class BridgeTests(unittest.TestCase):
    def test_exact_clusters_no_admission_reimplementation_or_private_content(self):
        raw = record([source(), source("payload_malware", .7)])
        doc = bridge.convert_records([raw], "candidate-sha256")
        case = doc["cases"][0]
        self.assertEqual(len(case["items"]), 2)  # Not four module votes.
        self.assertEqual(case["items"][0]["bpa"], {"b": .4, "d": 0, "u": .6})
        self.assertEqual(case["split"], "redteam")
        self.assertIsNone(case["label"])
        self.assertNotIn("PRIVATE", json.dumps(doc))
        self.assertEqual(case["adapter_trace"]["primary_bpa_parity"], "verified")
        self.assertFalse(case["adapter_trace"]["legacy_model_version"])
        report = ds.run_experiment(doc, projection="uniform_assumption")
        self.assertEqual(report["comparison_scope"], "cluster_level_only")
        self.assertEqual(report["adapter"]["artifact_id"], "candidate-sha256")
        for method in ("yager_raw", "cautious_yager", "pcr6_grouped", "noisy_or_grouped"):
            prediction = report["methods"][method]["cases"][0]
            self.assertAlmostEqual(prediction["evidence"]["belief"], .82)
            self.assertEqual(prediction["adapter_trace"]["primary_bpa_parity"], "verified")
            self.assertIsNone(report["methods"][method]["metrics"])

    def test_legacy_auth_rejected_or_explicitly_excluded_not_relabelled(self):
        raw = record([source(), source(bridge.LEGACY_AUTH, 0, .63)], version=1)
        with self.assertRaisesRegex(ValueError, "legacy auth"):
            bridge.convert_records([raw], "baseline")
        doc = bridge.convert_records([raw], "baseline", "exclude")
        case = doc["cases"][0]
        trace = case["adapter_trace"]
        self.assertEqual(len(case["items"]), 1)
        self.assertEqual(case["items"][0]["bpa"]["d"], 0)
        self.assertTrue(trace["legacy_model_version"])
        self.assertEqual(trace["adaptation_status"], "legacy_frame_excluded")
        self.assertEqual(trace["primary_bpa_parity"], "not_comparable_after_frame_exclusion")
        self.assertEqual(trace["source_counts"], {"original": 2, "retained": 1, "excluded": 1})
        self.assertAlmostEqual(trace["original_primary_bpa"]["b"], .148)
        report = ds.run_experiment(doc, projection="uniform_assumption")
        self.assertAlmostEqual(report["methods"]["yager_raw"]["cases"][0]["evidence"]["belief"], .4)

    def test_known_legacy_model_without_auth_is_still_marked(self):
        case = bridge.convert_records([record(version=2)], "legacy")["cases"][0]
        self.assertTrue(case["adapter_trace"]["legacy_model_version"])
        self.assertEqual(case["adapter_trace"]["primary_bpa_parity"], "verified")

    def test_revision_four_keeps_action_severity_floor_out_of_bpa(self):
        raw = record(version=4)
        raw["threat_level"] = "high"
        raw["risk_single"] = .65
        primary = raw["verdict"]["fusion_details"]["primary_result"]
        primary["risk_constrained"] = .65
        primary["active_constraints"] = [{"id": "qualified_harmful_action_high_minimum",
                                           "lower": .65, "upper": 1, "basis": ["synthetic-proof"]}]
        document = bridge.convert_records([raw], "revision-four")
        case = document["cases"][0]
        self.assertEqual(case["adapter_trace"]["model_version"], 4)
        self.assertFalse(case["adapter_trace"]["legacy_model_version"])
        self.assertEqual(case["adapter_trace"]["primary_bpa_parity"], "verified")
        self.assertEqual(case["adapter_trace"]["original_outcome"]["threat_level"], "high")
        self.assertEqual(case["items"][0]["bpa"], {"b": .4, "d": 0, "u": .6})
        result = ds.run_experiment(document, methods=("yager_raw",), projection="uniform_assumption")
        self.assertAlmostEqual(result["methods"]["yager_raw"]["cases"][0]["evidence"]["belief"], .4)

    def test_no_shadow_stdout_or_module_fallback(self):
        for raw in ({"file": "case.eml", "module_results": {}},
                    {**record(), "verdict": {"fusion_details": {"shadow_results": []}}}):
            with self.assertRaises(ValueError):
                bridge.convert_records([raw], "artifact")
        raw = record()
        raw["independent_holdout"] = True
        with self.assertRaises(ValueError):
            bridge.convert_records([raw], "artifact")

    def test_revision_five_bootstrap_preserves_exact_cluster_bpa(self):
        raw = record([source(), source("payload_malware", .7)], version=5)
        primary = raw["verdict"]["fusion_details"]["primary_result"]
        primary["learning_model"] = {"status": "bootstrap", "candidate_belief": .95,
                                     "candidate_probability": .98}
        primary["risk_constrained"] = .9
        document = bridge.convert_records([raw], "revision-five-bootstrap")
        case = document["cases"][0]
        self.assertEqual(case["adapter_trace"]["learning_status"], "bootstrap")
        self.assertEqual(case["adapter_trace"]["primary_bpa_parity"], "verified")
        result = ds.run_experiment(document, methods=("yager_raw",), projection="uniform_assumption")
        self.assertAlmostEqual(result["methods"]["yager_raw"]["cases"][0]["evidence"]["belief"], .82)

    def test_revision_five_learned_active_or_missing_status_is_not_cluster_parity(self):
        for status in ("validated_active", None):
            raw = record([source("learned_dependency_groups", .8)], version=5)
            if status is not None:
                raw["verdict"]["fusion_details"]["primary_result"]["learning_model"] = {"status": status}
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, "runtime item replay"):
                bridge.convert_records([raw], "revision-five-learned-active")

    def test_unknown_frame_cluster_version_and_open_world_rejected(self):
        for change in ("cluster", "frame", "normal_mass", "epsilon", "version", "sum"):
            raw = record()
            primary = raw["verdict"]["fusion_details"]["primary_result"]
            src = primary["source_details"][0]
            if change == "cluster":
                src["engine_id"] = "unregistered_new_cluster"
            elif change == "frame":
                src["frame"] = "authentication"
            elif change == "normal_mass":
                src["bpa"] = {"b": 0, "d": .4, "u": .6}
            elif change == "epsilon":
                src["bpa"]["epsilon"] = .1
            elif change == "sum":
                src["bpa"]["u"] = .9
            else:
                primary["model_version"] = 999
            with self.subTest(change=change), self.assertRaises(ValueError):
                bridge.convert_records([raw], "artifact")

    def test_incomplete_or_inconsistent_source_details_fail_closed(self):
        for change in ("bpa", "conflict", "risk", "duplicate"):
            raw = record()
            primary = raw["verdict"]["fusion_details"]["primary_result"]
            if change == "bpa":
                primary["source_details"][0]["bpa"] = {"b": .6, "d": 0, "u": .4}
            elif change == "conflict":
                primary["k_conflict"] = .1
            elif change == "risk":
                primary["risk_base"] = .8
            else:
                primary["source_details"].append(copy.deepcopy(primary["source_details"][0]))
            with self.subTest(change=change), self.assertRaises(ValueError):
                bridge.convert_records([raw], "artifact")

    def test_empty_evidence_remains_unknown(self):
        doc = bridge.convert_records([record([])], "artifact")
        report = ds.run_experiment(doc, projection="uniform_assumption")
        evidence = report["methods"]["yager_raw"]["cases"][0]["evidence"]
        self.assertEqual(evidence["bpa"], {"b": 0, "d": 0, "u": 1})
        self.assertEqual(report["methods"]["dbf_grouped"]["cases"][0]["status"], "unsupported")

    def test_cluster_replay_cannot_fit_or_be_promoted_to_holdout(self):
        doc = bridge.convert_records([record()], "artifact")
        for kwargs in ({"mode": "evaluate"}, {"projection": "training_prior"}):
            with self.assertRaises(ValueError):
                ds.run_experiment(doc, **{"projection": "uniform_assumption", **kwargs})
        for scope in ("top_level", "case_level"):
            altered = copy.deepcopy(doc)
            if scope == "case_level":
                del altered["comparison_scope"]
            altered["cases"][0]["split"] = "train"
            altered["cases"][0]["label"] = 1
            altered["cases"][0]["data_origin"] = "adjudicated"
            with self.assertRaises(ValueError):
                ds.run_experiment(altered, mode="evaluate", learn=True, projection="uniform_assumption")

    def test_duplicate_records_and_unsafe_paths_rejected(self):
        for records in ([], [record(), record()], [record(file="../case.eml")],
                        [record(file="/case.eml")], [record(file="./case.eml")]):
            with self.assertRaises(ValueError):
                bridge.convert_records(records, "artifact")

    def test_jsonl_rejects_nonfinite_duplicate_keys_blank_lines_and_legacy_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            for text in ('{"a": NaN}\n', '{"a":1,"a":2}\n', '{}\n\n', '[case] FINAL=Medium\n'):
                path.write_text(text)
                with self.assertRaises(ValueError):
                    bridge.read_jsonl(path)

    def test_cli_end_to_end_preserves_adapter_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            raw, converted, result = (path / name for name in ("raw.jsonl", "cases.json", "result.json"))
            raw.write_text(json.dumps(record()) + "\n")
            subprocess.run([sys.executable, str(ROOT / "scripts/ds_replay_to_experiment.py"),
                            "--input", str(raw), "--output", str(converted), "--artifact-id", "test-artifact"],
                           check=True, capture_output=True)
            subprocess.run([sys.executable, str(ROOT / "scripts/ds_fusion_experiment.py"),
                            "--input", str(converted), "--output", str(result),
                            "--projection", "uniform_assumption"], check=True, capture_output=True)
            report = json.loads(result.read_text())
            self.assertEqual(report["comparison_scope"], "cluster_level_only")
            self.assertIn("input_file_sha256", report["adapter"])
            self.assertTrue(report["comparison_limitations"])


class MathematicalFixtureTests(unittest.TestCase):
    def test_matrix_is_synthetic_development_only_and_expected_results_hold(self):
        document = json.loads((ROOT / "tests/fixtures/ds_fusion_mathematical_matrix.json").read_text())
        report = ds.run_experiment(document, projection="uniform_assumption")
        self.assertTrue(all(case["split"] == "development" and case["label"] is None
                            for case in document["cases"]))
        by_method = {method: {case["case_id"]: case for case in output["cases"]}
                     for method, output in report["methods"].items()}
        for case in document["cases"]:
            for method, expected in case.get("mathematical_expectations", {}).items():
                actual = by_method[method][case["case_id"]]
                with self.subTest(case=case["case_id"], method=method):
                    if expected == "unsupported":
                        self.assertEqual(actual["status"], "unsupported")
                    else:
                        self.assertEqual(actual["status"], "ok")
                        for focal, mass in expected.items():
                            self.assertAlmostEqual(actual["evidence"]["bpa"][focal], mass, places=9)
        for method in ds.METHODS:
            self.assertEqual(by_method[method]["authentication_wrong_frame"]["status"], "unsupported")


if __name__ == "__main__":
    unittest.main()
