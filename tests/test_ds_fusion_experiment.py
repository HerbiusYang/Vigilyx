"""Mathematical/protocol tests. Run on 77: python3 -m unittest discover -s tests -p test_ds_fusion_experiment.py."""

import copy
import hashlib
import importlib.util
import itertools
import json
import math
from pathlib import Path
import sys
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ds_fusion_experiment.py"
SPEC = importlib.util.spec_from_file_location("ds_fusion_experiment", SCRIPT)
ds = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ds
SPEC.loader.exec_module(ds)


def item(b=0.0, d=0.0, key="cause-a", source="detector-a", frame="email_threat"):
    return ds.Item(source, key, frame, ds.Mass(b, d, 1.0 - b - d))


def raw_case(case_id, split, label, b, source="detector-a"):
    return {"case_id": case_id, "group_id": "campaign-" + case_id,
            # Bind this numerical fixture only, not a real email or holdout.
            "content_sha256": hashlib.sha256(("numerical-fixture:" + case_id).encode()).hexdigest(),
            "split": split, "label": label,
            "data_origin": "independent_adjudicated" if split == "holdout" else "adjudicated",
            "items": [{"source_id": source, "causal_key": "cause-" + case_id,
                       "frame": "email_threat", "bpa": {"b": b, "d": 0.0, "u": 1 - b},
                       "basis": ["synthetic numerical fixture, not measured production evidence"]}]}


def evaluation_fixture():
    # Provenance values below exercise the gate; this synthetic test is NOT an
    # actual sealed holdout and must never be presented as a detection benchmark.
    cases = []
    for split in ("train", "calibration", "holdout"):
        for i, (label, b) in enumerate(((0, 0.05), (0, 0.15), (1, 0.7), (1, 0.9))):
            cases.append(raw_case(f"{split}-{i}", split, label, b))
    return {"schema_version": 1, "evaluation_protocol": {"holdout_frozen_before_fit": True}, "cases": cases}


class FusionMathTests(unittest.TestCase):
    def assertMass(self, mass, b, d, u):
        self.assertAlmostEqual(mass.b, b, places=10)
        self.assertAlmostEqual(mass.d, d, places=10)
        self.assertAlmostEqual(mass.u, u, places=10)

    def test_yager_closed_form_and_conflict(self):
        mass, meta = ds.yager([ds.Mass(.6, 0, .4), ds.Mass(.5, 0, .5), ds.Mass(0, .63, .37)])
        p = 1 - .4 * .5
        self.assertMass(mass, p * .37, (1 - p) * .63, (1 - p) * .37 + p * .63)
        self.assertAlmostEqual(meta["conjunctive_conflict"], p * .63)

    def test_yager_nary_not_pairwise_fold(self):
        t, n = ds.Mass(.8, 0, .2), ds.Mass(0, .8, .2)
        direct, _ = ds.yager([t, n, t])
        intermediate, _ = ds.yager([t, n])
        sequential, _ = ds.yager([intermediate, t])
        self.assertMass(direct, .192, .032, .776)
        self.assertMass(sequential, .704, .032, .264)

    def test_yager_empty_vacuous_and_permutation(self):
        self.assertEqual(ds.yager([])[0], ds.VACUOUS)
        masses = [ds.Mass(.2, .1, .7), ds.Mass(.7, 0, .3), ds.Mass(0, .3, .7)]
        reference = ds.yager(masses)[0]
        for perm in itertools.permutations(masses):
            result = ds.yager(list(perm) + [ds.VACUOUS])[0]
            self.assertMass(result, reference.b, reference.d, reference.u)

    def test_cautious_same_cause_is_idempotent_distinct_causes_accumulate(self):
        observations = [item(.4), item(.4, source="detector-b")]
        duplicated = ds.fuse(observations, "cautious_yager")
        self.assertAlmostEqual(duplicated["belief"], .4)
        self.assertAlmostEqual(ds.fuse(observations, "yager_raw")["belief"], .64)
        observations.append(item(.4, key="cause-b"))
        self.assertAlmostEqual(ds.fuse(observations, "cautious_yager")["belief"], .64)

    def test_no_multi_key_fallback_or_evidence_removal(self):
        observations = [item(.4386, key="host:one.invalid"), item(.4386, key="host:two.invalid")]
        before = ds.fuse(observations, "cautious_yager")["belief"]
        observations.append(item(.4386, key="host:two.invalid", source="detector-b"))
        after = ds.fuse(observations, "cautious_yager")["belief"]
        self.assertAlmostEqual(before, .68483004)
        self.assertAlmostEqual(after, before)

    def test_grouped_domain_is_explicit(self):
        with self.assertRaises(ds.Unsupported):
            ds.fuse([item(.3), item(d=.2, source="detector-b")], "cautious_yager")
        with self.assertRaises(ds.Unsupported):
            ds.fuse([item(.3, .2), item(.4, source="detector-b")], "cautious_yager")
        for method in ds.METHODS:
            with self.assertRaises(ds.Unsupported):
                ds.fuse([item(d=.63, frame="sender_authentication")], method)

    def test_general_triplet_singleton_groups_supported(self):
        value = ds.fuse([item(.2, .3)], "cautious_yager")
        self.assertAlmostEqual(value["belief"], .2)
        self.assertAlmostEqual(value["plausibility"], .7)

    def test_pcr6_three_sources_original_reference_not_binary_fold(self):
        t, n = ds.Mass(1, 0, 0), ds.Mass(0, 1, 0)
        for perm in itertools.permutations([t, n, n]):
            self.assertMass(ds.pcr6(list(perm))[0], 1 / 3, 2 / 3, 0)
        pair, _ = ds.pcr6([t, n])
        self.assertMass(ds.pcr6([pair, n])[0], 1 / 6, 5 / 6, 0)

    def test_pcr6_partial_conflict_two_source_formula(self):
        p, n = .9, .63
        mass, meta = ds.pcr6([ds.Mass(p, 0, 1 - p), ds.Mass(0, n, 1 - n)])
        self.assertMass(mass, p * (1 - n) + p * p * n / (p + n),
                        n * (1 - p) + n * n * p / (p + n), (1 - p) * (1 - n))
        self.assertAlmostEqual(meta["conjunctive_conflict"], p * n)

    def test_pcr6_theta_participates_in_eq18_and_limit_is_explicit(self):
        self.assertMass(ds.pcr6([ds.Mass(1, 0, 0), ds.Mass(0, 1, 0), ds.VACUOUS])[0],
                        1 / 3, 1 / 3, 1 / 3)
        with self.assertRaises(ds.Unsupported):
            ds.pcr6([ds.Mass(.2, .3, .5)] * 5, max_terms=100)

    def test_dbf_author_equations_for_opposing_nondogmatic_opinions(self):
        # PD=.8, CC=.64, DC=.512, eta=.488. Eq11 then Eq6.
        mass, meta = ds.dbf([ds.Mass(.8, 0, .2), ds.Mass(0, .8, .2)], 1)
        self.assertMass(mass, .1952, .1952, .6096)
        self.assertAlmostEqual(meta["discount_coefficients"][0], .488)
        self.assertAlmostEqual(meta["mean_pairwise_conflict"], .512)

    def test_dbf_lambda_and_generalized_average_not_noisy_or(self):
        m = ds.Mass(.5, .1, .4)
        fused, meta = ds.dbf([m, m, m], 3)
        self.assertMass(fused, .5, .1, .4)
        self.assertEqual(meta["discount_coefficients"], [1, 1, 1])
        low, _ = ds.dbf([ds.Mass(.8, 0, .2), ds.Mass(0, .8, .2)], 1)
        high, _ = ds.dbf([ds.Mass(.8, 0, .2), ds.Mass(0, .8, .2)], 3)
        self.assertGreater(low.u, high.u)

    def test_dbf_dogmatic_limits_not_silently_epsilon_smoothed(self):
        self.assertMass(ds.dbf([ds.Mass(1, 0, 0), ds.Mass(0, 1, 0)])[0], 0, 0, 1)
        with self.assertRaises(ds.Unsupported):
            ds.dbf([ds.Mass(1, 0, 0), ds.Mass(1, 0, 0)])
        self.assertMass(ds.dbf([ds.Mass(1, 0, 0)])[0], 1, 0, 0)
        with self.assertRaises(ds.Unsupported):
            ds.dbf([])

    def test_baseline_domains_and_uncertainty_projection_are_separate(self):
        observations = [item(.4), item(.3, key="cause-b")]
        self.assertAlmostEqual(ds.fuse(observations, "max_grouped")["belief"], .4)
        self.assertAlmostEqual(ds.fuse(observations, "noisy_or_grouped")["belief"], .58)
        for method in ("max_grouped", "noisy_or_grouped"):
            with self.assertRaises(ds.Unsupported):
                ds.fuse([item(d=.3)], method)
        self.assertAlmostEqual(ds.Mass(.118, 0, .882).project(.5), .559)
        self.assertEqual(ds.Mass(.118, 0, .882).b, .118)

    def test_nonfinite_negative_and_unnormalized_mass_rejected(self):
        for values in ((float("nan"), 0, 1), (float("inf"), 0, 0), (-.1, 0, 1.1), (.4, .4, .4)):
            with self.assertRaises(ValueError):
                ds.Mass(*values)


class ProtocolAndMetricTests(unittest.TestCase):
    def test_no_implicit_uniform_projection(self):
        document = {"schema_version": 1, "cases": []}
        with self.assertRaises(ValueError):
            ds.run_experiment(document)
        report = ds.run_experiment(document, projection="uniform_assumption")
        self.assertEqual(report["projection"]["assumption"], "uniform_assumption")
        self.assertFalse(report["projection"]["empirically_calibrated"])

    def test_data_provenance_gate_does_not_promote_development_to_holdout(self):
        document = evaluation_fixture()
        document["cases"][-1]["data_origin"] = "development"
        report = ds.run_experiment(document, mode="evaluate", projection="uniform_assumption")
        self.assertEqual(report["status"], "incomplete")
        self.assertTrue(report["limitations"])
        self.assertTrue(all(m["metrics"] is None for m in report["methods"].values()))

    def test_cross_split_campaign_hash_and_duplicate_id_rejected(self):
        for key in ("case_id", "group_id", "content_sha256"):
            document = evaluation_fixture()
            document["cases"][0][key] = "shared"
            document["cases"][-1][key] = "shared"
            with self.assertRaises(ValueError):
                ds.parse_dataset(document)

    def test_metrics_have_known_values(self):
        result = ds.probability_metrics([0, 1], [.1, .9])
        self.assertAlmostEqual(result["brier"], .01)
        self.assertAlmostEqual(result["nll"], -math.log(.9))
        decisions = ds.decision_metrics([0, 1, 1], [.01, .99, .5],
                                        {"false_negative": 1, "false_positive": 1, "review": .1})
        self.assertEqual(decisions["actions"], {"allow": 1, "block": 1, "review": 1})
        self.assertAlmostEqual(decisions["review_fraction"], 1 / 3)
        self.assertAlmostEqual(decisions["mean_realized_cost"], .1 / 3)

    def test_ece_fixed_bins_boundary_and_empty_bin_reporting(self):
        result = ds.probability_metrics([0, 1, 1, 0], [0, .1, 1, .9])["calibration_error"]
        self.assertAlmostEqual(result["ece"], .45)
        self.assertEqual(len(result["bins"]), 10)
        self.assertEqual(result["bins"][0]["n"], 1)
        self.assertEqual(result["bins"][1]["n"], 1)
        self.assertEqual(result["bins"][9]["n"], 2)
        self.assertAlmostEqual(result["bins"][9]["mean_p"], .95)
        self.assertAlmostEqual(result["bins"][9]["observed_rate"], .5)
        self.assertIsNone(result["bins"][2]["mean_p"])
        self.assertAlmostEqual(ds.probability_metrics([0, 1], [.15, .16])["calibration_error"]["ece"], .345)

    def test_wilson_and_zero_false_positive_exact_bound(self):
        result = ds.threshold_metrics([0] * 12 + [1] * 10, [0] * 12 + [.9] * 8 + [0] * 2, .5)
        self.assertEqual(result["fpr"], 0)
        self.assertAlmostEqual(result["recall"], .8)
        self.assertAlmostEqual(result["zero_fp_upper_95_one_sided"], 1 - .05 ** (1 / 12))
        self.assertGreater(result["zero_fp_upper_95_one_sided"], .22)
        self.assertAlmostEqual(result["recall_interval"]["lower"], .4901624715366417)
        self.assertAlmostEqual(result["recall_interval"]["upper"], .9433178485456247)
        self.assertEqual(result["fpr_interval"]["trials"], 12)
        self.assertIsNone(ds.threshold_metrics([1], [.9], .5)["fpr_interval"])
        self.assertIsNone(ds.threshold_metrics([0], [.9], .5)["zero_fp_upper_95_one_sided"])

    def test_default_fpr_budgets_match_frozen_plan(self):
        report = ds.run_experiment(evaluation_fixture(), mode="evaluate",
                                   methods=("cautious_yager",), projection="uniform_assumption")
        self.assertEqual(report["configuration"]["fpr_budgets"], [.005, .001, .01])
        self.assertEqual([m["requested_fpr_budget"] for m in
                          report["methods"]["cautious_yager"]["metrics"]["recall_at_fpr_budget"]],
                         [.005, .001, .01])

    def test_fpr_threshold_fits_calibration_only_and_handles_ties(self):
        calibration = [raw_case(str(i), "calibration", y, p)
                       for i, (y, p) in enumerate(((0, .8), (1, .8), (0, .2), (1, .9)))]
        threshold = ds.select_fpr_threshold(calibration, [.8, .8, .2, .9], 0)
        self.assertEqual(threshold, .9)
        metrics = ds.threshold_metrics([0, 1, 0, 1], [.8, .8, .2, .9], threshold)
        self.assertEqual(metrics["fpr"], 0)
        self.assertEqual(metrics["recall"], .5)
        calibration[0]["split"] = "holdout"
        with self.assertRaises(ValueError):
            ds.select_fpr_threshold(calibration, [.8, .8, .2, .9], 0)

    def test_holdout_and_redteam_cannot_change_fits_or_thresholds(self):
        document = evaluation_fixture()
        kwargs = dict(mode="evaluate", methods=("cautious_yager",), projection="training_prior", learn=True)
        first = ds.run_experiment(document, **kwargs)
        altered = copy.deepcopy(document)
        for case in altered["cases"]:
            if case["split"] == "holdout":
                case["label"] = 1 - case["label"]
                case["items"][0]["bpa"] = {"b": .99, "d": 0, "u": .01}
        altered["cases"].append(raw_case("redteam-only", "redteam", 1, .001))
        second = ds.run_experiment(altered, **kwargs)
        a, b = first["methods"]["cautious_yager"], second["methods"]["cautious_yager"]
        self.assertEqual(a["fit"], b["fit"])
        self.assertEqual(a["metrics"]["recall_at_fpr_budget"][0]["calibration"],
                         b["metrics"]["recall_at_fpr_budget"][0]["calibration"])
        self.assertEqual(a["metrics"]["raw_projection"]["n"], 4)
        self.assertNotEqual(a["metrics"]["calibrated_projection"]["brier"],
                            b["metrics"]["calibrated_projection"]["brier"])
        json.dumps(second, allow_nan=False)

    def test_missing_content_binding_blocks_fitting_and_quality_claims(self):
        for invalid in (None, "", "not-a-digest", "A" * 64):
            document = evaluation_fixture()
            case = document["cases"][0]
            if invalid is None:
                del case["content_sha256"]
            else:
                case["content_sha256"] = invalid
            # Empty strings already fail protocol parsing; other invalid or
            # absent bindings must block model fitting, not silently pass.
            if invalid == "":
                with self.assertRaises(ValueError):
                    ds.parse_dataset(document)
                continue
            result = ds.run_experiment(document, mode="evaluate",
                                       methods=("cautious_yager",),
                                       projection="uniform_assumption", learn=True)
            self.assertEqual(result["status"], "incomplete")
            self.assertTrue(any("content_sha256" in gap for gap in result["limitations"]))
            self.assertEqual(result["methods"]["cautious_yager"]["fit"], {})
            self.assertIsNone(result["methods"]["cautious_yager"]["metrics"])

    def test_train_only_discount_search_can_remove_inverted_source(self):
        raw = [raw_case("train-a", "train", 0, .9, "inverted"),
               raw_case("train-b", "train", 1, .1, "inverted")]
        cases = ds.parse_dataset({"schema_version": 1, "cases": raw})
        fit = ds.learn_discounts(cases, "cautious_yager", .5, {})
        self.assertEqual(fit["coefficients"]["inverted"], 0)
        self.assertLess(fit["fitted_training_loss"], fit["initial_training_loss"])
        cases[0]["split"] = "redteam"
        with self.assertRaises(ValueError):
            ds.learn_discounts(cases, "cautious_yager", .5, {})

    def test_platt_is_monotone_and_rejects_wrong_split(self):
        cases = [raw_case(str(i), "calibration", y, p)
                 for i, (y, p) in enumerate(((0, .2), (0, .3), (1, .6), (1, .8)))]
        fit = ds.fit_platt(cases, [.2, .3, .6, .8])
        self.assertGreaterEqual(fit["slope"], 0)
        self.assertLess(ds.apply_platt(.1, fit), ds.apply_platt(.9, fit))
        cases[0]["split"] = "holdout"
        with self.assertRaises(ValueError):
            ds.fit_platt(cases, [.2, .3, .6, .8])

    def test_unsupported_method_does_not_drop_hard_cases_from_metrics(self):
        document = evaluation_fixture()
        document["cases"][-1]["items"][0]["bpa"] = {"b": 0, "d": .5, "u": .5}
        result = ds.run_experiment(document, mode="evaluate", methods=("noisy_or_grouped",),
                                   projection="uniform_assumption")
        method = result["methods"]["noisy_or_grouped"]
        self.assertEqual(method["evaluation_status"], "unsupported")
        self.assertIsNone(method["metrics"])
        self.assertEqual(method["unsupported_case_ids"], [document["cases"][-1]["case_id"]])


if __name__ == "__main__":
    unittest.main()
