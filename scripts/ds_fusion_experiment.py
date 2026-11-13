#!/usr/bin/env python3
"""Offline binary belief-fusion comparison; never changes the production model.

Input JSON (schema_version=1): cases contain case_id, group_id, split
(train/calibration/holdout/redteam/development), label (0/1/null), and items.
Each item contains source_id, causal_key, frame='email_threat', bpa={b,d,u},
and optional basis. Authentication evidence belongs to another frame and must
not be relabelled as benign-email evidence to use this tool.

Evidence-only example:
  python3 scripts/ds_fusion_experiment.py --input cases.json --output result.json \
      --projection uniform_assumption

Evaluation additionally requires --mode evaluate, disjoint group_id/case_id/
content_sha256 values across splits, evaluation_protocol.holdout_frozen_before_fit
true, and holdout data_origin='independent_adjudicated'. These are asserted
provenance, not an independent audit or permission to claim release readiness.
No redteam/development case participates in fitting or aggregate metrics.

Algorithms:
* Yager: one n-ary conjunctive calculation, then one transfer of conflict to Θ.
* Cautious groups: max for same-cause simple supports of the SAME focal set.
  This restricted case is not a general-purpose cautious implementation.
* PCR6: Martin/Osswald, https://arxiv.org/pdf/0806.1797, Eq. (18), genuine
  n-ary focal-tuple redistribution, including any Θ in a conflicting tuple.
* DBF: Bezirganyan et al., AISTATS 2025,
  https://arxiv.org/html/2412.18024v2, Eqs. (6), (11)-(14), Algorithm 1.
  Internal opinions use the paper's uniform base rate. Final projection is
  explicitly configured separately. This does not reproduce neural training.

Only Python's standard library is needed. All tests must run on the remote
builder/server, as required by this repository's AGENTS.md.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


EPS = 1e-12
METHODS = (
    "yager_raw", "cautious_yager", "pcr6_grouped", "dbf_grouped",
    "max_grouped", "noisy_or_grouped",
)
FIT_SPLITS = {"train", "calibration", "holdout"}
ALL_SPLITS = FIT_SPLITS | {"redteam", "development"}
DEFAULT_FPR_BUDGETS = (0.005, 0.001, 0.01)


class Unsupported(ValueError):
    """The specified algorithm is not defined/supported for this input."""


def finite_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number")
    value = float(value)
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    return value


@dataclass(frozen=True)
class Mass:
    b: float
    d: float
    u: float

    def __post_init__(self) -> None:
        values = [finite_number(x, "BPA mass") for x in (self.b, self.d, self.u)]
        if any(x < 0 or x > 1 for x in values):
            raise ValueError("BPA masses must lie in [0,1]")
        if not math.isclose(math.fsum(values), 1.0, abs_tol=1e-10, rel_tol=0):
            raise ValueError("BPA b+d+u must equal one; inputs are not silently normalized")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Mass:
        if not isinstance(value, dict) or set(value) != {"b", "d", "u"}:
            raise ValueError("BPA must contain exactly b,d,u (closed binary frame)")
        return cls(*(finite_number(value[k], k) for k in ("b", "d", "u")))

    def discount(self, reliability: float) -> Mass:
        if not 0 <= reliability <= 1 or not math.isfinite(reliability):
            raise ValueError("source discount must lie in [0,1]")
        return mass_from_output(self.b * reliability, self.d * reliability,
                                1 - reliability + reliability * self.u)

    def project(self, base_rate: float) -> float:
        if not 0 <= base_rate <= 1 or not math.isfinite(base_rate):
            raise ValueError("base_rate must lie in [0,1]")
        return self.b + base_rate * self.u


VACUOUS = Mass(0.0, 0.0, 1.0)


def mass_from_output(b: float, d: float, u: float) -> Mass:
    """Correct roundoff only; a materially invalid algorithm output is an error."""
    values = [b, d, u]
    if any(not math.isfinite(v) or v < -1e-10 or v > 1 + 1e-10 for v in values):
        raise ArithmeticError("fusion produced an invalid BPA")
    total = math.fsum(values)
    if not math.isclose(total, 1.0, abs_tol=1e-9, rel_tol=0):
        raise ArithmeticError(f"fusion mass is not conserved: {total}")
    values = [max(0.0, min(1.0, v)) for v in values]
    # Put the tiny residual on the largest component, not an absent focal set.
    largest = max(range(3), key=values.__getitem__)
    values[largest] += 1.0 - math.fsum(values)
    return Mass(*values)


@dataclass(frozen=True)
class Item:
    source_id: str
    causal_key: str
    frame: str
    bpa: Mass
    basis: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Item:
        for key in ("source_id", "causal_key", "frame"):
            if not isinstance(value.get(key), str) or not value[key].strip():
                raise ValueError(f"item requires a nonempty {key}")
        basis = value.get("basis", [])
        if not isinstance(basis, list) or any(not isinstance(x, str) for x in basis):
            raise ValueError("item basis must be a list of strings")
        return cls(value["source_id"], value["causal_key"], value["frame"],
                   Mass.from_dict(value["bpa"]), tuple(basis))


def yager(masses: list[Mass]) -> tuple[Mass, dict[str, Any]]:
    if not masses:
        return VACUOUS, {"conjunctive_conflict": 0.0}
    u = math.prod(m.u for m in masses)
    b = max(0.0, math.prod(m.b + m.u for m in masses) - u)
    d = max(0.0, math.prod(m.d + m.u for m in masses) - u)
    conflict = max(0.0, min(1.0, 1.0 - math.fsum((b, d, u))))
    return mass_from_output(b, d, u + conflict), {"conjunctive_conflict": conflict}


def cautious_groups(items: list[Item]) -> tuple[list[Mass], list[dict[str, Any]]]:
    groups: dict[str, list[Item]] = defaultdict(list)
    for item in items:
        groups[item.causal_key].append(item)
    masses, trace = [], []
    for key in sorted(groups):
        group = groups[key]
        if len(group) == 1:
            combined = group[0].bpa
        else:
            # Cautious combination of same-focal simple supports is max.
            # Do not extend this to arbitrary triplets by taking component maxima.
            signs = set()
            for item in group:
                m = item.bpa
                if m.b > 0 and m.d > 0:
                    raise Unsupported(f"causal group {key!r} is not simple support")
                if m.b > 0:
                    signs.add("threat")
                if m.d > 0:
                    signs.add("normal")
            if len(signs) > 1:
                raise Unsupported(f"causal group {key!r} has opposing focal sets")
            b, d = max(x.bpa.b for x in group), max(x.bpa.d for x in group)
            combined = mass_from_output(b, d, 1.0 - b - d)
        masses.append(combined)
        trace.append({"causal_key": key, "source_ids": sorted(x.source_id for x in group),
                      "observations": len(group), "bpa": asdict(combined)})
    return masses, trace


def pcr6(masses: list[Mass], max_terms: int = 1_000_000) -> tuple[Mass, dict[str, Any]]:
    if not masses:
        return VACUOUS, {"conjunctive_conflict": 0.0, "focal_tuples": 0}
    # Bit masks: 1={threat}, 2={normal}, 3=Θ.
    supports = [[(mask, value) for mask, value in zip((1, 2, 3), (m.b, m.d, m.u))
                 if value > 0] for m in masses]
    terms = math.prod(len(s) for s in supports)
    if terms > max_terms:
        raise Unsupported(f"exact n-ary PCR6 needs {terms} focal tuples; limit={max_terms}")
    out = {1: [], 2: [], 3: []}
    conflicts = []
    for term in itertools.product(*supports):
        intersection = 3
        for focal, _ in term:
            intersection &= focal
        product = math.prod(value for _, value in term)
        if intersection:
            out[intersection].append(product)
        else:
            conflicts.append(product)
            denominator = math.fsum(value for _, value in term)
            for focal, value in term:
                out[focal].append(product * value / denominator)
    return (mass_from_output(*(math.fsum(out[k]) for k in (1, 2, 3))),
            {"conjunctive_conflict": math.fsum(conflicts), "focal_tuples": terms,
             "definition": "Martin-Osswald Eq18; includes Theta in conflicting tuples"})


def dbf(masses: list[Mass], lam: float = 1.0) -> tuple[Mass, dict[str, Any]]:
    if not math.isfinite(lam) or lam <= 0:
        raise ValueError("DBF lambda must be finite and positive")
    if not masses:
        raise Unsupported("DBF requires at least one opinion")
    n = len(masses)
    projected = [m.project(0.5) for m in masses]
    conflict = [[abs(projected[i] - projected[j]) * (1 - masses[i].u) * (1 - masses[j].u)
                 for j in range(n)] for i in range(n)]
    # Eq14 + Eq13, then Eq11. The internal uniform projection is part of DBF.
    reliability = [math.prod(max(0.0, 1.0 - c ** lam) ** (1.0 / lam) for c in row)
                   for row in conflict]
    discounted = [m.discount(r) for m, r in zip(masses, reliability)]
    dogmatic = [m for m in discounted if m.u == 0]
    if len(dogmatic) > 1:
        raise Unsupported("DBF Eq6 has 0/0 for multiple undiscounted dogmatic opinions")
    if dogmatic:
        fused = dogmatic[0]  # Exactly one zero uncertainty: Eq6 has a unique value.
    else:
        # Algebraically Eq6, scaled to avoid products underflow / reciprocals overflow.
        smallest_u = min(m.u for m in discounted)
        inverse_weights = [smallest_u / m.u for m in discounted]
        denominator = math.fsum(inverse_weights)
        fused = mass_from_output(
            math.fsum(m.b * w for m, w in zip(discounted, inverse_weights)) / denominator,
            math.fsum(m.d * w for m, w in zip(discounted, inverse_weights)) / denominator,
            n * smallest_u / denominator,
        )
    return fused, {"lambda": lam, "internal_base_rate": 0.5,
                   "discount_coefficients": reliability,
                   "mean_pairwise_conflict": (
                       math.fsum(conflict[i][j] for i in range(n) for j in range(i))
                       / (n * (n - 1) / 2) if n > 1 else 0.0),
                   "conjunctive_conflict": yager(masses)[1]["conjunctive_conflict"]}


def fuse(items: list[Item], method: str, discounts: dict[str, float] | None = None,
         dbf_lambda: float = 1.0, max_pcr_terms: int = 1_000_000) -> dict[str, Any]:
    if method not in METHODS:
        raise ValueError(f"unknown method {method}")
    if any(item.frame != "email_threat" for item in items):
        raise Unsupported("only the email_threat frame is supported; frame mixing is forbidden")
    discounts = discounts or {}
    adjusted = [Item(i.source_id, i.causal_key, i.frame,
                     i.bpa.discount(discounts.get(i.source_id, 1.0)), i.basis) for i in items]
    if method == "yager_raw":
        masses, group_trace = [i.bpa for i in adjusted], []
    else:
        masses, group_trace = cautious_groups(adjusted)
    if method in ("yager_raw", "cautious_yager"):
        fused, metadata = yager(masses)
    elif method == "pcr6_grouped":
        fused, metadata = pcr6(masses, max_pcr_terms)
    elif method == "dbf_grouped":
        fused, metadata = dbf(masses, dbf_lambda)
    else:
        if any(m.d > 0 for m in masses):
            raise Unsupported("max/noisy-OR baselines support threat-only simple BPAs")
        b = (max((m.b for m in masses), default=0.0) if method == "max_grouped"
             else 1.0 - math.prod(1.0 - m.b for m in masses))
        fused = mass_from_output(b, 0.0, 1.0 - b)
        metadata = {"conjunctive_conflict": 0.0}
    return {"bpa": asdict(fused), "belief": fused.b, "plausibility": 1.0 - fused.d,
            "uncertainty": fused.u, "input_count": len(items), "fused_sources": len(masses),
            "causal_groups": group_trace, "diagnostics": metadata}


def parse_dataset(document: dict[str, Any]) -> list[dict[str, Any]]:
    if document.get("schema_version") != 1 or not isinstance(document.get("cases"), list):
        raise ValueError("expected schema_version=1 and cases array")
    cases = []
    owners: dict[str, dict[str, str]] = {"case_id": {}, "group_id": {}, "content_sha256": {}}
    for raw in document["cases"]:
        case = dict(raw)
        if not isinstance(case.get("case_id"), str) or not case["case_id"].strip():
            raise ValueError("case_id is required")
        split = case.get("split", "development")
        if split not in ALL_SPLITS:
            raise ValueError(f"unknown split: {split}")
        case["split"] = split
        if case.get("evidence_scope") == "cluster_level_only" and split in FIT_SPLITS:
            raise ValueError("cluster-level replay is mathematical evidence only, never fitting/evaluation data")
        label = case.get("label")
        if label is not None and (type(label) is not int or label not in (0, 1)):
            raise ValueError("label must be integer 0, integer 1, or null")
        for key in owners:
            value = case.get(key)
            if value is None:
                continue
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{key} must be a nonempty string")
            previous = owners[key].get(value)
            if previous is not None and (key == "case_id" or previous != split):
                raise ValueError(f"duplicate/cross-split {key}: {value}")
            owners[key][value] = split
        if not isinstance(case.get("items"), list):
            raise ValueError("case items must be an array")
        case["items"] = [Item.from_dict(item) for item in case["items"]]
        cases.append(case)
    return cases


def evaluation_gaps(document: dict[str, Any], cases: list[dict[str, Any]]) -> list[str]:
    gaps = []
    for split in FIT_SPLITS:
        subset = [c for c in cases if c["split"] == split]
        if not subset:
            gaps.append(f"missing {split} split")
        if any(c.get("label") is None for c in subset):
            gaps.append(f"unlabelled {split} cases")
        if any(not c.get("group_id") for c in subset):
            gaps.append(f"missing campaign/duplicate group_id in {split}")
        # A split name and campaign label alone cannot detect an identical
        # message relabelled under a different ID. Require the byte binding;
        # near-duplicate/campaign grouping still needs an external audit.
        if any(not isinstance(c.get("content_sha256"), str)
               or len(c["content_sha256"]) != 64
               or any(ch not in "0123456789abcdef" for ch in c["content_sha256"])
               for c in subset):
            gaps.append(f"missing/invalid canonical content_sha256 in {split}")
    holdout = [c for c in cases if c["split"] == "holdout"]
    if any(c.get("data_origin") != "independent_adjudicated" for c in holdout):
        gaps.append("holdout must be independent_adjudicated, never development/redteam")
    if document.get("evaluation_protocol", {}).get("holdout_frozen_before_fit") is not True:
        gaps.append("missing frozen-before-fit holdout provenance assertion")
    for split in ("train", "calibration", "holdout"):
        if {c.get("label") for c in cases if c["split"] == split} != {0, 1}:
            gaps.append(f"{split} requires both adjudicated classes")
    if any(c.get("data_origin") in {"redteam", "development"}
           for c in cases if c["split"] in FIT_SPLITS):
        gaps.append("redteam/development data cannot be relabelled as fitting/evaluation data")
    return gaps


def choose_base_rate(projection: str, base_rate: float | None,
                     train: list[dict[str, Any]]) -> tuple[float | None, dict[str, Any]]:
    if projection == "explicit":
        if base_rate is None or not math.isfinite(base_rate) or not 0 <= base_rate <= 1:
            raise ValueError("explicit projection requires --base-rate in [0,1]")
        return base_rate, {"assumption": "explicit_base_rate", "empirically_calibrated": False}
    if base_rate is not None:
        raise ValueError("--base-rate is only valid with --projection explicit")
    if projection == "uniform_assumption":
        return 0.5, {"assumption": "uniform_assumption", "empirically_calibrated": False}
    if projection != "training_prior":
        raise ValueError(f"unknown projection: {projection}")
    if not train or any(c.get("label") is None for c in train):
        return None, {"status": "incomplete", "reason": "labelled train split required for prior"}
    if any(c["split"] != "train" or c.get("data_origin") in {"redteam", "development"}
           for c in train):
        raise ValueError("prior may use the train split only")
    return ((sum(c["label"] for c in train) + 1) / (len(train) + 2),
            {"assumption": "training_prevalence_Beta_1_1", "fit_split": "train",
             "training_n": len(train), "empirically_calibrated": False})


def predict_probability(case: dict[str, Any], method: str, base_rate: float,
                        discounts: dict[str, float], options: dict[str, Any]) -> float:
    result = fuse(case["items"], method, discounts, **options)
    return Mass.from_dict(result["bpa"]).project(base_rate)


def learn_discounts(train: list[dict[str, Any]], method: str, base_rate: float,
                    options: dict[str, Any], passes: int = 2) -> dict[str, Any]:
    if not train or any(c["split"] != "train" or c.get("label") not in (0, 1)
                        or c.get("data_origin") in {"redteam", "development"}
                        or c.get("evidence_scope") == "cluster_level_only" for c in train):
        raise ValueError("discount fitting requires labelled train data only")
    sources = sorted({i.source_id for c in train for i in c["items"]})
    coefficients = dict.fromkeys(sources, 1.0)

    def loss(candidate: dict[str, float]) -> float:
        return math.fsum((predict_probability(c, method, base_rate, candidate, options)
                          - c["label"]) ** 2 for c in train) / len(train)

    initial = current = loss(coefficients)
    for _ in range(passes):
        changed = False
        for source in sources:
            best_value, best_loss = coefficients[source], current
            for value in (0.0, 0.25, 0.5, 0.75, 1.0):
                trial = dict(coefficients, **{source: value})
                candidate_loss = loss(trial)
                if candidate_loss < best_loss - 1e-12:
                    best_value, best_loss = value, candidate_loss
            if best_value != coefficients[source]:
                coefficients[source], current = best_value, best_loss
                changed = True
        if not changed:
            break
    return {"coefficients": coefficients, "fit_split": "train", "objective": "Brier",
            "search": "bounded_coordinate_grid", "grid": [0, 0.25, 0.5, 0.75, 1],
            "passes_limit": passes, "initial_training_loss": initial,
            "fitted_training_loss": current, "training_n": len(train),
            "empirically_calibrated": False}


def sigmoid(value: float) -> float:
    if value >= 0:
        return 1.0 / (1.0 + math.exp(-value))
    exp = math.exp(value)
    return exp / (1.0 + exp)


def logit(probability: float) -> float:
    probability = min(1 - 1e-12, max(1e-12, probability))
    return math.log(probability) - math.log1p(-probability)


def fit_platt(calibration: list[dict[str, Any]], probabilities: list[float]) -> dict[str, Any]:
    if len(probabilities) != len(calibration) or not calibration:
        raise ValueError("Platt fitting requires matching nonempty calibration data")
    if any(c["split"] != "calibration" or c.get("data_origin") in {"redteam", "development"}
           for c in calibration) or {c.get("label") for c in calibration} != {0, 1}:
        raise ValueError("Platt fitting requires both labels in calibration only")
    xs, ys = list(map(logit, probabilities)), [c["label"] for c in calibration]
    n, ridge = len(xs), 1e-4
    # Monotone Platt mapping sigmoid(a*logit(p)+b), a>=0. No holdout access.
    a, b = 1.0, 0.0

    def objective(slope: float, intercept: float) -> float:
        return (math.fsum(max(z, 0) + math.log1p(math.exp(-abs(z))) - y * z
                          for x, y in zip(xs, ys) for z in [slope * x + intercept]) / n
                + 0.5 * ridge * ((slope - 1) ** 2 + intercept ** 2))

    # Projected gradient with a global smoothness bound and backtracking.
    step0 = 1.0 / (0.25 * math.fsum(x * x + 1 for x in xs) / n + ridge)
    converged = False
    for iteration in range(4000):
        residuals = [sigmoid(a * x + b) - y for x, y in zip(xs, ys)]
        ga = math.fsum(r * x for r, x in zip(residuals, xs)) / n + ridge * (a - 1)
        gb = math.fsum(residuals) / n + ridge * b
        current, step = objective(a, b), step0
        for _ in range(40):
            aa, bb = max(0.0, a - step * ga), b - step * gb
            if objective(aa, bb) <= current + 1e-14:
                break
            step *= 0.5
        if max(abs(aa - a), abs(bb - b)) < 1e-9:
            converged = True
            a, b = aa, bb
            break
        a, b = aa, bb
    return {"slope": a, "intercept": b, "fit_split": "calibration", "n": n,
            "method": "monotone_Platt_on_logit", "ridge": ridge,
            "iterations": iteration + 1, "converged": converged}


def apply_platt(probability: float, parameters: dict[str, Any]) -> float:
    return sigmoid(parameters["slope"] * logit(probability) + parameters["intercept"])


def probability_metrics(labels: list[int], probabilities: list[float]) -> dict[str, Any]:
    n = len(labels)
    if n == 0 or n != len(probabilities):
        raise ValueError("metrics require matching nonempty labels and probabilities")
    if any(type(y) is not int or y not in (0, 1) for y in labels):
        raise ValueError("metrics require binary integer labels")
    if any(not math.isfinite(p) or not 0 <= p <= 1 for p in probabilities):
        raise ValueError("metrics require finite probabilities in [0,1]")
    clipped = [min(1 - 1e-12, max(1e-12, p)) for p in probabilities]
    # Frozen equal-width bins, never selected after observing evaluation data.
    # ECE is a sample/bin-dependent diagnostic, not a calibration guarantee.
    bins = []
    for index in range(10):
        members = [(y, p) for y, p in zip(labels, probabilities)
                   if min(9, int(p * 10)) == index]
        count = len(members)
        mean_p = math.fsum(p for _, p in members) / count if count else None
        observed = sum(y for y, _ in members) / count if count else None
        bins.append({"lower": index / 10, "upper": (index + 1) / 10,
                     "upper_inclusive": index == 9, "n": count,
                     "mean_p": mean_p, "observed_rate": observed})
    ece = math.fsum(bin_["n"] / n * abs(bin_["mean_p"] - bin_["observed_rate"])
                    for bin_ in bins if bin_["n"])
    return {"n": n, "positives": sum(labels), "negatives": n - sum(labels),
            "brier": math.fsum((p - y) ** 2 for p, y in zip(probabilities, labels)) / n,
            "nll": -math.fsum(y * math.log(p) + (1 - y) * math.log1p(-p)
                               for p, y in zip(clipped, labels)) / n,
            "nll_probability_clip": 1e-12,
            "calibration_error": {"method": "ECE_10_fixed_equal_width_bins", "ece": ece,
                                  "bins": bins, "limitation": "sample- and bin-dependent diagnostic"}}


def wilson_interval(successes: int, trials: int) -> dict[str, Any] | None:
    if type(successes) is not int or type(trials) is not int or not 0 <= successes <= trials:
        raise ValueError("interval requires integer 0 <= successes <= trials")
    if trials == 0:
        return None
    z = 1.959963984540054
    p = successes / trials
    denominator = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denominator
    radius = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator
    return {"lower": max(0.0, center - radius), "upper": min(1.0, center + radius),
            "confidence_level": 0.95, "method": "Wilson_two_sided",
            "successes": successes, "trials": trials,
            "assumption": "independent Bernoulli trials; unadjusted for campaign dependence or threshold selection"}


def threshold_metrics(labels: list[int], probabilities: list[float], threshold: float) -> dict[str, Any]:
    if len(labels) != len(probabilities) or not math.isfinite(threshold):
        raise ValueError("threshold metrics require matching arrays and a finite threshold")
    if any(type(y) is not int or y not in (0, 1) for y in labels):
        raise ValueError("threshold metrics require binary integer labels")
    if any(not math.isfinite(p) or not 0 <= p <= 1 for p in probabilities):
        raise ValueError("threshold metrics require finite probabilities in [0,1]")
    positive, negative = sum(labels), len(labels) - sum(labels)
    tp = sum(y == 1 and p >= threshold for y, p in zip(labels, probabilities))
    fp = sum(y == 0 and p >= threshold for y, p in zip(labels, probabilities))
    return {"threshold": threshold, "tp": tp, "fp": fp, "fn": positive - tp,
            "tn": negative - fp, "recall": tp / positive if positive else None,
            "fpr": fp / negative if negative else None,
            "recall_interval": wilson_interval(tp, positive),
            "fpr_interval": wilson_interval(fp, negative),
            "zero_fp_upper_95_one_sided": (1 - 0.05 ** (1 / negative)
                                            if negative and fp == 0 else None),
            "zero_fp_upper_method": "exact_binomial; independent negatives; no threshold-selection adjustment"}


def select_fpr_threshold(calibration: list[dict[str, Any]], probabilities: list[float],
                         budget: float) -> float:
    if not 0 <= budget <= 1 or not math.isfinite(budget):
        raise ValueError("FPR budget must lie in [0,1]")
    if len(calibration) != len(probabilities) or not calibration:
        raise ValueError("threshold fitting requires matching calibration data")
    if any(c["split"] != "calibration" or c.get("data_origin") in {"redteam", "development"}
           for c in calibration):
        raise ValueError("thresholds may be selected on calibration only")
    labels = [c["label"] for c in calibration]
    if 0 not in labels:
        raise ValueError("FPR threshold needs calibration negatives")
    candidates = sorted({0.0, *probabilities, math.nextafter(max(probabilities), math.inf)})
    return next(t for t in candidates if threshold_metrics(labels, probabilities, t)["fpr"] <= budget)


def decision_metrics(labels: list[int], probabilities: list[float], costs: dict[str, float]) -> dict[str, Any]:
    if not labels or len(labels) != len(probabilities):
        raise ValueError("decision metrics require matching nonempty arrays")
    decisions, losses = Counter(), []
    for y, p in zip(labels, probabilities):
        expected = {"allow": costs["false_negative"] * p,
                    "block": costs["false_positive"] * (1 - p), "review": costs["review"]}
        # Review wins exact ties; costs are supplied before seeing holdout.
        action = min(("review", "allow", "block"), key=expected.__getitem__)
        decisions[action] += 1
        losses.append(costs["review"] if action == "review" else
                      costs["false_negative"] * y if action == "allow" else
                      costs["false_positive"] * (1 - y))
    n = len(labels)
    return {"n": n, "actions": dict(decisions), "review_fraction": decisions["review"] / n,
            "automatic_coverage": 1 - decisions["review"] / n,
            "mean_realized_cost": math.fsum(losses) / n, "costs": costs,
            "review_assumption": "fixed review cost; no assumed post-review outcome"}


def run_experiment(document: dict[str, Any], *, mode: str = "evidence",
                   methods: tuple[str, ...] = METHODS, projection: str = "explicit",
                   base_rate: float | None = None, learn: bool = False,
                   dbf_lambda: float = 1.0, max_pcr_terms: int = 1_000_000,
                   fpr_budgets: tuple[float, ...] = DEFAULT_FPR_BUDGETS,
                   costs: dict[str, float] | None = None) -> dict[str, Any]:
    if mode not in {"evidence", "evaluate"}:
        raise ValueError("mode must be evidence or evaluate")
    if not methods or any(m not in METHODS for m in methods) or len(set(methods)) != len(methods):
        raise ValueError("methods must be a nonempty unique subset of supported methods")
    if learn and mode != "evaluate":
        raise ValueError("discount learning is only available in evaluate mode")
    if type(max_pcr_terms) is not int or max_pcr_terms <= 0:
        raise ValueError("max_pcr_terms must be a positive integer")
    if not math.isfinite(dbf_lambda) or dbf_lambda <= 0:
        raise ValueError("DBF lambda must be finite and positive")
    if any(not math.isfinite(b) or not 0 <= b <= 1 for b in fpr_budgets):
        raise ValueError("invalid FPR budget")
    if costs is not None:
        if set(costs) != {"false_negative", "false_positive", "review"}:
            raise ValueError("costs require false_negative,false_positive,review")
        costs = {k: finite_number(v, k) for k, v in costs.items()}
        if any(v < 0 for v in costs.values()):
            raise ValueError("costs must be nonnegative")
    cases = parse_dataset(document)
    cluster_only = document.get("comparison_scope") == "cluster_level_only" or any(
        case.get("evidence_scope") == "cluster_level_only" for case in cases)
    if cluster_only and (mode != "evidence" or learn or projection == "training_prior"):
        raise ValueError("cluster-level replay permits mathematical evidence comparison only; no fitting/evaluation")
    splits = {s: [c for c in cases if c["split"] == s] for s in ALL_SPLITS}
    gaps = evaluation_gaps(document, cases) if mode == "evaluate" else []
    prior, projection_meta = choose_base_rate(projection, base_rate, splits["train"])
    if prior is None:
        gaps.append("probability projection unavailable")
    options = {"dbf_lambda": dbf_lambda, "max_pcr_terms": max_pcr_terms}
    report: dict[str, Any] = {
        "schema_version": 1, "status": "incomplete" if gaps else "completed",
        "mode": mode, "limitations": gaps, "projection": {"base_rate": prior, **projection_meta},
        "configuration": {"methods": list(methods), "learn_discounts": learn,
                          "dbf_lambda": dbf_lambda, "max_pcr_terms": max_pcr_terms,
                          "fpr_budgets": list(fpr_budgets), "decision_costs": costs},
        "implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "provenance_verification": "caller assertions; not independently verified by this tool",
        "input_sha256": hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":"),
                                                 allow_nan=False).encode()).hexdigest(),
        "split_counts": {s: len(splits[s]) for s in sorted(ALL_SPLITS)},
        "evaluation_claim": "offline_experiment_only; no platform-rate or release claim",
        "comparison_scope": "cluster_level_only" if cluster_only else document.get("comparison_scope", "typed_items"),
        "comparison_limitations": document.get("comparison_limitations", []),
        "adapter": document.get("adapter"),
        "methods": {},
    }
    for method in methods:
        output: dict[str, Any] = {"cases": [], "fit": {}, "metrics": None,
                                  "preprocessing": "none" if method == "yager_raw" else
                                  "same_cause_same_focal_simple_support_max"}
        report["methods"][method] = output
        discounts: dict[str, float] = {}
        if learn and not gaps:
            try:
                fitted = learn_discounts(splits["train"], method, prior, options)
                output["fit"]["reliability"] = fitted
                discounts = fitted["coefficients"]
            except Unsupported as error:
                output["fit"]["status"] = "unsupported"
                output["fit"]["reason"] = str(error)
        for case in cases:
            prediction = {"case_id": case["case_id"], "split": case["split"], "status": "ok"}
            if "adapter_trace" in case:
                prediction["adapter_trace"] = case["adapter_trace"]
            try:
                prediction["evidence"] = fuse(case["items"], method, discounts, **options)
                if prior is not None:
                    mass = Mass.from_dict(prediction["evidence"]["bpa"])
                    prediction["projection"] = {"raw_probability": mass.project(prior),
                                                 "calibrated_probability": None}
            except Unsupported as error:
                prediction.update(status="unsupported", reason=str(error))
            output["cases"].append(prediction)
        if mode != "evaluate" or gaps or output["fit"].get("status") == "unsupported":
            continue
        by_id = {p["case_id"]: p for p in output["cases"]}
        failures = [c["case_id"] for s in FIT_SPLITS for c in splits[s]
                    if by_id[c["case_id"]]["status"] != "ok"]
        if failures:
            output["evaluation_status"] = "unsupported"
            output["unsupported_case_ids"] = failures
            # Do not silently evaluate a method on an easier surviving subset.
            continue
        calibration_p = [by_id[c["case_id"]]["projection"]["raw_probability"]
                         for c in splits["calibration"]]
        platt = fit_platt(splits["calibration"], calibration_p)
        output["fit"]["projection_calibration"] = platt
        for prediction in output["cases"]:
            if prediction["status"] == "ok":
                pred_projection = prediction["projection"]
                pred_projection["calibrated_probability"] = apply_platt(pred_projection["raw_probability"], platt)
        cal_prob = [apply_platt(p, platt) for p in calibration_p]
        hold_prob = [by_id[c["case_id"]]["projection"]["calibrated_probability"]
                     for c in splits["holdout"]]
        hold_raw = [by_id[c["case_id"]]["projection"]["raw_probability"]
                    for c in splits["holdout"]]
        labels = [c["label"] for c in splits["holdout"]]
        thresholds = []
        for budget in fpr_budgets:
            threshold = select_fpr_threshold(splits["calibration"], cal_prob, budget)
            thresholds.append({"requested_fpr_budget": budget, "fit_split": "calibration",
                               "calibration": threshold_metrics([c["label"] for c in splits["calibration"]], cal_prob, threshold),
                               "holdout": threshold_metrics(labels, hold_prob, threshold),
                               "guarantee": "empirical calibration budget, not a population bound"})
        output["metrics"] = {"split": "holdout", "raw_projection": probability_metrics(labels, hold_raw),
                             "calibrated_projection": probability_metrics(labels, hold_prob),
                             "recall_at_fpr_budget": thresholds,
                             "decision": decision_metrics(labels, hold_prob, costs) if costs is not None else None}
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("evidence", "evaluate"), default="evidence")
    parser.add_argument("--methods", nargs="+", choices=METHODS, default=list(METHODS))
    parser.add_argument("--projection", choices=("explicit", "uniform_assumption", "training_prior"), default="explicit")
    parser.add_argument("--base-rate", type=float)
    parser.add_argument("--learn-discounts", action="store_true")
    parser.add_argument("--dbf-lambda", type=float, default=1.0)
    parser.add_argument("--max-pcr-terms", type=int, default=1_000_000)
    parser.add_argument("--fpr-budgets", type=float, nargs="+", default=list(DEFAULT_FPR_BUDGETS))
    parser.add_argument("--costs", type=float, nargs=3, metavar=("FALSE_NEGATIVE", "FALSE_POSITIVE", "REVIEW"))
    args = parser.parse_args()
    try:
        def reject_nonfinite(value: str) -> None:
            raise ValueError(f"non-finite JSON number: {value}")

        document = json.loads(args.input.read_text(encoding="utf-8"), parse_constant=reject_nonfinite)
        costs = dict(zip(("false_negative", "false_positive", "review"), args.costs)) if args.costs else None
        result = run_experiment(document, mode=args.mode, methods=tuple(args.methods),
                                projection=args.projection, base_rate=args.base_rate,
                                learn=args.learn_discounts, dbf_lambda=args.dbf_lambda,
                                max_pcr_terms=args.max_pcr_terms, fpr_budgets=tuple(args.fpr_budgets), costs=costs)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    except (ValueError, ArithmeticError, OSError, KeyError, TypeError) as error:
        parser.exit(2, f"ds_fusion_experiment: {error}\n")


if __name__ == "__main__":
    main()
