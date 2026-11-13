#!/usr/bin/env python3
"""Offline, dependency-aware DS learning. Standard library only; never activates models.

Run training/tests on the remote build host. Input feedback is protected data and
must remain outside Git. This tool deliberately separates belief, probability,
confirmed anchors, training diagnostics, and independent evaluation.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import struct
import sys


EPS = 1e-12
SOURCE_DEFAULT = {"slope": 4.0, "intercept": -2.0, "reliability": 0.8}
SOURCE_BOUNDS = {"slope": (0.0, 16.0), "intercept": (-16.0, 16.0),
                 "reliability": (0.0, 1.0)}
HASH = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
SPLITS = ("train", "calibration", "holdout")
DEPENDENCE_ASSUMPTION = "same_source_or_same_causal_key_transitive_max_v1"


class ContractError(ValueError):
    """Malformed input or an unsupported statistical claim."""


def number(value, name, low=0.0, high=1.0):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{name}: finite number required")
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise ContractError(f"{name}: finite number required") from exc
    if not math.isfinite(result) or not low <= result <= high:
        raise ContractError(f"{name}: expected finite [{low}, {high}]")
    return result


def integer(value, name, low=0, high=(1 << 64) - 1):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ContractError(f"{name}: integer in [{low}, {high}] required")
    return value


def nonempty(value, name, max_bytes=4096):
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{name}: nonempty bounded string required")
    try:
        length = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ContractError(f"{name}: valid Unicode required") from exc
    if length > max_bytes:
        raise ContractError(f"{name}: string exceeds {max_bytes} UTF-8 bytes")
    return value


def shape(value, required, optional=(), name="object"):
    if not isinstance(value, dict):
        raise ContractError(f"{name}: object required")
    missing, extra = set(required) - value.keys(), value.keys() - set(required) - set(optional)
    if missing or extra:
        raise ContractError(f"{name}: missing {sorted(missing)}, unexpected {sorted(extra)}")


def sigmoid(value):
    if value >= 0:
        return 1.0 / (1.0 + math.exp(-value))
    e = math.exp(value)
    return e / (1.0 + e)


def logit(value):
    value = max(EPS, min(1.0 - EPS, value))
    return math.log(value) - math.log1p(-value)


def validate_parameters(raw):
    shape(raw, ("schema_version", "parameter_version", "training_status", "sources",
                "base_rate", "calibration", "training_sample_count"), name="parameters")
    if integer(raw["schema_version"], "schema_version") != 1:
        raise ContractError("unsupported parameter schema")
    nonempty(raw["parameter_version"], "parameter_version", 128)
    if raw["training_status"] not in ("candidate", "validated", "bootstrap"):
        raise ContractError("invalid training_status")
    integer(raw["training_sample_count"], "training_sample_count")
    number(raw["base_rate"], "base_rate")
    if not isinstance(raw["sources"], dict) or len(raw["sources"]) > 512:
        raise ContractError("sources must be an object with at most 512 sources")
    for source, params in raw["sources"].items():
        nonempty(source, "source_id", 256)
        if ":" not in source or not all(p.strip() for p in source.split(":", 1)):
            raise ContractError("source_id must have module:category form")
        shape(params, SOURCE_BOUNDS, name=f"sources[{source}]")
        for key, bounds in SOURCE_BOUNDS.items():
            number(params[key], f"{source}.{key}", *bounds)
    if raw["calibration"] is not None:
        shape(raw["calibration"], ("slope", "intercept"), name="calibration")
        number(raw["calibration"]["slope"], "calibration.slope", 0, 16)
        number(raw["calibration"]["intercept"], "calibration.intercept", -16, 16)
    return copy.deepcopy(raw)


def parameter_content_sha256(parameters):
    """Cross-language identity; different from the exact JSON artifact byte hash."""
    value = validate_parameters(parameters)

    def binary64(number_value):
        normalized = float(number_value)
        # JSON -0 may be decoded as an integer by Python and float by Rust.
        return struct.pack(">d", 0.0 if normalized == 0.0 else normalized).hex()

    value["base_rate"] = binary64(value["base_rate"])
    for source in value["sources"].values():
        for key in SOURCE_BOUNDS:
            source[key] = binary64(source[key])
    if value["calibration"] is not None:
        for key in ("slope", "intercept"):
            value["calibration"][key] = binary64(value["calibration"][key])
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(b"vigilyx-ds-parameters-ieee754-v1\0" + encoded).hexdigest()


@dataclass(frozen=True)
class Evidence:
    source_id: str
    causal_key: str | None
    cluster: str
    raw_score: float
    confidence: float
    item_scored: bool
    legacy_mass: float
    confirmed_anchor_mass: float

    @property
    def admitted(self):
        # Structural dependency must not change when a learned reliability hits 0.
        return (self.raw_score > 0 and self.confidence > 0
                and (self.item_scored or self.legacy_mass > 0))


def parse_items(raw):
    if not isinstance(raw, list) or len(raw) > 512:
        raise ContractError("items must be an array with at most 512 items")
    result = []
    for item in raw:
        shape(item, Evidence.__dataclass_fields__, name="evidence item")
        source = nonempty(item["source_id"], "source_id", 256)
        if ":" not in source or not all(p.strip() for p in source.split(":", 1)):
            raise ContractError("source_id must have module:category form")
        key = item["causal_key"]
        if key is not None:
            nonempty(key, "causal_key", 8192)
        nonempty(item["cluster"], "cluster", 256)
        if not isinstance(item["item_scored"], bool):
            raise ContractError("item_scored must be boolean")
        values = {k: number(item[k], k) for k in
                  ("raw_score", "confidence", "legacy_mass", "confirmed_anchor_mass")}
        if values["confirmed_anchor_mass"] > values["legacy_mass"]:
            raise ContractError("confirmed_anchor_mass exceeds admitted legacy_mass")
        result.append(Evidence(source, key, item["cluster"], item["raw_score"],
                               item["confidence"], item["item_scored"],
                               item["legacy_mass"], item["confirmed_anchor_mass"]))
    # Deterministic max subgradient selection, including permuted duplicate rows.
    return tuple(sorted(result, key=lambda i: (
        i.source_id, i.causal_key is None, i.causal_key or "", i.cluster,
        i.raw_score, i.confidence, i.item_scored, i.legacy_mass, i.confirmed_anchor_mass)))


def _components(items):
    parent = {i.source_id: i.source_id for i in items if i.admitted and i.causal_key is not None}

    def root(source):
        while parent[source] != source:
            parent[source] = parent[parent[source]]
            source = parent[source]
        return source

    by_key = {}
    for item in items:
        if not item.admitted or item.causal_key is None:
            continue
        old = by_key.setdefault(item.causal_key, item.source_id)
        left, right = root(old), root(item.source_id)
        parent[max(left, right)] = min(left, right)
    groups = {}
    unbound = []
    for idx, item in enumerate(items):
        if not item.admitted:
            continue
        if item.causal_key is None:
            unbound.append(idx)
        else:
            groups.setdefault(root(item.source_id), []).append(idx)
    return tuple(tuple(groups[key]) for key in sorted(groups)), tuple(unbound)


def _item_mass(item, model):
    if not item.admitted:
        return 0.0, None, "no_positive_evidence"
    params = model["sources"].get(item.source_id)
    if not item.item_scored or params is None:
        return item.legacy_mass, None, "legacy_fallback"
    q = sigmoid(params["slope"] * item.raw_score + params["intercept"])
    mass = params["reliability"] * item.confidence * q
    common = params["reliability"] * item.confidence * q * (1.0 - q)
    derivative = {"slope": common * item.raw_score, "intercept": common,
                  "reliability": item.confidence * q}
    return mass, derivative, "learned"


def _predict(items, model, topology=None, gradients=False):
    groups, unbound = topology if topology is not None else _components(items)
    masses = [_item_mass(item, model) for item in items]
    winners = [max(indices, key=lambda j: masses[j][0]) for indices in groups]
    bound = 1.0 - math.prod(1.0 - masses[j][0] for j in winners)
    unknown_winner = max(unbound, key=lambda j: masses[j][0]) if unbound else None
    unknown = masses[unknown_winner][0] if unknown_winner is not None else 0.0
    belief = max(bound, unknown)
    uncertainty = 1.0 - belief
    uncalibrated = belief + model["base_rate"] * uncertainty
    probability = uncalibrated
    if model["calibration"] is not None:
        cp = model["calibration"]
        probability = sigmoid(cp["slope"] * logit(uncalibrated) + cp["intercept"])
    anchor = max((i.confirmed_anchor_mass for i in items if i.admitted), default=0.0)
    gradient = {}
    if gradients:
        active = [(unknown_winner, 1.0)] if unknown > bound else [
            (j, math.prod(1.0 - masses[k][0] for k in winners if k != j)) for j in winners]
        for j, weight in active:
            if j is None or masses[j][1] is None:
                continue
            source = items[j].source_id
            row = gradient.setdefault(source, {key: 0.0 for key in SOURCE_BOUNDS})
            for key in row:
                row[key] += (1.0 - model["base_rate"]) * weight * masses[j][1][key]
    trace = [{"source_ids": sorted({items[j].source_id for j in indices}),
              "causal_keys": sorted({items[j].causal_key for j in indices}),
              "belief": masses[winner][0], "selected_source_id": items[winner].source_id}
             for indices, winner in zip(groups, winners)]
    output = {"belief": belief, "disbelief": 0.0, "uncertainty": uncertainty,
              "plausibility": 1.0, "conflict": 0.0, "bound_belief": bound,
              "unbound_belief": unknown,
              "unbound_residual": (unknown - bound) / (1 - bound) if unknown > bound else 0.0,
              "probability_uncalibrated": uncalibrated, "probability": probability,
              "probability_calibration_applied": model["calibration"] is not None,
              "confirmed_anchor_mass": anchor, "risk_constrained": max(probability, anchor),
              "learned_items": sum(m[2] == "learned" for m in masses),
              "fallback_items": sum(m[2] == "legacy_fallback" for m in masses),
              "dependency_groups": len(groups) + int(unknown > bound),
              "dependence_assumption": DEPENDENCE_ASSUMPTION, "components": trace,
              "item_trace": [{"source_id": item.source_id, "causal_key": item.causal_key,
                              "belief": masses[j][0], "mapping": masses[j][2]}
                             for j, item in enumerate(items)]}
    return output, gradient


def predict(raw_items, parameters):
    return _predict(parse_items(raw_items), validate_parameters(parameters))[0]


def timestamp(value, name):
    if value is None:
        return None
    try:
        result = datetime.fromisoformat(nonempty(value, name).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError(f"{name}: RFC3339 timestamp required") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise ContractError(f"{name}: timezone required")
    return result.astimezone(timezone.utc)


@dataclass(frozen=True)
class Case:
    case_id: str
    group_id: str | None
    content_sha256: str
    label: int
    split: str
    items: tuple
    observed_at: datetime | None
    labeled_at: datetime | None
    adjudicated: bool


def parse_feedback(raw):
    if not isinstance(raw, dict) or integer(raw.get("schema_version"), "schema_version") != 1:
        raise ContractError("unsupported feedback schema")
    rows = raw.get("cases")
    if not isinstance(rows, list) or not rows:
        raise ContractError("nonempty feedback cases required")
    seen_ids, hashes, groups, result = set(), {}, {}, []
    for row in rows:
        if not isinstance(row, dict):
            raise ContractError("case must be an object")
        case_id = nonempty(row.get("case_id"), "case_id")
        if case_id in seen_ids:
            raise ContractError("duplicate case_id")
        seen_ids.add(case_id)
        if row.get("label_source") != "analyst_feedback":
            raise ContractError("only explicit analyst_feedback labels may train")
        origin = row.get("data_origin", "analyst_feedback")
        if origin not in ("analyst_feedback", "production_feedback", "independent_adjudicated"):
            raise ContractError("synthetic, automatic and model-derived labels cannot train")
        if row.get("synthetic", False) is not False or row.get("automated_label", False) is not False:
            raise ContractError("synthetic/automatic label provenance is forbidden")
        label = integer(row.get("label"), "label", 0, 1)
        split = row.get("split")
        if split not in SPLITS:
            raise ContractError("split must be train, calibration, or holdout")
        digest = row.get("content_sha256")
        if not isinstance(digest, str) or HASH.fullmatch(digest) is None:
            raise ContractError("content_sha256 must bind the original message bytes")
        digest = digest.removeprefix("sha256:")
        # Repeated content must be resolved upstream, including multiple reviewers.
        if digest in hashes:
            raise ContractError("duplicate content hash; adjudicate/deduplicate before training")
        hashes[digest] = split
        group = row.get("group_id")
        if group is not None:
            nonempty(group, "group_id")
            if group in groups and groups[group] != split:
                raise ContractError("group leakage across train/calibration/holdout")
            groups[group] = split
        level = row.get("corrected_threat_level")
        if level is not None and level not in ("unknown", "safe", "low", "medium", "high", "critical"):
            raise ContractError("invalid corrected_threat_level")
        adjudicated = row.get("adjudicated", False)
        if not isinstance(adjudicated, bool):
            raise ContractError("adjudicated must be boolean")
        observed = timestamp(row.get("observed_at"), "observed_at")
        labeled = timestamp(row.get("labeled_at"), "labeled_at")
        if observed is not None and labeled is not None and labeled < observed:
            raise ContractError("feedback label predates the message")
        result.append(Case(case_id, group, digest, label, split, parse_items(row.get("items")),
                           observed, labeled, adjudicated))
    result.sort(key=lambda c: c.case_id)
    # Enforce chronology wherever both complete windows are supplied. Missing
    # metadata permits candidate training, never independent evaluation.
    for idx, left in enumerate(SPLITS):
        for right in SPLITS[idx + 1:]:
            a, b = [c for c in result if c.split == left], [c for c in result if c.split == right]
            if a and b and all(c.observed_at is not None for c in a + b):
                if max(c.observed_at for c in a) >= min(c.observed_at for c in b):
                    raise ContractError("split time windows overlap or are not chronological")
    return tuple(result)


def _nll(probability, label):
    p = max(EPS, min(1.0 - EPS, probability))
    return -math.log(p if label else 1.0 - p)


def _adam_step(values, grads, moments, epoch, learning_rate, bounds):
    for key in sorted(values):
        g = grads[key]
        m, v = moments.get(key, (0.0, 0.0))
        m, v = 0.9 * m + 0.1 * g, 0.999 * v + 0.001 * g * g
        moments[key] = (m, v)
        update = learning_rate * (m / (1 - 0.9 ** epoch)) / (math.sqrt(v / (1 - 0.999 ** epoch)) + 1e-8)
        lo, hi = bounds[key]
        values[key] = max(lo, min(hi, values[key] - update))


def _fit_calibration(cases, model, epochs, learning_rate, regularization):
    # Source mapping is frozen before calibration. No severity/anchor target.
    pairs = [(logit(_predict(c.items, model)[0]["probability_uncalibrated"]), c.label) for c in cases]
    params, moments = {"slope": 1.0, "intercept": 0.0}, {}
    for epoch in range(1, epochs + 1):
        grad = {"slope": 0.0, "intercept": 0.0}
        for x, y in pairs:
            error = sigmoid(params["slope"] * x + params["intercept"]) - y
            grad["slope"] += error * x / len(pairs)
            grad["intercept"] += error / len(pairs)
        grad["slope"] += 2 * regularization * (params["slope"] - 1) / 256
        grad["intercept"] += 2 * regularization * params["intercept"] / 256
        _adam_step(params, grad, moments, epoch, learning_rate,
                   {"slope": (0, 16), "intercept": (-16, 16)})
    return params


def _independence_gaps(cases, protocol):
    gaps = []
    for split in SPLITS:
        rows = [c for c in cases if c.split == split]
        if not rows:
            gaps.append(f"missing_{split}_split")
        elif {c.label for c in rows} != {0, 1}:
            gaps.append(f"{split}_requires_both_labels")
    if any(c.group_id is None for c in cases):
        gaps.append("missing_campaign_group_ids")
    if any(c.observed_at is None for c in cases):
        gaps.append("missing_observed_timestamps")
    if any(c.labeled_at is None for c in cases):
        gaps.append("missing_feedback_timestamps")
    if any(not c.adjudicated for c in cases):
        gaps.append("labels_not_independently_adjudicated")
    if not isinstance(protocol, dict) or protocol.get("holdout_frozen_before_fit") is not True:
        gaps.append("holdout_not_frozen_before_fit")
    else:
        frozen = timestamp(protocol.get("holdout_frozen_at"), "holdout_frozen_at")
        holdout = [c for c in cases if c.split == "holdout"]
        if frozen is None:
            gaps.append("missing_holdout_freeze_timestamp")
        elif holdout and all(c.observed_at is not None for c in holdout):
            if frozen >= min(c.observed_at for c in holdout):
                raise ContractError("holdout freeze must precede the holdout window")
    if not isinstance(protocol, dict) or protocol.get("holdout_labels_hidden_during_fit") is not True:
        gaps.append("holdout_labels_not_sealed_from_fitting")
    return sorted(gaps)


def wilson(successes, total):
    if total == 0:
        return None
    z = 1.959963984540054
    p, z2 = successes / total, z * z
    center = (p + z2 / (2 * total)) / (1 + z2 / total)
    half = z * math.sqrt(p * (1 - p) / total + z2 / (4 * total * total)) / (1 + z2 / total)
    return [max(0.0, center - half), min(1.0, center + half)]


def _fixed_fpr_threshold(rows, target):
    negatives = sum(y == 0 for _, y in rows)
    candidates = sorted({p for p, _ in rows} | {math.nextafter(1.0, math.inf)})
    for threshold in candidates:
        fp = sum(y == 0 and p >= threshold for p, y in rows)
        if fp / negatives <= target:
            return threshold
    raise AssertionError("reject-none threshold must be feasible")


def _metrics(cases, model, threshold, review_low, costs):
    rows = [(c, _predict(c.items, model)[0]) for c in cases]
    probabilities = [(o["probability"], c.label) for c, o in rows]
    tp = sum(p >= threshold and y == 1 for p, y in probabilities)
    fp = sum(p >= threshold and y == 0 for p, y in probabilities)
    positive, negative = sum(c.label for c in cases), sum(1 - c.label for c in cases)
    review = alert_fp = pass_fn = 0
    for case, output in rows:
        score = output["risk_constrained"]
        if score >= threshold:
            alert_fp += case.label == 0
        elif score >= review_low:
            review += 1
        else:
            pass_fn += case.label == 1
    n = len(cases)
    return {"n": n, "positive_n": positive, "negative_n": negative,
            "brier": sum((p - y) ** 2 for p, y in probabilities) / n,
            "nll": sum(_nll(p, y) for p, y in probabilities) / n,
            "recall_at_calibration_fixed_fpr": tp / positive,
            "recall_wilson95": wilson(tp, positive), "false_positive_rate": fp / negative,
            "fpr_wilson95": wilson(fp, negative), "true_positive_n": tp, "false_positive_n": fp,
            "triage_with_confirmed_anchors": {
                "review_n": review, "review_per_1000": review * 1000 / n,
                "alert_false_positive_n": alert_fp, "pass_false_negative_n": pass_fn,
                "assumed_cost_per_message": (costs["false_positive"] * alert_fp
                    + costs["false_negative"] * pass_fn + costs["review"] * review) / n}}


def train_candidate(raw, initial=None, parameter_version="feedback-candidate-v1", epochs=100,
                    learning_rate=0.03, regularization=0.01, base_rate=None,
                    target_fpr=0.01, review_low=0.15, costs=None):
    cases = parse_feedback(raw)
    integer(epochs, "epochs", 1, 10000)
    number(learning_rate, "learning_rate", 1e-8, 1)
    number(regularization, "regularization", 0, 100)
    number(target_fpr, "target_fpr", 0, 1)
    number(review_low, "review_low")
    nonempty(parameter_version, "parameter_version")
    costs = dict(costs or {"false_positive": 1.0, "false_negative": 10.0, "review": 0.2})
    shape(costs, ("false_positive", "false_negative", "review"), name="costs")
    for key, value in costs.items():
        number(value, key, 0, 1e9)
    model = validate_parameters(initial) if initial is not None else {
        "schema_version": 1, "parameter_version": parameter_version, "training_status": "candidate",
        "sources": {}, "base_rate": 0.01, "calibration": None, "training_sample_count": 0}
    if base_rate is not None:
        model["base_rate"] = number(base_rate, "base_rate")
    train = [c for c in cases if c.split == "train"]
    if not train:
        raise ContractError("at least one train feedback is required")
    calibration = [c for c in cases if c.split == "calibration"]
    active_sources = sorted({i.source_id for c in train for i in c.items if i.admitted and i.item_scored})
    for source in active_sources:
        model["sources"].setdefault(source, dict(SOURCE_DEFAULT))
    model.update(parameter_version=parameter_version, training_status="candidate",
                 training_sample_count=len(train), calibration=None)
    model = validate_parameters(model)
    prior = copy.deepcopy(model["sources"])
    topology = {c.case_id: _components(c.items) for c in train}
    moments = {s: {} for s in active_sources}

    def train_loss():
        return sum(_nll(_predict(c.items, model, topology[c.case_id])[0]["probability_uncalibrated"],
                        c.label) for c in train) / len(train)

    before = train_loss()
    for epoch in range(1, epochs + 1):
        gradients = {s: {k: 0.0 for k in SOURCE_BOUNDS} for s in active_sources}
        for case in train:
            output, derivative = _predict(case.items, model, topology[case.case_id], gradients=True)
            p = max(EPS, min(1 - EPS, output["probability_uncalibrated"]))
            scale = (p - case.label) / (p * (1 - p) * len(train))
            for source, row in derivative.items():
                if source in gradients:
                    for key in row:
                        gradients[source][key] += scale * row[key]
        for source in active_sources:
            for key in SOURCE_BOUNDS:
                norm = 1 if key == "reliability" else 16
                gradients[source][key] += (2 * regularization
                    * (model["sources"][source][key] - prior[source][key]) / (norm * norm))
            _adam_step(model["sources"][source], gradients[source], moments[source], epoch,
                       learning_rate, SOURCE_BOUNDS)
    after = train_loss()
    gaps = _independence_gaps(cases, raw.get("evaluation_protocol"))
    # A held-out calibration set with both classes is necessary, but missing
    # split provenance means it cannot be called an independently calibrated model.
    calibration_fit = bool(calibration) and {c.label for c in calibration} == {0, 1}
    calibration_provenance = all(c.group_id is not None and c.adjudicated
                                and c.observed_at is not None and c.labeled_at is not None
                                for c in train + calibration)
    if calibration_fit and calibration_provenance:
        model["calibration"] = _fit_calibration(calibration, model, epochs, learning_rate, regularization)
    else:
        gaps.append("independent_calibration_not_fitted")
    report = {"schema_version": 1, "parameter_version": parameter_version,
              "training_status": "candidate", "automatic_activation": False,
              "release_ready": False, "milestone": "implemented",
              "dependence_assumption": DEPENDENCE_ASSUMPTION,
              "split_counts": {s: sum(c.split == s for c in cases) for s in SPLITS},
              "training_diagnostics_not_validation": {
                  "nll_before": before, "nll_after": after, "epochs": epochs,
                  "learning_rate": learning_rate, "regularization": regularization,
                  "trained_source_count": len(active_sources),
                  "retained_unobserved_source_count": len(model["sources"]) - len(active_sources),
                  "base_rate": model["base_rate"], "base_rate_estimated_from_feedback": False,
                  "target": "analyst binary threat label; severity and anchors excluded"},
              "calibration_fitted": model["calibration"] is not None,
              "independent_evaluation": None,
              "pending_gates": sorted(set(gaps + ["external_complete_capability_preservation",
                  "external_preregistered_quality_and_label_agreement",
                  "external_artifact_and_rollout_validation"]))}
    if not gaps:
        rows = [(_predict(c.items, model)[0]["probability"], c.label) for c in calibration]
        threshold = _fixed_fpr_threshold(rows, target_fpr)
        holdout = [c for c in cases if c.split == "holdout"]
        held = _metrics(holdout, model, threshold, review_low, costs)
        report["independent_evaluation"] = {
            "scope": "provided independent feedback splits; not population performance",
            "threshold_fit_split": "calibration", "target_fpr": target_fpr,
            "threshold": threshold, "review_lower_bound": review_low, "assumed_costs": costs,
            "calibration": _metrics(calibration, model, threshold, review_low, costs),
            "holdout": held,
            "holdout_fpr_upper95_meets_target": held["fpr_wilson95"][1] <= target_fpr}
        if held["fpr_wilson95"][1] > target_fpr:
            report["pending_gates"].append("holdout_fpr_precision_or_performance_insufficient")
    return validate_parameters(model), report


def _object_pairs(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ContractError(f"duplicate JSON key: {key}")
        output[key] = value
    return output


def read_json(path):
    raw = Path(path).read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object_pairs,
                           parse_constant=lambda value: (_ for _ in ()).throw(
                               ContractError(f"nonfinite JSON constant: {value}")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("invalid UTF-8 JSON") from exc
    return value, hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    Path(path).write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    train = commands.add_parser("train", help="write candidate only; never activate")
    train.add_argument("--input", required=True)
    train.add_argument("--output", required=True)
    train.add_argument("--report", required=True)
    train.add_argument("--initial-model")
    train.add_argument("--parameter-version", default="feedback-candidate-v1")
    train.add_argument("--epochs", type=int, default=100)
    train.add_argument("--learning-rate", type=float, default=0.03)
    train.add_argument("--regularization", type=float, default=0.01)
    train.add_argument("--base-rate", type=float)
    train.add_argument("--target-fpr", type=float, default=0.01)
    train.add_argument("--review-low", type=float, default=0.15)
    infer = commands.add_parser("predict")
    infer.add_argument("--model", required=True)
    infer.add_argument("--input", required=True, help="JSON object containing items")
    infer.add_argument("--output", required=True)
    check = commands.add_parser("validate", help="schema validation only, not statistical validation")
    check.add_argument("--model", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "train":
            feedback, input_hash = read_json(args.input)
            initial, initial_hash = read_json(args.initial_model) if args.initial_model else (None, None)
            model, report = train_candidate(feedback, initial, args.parameter_version, args.epochs,
                args.learning_rate, args.regularization, args.base_rate, args.target_fpr, args.review_low)
            output_paths = [Path(args.output).resolve(), Path(args.report).resolve()]
            inputs = [Path(args.input).resolve()] + ([Path(args.initial_model).resolve()] if args.initial_model else [])
            if len(set(output_paths)) != 2 or any(p in inputs for p in output_paths):
                raise ContractError("artifact/report must be distinct and must not overwrite inputs")
            report["parameter_artifact_sha256"] = write_json(args.output, model)
            report["parameter_content_sha256"] = parameter_content_sha256(model)
            report["feedback_input_sha256"] = input_hash
            report["initial_parameter_artifact_sha256"] = initial_hash
            write_json(args.report, report)
            print(json.dumps({"training_status": "candidate", "automatic_activation": False,
                              "parameter_artifact_sha256": report["parameter_artifact_sha256"],
                              "pending_gates": report["pending_gates"]}))
        else:
            model, digest = read_json(args.model)
            model = validate_parameters(model)
            if args.command == "validate":
                print(json.dumps({"schema_valid": True, "statistically_validated": False,
                                  "parameter_content_sha256": parameter_content_sha256(model),
                                  "parameter_artifact_sha256": digest}))
            else:
                data, _ = read_json(args.input)
                if not isinstance(data, dict):
                    raise ContractError("prediction input must be an object containing items")
                if Path(args.output).resolve() in (Path(args.input).resolve(), Path(args.model).resolve()):
                    raise ContractError("prediction output must not overwrite inputs")
                output = predict(data.get("items"), model)
                output["parameter_artifact_sha256"] = digest
                output["parameter_content_sha256"] = parameter_content_sha256(model)
                output["parameter_version"] = model["parameter_version"]
                write_json(args.output, output)
    except (ContractError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
