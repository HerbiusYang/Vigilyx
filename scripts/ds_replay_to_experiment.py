#!/usr/bin/env python3
"""Convert exact redteam harness snapshots to cluster-level mathematical inputs.

This adapter never reconstructs Rust admission from module_results. The only
accepted source is verdict.fusion_details.primary_result.source_details from a
clustered_ds_v2 synthetic_capability_regression JSONL export. No message content,
module snippets, labels, or key_factors are copied. These aggregated clusters do
not expose runtime causal items or detector reliability.

Revision 5 is supported only in its explicit bootstrap state. A validated
learned model emits dependency-group summaries, which are not the original
threat clusters and cannot be replayed by this cluster-only adapter.

Legacy normal_identity_relationship is a different frame: reject it by default,
or explicitly exclude it with --legacy-auth exclude. Exclusion is recorded and
prevents any claim of parity with the original fused result.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
from typing import Any

from ds_fusion_experiment import Mass, finite_number, yager


CLUSTERS = frozenset({
    "inherited_gateway_prior", "delivery_integrity", "sender_identity_authenticity",
    "link_and_html_deception", "payload_malware", "external_reputation_ioc",
    "social_engineering_intent", "business_sensitivity",
})
LEGACY_AUTH = "normal_identity_relationship"
SOURCE_PATH = "verdict.fusion_details.primary_result.source_details"
LIMITATIONS = [
    "Cluster-level mathematical comparison only; not runtime item admission replay.",
    "Cluster identifiers are placeholders, not causal keys or independent detector identities.",
    "Cannot evaluate same-cause deduplication, source reliability, or within-cluster aggregation.",
    "Synthetic redteam data cannot train discounts, calibrate probability, or establish detection rates.",
    "Policy floors, coverage and disposition are original telemetry, not recomputed by this comparison.",
    "With threat-only inputs, n-ary Yager, PCR6 and noisy-OR coincide; a larger score is not a win.",
    "Learned-active dependency groups require runtime item replay and are rejected by this adapter.",
]


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def closed_mass(value: Any) -> Mass:
    if not isinstance(value, dict) or set(value) not in ({"b", "d", "u"}, {"b", "d", "u", "epsilon"}):
        raise ValueError("runtime BPA must contain b,d,u and optional epsilon only")
    if finite_number(value.get("epsilon", 0), "epsilon") != 0:
        raise ValueError("open-world epsilon is unsupported; no silent renormalization")
    return Mass.from_dict({key: value[key] for key in ("b", "d", "u")})


def relative_file(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("file must be a nonempty relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) != value or value == ".":
        raise ValueError("file must be a normalized relative POSIX path")
    return value


def convert_record(record: dict[str, Any], artifact_id: str, line: int,
                   legacy_auth: str = "reject") -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ValueError("each JSONL record must be an object")
    if (type(record.get("schema_version")) is not int or record["schema_version"] != 1
            or record.get("record_type") != "synthetic_capability_regression"
            or record.get("independent_holdout") is not False):
        raise ValueError("requires schema 1 synthetic_capability_regression, independent_holdout=false")
    file = relative_file(record.get("file"))
    primary = record.get("verdict", {}).get("fusion_details", {}).get("primary_result")
    if not isinstance(primary, dict) or primary.get("model") != "clustered_ds_v2":
        raise ValueError("requires exact clustered_ds_v2 primary_result; no legacy/stdout/module fallback")
    version = primary.get("model_version")
    # Revision 4 adds a separate action-severity policy. Revision 5 preserves
    # cluster scoring only in bootstrap mode. Policy/calibrated probabilities
    # must never be copied into mathematical evidence mass.
    if type(version) is not int or version not in (1, 2, 3, 4, 5):
        raise ValueError("unsupported clustered_ds_v2 model_version (known: 1,2,3,4,5)")
    learning_status = None
    if version == 5:
        learning = primary.get("learning_model")
        learning_status = learning.get("status") if isinstance(learning, dict) else None
        if learning_status != "bootstrap":
            raise ValueError("revision 5 cluster replay requires explicit bootstrap status; "
                             "learned-active dependency groups require runtime item replay")
    sources = primary.get("source_details")
    if not isinstance(sources, list):
        raise ValueError("primary_result.source_details must be an array")
    original_mass = closed_mass(primary.get("fused_bpa"))
    risk_base = finite_number(primary.get("risk_base"), "risk_base")
    if not math.isclose(risk_base, original_mass.b, abs_tol=1e-9, rel_tol=0):
        raise ValueError("risk_base must match primary fused belief")
    seen, items, excluded = set(), [], []
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("source_details entries must be objects")
        engine = source.get("engine_id")
        if not isinstance(engine, str) or engine in seen:
            raise ValueError("source_details require unique string engine_id values")
        seen.add(engine)
        mass = closed_mass(source.get("bpa"))
        if engine == LEGACY_AUTH:
            if legacy_auth != "exclude":
                raise ValueError("legacy auth cannot become normal email evidence; use --legacy-auth exclude explicitly")
            excluded.append({"engine_id": engine, "original_bpa": asdict(mass),
                             "reason": "authentication/relationship is outside email_threat frame"})
            continue
        if engine not in CLUSTERS:
            raise ValueError(f"unknown cluster {engine!r}; no inferred frame mapping")
        if source.get("frame", "email_threat") != "email_threat" or mass.d != 0:
            raise ValueError("runtime threat clusters must have d=0 in the email_threat frame")
        # Each cluster already aggregates runtime artifacts. Never parse truncated
        # key_factors or expand modules as if they were separate evidence votes.
        items.append({"source_id": f"cluster:{engine}",
                      "causal_key": f"aggregate-placeholder:{engine}",
                      "frame": "email_threat", "bpa": asdict(mass),
                      "basis": [SOURCE_PATH, "cluster_level_only; not runtime causal items"]})
    replay_mass, diagnostics = yager([Mass.from_dict(item["bpa"]) for item in items])
    original_conflict = finite_number(primary.get("k_conflict"), "k_conflict")
    if not 0 <= original_conflict <= 1:
        raise ValueError("k_conflict must lie in [0,1]")
    if not excluded:
        if any(not math.isclose(a, b, abs_tol=1e-9, rel_tol=0)
               for a, b in zip(asdict(replay_mass).values(), asdict(original_mass).values())):
            raise ValueError("source_details do not reproduce stored primary fused BPA")
        if not math.isclose(diagnostics["conjunctive_conflict"], original_conflict, abs_tol=1e-9, rel_tol=0):
            raise ValueError("source_details do not reproduce stored primary conflict")
    trace = {
        "artifact_id": artifact_id, "file": file, "input_line": line,
        "record_sha256": canonical_sha256(record), "source_path": SOURCE_PATH,
        "model": primary["model"], "model_version": version,
        "learning_status": learning_status,
        "legacy_model_version": version < 3,
        "adaptation_status": "legacy_frame_excluded" if excluded else "exact_cluster_bpa_copy",
        "excluded_sources": excluded,
        "original_primary_bpa": asdict(original_mass), "original_risk_base": risk_base,
        "original_k_conflict": original_conflict,
        "primary_bpa_parity": "not_comparable_after_frame_exclusion" if excluded else "verified",
        "source_counts": {"original": len(sources), "retained": len(items), "excluded": len(excluded)},
        "original_outcome": {key: record.get(key) for key in
                             ("threat_level", "classification", "inspection_coverage", "would_deliver")},
    }
    return {"case_id": f"{artifact_id}:{file}", "group_id": f"synthetic-file:{file}",
            "split": "redteam", "label": None, "data_origin": "redteam",
            "evidence_scope": "cluster_level_only", "items": items, "adapter_trace": trace}


def convert_records(records: list[dict[str, Any]], artifact_id: str,
                    legacy_auth: str = "reject") -> dict[str, Any]:
    if not isinstance(artifact_id, str) or not artifact_id.strip():
        raise ValueError("artifact_id must identify the exported engine artifact")
    if legacy_auth not in {"reject", "exclude"}:
        raise ValueError("legacy_auth must be reject or exclude")
    if not records:
        raise ValueError("empty replay input")
    cases = [convert_record(record, artifact_id, line, legacy_auth)
             for line, record in enumerate(records, 1)]
    if len({case["case_id"] for case in cases}) != len(cases):
        raise ValueError("duplicate file records; export each artifact to a fresh JSONL file")
    return {"schema_version": 1, "comparison_scope": "cluster_level_only",
            "comparison_limitations": LIMITATIONS,
            "adapter": {"name": "ds_replay_to_experiment", "version": 1,
                        "artifact_id": artifact_id, "artifact_identity": "caller_asserted",
                        "legacy_auth": legacy_auth, "source_path": SOURCE_PATH,
                        "implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        "group_id_semantics": "file identity only; no campaign independence claim",
                        "input_records_sha256": canonical_sha256(records)},
            "evaluation_protocol": {"holdout_frozen_before_fit": False,
                                    "permitted_use": "evidence_only; no fitting or detection metrics"},
            "cases": cases}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    records = []
    for line, text in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not text.strip():
            raise ValueError(f"blank JSONL line {line}; export must contain one record per line")
        try:
            records.append(json.loads(text, parse_constant=reject_constant, object_pairs_hook=unique_object))
        except ValueError as error:
            raise ValueError(f"JSONL line {line}: {error}") from error
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--artifact-id", required=True, help="engine build/artifact identifier, recorded as asserted")
    parser.add_argument("--legacy-auth", choices=("reject", "exclude"), default="reject")
    args = parser.parse_args()
    try:
        document = convert_records(read_jsonl(args.input), args.artifact_id, args.legacy_auth)
        document["adapter"]["input_file_sha256"] = hashlib.sha256(args.input.read_bytes()).hexdigest()
        args.output.write_text(json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    except (ValueError, TypeError, KeyError, AttributeError, OSError) as error:
        parser.exit(2, f"ds_replay_to_experiment: {error}\n")


if __name__ == "__main__":
    main()
