#!/usr/bin/env python3
"""Validate Vigilyx evidence-category metadata and its one-hop promotion DAG."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict, deque
from pathlib import Path
from typing import Any


ALLOWED_CLASSES = {
    "diagnostic",
    "observation",
    "native_actionable",
    "auth",
    "coverage",
    "dlp",
    "spam",
}
NON_DIRECT_CLASSES = {"diagnostic", "observation", "coverage", "dlp", "spam"}
PROMOTION_TRIGGER_CLASSES = {"native_actionable", "auth"}
AUTH_PROVENANCE = {
    "local_pass",
    "trusted_gateway_pass",
    "local_fail_original_bytes",
    "trusted_gateway_fail",
    "unknown_modified",
    "unknown_untrusted_claim",
    "not_present",
}
AUTH_PROMOTION_PROVENANCE = {"local_fail_original_bytes", "trusted_gateway_fail"}
CATEGORY_ID = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
CAUSAL_TEMPLATE_PLACEHOLDER = re.compile(r"\{[a-z][a-z0-9_]{0,63}\}")
SUPPORTED_VERSIONS = {1, 2}


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON {path}: {exc}") from exc


def non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def duplicate_values(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if isinstance(value, str):
            if value in seen:
                duplicates.add(value)
            seen.add(value)
    return sorted(duplicates)


def category_reference(value: Any, field: str, categories: dict[str, Any], errors: list[str]) -> bool:
    if not isinstance(value, str):
        errors.append(f"{field} must be a registered category id string")
        return False
    if value not in categories:
        errors.append(f"{field} references unknown category {value!r}")
        return False
    return True


def validate_category(
    category_id: str,
    metadata: Any,
    version: int,
    categories: dict[str, Any],
    errors: list[str],
) -> None:
    if not isinstance(metadata, dict):
        errors.append(f"{category_id}: metadata must be an object")
        return
    required = {
        "evidence_class",
        "cluster",
        "causal_family",
        "breaker_eligible",
        "promotion_authority",
        "ui",
    }
    if version >= 2:
        required |= {"causal_key_template", "direct_fusion"}
    missing = sorted(required - metadata.keys())
    if missing:
        errors.append(f"{category_id}: missing fields {', '.join(missing)}")
        return

    evidence_class = metadata.get("evidence_class")
    if not isinstance(evidence_class, str) or evidence_class not in ALLOWED_CLASSES:
        errors.append(f"{category_id}: invalid evidence_class {evidence_class!r}")
    cluster = metadata.get("cluster")
    if not isinstance(cluster, (str, type(None))):
        errors.append(f"{category_id}: cluster must be a string or null")
    if isinstance(evidence_class, str) and evidence_class in {"observation", "native_actionable", "auth"} and not non_empty_string(
        cluster
    ):
        errors.append(f"{category_id}: {evidence_class} requires a non-empty cluster")
    if not non_empty_string(metadata.get("causal_family")):
        errors.append(f"{category_id}: causal_family must be a non-empty string")
    if version >= 2:
        causal_key_template = metadata.get("causal_key_template")
        if not non_empty_string(causal_key_template):
            errors.append(f"{category_id}: causal_key_template must be a non-empty string")
        elif CAUSAL_TEMPLATE_PLACEHOLDER.search(causal_key_template) is None:
            errors.append(
                f"{category_id}: causal_key_template must contain a runtime placeholder such as {{message_hash}}"
            )
    for field in ("breaker_eligible", "promotion_authority"):
        if not isinstance(metadata.get(field), bool):
            errors.append(f"{category_id}: {field} must be boolean")
    if version >= 2 and not isinstance(metadata.get("direct_fusion"), bool):
        errors.append(f"{category_id}: direct_fusion must be boolean")

    ui = metadata.get("ui")
    if not isinstance(ui, dict) or not all(
        non_empty_string(ui.get(language)) for language in ("zh", "en")
    ):
        errors.append(f"{category_id}: ui must contain non-empty zh and en labels")

    breaker_eligible = metadata.get("breaker_eligible") is True
    promotion_authority = metadata.get("promotion_authority") is True
    if isinstance(evidence_class, str) and evidence_class in NON_DIRECT_CLASSES and breaker_eligible:
        errors.append(f"{category_id}: {evidence_class} cannot be breaker_eligible")
    if promotion_authority and (
        not isinstance(evidence_class, str) or evidence_class not in PROMOTION_TRIGGER_CLASSES
    ):
        errors.append(f"{category_id}: only auth or native_actionable may have promotion_authority")

    if version >= 2:
        direct_fusion = metadata.get("direct_fusion") is True
        if isinstance(evidence_class, str) and evidence_class in NON_DIRECT_CLASSES and direct_fusion:
            errors.append(f"{category_id}: {evidence_class} cannot directly enter threat fusion")
        if evidence_class == "native_actionable" and not direct_fusion:
            errors.append(f"{category_id}: native_actionable must set direct_fusion=true")
        if evidence_class == "auth" and direct_fusion:
            errors.append(f"{category_id}: auth cannot directly enter threat fusion")
        if breaker_eligible:
            if evidence_class != "native_actionable" or not direct_fusion:
                errors.append(
                    f"{category_id}: breaker eligibility requires direct native_actionable evidence"
                )
            basis = metadata.get("breaker_basis")
            if not isinstance(basis, dict):
                errors.append(f"{category_id}: breaker_basis must be an object")
            else:
                basis_ids = basis.get("category_ids")
                if not isinstance(basis_ids, list) or not basis_ids:
                    errors.append(f"{category_id}: breaker_basis.category_ids must be a non-empty array")
                else:
                    if not all(isinstance(value, str) for value in basis_ids):
                        errors.append(f"{category_id}: breaker_basis.category_ids must contain strings")
                    elif len(set(basis_ids)) != len(basis_ids):
                        errors.append(f"{category_id}: breaker_basis.category_ids must contain unique strings")
                    for index, value in enumerate(basis_ids):
                        category_reference(
                            value,
                            f"{category_id}.breaker_basis.category_ids[{index}]",
                            categories,
                            errors,
                        )
                        if value == category_id:
                            errors.append(f"{category_id}: breaker_basis cannot reference itself")
                if not non_empty_string(basis.get("rationale")):
                    errors.append(f"{category_id}: breaker_basis.rationale must be a non-empty string")

        provenance = metadata.get("auth_provenance")
        if evidence_class == "auth":
            if not isinstance(provenance, str) or provenance not in AUTH_PROVENANCE:
                errors.append(f"{category_id}: auth requires a valid auth_provenance")
            if promotion_authority and (
                not isinstance(provenance, str) or provenance not in AUTH_PROMOTION_PROVENANCE
            ):
                errors.append(
                    f"{category_id}: only a provenance-qualified authentication failure may promote threat evidence"
                )
        elif provenance is not None:
            errors.append(f"{category_id}: auth_provenance is valid only for auth evidence")


def validate_floors(document: dict[str, Any], categories: dict[str, Any], errors: list[str]) -> None:
    floors = document.get("floors", [])
    if not isinstance(floors, list):
        errors.append("floors must be an array")
        return
    seen_ids: set[str] = set()
    for index, floor in enumerate(floors):
        prefix = f"floors[{index}]"
        if not isinstance(floor, dict):
            errors.append(f"{prefix}: must be an object")
            continue
        floor_id = floor.get("id")
        if not isinstance(floor_id, str) or not CATEGORY_ID.fullmatch(floor_id):
            errors.append(f"{prefix}.id must be a valid category-style id")
        elif floor_id in seen_ids:
            errors.append(f"{prefix}.id is duplicated: {floor_id}")
        else:
            seen_ids.add(floor_id)

        trigger_categories = floor.get("trigger_categories")
        if not isinstance(trigger_categories, list) or not trigger_categories:
            errors.append(f"{prefix}.trigger_categories must be a non-empty array")
            trigger_categories = []
        elif not all(isinstance(value, str) for value in trigger_categories):
            errors.append(f"{prefix}.trigger_categories must contain strings")
        elif len(set(trigger_categories)) != len(trigger_categories):
            errors.append(f"{prefix}.trigger_categories must contain unique strings")

        metadata_items: list[dict[str, Any]] = []
        for item_index, category_id in enumerate(trigger_categories):
            if not category_reference(
                category_id,
                f"{prefix}.trigger_categories[{item_index}]",
                categories,
                errors,
            ):
                continue
            metadata = categories.get(category_id)
            if not isinstance(metadata, dict):
                continue
            metadata_items.append(metadata)
            if metadata.get("evidence_class") != "native_actionable" or metadata.get("direct_fusion") is not True:
                errors.append(
                    f"{prefix}: floor trigger {category_id} must be direct native_actionable evidence"
                )

        minimum = floor.get("minimum_independent_causes")
        if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 2:
            errors.append(f"{prefix}.minimum_independent_causes must be an integer >= 2")
        elif len(metadata_items) < minimum:
            errors.append(f"{prefix}: trigger_categories must provide at least {minimum} registered causes")
        causal_families = [item.get("causal_family") for item in metadata_items]
        if all(isinstance(value, str) for value in causal_families) and len(set(causal_families)) != len(causal_families):
            errors.append(f"{prefix}: floor triggers must use independent causal_family values")
        if floor.get("require_distinct_runtime_causal_keys") is not True:
            errors.append(f"{prefix}.require_distinct_runtime_causal_keys must be true")

        basis = floor.get("basis")
        if not isinstance(basis, dict):
            errors.append(f"{prefix}.basis must be an object")
        else:
            basis_ids = basis.get("category_ids")
            if not isinstance(basis_ids, list) or not basis_ids:
                errors.append(f"{prefix}.basis.category_ids must be a non-empty array")
            else:
                if not all(isinstance(value, str) for value in basis_ids):
                    errors.append(f"{prefix}.basis.category_ids must contain strings")
                else:
                    for item_index, category_id in enumerate(basis_ids):
                        category_reference(
                            category_id,
                            f"{prefix}.basis.category_ids[{item_index}]",
                            categories,
                            errors,
                        )
                    if all(isinstance(value, str) for value in trigger_categories) and set(basis_ids) != set(trigger_categories):
                        errors.append(
                            f"{prefix}.basis.category_ids must name exactly the floor trigger categories"
                        )
            if not non_empty_string(basis.get("rationale")):
                errors.append(f"{prefix}.basis.rationale must be a non-empty string")


def validate_registry(document: Any) -> tuple[list[str], dict[str, set[str]]]:
    errors: list[str] = []
    graph: dict[str, set[str]] = defaultdict(set)
    if not isinstance(document, dict):
        return ["registry root must be an object"], graph
    version = document.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version not in SUPPORTED_VERSIONS:
        errors.append("version must be 1 or 2")
        return errors, graph

    categories = document.get("categories")
    if not isinstance(categories, dict) or not categories:
        return errors + ["categories must be a non-empty object"], graph
    for category_id, metadata in sorted(categories.items()):
        if not isinstance(category_id, str) or not CATEGORY_ID.fullmatch(category_id):
            errors.append(f"invalid category id: {category_id!r}")
            continue
        validate_category(category_id, metadata, version, categories, errors)

    if version >= 2:
        validate_floors(document, categories, errors)

    promotions = document.get("promotions", [])
    if not isinstance(promotions, list):
        return errors + ["promotions must be an array"], graph

    promotion_results: set[str] = set()
    seen_promotion_ids: set[str] = set()
    for index, promotion in enumerate(promotions):
        prefix = f"promotions[{index}]"
        if not isinstance(promotion, dict):
            errors.append(f"{prefix}: must be an object")
            continue
        promotion_id = promotion.get("id")
        observations = promotion.get("observations")
        triggers = promotion.get("triggers")
        result = promotion.get("result")
        if not isinstance(promotion_id, str) or not CATEGORY_ID.fullmatch(promotion_id):
            errors.append(f"{prefix}: invalid id")
        elif promotion_id in seen_promotion_ids:
            errors.append(f"{prefix}: duplicate id {promotion_id}")
        else:
            seen_promotion_ids.add(promotion_id)

        if not isinstance(observations, list) or not observations:
            errors.append(f"{prefix}: observations must be a non-empty array")
            observations = []
        if not isinstance(triggers, list) or not triggers:
            errors.append(f"{prefix}: triggers must be a non-empty array")
            triggers = []
        for field, values in (("observations", observations), ("triggers", triggers)):
            duplicates = duplicate_values(values)
            if duplicates:
                errors.append(f"{prefix}.{field} contains duplicates: {', '.join(duplicates)}")
        if version >= 2 and not non_empty_string(promotion.get("causal_independence")):
            errors.append(f"{prefix}.causal_independence must explain why the trigger is independent")
        if version >= 2 and promotion.get("require_distinct_runtime_causal_keys") is not True:
            errors.append(f"{prefix}.require_distinct_runtime_causal_keys must be true")

        if not isinstance(result, str) or result not in categories:
            errors.append(f"{prefix}: result must name a registered category")
            result = None
        elif not isinstance(categories[result], dict) or categories[result].get(
            "evidence_class"
        ) != "native_actionable":
            errors.append(f"{prefix}: result {result} must be native_actionable")
        elif categories[result].get("promotion_authority"):
            errors.append(f"{prefix}: promoted result {result} cannot have promotion_authority")
        elif version >= 2 and categories[result].get("direct_fusion") is not True:
            errors.append(f"{prefix}: promoted result {result} must set direct_fusion=true")
        else:
            promotion_results.add(result)

        for observation in observations:
            if not category_reference(observation, f"{prefix}.observations", categories, errors):
                continue
            metadata = categories[observation]
            if not isinstance(metadata, dict) or metadata.get("evidence_class") != "observation":
                errors.append(f"{prefix}: {observation} is not an observation")
            if result:
                graph[observation].add(result)
        for trigger in triggers:
            if not category_reference(trigger, f"{prefix}.triggers", categories, errors):
                continue
            metadata = categories[trigger]
            if not isinstance(metadata, dict) or metadata.get(
                "evidence_class"
            ) not in PROMOTION_TRIGGER_CLASSES:
                errors.append(f"{prefix}: {trigger} has an illegal trigger class")
            elif metadata.get("promotion_authority") is not True:
                errors.append(f"{prefix}: {trigger} lacks promotion_authority")
            if result:
                graph[trigger].add(result)

    for index, promotion in enumerate(promotions):
        if not isinstance(promotion, dict):
            continue
        for trigger in promotion.get("triggers", []):
            if isinstance(trigger, str) and trigger in promotion_results:
                errors.append(
                    f"promotions[{index}]: promoted result {trigger} cannot trigger another promotion"
                )

    indegree = {category_id: 0 for category_id in categories}
    for source, targets in graph.items():
        indegree.setdefault(source, 0)
        for target in targets:
            indegree[target] = indegree.get(target, 0) + 1
    queue = deque(sorted(node for node, degree in indegree.items() if degree == 0))
    visited = 0
    while queue:
        node = queue.popleft()
        visited += 1
        for target in sorted(graph.get(node, set())):
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
    if visited != len(indegree):
        cycle_nodes = sorted(node for node, degree in indegree.items() if degree > 0)
        errors.append(f"promotion graph contains a cycle involving: {', '.join(cycle_nodes)}")

    return errors, graph


def emitted_categories(document: Any) -> list[str]:
    if isinstance(document, list):
        values = document
    elif isinstance(document, dict) and isinstance(document.get("categories"), list):
        values = document["categories"]
    else:
        raise ValueError("emitted manifest must be an array or an object with a categories array")
    if not all(isinstance(value, str) for value in values):
        raise ValueError("every emitted category must be a string")
    return sorted(set(values))


def write_dot(path: Path, graph: dict[str, set[str]]) -> None:
    lines = ["digraph evidence_promotions {", "  rankdir=LR;"]
    nodes = sorted(set(graph) | {target for targets in graph.values() for target in targets})
    for node in nodes:
        lines.append(f'  "{node}";')
    for source in sorted(graph):
        for target in sorted(graph[source]):
            lines.append(f'  "{source}" -> "{target}";')
    lines.append("}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--emitted", type=Path)
    parser.add_argument("--dot", type=Path)
    parser.add_argument("--allow-legacy", action="store_true", help="allow v1 compatibility validation to exit 0")
    args = parser.parse_args()

    try:
        registry = load_json(args.registry)
        errors, graph = validate_registry(registry)
        categories = registry.get("categories", {}) if isinstance(registry, dict) else {}
        if args.emitted:
            emitted = emitted_categories(load_json(args.emitted))
            for category_id in emitted:
                if category_id not in categories:
                    errors.append(f"emitted category is not registered: {category_id}")
            for category_id in sorted(set(categories) - set(emitted)):
                errors.append(f"registered category is never emitted: {category_id}")
        if args.dot and not errors:
            args.dot.parent.mkdir(parents=True, exist_ok=True)
            write_dot(args.dot, graph)
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
    version = registry.get("version") if isinstance(registry, dict) else "unknown"
    if version == 1 and not args.allow_legacy:
        print(
            "legacy_error: v1 registries are compatibility-only; rerun with --allow-legacy "
            "for historical replay",
            file=sys.stderr,
        )
        return 1
    suffix = " (legacy compatibility)" if version == 1 else ""
    print(
        f"valid: registry v{version}{suffix}, {len(categories)} categories, "
        f"{sum(map(len, graph.values()))} promotion edges"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
