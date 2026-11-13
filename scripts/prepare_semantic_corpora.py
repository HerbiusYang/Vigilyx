#!/usr/bin/env python3
"""Import the user-supplied research archives without modifying their text.

Only the adapter belongs in Git. Corpus text and reports go under ignored data/.
No archive paths are extracted, and no URLs in the corpora are requested.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import zipfile


def digest(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def read_rows(archive, member):
    info = archive.getinfo(member)
    if info.file_size > 64 * 1024 * 1024:
        raise ValueError(f"oversized member: {member}")
    payload = archive.read(member)
    rows = json.loads(payload)
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValueError(f"expected an array of records: {member}")
    return rows, {"member": member, "sha256": digest(payload), "records": len(rows)}


def text_field(row, key):
    value = row[key]
    if not isinstance(value, str):
        raise ValueError(f"non-string {key}")
    return value


def prepare(ephish, fraud, output):
    records = {}
    members = []
    excluded = Counter()
    empty = Counter()
    missing = Counter()
    structured = Counter()
    source_counts = Counter()
    label_counts = Counter()

    def add(subject, body, source):
        if not body.strip():
            empty[f"{source['dataset']}/{source['variant']}"] += 1
            return
        # Exact text identity: no whitespace, case, punctuation or Unicode folding.
        identity = digest(encoded({"subject": subject, "body": body}))
        record = records.setdefault(identity, {
            "schema_version": 1, "content_id": identity,
            "subject": subject, "body": body, "content_type": "text/plain",
            "sources": [],
        })
        record["sources"].append(source)
        source_counts[f"{source['dataset']}/{source['language']}/{source['data_type']}/{source['variant']}"] += 1
        label_counts[f"{source['dataset']}/{source['label']}"] += 1

    with zipfile.ZipFile(ephish) as archive:
        member = "E-PhishLLM/ephishLLM.json"
        rows, metadata = read_rows(archive, member)
        members.append(metadata)
        for index, row in enumerate(rows):
            if type(row["type"]) is not int or row["type"] not in (0, 1):
                raise ValueError(f"unknown E-PhishLLM label at {index}")
            add(text_field(row, "Subject"), text_field(row, "Body"), {
                "sample_id": f"ephish/{index}", "dataset": "E-PhishLLM",
                "member": member, "record_index": index,
                "variant": "original", "language": text_field(row, "Language"),
                "data_type": "email", "category": "phishing" if row["type"] else "benign",
                "subcategory": "", "label": "malicious" if row["type"] else "benign",
                "field": "Body", "round": None,
            })
        subset, metadata = read_rows(archive, "E-PhishLLM/ephishLLM_phishing_only.json")
        members.append(metadata)
        if subset != [row for row in rows if row["type"] == 1]:
            raise ValueError("E-PhishLLM phishing-only file is not the documented subset")
        excluded["ephish_phishing_subset"] = len(subset)

    with zipfile.ZipFile(fraud) as archive:
        for language in ("Chinese", "English"):
            base_member = f"Fraud-R1/FP-base-full/FP-base-{language}.json"
            base, metadata = read_rows(archive, base_member)
            members.append(metadata)
            up_member = f"Fraud-R1/FP-levelup-full/FP-levelup-{language}.json"
            upgraded, metadata = read_rows(archive, up_member)
            members.append(metadata)
            by_id = {row["id"]: row for row in base}
            if len(by_id) != len(base) or {row["id"] for row in upgraded} != set(by_id):
                raise ValueError(f"Fraud-R1 IDs are not aligned: {language}")
            for index, row in enumerate(base):
                shared = {
                    "dataset": "Fraud-R1", "language": text_field(row, "language"),
                    "record_id": row["id"], "data_type": text_field(row, "data_type"),
                    "category": text_field(row, "category"),
                    "subcategory": text_field(row, "subcategory"),
                    # Commercial spam is not a benign control or a phishing positive.
                    "label": "spam" if row["subcategory"] == "commercial spam" else "malicious",
                }
                for field, variant in (("raw_data", "raw"), ("generated text", "generated")):
                    if field == "raw_data" and field not in row:
                        missing[f"Fraud-R1/{language}/{field}"] += 1
                        continue
                    if field == "raw_data" and isinstance(row[field], dict):
                        # Structured job-posting records have no original text
                        # representation. Their generated text is still replayed.
                        structured[f"Fraud-R1/{language}/{field}"] += 1
                        continue
                    add(None, text_field(row, field), {
                        **shared, "member": base_member, "record_index": index,
                        "sample_id": f"fraud/{language}/{row['id']}/{variant}",
                        "variant": variant, "field": field, "round": None,
                    })
            for index, row in enumerate(upgraded):
                original = by_id[row["id"]]
                if any(row[key] != original[key] for key in original):
                    raise ValueError(f"Fraud-R1 base/levelup differ outside rounds: {language}/{row['id']}")
                rounds = row["multi-rounds fraud"]
                if [item["round"] for item in rounds] != [1, 2, 3, 4]:
                    raise ValueError(f"unexpected rounds: {language}/{row['id']}")
                if rounds[0]["generated_data"] != row["generated text"]:
                    raise ValueError(f"round 1 differs from generated text: {language}/{row['id']}")
                excluded["fraud_levelup_generated_copy"] += 1
                excluded["fraud_round1_copy"] += 1
                for item in rounds[1:]:
                    add(None, text_field(item, "generated_data"), {
                        "dataset": "Fraud-R1", "language": row["language"],
                        "record_id": row["id"], "data_type": row["data_type"],
                        "category": row["category"], "subcategory": row["subcategory"],
                        "label": "spam" if row["subcategory"] == "commercial spam" else "malicious",
                        "member": up_member, "record_index": index,
                        "sample_id": f"fraud/{language}/{row['id']}/round{item['round']}",
                        "variant": f"round{item['round']}", "round": item["round"],
                        "field": "multi-rounds fraud.generated_data",
                    })
            # Validate the supplied filtered copies, but never replay them twice.
            for name, full in ((base_member, base), (up_member, upgraded)):
                subset_name = name.removesuffix(".json") + "_no_spam.json"
                subset, metadata = read_rows(archive, subset_name)
                members.append(metadata)
                if subset != [row for row in full if row["subcategory"] != "commercial spam"]:
                    raise ValueError(f"no-spam file differs from documented filter: {subset_name}")
                excluded["fraud_no_spam_subset"] += len(subset)

    output.mkdir(parents=True, exist_ok=True)
    corpus_path = output / "cases.jsonl"
    # Refuse to overwrite an earlier experiment, including partially written imports.
    with corpus_path.open("xb") as stream:
        for record in records.values():
            stream.write(encoded(record) + b"\n")
    count = sum(len(record["sources"]) for record in records.values())
    conflicts = sum(len({s["label"] for s in r["sources"]}) > 1 for r in records.values())
    manifest = {
        "schema_version": 1,
        "archives": [{"name": p.name, "sha256": digest(p.read_bytes())} for p in (ephish, fraud)],
        "members": members, "unique_contents": len(records), "source_instances": count,
        "exact_duplicate_instances": count - len(records), "conflicting_label_contents": conflicts,
        "excluded_copies": dict(excluded), "empty_fields": dict(empty), "missing_fields": dict(missing),
        "structured_raw_fields_not_text": dict(structured),
        "strata": dict(sorted(source_counts.items())), "labels": dict(sorted(label_counts.items())),
        "corpus_sha256": digest(corpus_path.read_bytes()),
        "semantics": {
            "input": "exact Subject+Body or exact individual Fraud-R1 text field; plain-text path",
            "no_inferred_facts": "no envelope, sender domain, authentication, thread headers or link ownership invented",
            "scope": "raw Fraud-R1 reports/dialogues, messages and job postings are diagnostic strata",
            "labels": "dataset labels retained, not independently adjudicated semantic expectations",
            "rounds": "each generated round replayed independently; no cross-message memory",
        },
    }
    with (output / "manifest.json").open("x") as stream:
        json.dump(manifest, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({k: manifest[k] for k in (
        "unique_contents", "source_instances", "exact_duplicate_instances",
        "conflicting_label_contents", "empty_fields", "missing_fields",
        "structured_raw_fields_not_text", "labels", "corpus_sha256",
    )}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ephish", required=True, type=Path)
    parser.add_argument("--fraud", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    prepare(args.ephish, args.fraud, args.output)
