#!/usr/bin/env python3
"""Train-only English anti-fraud awareness notices (runs on 77, stdlib only).

The frozen split has Chinese anti-fraud bulletins (zh/anti_fraud) in train but
no English counterpart: the only English awareness type (security_awareness)
landed in test. A Chinese-only encoder such as bge-small-zh cannot carry the
Chinese lesson over, so it flags English bulletins that describe scams.

This writes one extra benign type, en/anti_fraud, whose sentence pool is a
translation of the zh/anti_fraud training pool (not of the test pool), using
the generator's own composition so salutations, closings and disclaimers match
the other types. Records use the split schema and are appended to train only;
dev and test stay byte-identical. The generator itself is not modified, so the
frozen split is unchanged. Only benign mail is produced.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import random

EN_ANTI_FRAUD = {
    "orgs": ["{city} Police Anti-Fraud Center", "{org_bank} Consumer Protection Department", "Corporate Security Office",
             "{city} Anti-Fraud Joint Office"],
    "subjects": ["Fraud risk alert", "Beware of fake customer service calls", "Tips to prevent phone and online fraud",
                 "Security reminder about recent phishing emails"],
    "intro": ["Fraudsters have recently been posing as online store customer service, using \"refunds\" or \"compensation\" "
              "as a pretext to get victims to transfer money.",
              "There have been scams in which callers impersonate police or prosecutors, say you are \"suspected of money "
              "laundering and must cooperate with an investigation\", and demand a transfer to a \"safe account\".",
              "We have found phishing emails with subjects such as \"Your mailbox will soon be deactivated, click to verify\".",
              "Scammers have been impersonating managers on messaging apps and asking employees to make urgent transfers."],
    "details": ["The police have no such thing as a \"safe account\" and do not handle cases over the phone.",
                "Genuine customer service will never ask you to download screen-sharing software or give them a verification code.",
                "Whenever someone asks you to transfer money, confirm it through a reliable channel such as a phone number you already have.",
                "If you have already transferred money, call the police immediately."],
    "actions": ["If a message looks suspicious, leave its links alone and let the security department know.",
                "Please stay alert and pass this reminder on to others."],
    "slots": {"org_bank": ["Keystone Federal", "{city} Community Credit Union"]},
}


def load_generator(path):
    spec = importlib.util.spec_from_file_location("synthetic_benign_generator", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generator", required=True, type=Path, help="scripts/generate_semantic_synthetic_benign.py")
    parser.add_argument("--split", required=True, type=Path, help="frozen split directory (ids to avoid)")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--count", type=int, default=111, help="same size as one v1 notice type")
    parser.add_argument("--seed", default="vigilyx-synthetic-benign-supplement-en-anti-fraud-v1")
    args = parser.parse_args()
    generator = load_generator(args.generator)
    seen = set()
    for name in ("train", "dev", "test"):
        for line in open(args.split / f"{name}.jsonl", encoding="utf-8"):
            if line.strip():
                seen.add(json.loads(line)["content_id"])
    rng = random.Random(args.seed)
    records, attempts = [], 0
    while len(records) < args.count:
        attempts += 1
        if attempts > args.count * 20:
            raise RuntimeError("not enough distinct samples")
        subject, body = generator.compose(rng, EN_ANTI_FRAUD, False)
        content_id = generator.digest(json.dumps({"subject": subject, "body": body}, ensure_ascii=False,
                                                 sort_keys=True).encode())
        if content_id in seen:
            continue
        seen.add(content_id)
        records.append({
            "schema_version": 1, "content_id": content_id, "subject": subject, "body": body, "content_type": "text/plain",
            "sources": [{"dataset": generator.DATASET, "language": "en", "label": "benign", "category": "anti_fraud",
                         "subcategory": "", "data_type": "email", "variant": "supplement",
                         "sample_id": "synthetic-supplement/en/anti_fraud/%d" % (len(records) + 1),
                         "notice_type": "en/anti_fraud"}],
        })
    args.output.mkdir(parents=True)
    path = args.output / "cases.jsonl"
    with path.open("xb") as stream:
        for record in records:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    manifest = {"schema_version": 1, "dataset": generator.DATASET, "seed": args.seed, "notice_type": "en/anti_fraud",
                "split": "train-only", "records": len(records), "cases_sha256": generator.digest(path.read_bytes())}
    with (args.output / "manifest.json").open("x") as stream:
        json.dump(manifest, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
