#!/usr/bin/env python3
"""Export the red-team EML corpus as plain-text cases for evaluation only.

The red-team corpus (`crates/vigilyx-engine/tests/redteam_cases`) is an
evaluation set. This export feeds evaluation code paths only; nothing here
produces training data, and the PoC never fits a model on these rows.

Text extraction follows the 2026-11-05 diagnostic export so numbers stay
comparable: text/plain parts when present, otherwise tag-stripped HTML; the
Subject is kept as a separate field; exact duplicate contents are dropped.
Labels come from `labels.json` and every `synth/labels*.jsonl` file (the synth
labels are stored in batches). Output follows the semantic_external_harness
case schema. Python 3.9 compatible, stdlib only.
"""

import argparse
import email
from email import policy
import hashlib
import html
import json
from pathlib import Path
import re

CJK = re.compile(r"[一-鿿]")
LATIN = re.compile(r"[A-Za-z]")
TAG = re.compile(r"<[^>]+>")


def load_labels(root):
    rows = []
    for case in json.loads((root / "labels.json").read_text())["cases"]:
        rows.append((case["file"], case["label"], case.get("family", "")))
    decoder = json.JSONDecoder()
    for path in sorted((root / "synth").glob("labels*.jsonl")):
        # Some batch files hold several records on one physical line, and some
        # separate records with array-style commas.
        for line in path.read_text().splitlines():
            position = 0
            while True:
                while position < len(line) and (line[position].isspace() or line[position] in ",[]"):
                    position += 1
                if position >= len(line):
                    break
                case, position = decoder.raw_decode(line, position)
                rows.append((case["file"], case["label"], case.get("family", "")))
    return rows


def extract(path):
    message = email.message_from_bytes(path.read_bytes(), policy=policy.default)
    plain, htmls = [], []
    for part in message.walk():
        kind = part.get_content_type()
        if kind == "text/plain":
            plain.append(part.get_content())
        elif kind == "text/html":
            htmls.append(part.get_content())
    body = "\n".join(plain) if plain else html.unescape(TAG.sub(" ", "\n".join(htmls)))
    subject = str(message.get("subject") or "") or None
    return subject, body


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="redteam_cases directory")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    seen_files, seen_content = set(), set()
    counts = {"written": 0, "duplicate_label": 0, "missing_file": 0, "parse_error": 0,
              "empty_body": 0, "duplicate_content": 0, "other_label": 0}
    with args.output.open("x") as out:
        for name, label, family in load_labels(args.root):
            if label not in ("benign", "malicious"):
                counts["other_label"] += 1
                continue
            path = args.root / name
            if not path.exists():
                path = args.root / "synth" / name
            key = str(path.resolve())
            if key in seen_files:
                counts["duplicate_label"] += 1
                continue
            seen_files.add(key)
            if not path.exists():
                counts["missing_file"] += 1
                continue
            try:
                subject, body = extract(path)
            except Exception:
                counts["parse_error"] += 1
                continue
            if not body.strip():
                counts["empty_body"] += 1
                continue
            content_id = hashlib.sha256(
                json.dumps([subject, body], ensure_ascii=False).encode()).hexdigest()
            if content_id in seen_content:
                counts["duplicate_content"] += 1
                continue
            seen_content.add(content_id)
            cjk, latin = len(CJK.findall(body)), len(LATIN.findall(body))
            language = "cjk" if cjk / max(1, cjk + latin) >= 0.3 else "latin"
            relative = path.relative_to(args.root).as_posix()
            out.write(json.dumps({
                "schema_version": 1, "content_id": content_id, "subject": subject,
                "body": body, "content_type": "text/plain",
                "sources": [{"sample_id": "redteam/" + relative, "dataset": "redteam",
                             "language": language, "data_type": "email",
                             "variant": "original", "category": family,
                             "subcategory": "", "label": label}],
            }, ensure_ascii=False) + "\n")
            counts["written"] += 1
    print(json.dumps(counts))


if __name__ == "__main__":
    main()
