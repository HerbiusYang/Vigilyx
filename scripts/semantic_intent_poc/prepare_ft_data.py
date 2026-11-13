#!/usr/bin/env python3
"""Prepare fine-tuning inputs from the frozen split (runs on 77).

train/dev/test come from the E-PhishLLM + Fraud-R1 + synthetic-benign split
and are the only files sent to the training server. The red-team and demo
exports are written to a separate directory that stays on 77 for scoring;
the training server never receives the evaluation corpus.

`--train-extra` appends split-schema records (e.g. supplement_en_anti_fraud.py
output) to train only; dev, test and the 77-only exports are unchanged.

Labels: 1 malicious, 0 benign, -1 commercial spam (test only, reported).
`--strip-symbols` drops Unicode So/Sk symbols (emoji, dingbats, arrows):
Fraud-R1's Chinese positives are full of them while the Chinese benign rows
are synthetic notices, so symbols are a dataset artefact a model could learn.
"""

import argparse
import json
from pathlib import Path
import unicodedata

from poc_text import SPACE, normalize

LABELS = {"malicious": 1, "benign": 0, "spam": -1}


def clean(text, strip_symbols, identities=True):
    text = normalize(text, identities)
    if strip_symbols:
        # Other/modifier symbols only; currency and math symbols carry meaning.
        text = "".join(ch for ch in text if unicodedata.category(ch) not in ("So", "Sk"))
    return "\n".join(line for line in (SPACE.sub(" ", raw).strip() for raw in text.split("\n")) if line)


def convert(srcs, dst, strip_symbols, identities):
    count = 0
    with open(dst, "x", encoding="utf-8") as out:
        for line in (line for src in srcs for line in open(src, encoding="utf-8")):
            if not line.strip():
                continue
            record = json.loads(line)
            source = record["sources"][0]
            subject = clean(record.get("subject") or "", strip_symbols, identities)
            body = clean(record.get("body") or "", strip_symbols, identities)
            out.write(json.dumps({
                "id": record["content_id"], "text": (subject + "\n" + body).strip(),
                "label": LABELS[source["label"]],
                "group": "%s/%s" % ("synthetic" if "notice_type" in source else source.get("dataset", ""),
                                    source.get("language", "")),
            }, ensure_ascii=False) + "\n")
            count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--train-out", required=True, type=Path, help="sent to the training server")
    parser.add_argument("--eval-out", required=True, type=Path, help="stays on 77")
    parser.add_argument("--strip-symbols", action="store_true")
    parser.add_argument("--no-identity-mask", action="store_true", help="links and e-mails only (first PoC runs)")
    parser.add_argument("--train-extra", type=Path, action="append", default=[], help="extra train-only records")
    parser.add_argument("--split-name", default="split", help="split directory under --data (e.g. split-spam-by-round)")
    args = parser.parse_args()
    args.train_out.mkdir(parents=True)
    args.eval_out.mkdir(parents=True)
    counts = {}
    for name in ("train", "dev", "test"):
        extra = args.train_extra if name == "train" else []
        counts[name] = convert([args.data / args.split_name / f"{name}.jsonl"] + extra, args.train_out / f"{name}.jsonl", args.strip_symbols, not args.no_identity_mask)
    for name in ("dev", "test"):
        convert([args.data / args.split_name / f"{name}.jsonl"], args.eval_out / f"{name}.jsonl", args.strip_symbols, not args.no_identity_mask)
    for name in ("redteam", "demo"):
        counts[name] = convert([args.data / f"{name}.jsonl"], args.eval_out / f"{name}.jsonl", args.strip_symbols, not args.no_identity_mask)
    print(json.dumps(counts))


if __name__ == "__main__":
    main()
