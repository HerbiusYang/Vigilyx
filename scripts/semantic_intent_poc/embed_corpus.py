#!/usr/bin/env python3
"""Segment and encode corpus JSONL files once per encoder (PoC, CPU only).

Writes, per input NAME: NAME.emb.npy (float16 sentence vectors),
NAME.offsets.npy (email -> sentence range), NAME.meta.jsonl and
NAME.sents.jsonl. Inputs use the semantic_external_harness case schema.
"""

import argparse
import json
from pathlib import Path
import time

import numpy as np

from poc_encoder import Encoder
from poc_text import sentences


def meta_for(record, units, truncated):
    source = record["sources"][0]
    return {
        "content_id": record["content_id"], "label": source["label"],
        "dataset": source.get("dataset", ""), "language": source.get("language", ""),
        "data_type": source.get("data_type", ""),
        "category": source.get("category") or source.get("notice_type", ""),
        "subcategory": source.get("subcategory", ""),
        "synthetic": "notice_type" in source,
        "n_sent": len(units), "truncated": truncated,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models-root", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--variant", default="int8")
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--input", action="append", required=True, help="NAME=PATH")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    encoder = Encoder(args.models_root, args.model, args.variant, args.threads)
    args.output.mkdir(parents=True, exist_ok=True)
    for spec in args.input:
        name, path = spec.split("=", 1)
        if (args.output / f"{name}.emb.npy").exists():
            print(f"{name}: exists, skipped", flush=True)
            continue
        started = time.time()
        metas, all_units, offsets = [], [], [0]
        for line in open(path, encoding="utf-8"):
            if not line.strip():
                continue
            record = json.loads(line)
            units, truncated = sentences(record.get("subject"), record.get("body") or "")
            metas.append(meta_for(record, units, truncated))
            all_units.append(units)
            offsets.append(offsets[-1] + len(units))
        flat = [unit for units in all_units for unit in units]
        chunks = []
        for start in range(0, len(flat), 4096):
            chunks.append(encoder.encode(flat[start:start + 4096]).astype(np.float16))
            print(f"{name}: {start + len(chunks[-1])}/{len(flat)} sentences "
                  f"{time.time() - started:.0f}s", flush=True)
        vectors = np.concatenate(chunks) if chunks else np.zeros((0, 1), np.float16)
        np.save(args.output / f"{name}.emb.npy", vectors)
        np.save(args.output / f"{name}.offsets.npy", np.asarray(offsets, dtype=np.int64))
        with open(args.output / f"{name}.meta.jsonl", "w", encoding="utf-8") as stream:
            for meta in metas:
                stream.write(json.dumps(meta, ensure_ascii=False) + "\n")
        with open(args.output / f"{name}.sents.jsonl", "w", encoding="utf-8") as stream:
            for units in all_units:
                stream.write(json.dumps(units, ensure_ascii=False) + "\n")
        elapsed = time.time() - started
        print(json.dumps({"input": name, "emails": len(metas), "sentences": len(flat),
                          "truncated": sum(m["truncated"] for m in metas),
                          "seconds": round(elapsed, 1),
                          "sentences_per_second": round(len(flat) / max(elapsed, 1e-9), 1)}),
              flush=True)


if __name__ == "__main__":
    main()
