#!/usr/bin/env python3
"""Python reference outputs for the Rust intent-model port (runs on 77).

Text mode writes {subject, body, text} for every split record: the training
preprocessing (prepare_ft_data.clean + subject/body join) that
intent_text::model_text must reproduce byte for byte. Model mode samples
records and adds each member's logit, computed like score_onnx.py
(tokenizers + onnxruntime, head+tail truncation), for intent_model_parity.
Output stays on 77: it contains dataset text, which must not be redistributed.
"""

import argparse
import json
from pathlib import Path
import random

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

from prepare_ft_data import clean


def model_text(subject, body):
    return (clean(subject or "", False, True) + "\n" + clean(body or "", False, True)).strip()


class Member:
    def __init__(self, directory, threads):
        self.config = json.loads((directory / "classifier_config.json").read_text())
        self.tokenizer = Tokenizer.from_file(str(directory / "tokenizer.json"))
        self.tokenizer.no_truncation()
        self.tokenizer.no_padding()
        options = ort.SessionOptions()
        options.intra_op_num_threads = threads
        options.inter_op_num_threads = 1
        options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        self.session = ort.InferenceSession(str(directory / "model.onnx"), options, providers=["CPUExecutionProvider"])

    def logit(self, text):
        ids = self.tokenizer.encode(self.config["prefix"] + text).ids
        if len(ids) > self.config["max_len"]:
            head = self.config["head_tokens"]
            ids = ids[:head] + ids[-(self.config["max_len"] - head):]
        batch = np.array([ids], dtype=np.int64)
        return float(self.session.run(["logit"], {"input_ids": batch, "attention_mask": np.ones_like(batch)})[0][0])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", required=True, type=Path, help="split directory with raw subject/body records")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--package", type=Path, help="packaged ensemble directory (model mode)")
    parser.add_argument("--sample", type=int, default=0, help="records to score in model mode (0: text mode)")
    parser.add_argument("--threads", type=int, default=8)
    args = parser.parse_args()
    records = [json.loads(line) for name in ("train", "dev", "test")
               for line in open(args.split / f"{name}.jsonl", encoding="utf-8") if line.strip()]
    members = {}
    if args.sample:
        spec = json.loads((args.package / "ensemble.json").read_text())
        members = {m["name"]: Member(args.package / m["dir"], args.threads) for m in spec["members"]}
        random.Random(20261111).shuffle(records)
        records = records[:args.sample]
    with open(args.output, "x", encoding="utf-8") as out:
        for record in records:
            subject, body = record.get("subject"), record.get("body") or ""
            text = model_text(subject, body)
            row = {"subject": subject, "body": body, "text": text}
            if members:
                row["logits"] = {name: member.logit(text) for name, member in members.items()}
            out.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(len(records), "records")


if __name__ == "__main__":
    main()
