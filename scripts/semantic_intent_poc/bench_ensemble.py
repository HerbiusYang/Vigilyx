#!/usr/bin/env python3
"""Per-email CPU latency of an ensemble of fine-tuned ONNX members (runs on 77).

Each --member is a train_classifier.py run directory (model.onnx or
--int8-name, tokenizer.json, classifier_config.json); a directory may repeat
to stand in for another seed of the same architecture, since latency does not
depend on the weights. Every email is tokenised and scored by all members,
either one after another (`sequential`) or concurrently on a thread pool
(`parallel`); the reported time is the whole ensemble for one email.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import random
import time

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer


class Member:
    def __init__(self, run, threads, model_name):
        self.config = json.loads((run / "classifier_config.json").read_text())
        self.tokenizer = Tokenizer.from_file(str(run / "tokenizer.json"))
        self.tokenizer.no_truncation()
        self.tokenizer.no_padding()
        options = ort.SessionOptions()
        options.intra_op_num_threads = threads
        options.inter_op_num_threads = 1
        options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        self.session = ort.InferenceSession(str(run / model_name), options, providers=["CPUExecutionProvider"])

    def __call__(self, text):
        ids = self.tokenizer.encode(self.config["prefix"] + text).ids
        if len(ids) > self.config["max_len"]:
            head = self.config["head_tokens"]
            ids = ids[:head] + ids[-(self.config["max_len"] - head):]
        ids = np.array([ids], dtype=np.int64)
        return float(self.session.run(["logit"], {"input_ids": ids, "attention_mask": np.ones_like(ids)})[0][0])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--member", action="append", required=True, type=Path)
    parser.add_argument("--model-name", default="model.onnx")
    parser.add_argument("--eval", required=True, type=Path, help="jsonl with a text field")
    parser.add_argument("--threads", type=int, default=4, help="intra-op threads per member")
    parser.add_argument("--sample", type=int, default=400)
    parser.add_argument("--mode", choices=("sequential", "parallel"), default="sequential")
    args = parser.parse_args()
    texts = [json.loads(line)["text"] for line in open(args.eval, encoding="utf-8") if line.strip()]
    random.Random(20261111).shuffle(texts)
    texts = texts[:args.sample]
    members = [Member(run, args.threads, args.model_name) for run in args.member]
    for member in members:  # warm-up
        member(texts[0])
    pool = ThreadPoolExecutor(len(members)) if args.mode == "parallel" else None
    timings = []
    for text in texts:
        start = time.perf_counter()
        if pool:
            list(pool.map(lambda m: m(text), members))
        else:
            for member in members:
                member(text)
        timings.append((time.perf_counter() - start) * 1000)
    timings.sort()
    pick = lambda q: round(timings[min(len(timings) - 1, int(round(q * (len(timings) - 1))))], 1)
    print(json.dumps({"mode": args.mode, "members": len(members), "threads_per_member": args.threads,
                      "emails": len(timings), "ms": {"p50": pick(0.5), "p95": pick(0.95), "p99": pick(0.99),
                                                      "max": round(timings[-1], 1)}}))


if __name__ == "__main__":
    main()
