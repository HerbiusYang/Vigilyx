#!/usr/bin/env python3
"""Score a fine-tuned ONNX classifier on 77 (CPU) and report against dev thresholds.

* Checks ONNX vs torch parity on dev (logits saved by train_classifier.py).
* Builds an INT8 dynamic-quantised copy and reports FP32/INT8 decision agreement.
* Thresholds come from dev only (benign FPR 1% and 3%); test, red team and
  demo are scored with them unchanged. The red team is evaluation-only.
* Red-team breakdowns: family, language, and the ham/malicious minimal pairs.
* Latency: one forward pass per email on the configured thread count.
"""

import argparse
import glob
import json
import math
from pathlib import Path
import time

import numpy as np
import onnx
import onnxruntime as ort
from onnxruntime.quantization import QuantType, quantize_dynamic
from tokenizers import Tokenizer

SETS = ("dev", "test", "redteam", "demo")


def session(path, threads):
    options = ort.SessionOptions()
    options.intra_op_num_threads = threads
    options.inter_op_num_threads = 1
    options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    return ort.InferenceSession(str(path), options, providers=["CPUExecutionProvider"])


def encode(tokenizer, config, text):
    ids = tokenizer.encode(config["prefix"] + text).ids
    if len(ids) > config["max_len"]:
        head = config["head_tokens"]
        ids = ids[:head] + ids[-(config["max_len"] - head):]
    return ids


def score(sess, encoded, pad_id, batch=32):
    order = sorted(range(len(encoded)), key=lambda i: len(encoded[i]))
    out = np.zeros(len(encoded), dtype=np.float32)
    for start in range(0, len(order), batch):
        index = order[start:start + batch]
        width = max(len(encoded[i]) for i in index)
        ids = np.full((len(index), width), pad_id, dtype=np.int64)
        mask = np.zeros((len(index), width), dtype=np.int64)
        for row, i in enumerate(index):
            ids[row, :len(encoded[i])] = encoded[i]
            mask[row, :len(encoded[i])] = 1
        out[index] = sess.run(["logit"], {"input_ids": ids, "attention_mask": mask})[0]
    return out


def auc(scores, labels):
    pos, neg = scores[labels == 1], scores[labels == 0]
    if not len(pos) or not len(neg):
        return None
    both = np.concatenate([pos, neg])
    order = both.argsort(kind="mergesort")
    ranks = np.empty(len(both))
    ranks[order] = np.arange(1, len(both) + 1)
    values = both[order]
    i = 0
    while i < len(values):
        j = i
        while j + 1 < len(values) and values[j + 1] == values[i]:
            j += 1
        if j > i:
            ranks[order[i:j + 1]] = (i + j + 2) / 2.0
        i = j + 1
    return float((ranks[:len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def threshold(scores, labels, fpr):
    benign = np.sort(scores[labels == 0])
    return float(benign[max(int(math.ceil(len(benign) * (1 - fpr))) - 1, 0)])


def breakdown(scores, rows, tau, key):
    groups = {}
    for row, value in zip(rows, scores):
        k = f"{row['label']}|{key(row)}"
        n, f = groups.get(k, (0, 0))
        groups[k] = (n + 1, f + int(value > tau))
    return {k: {"n": n, "rate": round(f / n, 4)} for k, (n, f) in sorted(groups.items())}


def summary(scores, rows, tau, key):
    labels = np.array([r["label"] for r in rows])
    flagged = scores > tau
    return {"auc": auc(scores, labels),
            "recall": float(flagged[labels == 1].mean()) if (labels == 1).any() else None,
            "fpr": float(flagged[labels == 0].mean()) if (labels == 0).any() else None,
            "spam_flag_rate": float(flagged[labels == -1].mean()) if (labels == -1).any() else None,
            "groups": breakdown(scores, rows, tau, key)}


def redteam_meta(data_dir, synth_dir):
    meta = {}
    for line in open(data_dir / "redteam.jsonl", encoding="utf-8"):
        record = json.loads(line)
        source = record["sources"][0]
        meta[record["content_id"]] = {"family": source["category"], "language": source["language"],
                                      "file": source["sample_id"].split("/")[-1]}
    pairs = []
    if synth_dir:
        decoder = json.JSONDecoder()
        for path in sorted(glob.glob(str(Path(synth_dir) / "labels*.jsonl"))):
            for line in open(path, encoding="utf-8"):
                pos = 0
                while True:
                    while pos < len(line) and (line[pos].isspace() or line[pos] in ",[]"):
                        pos += 1
                    if pos >= len(line):
                        break
                    obj, pos = decoder.raw_decode(line, pos)
                    if obj.get("label") == "malicious" and obj.get("pair"):
                        ham = obj["pair"] if obj["pair"].endswith(".eml") else obj["pair"] + ".eml"
                        pairs.append((obj["file"].split("/")[-1], ham.split("/")[-1]))
    return meta, pairs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path, help="directory exported by train_classifier.py")
    parser.add_argument("--eval", required=True, type=Path, help="eval-77 directory from prepare_ft_data.py")
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--synth-labels", default=None)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--threads", type=int, default=12)
    parser.add_argument("--bench-threads", type=int, default=4)
    parser.add_argument("--parity-group-prefix", default="E-PhishLLM/",
                        help="dev subset used for the torch parity check when the run trained on a filtered split")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    config = json.load(open(args.run / "classifier_config.json"))
    tokenizer = Tokenizer.from_file(str(args.run / "tokenizer.json"))
    tokenizer.no_truncation()
    tokenizer.no_padding()
    rows = {n: [json.loads(l) for l in open(args.eval / f"{n}.jsonl", encoding="utf-8") if l.strip()] for n in SETS}
    encoded = {n: [encode(tokenizer, config, r["text"]) for r in rows[n]] for n in SETS}

    int8_path = args.output / "model.int8.onnx"
    variants = {"fp32": session(args.run / "model.onnx", args.threads)}
    try:
        if not int8_path.exists():
            # Dynamo exports carry value_info that conflicts with ORT's shape inference; drop it.
            model = onnx.load(str(args.run / "model.onnx"))
            model.graph.ClearField("value_info")
            stripped = args.output / "model.fp32.stripped.onnx"
            onnx.save(model, str(stripped))
            quantize_dynamic(str(stripped), str(int8_path), weight_type=QuantType.QInt8)
            stripped.unlink()
        variants["int8"] = session(int8_path, args.threads)
    except Exception as error:
        print(f"int8 quantisation failed: {type(error).__name__}: {error}")
    scores = {v: {n: score(s, encoded[n], config["pad_id"]) for n in SETS} for v, s in variants.items()}

    torch_dev = np.load(args.run / "dev_logits_torch.npy")
    onnx_dev = scores["fp32"]["dev"]
    if len(onnx_dev) != len(torch_dev):
        # Runs trained on a filtered split saved logits for that subset, in split order.
        onnx_dev = onnx_dev[[i for i, r in enumerate(rows["dev"]) if r["group"].startswith(args.parity_group_prefix)]]
    parity = float(np.abs(onnx_dev - torch_dev).max()) if len(onnx_dev) == len(torch_dev) else None
    report = {"run": str(args.run), "config": config, "parity_fp32_vs_torch_max_abs": parity}
    meta, pairs = redteam_meta(args.data, args.synth_labels)
    by_file = {meta[r["id"]]["file"]: i for i, r in enumerate(rows["redteam"])}
    for variant in variants:
        s = scores[variant]
        dev_labels = np.array([r["label"] for r in rows["dev"]])
        entry = {}
        for op, fpr in (("fpr1", 0.01), ("fpr3", 0.03)):
            tau = threshold(s["dev"], dev_labels, fpr)
            entry[op] = {
                "threshold": tau,
                "dev": summary(s["dev"], rows["dev"], tau, lambda r: r["group"]),
                "test": summary(s["test"], rows["test"], tau, lambda r: r["group"]),
                "redteam": summary(s["redteam"], rows["redteam"], tau, lambda r: meta[r["id"]]["family"]),
                "redteam_language": breakdown(s["redteam"], rows["redteam"], tau, lambda r: meta[r["id"]]["language"]),
                "demo": [{"id": r["id"], "logit": round(float(v), 3), "flagged": bool(v > tau)}
                         for r, v in zip(rows["demo"], s["demo"])],
            }
        wins = n = 0
        for mal, ham in pairs:
            if mal in by_file and ham in by_file:
                n += 1
                wins += s["redteam"][by_file[mal]] > s["redteam"][by_file[ham]]
        entry["redteam_pairs"] = {"pairs": n, "malicious_scored_higher": round(wins / max(n, 1), 4)}
        report[variant] = entry
    if "int8" in variants:
        tau32 = report["fp32"]["fpr1"]["threshold"]
        tau8 = report["int8"]["fpr1"]["threshold"]
        report["int8_decision_agreement"] = {
            n: float(((scores["fp32"][n] > tau32) == (scores["int8"][n] > tau8)).mean()) for n in ("dev", "test", "redteam")}

    bench = {}
    paths = {"fp32": args.run / "model.onnx", "int8": int8_path}
    for variant in variants:
        path = paths[variant]
        sess = session(path, args.bench_threads)
        sample = encoded["test"][:300] + encoded["redteam"][:300]
        score(sess, sample[:8], config["pad_id"])
        timings = []
        for ids in sample:
            t = time.perf_counter()
            sess.run(["logit"], {"input_ids": np.array([ids], dtype=np.int64),
                                 "attention_mask": np.ones((1, len(ids)), dtype=np.int64)})
            timings.append((time.perf_counter() - t) * 1000)
        timings.sort()
        bench[variant] = {p: round(timings[min(len(timings) - 1, int(round(q * (len(timings) - 1))))], 2)
                          for p, q in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99), ("max", 1.0))}
    report["latency_ms_per_email"] = {"threads": args.bench_threads, **bench}
    with open(args.output / "metrics.json", "w", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=1)
    np.savez(args.output / "scores.npz", **{f"{v}__{n}": a for v, d in scores.items() for n, a in d.items()})

    print(f"run={args.run.name} parity_max_abs={report['parity_fp32_vs_torch_max_abs']} "
          f"int8_agreement={report.get('int8_decision_agreement')}")
    for variant in variants:
        for op in ("fpr1", "fpr3"):
            e = report[variant][op]
            cells = [f"{100 * e[n]['recall']:5.1f}/{100 * e[n]['fpr']:5.1f}" for n in ("dev", "test", "redteam")]
            print(f"  {variant} {op} dev {cells[0]} test {cells[1]} redteam {cells[2]} "
                  f"auc(test/red)={e['test']['auc']:.3f}/{e['redteam']['auc']:.3f} "
                  f"demo={''.join('X' if d['flagged'] else '.' for d in e['demo'])}")
        print(f"  {variant} pairs={report[variant]['redteam_pairs']}")
    print("  latency", json.dumps(report["latency_ms_per_email"]))


if __name__ == "__main__":
    main()
