#!/usr/bin/env python3
"""CPU latency and memory benchmark for the PoC encoders (plan item E5).

Measures cold start, batch latency for 1/8/32 sentences, real per-email
latency (segmentation + encoding) on test and red-team emails, throughput
with 4 concurrent callers sharing one session, and resident memory. Run it
pinned to a fixed CPU set so the numbers reflect a per-module budget.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import random
import time

from poc_encoder import Encoder
from poc_text import sentences


def status_mb(field):
    for line in open("/proc/self/status"):
        if line.startswith(field + ":"):
            return round(int(line.split()[1]) / 1024, 1)
    return None


def percentiles(values):
    ordered = sorted(values)

    def at(p):
        return round(ordered[min(len(ordered) - 1, int(round(p / 100 * (len(ordered) - 1))))], 2)
    return {"p50": at(50), "p95": at(95), "p99": at(99), "max": round(ordered[-1], 2), "n": len(ordered)}


def load_emails(path, count, rng):
    rows = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
    return [(r.get("subject"), r.get("body") or "") for r in rng.sample(rows, min(count, len(rows)))]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models-root", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--variant", default="int8")
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--emails", action="append", required=True)
    parser.add_argument("--samples", type=int, default=400)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    rng = random.Random(20261110)

    rss_start = status_mb("VmRSS")
    started = time.perf_counter()
    encoder = Encoder(args.models_root, args.model, args.variant, args.threads)
    load_ms = (time.perf_counter() - started) * 1000
    started = time.perf_counter()
    encoder.encode(["warm-up sentence for the first inference"])
    first_ms = (time.perf_counter() - started) * 1000
    rss_loaded = status_mb("VmRSS")

    emails = []
    for path in args.emails:
        emails += load_emails(path, args.samples, rng)
    pool = [unit for subject, body in emails for unit in sentences(subject, body)[0]]

    batches = {}
    for n, runs in ((1, 300), (8, 200), (32, 100)):
        timings = []
        for _ in range(runs):
            batch = rng.sample(pool, n)
            t = time.perf_counter()
            encoder.encode(batch)
            timings.append((time.perf_counter() - t) * 1000)
        batches[str(n)] = percentiles(timings)

    per_email, sentence_counts, token_counts = [], [], []
    for subject, body in emails:
        t = time.perf_counter()
        units, _ = sentences(subject, body)
        encoder.encode(units)
        per_email.append((time.perf_counter() - t) * 1000)
        sentence_counts.append(len(units))
        token_counts.append(sum(encoder.token_counts(units)) if units else 0)

    def one(item):
        units, _ = sentences(*item)
        encoder.encode(units)
    t = time.perf_counter()
    with ThreadPoolExecutor(max_workers=4) as pool_exec:
        list(pool_exec.map(one, emails))
    concurrent_eps = len(emails) / (time.perf_counter() - t)

    report = {
        "model": args.model, "variant": args.variant, "intra_op_threads": args.threads,
        "cold_start_ms": {"session_load": round(load_ms, 1), "first_inference": round(first_ms, 1)},
        "batch_latency_ms": batches,
        "per_email_latency_ms": percentiles(per_email),
        "per_email_sentences": percentiles(sentence_counts),
        "per_email_tokens": percentiles(token_counts),
        "throughput_4_callers_emails_per_s": round(concurrent_eps, 1),
        "rss_mb": {"start": rss_start, "loaded": rss_loaded, "end": status_mb("VmRSS"),
                   "peak": status_mb("VmHWM")},
    }
    with open(args.output, "w") as stream:
        json.dump(report, stream, indent=1)
    print(json.dumps(report))


if __name__ == "__main__":
    main()
