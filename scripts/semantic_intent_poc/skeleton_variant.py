#!/usr/bin/env python3
"""Skeleton-gated variant: the Rust semantic skeleton supplies the units.

Units are the claim spans emitted by the deployed semantic_scan (baseline
replay, `details.semantic_context.claims`). The encoder scores each claim
against the intent prototypes; the skeleton decides whether the claim counts
as a current request from the sender to the recipient. Gate rules are fixed
by design, not fitted:

* request-like: speech_act request/instruction, target recipient, or the
  recipient request frame provenance;
* original: not quoted or forwarded.

Thresholds come from the dev split only (same rules as evaluate.py). The
red-team corpus is evaluation-only.
"""

import argparse
import json
from pathlib import Path

import numpy as np

from evaluate import Features, auc, labels_of, prototypes, seg_reduce, summarize, threshold
from poc_encoder import Encoder
from poc_text import SPACE, WORD, normalize

SETS = {"dev": "split/dev.jsonl", "test": "split/test.jsonl", "redteam": "redteam.jsonl", "demo": "demo.jsonl"}
REQUEST_FRAMES = {"semantic_recipient_request_frame_v1", "semantic_request_list_frame_v1",
                  "semantic_construction_modal_request_v1", "semantic_construction_recipient_directive_v1"}
MAX_CLAIMS, HEAD, TAIL = 48, 36, 12


def claims_for(case, row):
    ctx = (row.get("details") or {}).get("semantic_context")
    claims = ctx.get("claims", []) if isinstance(ctx, dict) else []
    sources = {"plain_text": (case.get("body") or "").encode(), "header": (case.get("subject") or "").encode()}
    units, seen = [], set()
    for claim in claims:
        source = sources.get(claim.get("source_part"))
        span = claim.get("span") or {}
        if source is None or span.get("end_byte") is None:
            continue
        text = SPACE.sub(" ", normalize(source[span["start_byte"]:span["end_byte"]].decode("utf-8", "replace"))).strip()
        if len(WORD.findall(text)) < 4 or text in seen:
            continue
        seen.add(text)
        request = (claim.get("speech_act") in ("request", "instruction") or claim.get("target_role") == "recipient"
                   or claim.get("action_destination") == "recipient"
                   or bool(REQUEST_FRAMES.intersection(claim.get("provenance", []))))
        original = claim.get("quote_or_forward_status", "original") == "original"
        units.append((text, request and original))
    if len(units) > MAX_CLAIMS:
        units = units[:HEAD] + units[-TAIL:]
    return units


def build(root, baseline, encoder, name):
    cases = {}
    for line in open(root / "data" / SETS[name], encoding="utf-8"):
        if line.strip():
            case = json.loads(line)
            cases[case["content_id"]] = case
    meta, texts, gates, offsets = [], [], [], [0]
    for line in open(baseline / name / "results.jsonl", encoding="utf-8"):
        row = json.loads(line)
        case = cases[row["content_id"]]
        units = claims_for(case, row)
        source = case["sources"][0]
        meta.append({"content_id": case["content_id"], "label": source["label"],
                     "dataset": source.get("dataset", ""), "language": source.get("language", ""),
                     "data_type": source.get("data_type", ""),
                     "category": source.get("category") or source.get("notice_type", ""),
                     "synthetic": "notice_type" in source, "n_claims": len(units),
                     "n_request": sum(g for _, g in units)})
        texts += [t for t, _ in units]
        gates += [g for _, g in units]
        offsets.append(len(texts))
    emb = encoder.encode(texts) if texts else np.zeros((0, 1), np.float32)
    return {"emb": emb, "offsets": np.asarray(offsets), "meta": meta,
            "gate": np.asarray(gates, dtype=np.float32), "texts": texts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--models-root", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--variant", default="int8")
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--intents", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    encoder = Encoder(args.models_root, args.model, args.variant, args.threads)
    rows, vectors = prototypes(json.load(open(args.intents, encoding="utf-8")), encoder)
    feats = Features(rows, vectors)
    sets = {name: build(args.root, args.baseline, encoder, name) for name in SETS}
    scores = {name: {} for name in SETS}
    for name, data in sets.items():
        groups = feats.sentence_groups(data["emb"])
        margin = groups["core"].max(1) - groups["benign"].max(1)
        offsets = data["offsets"]
        scores[name]["claim_margin"] = seg_reduce(margin, offsets, np.maximum, -1.0)
        for penalty in (0.05, 0.10):
            gated = margin - penalty * (1.0 - data["gate"])
            scores[name][f"claim_gated_soft{int(penalty * 100):02d}"] = seg_reduce(gated, offsets, np.maximum, -1.0)
        hard = np.where(data["gate"] > 0, margin, -1.0).astype(np.float32)
        scores[name]["claim_gated_hard"] = seg_reduce(hard, offsets, np.maximum, -1.0)
        data["margin"], data["core"] = margin, groups["core"]

    dev_y = labels_of(sets["dev"])
    report = {"model": args.model, "variant": args.variant, "methods": {}}
    print(f"model={args.model} claims: " + ", ".join(f"{n}={len(d['texts'])}" for n, d in sets.items()))
    print(f"{'method':22} {'op':5} {'dev R/F':>13} {'test R/F':>13} {'redteam R/F':>13} {'AUC dev/test/red':>20} demo")
    for method in scores["dev"]:
        entry = {"auc": {n: auc(scores[n][method], labels_of(sets[n])) for n in ("dev", "test", "redteam")}}
        for op, fpr in (("fpr1", 0.01), ("fpr3", 0.03)):
            tau = threshold(scores["dev"][method], dev_y, fpr)
            entry[op] = {"threshold": tau, **{n: summarize(scores[n][method], sets[n], n, tau) for n in ("dev", "test", "redteam")},
                         "demo": [bool(s > tau) for s in scores["demo"][method]]}
            cells = [f"{100 * entry[op][n]['recall']:5.1f}/{100 * entry[op][n]['fpr']:5.1f}" for n in ("dev", "test", "redteam")]
            a = entry["auc"]
            print(f"{method:22} {op:5} {cells[0]:>13} {cells[1]:>13} {cells[2]:>13} "
                  f"{a['dev']:.3f}/{a['test']:.3f}/{a['redteam']:.3f} {''.join('X' if f else '.' for f in entry[op]['demo'])}")
        report["methods"][method] = entry
    with open(args.output / "metrics.json", "w", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=1)
    np.savez(args.output / "scores.npz", **{f"{n}__{m}": v for n, d in scores.items() for m, v in d.items()})


if __name__ == "__main__":
    main()
