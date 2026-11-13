#!/usr/bin/env python3
"""Evaluate intent-model PoC variants on the frozen split, red team and demo.

Rules fixed before looking at results:
* Thresholds are chosen on the dev split only (benign FPR <= 1%, and a 3%
  operating point), then applied unchanged to test, red team and demo.
* Models are fitted on the hand-written prototypes or the train split only.
  The red-team corpus is evaluation-only: never fitted on, never used to pick
  thresholds or hyper-parameters.
* Commercial spam is neither positive nor benign; its flag rate is reported.
"""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression

from poc_encoder import Encoder
from poc_text import SPACE, normalize

EVAL_SETS = ("dev", "test", "redteam", "demo")


def load_set(emb_dir, name, with_sentences=False):
    data = {
        "emb": np.load(emb_dir / f"{name}.emb.npy").astype(np.float32),
        "offsets": np.load(emb_dir / f"{name}.offsets.npy"),
        "meta": [json.loads(line) for line in open(emb_dir / f"{name}.meta.jsonl", encoding="utf-8")],
    }
    if with_sentences:
        data["sents"] = [json.loads(line) for line in open(emb_dir / f"{name}.sents.jsonl", encoding="utf-8")]
    return data


def seg_reduce(values, offsets, ufunc, empty):
    lengths = np.diff(offsets)
    out = np.full((len(lengths),) + values.shape[1:], empty, dtype=np.float32)
    nonempty = lengths > 0
    if values.shape[0] and nonempty.any():
        out[nonempty] = ufunc.reduceat(values, offsets[:-1][nonempty], axis=0)
    return out


def seg_mean(values, offsets):
    lengths = np.diff(offsets).astype(np.float32)
    sums = seg_reduce(values, offsets, np.add, 0.0)
    shape = (-1,) + (1,) * (values.ndim - 1)
    return sums / np.maximum(lengths, 1).reshape(shape)


def prototypes(intents, encoder):
    rows = []
    for kind in ("core", "modifier", "benign"):
        for group, spec in intents[kind].items():
            for lang in ("zh", "en"):
                for text in spec.get(lang, []):
                    rows.append((kind, group, lang, SPACE.sub(" ", normalize(text)).strip()))
    vectors = encoder.encode([row[3] for row in rows])
    return rows, vectors


class Features:
    """Per-sentence group similarities and the derived email-level features."""

    def __init__(self, rows, vectors):
        self.vectors = vectors
        self.groups = {kind: sorted({r[1] for r in rows if r[0] == kind}) for kind in ("core", "modifier", "benign")}
        self.columns = {
            (kind, group): np.array([i for i, r in enumerate(rows) if r[0] == kind and r[1] == group])
            for kind in self.groups for group in self.groups[kind]
        }

    def sentence_groups(self, emb):
        out = {kind: np.zeros((emb.shape[0], len(groups)), np.float32) for kind, groups in self.groups.items()}
        for start in range(0, emb.shape[0], 65536):
            sims = emb[start:start + 65536] @ self.vectors.T
            for kind, groups in self.groups.items():
                for j, group in enumerate(groups):
                    out[kind][start:start + 65536, j] = sims[:, self.columns[(kind, group)]].max(1)
        return out

    def compute(self, data):
        groups = self.sentence_groups(data["emb"])
        margin = groups["core"].max(1) - groups["benign"].max(1)
        offsets = data["offsets"]
        email = {
            "core": seg_reduce(groups["core"], offsets, np.maximum, 0.0),
            "core_margin": seg_reduce(groups["core"] - groups["benign"].max(1)[:, None], offsets, np.maximum, -1.0),
            "modifier": seg_reduce(groups["modifier"], offsets, np.maximum, 0.0),
            "benign": seg_reduce(groups["benign"], offsets, np.maximum, 0.0),
            "margin": seg_reduce(margin, offsets, np.maximum, -1.0),
            "core_max": seg_reduce(groups["core"].max(1), offsets, np.maximum, -1.0),
            "margin_pos": seg_mean((margin > 0).astype(np.float32), offsets),
        }
        # Mean of the top-3 sentence margins (fewer sentences: mean of what exists).
        top3 = np.full(len(offsets) - 1, -1.0, np.float32)
        for i in range(len(offsets) - 1):
            part = margin[offsets[i]:offsets[i + 1]]
            if part.size:
                top3[i] = np.sort(part)[-3:].mean()
        email["margin_top3"] = top3
        data["sentence_groups"], data["sentence_margin"], data["email"] = groups, margin, email
        return data

    def hybrid_matrix(self, data):
        e = data["email"]
        return np.hstack([e["core"], e["modifier"], e["benign"], e["margin"][:, None],
                          e["margin_top3"][:, None], e["margin_pos"][:, None]])


def labels_of(data):
    return np.array([m["label"] for m in data["meta"]])


def auc(scores, labels):
    pos, neg = scores[labels == "malicious"], scores[labels == "benign"]
    if not len(pos) or not len(neg):
        return None
    both = np.concatenate([pos, neg])
    order = both.argsort(kind="mergesort")
    ranks = np.empty(len(both))
    ranks[order] = np.arange(1, len(both) + 1)
    # Average ranks for ties.
    sorted_vals = both[order]
    i = 0
    while i < len(sorted_vals):
        j = i
        while j + 1 < len(sorted_vals) and sorted_vals[j + 1] == sorted_vals[i]:
            j += 1
        if j > i:
            ranks[order[i:j + 1]] = (i + j + 2) / 2.0
        i = j + 1
    return float((ranks[:len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def threshold(dev_scores, dev_labels, fpr):
    # Flag when score > threshold; at most floor(n * fpr) dev benign rows exceed it.
    benign = np.sort(dev_scores[dev_labels == "benign"])
    k = int(np.ceil(len(benign) * (1 - fpr)))
    return float(benign[max(k - 1, 0)])


def group_key(meta, set_name):
    if set_name == "redteam":
        return meta["category"]
    if meta["synthetic"]:
        return f"synthetic/{meta['language']}"
    return f"{meta['dataset']}/{meta['language']}/{meta['data_type']}"


def summarize(scores, data, set_name, tau):
    labels = labels_of(data)
    flagged = scores > tau
    out = {"n_malicious": int((labels == "malicious").sum()), "n_benign": int((labels == "benign").sum())}
    mal, ben = labels == "malicious", labels == "benign"
    out["recall"] = float(flagged[mal].mean()) if mal.any() else None
    out["fpr"] = float(flagged[ben].mean()) if ben.any() else None
    spam = labels == "spam"
    if spam.any():
        out["spam_flag_rate"] = float(flagged[spam].mean())
    groups = defaultdict(lambda: [0, 0])
    for meta, flag in zip(data["meta"], flagged):
        key = f"{meta['label']}|{group_key(meta, set_name)}"
        groups[key][0] += 1
        groups[key][1] += int(flag)
    out["groups"] = {k: {"n": v[0], "flagged": v[1], "rate": round(v[1] / v[0], 4)} for k, v in sorted(groups.items())}
    if set_name == "redteam":
        lang = defaultdict(lambda: [0, 0])
        for meta, flag in zip(data["meta"], flagged):
            lang[f"{meta['label']}|{meta['language']}"][0] += 1
            lang[f"{meta['label']}|{meta['language']}"][1] += int(flag)
        out["by_language"] = {k: {"n": v[0], "rate": round(v[1] / v[0], 4)} for k, v in sorted(lang.items())}
    return out


def calibrated(per_intent, dev_per_intent, dev_labels, quantile=0.995):
    """Per-intent calibration on dev benign rows: max_i (x_i - q_i) / sd_i."""
    benign = dev_per_intent[dev_labels == "benign"]
    q = np.quantile(benign, quantile, axis=0)
    sd = benign.std(0) + 1e-6
    return ((per_intent - q) / sd).max(1)


def center(sets, train, vectors):
    mean = train["emb"].mean(0)
    def fix(x):
        x = x - mean
        return x / np.maximum(np.linalg.norm(x, axis=1, keepdims=True), 1e-12)
    for data in list(sets.values()) + [train]:
        data["emb"] = fix(data["emb"]).astype(np.float32)
    return fix(vectors).astype(np.float32)


def fit_lr(x, y, dev_x, dev_y, cs=(0.03, 0.1, 0.3, 1.0, 3.0)):
    mean, std = x.mean(0), x.std(0) + 1e-6
    best = None
    for c in cs:
        model = LogisticRegression(C=c, class_weight="balanced", max_iter=3000)
        model.fit((x - mean) / std, y)
        score = model.decision_function((dev_x - mean) / std)
        value = auc(score, dev_y)
        if best is None or value > best[0]:
            best = (value, c, model)
    _, c, model = best
    return (lambda z: model.decision_function((z - mean) / std)), c


def explain(data, i, feats):
    start, end = data["offsets"][i], data["offsets"][i + 1]
    if start == end:
        return None
    margin = data["sentence_margin"][start:end]
    k = int(margin.argmax())
    core = data["sentence_groups"]["core"][start + k]
    benign = data["sentence_groups"]["benign"][start + k]
    return {
        "sentence_index": k, "sentence": data["sents"][i][k][:160],
        "top_intent": feats.groups["core"][int(core.argmax())], "intent_sim": round(float(core.max()), 3),
        "top_benign": feats.groups["benign"][int(benign.argmax())], "benign_sim": round(float(benign.max()), 3),
        "margin": round(float(margin[k]), 3),
    }


def baseline_scores(baseline_dir, name, data):
    path = baseline_dir / name / "results.jsonl"
    if not path.exists():
        return None
    rows = {}
    for line in open(path, encoding="utf-8"):
        row = json.loads(line)
        rows[row.get("content_id")] = row
    rule, clf, missing = [], [], 0
    for meta in data["meta"]:
        row = rows.get(meta["content_id"])
        if row is None:
            missing += 1
            rule.append(0.0)
            clf.append(0.0)
            continue
        rule.append(1.0 if row.get("threat_level") not in (None, "safe") else 0.0)
        classifier = (row.get("details") or {}).get("semantic_text_classifier") or {}
        clf.append(1.0 if classifier.get("fired") is True else 0.0)
    return {"rules": np.array(rule), "shadow_classifier": np.array(clf), "missing": missing}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models-root", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--variant", default="int8")
    parser.add_argument("--emb-dir", required=True, type=Path)
    parser.add_argument("--intents", required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--center", action="store_true", help="subtract the train-split mean vector")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    encoder = Encoder(args.models_root, args.model, args.variant, threads=4)
    intents = json.load(open(args.intents, encoding="utf-8"))
    rows, vectors = prototypes(intents, encoder)
    sets = {name: load_set(args.emb_dir, name, with_sentences=name in ("redteam", "demo")) for name in EVAL_SETS}
    train = load_set(args.emb_dir, "train")
    if args.center:
        vectors = center(sets, train, vectors)
    feats = Features(rows, vectors)
    sets = {name: feats.compute(data) for name, data in sets.items()}
    train = feats.compute(train)
    train_y = labels_of(train)
    keep = train_y != "spam"

    scores = {name: {} for name in EVAL_SETS}
    notes = {}
    for name, data in sets.items():
        scores[name]["proto_core"] = data["email"]["core_max"]
        scores[name]["proto_margin"] = data["email"]["margin"]

    # Few-shot head on the prototypes only (SetFit step 2 with a frozen encoder).
    proto_y = np.array([1 if r[0] == "core" else 0 for r in rows])
    proto_keep = np.array([r[0] != "modifier" for r in rows])
    head = LogisticRegression(C=1.0, class_weight="balanced", max_iter=3000)
    head.fit(vectors[proto_keep], proto_y[proto_keep])
    for name, data in sets.items():
        sentence_score = head.decision_function(data["emb"]) if data["emb"].shape[0] else np.zeros(0)
        scores[name]["fewshot_head"] = seg_reduce(sentence_score.astype(np.float32), data["offsets"], np.maximum, -1e3)

    dev_y = labels_of(sets["dev"])
    dev_keep = dev_y != "spam"

    # Per-intent calibration on dev benign rows (plan section 3: per-intent thresholds).
    for name, data in sets.items():
        scores[name]["proto_calibrated"] = calibrated(data["email"]["core"], sets["dev"]["email"]["core"], dev_y)
        scores[name]["proto_calibrated_margin"] = calibrated(
            data["email"]["core_margin"], sets["dev"]["email"]["core_margin"], dev_y)

    # Email-level logistic regression on pooled sentence vectors (train split).
    def pooled(data):
        return np.hstack([seg_reduce(data["emb"], data["offsets"], np.maximum, 0.0), seg_mean(data["emb"], data["offsets"])])
    predict, c = fit_lr(pooled(train)[keep], train_y[keep] == "malicious", pooled(sets["dev"])[dev_keep], dev_y[dev_keep])
    notes["corpus_lr_pooled_C"] = c
    for name, data in sets.items():
        scores[name]["corpus_lr_pooled"] = predict(pooled(data)).astype(np.float32)

    # Email-level logistic regression on low-dimensional intent similarities (train split).
    predict, c = fit_lr(feats.hybrid_matrix(train)[keep], train_y[keep] == "malicious",
                        feats.hybrid_matrix(sets["dev"])[dev_keep], dev_y[dev_keep])
    notes["intent_lr_C"] = c
    for name, data in sets.items():
        scores[name]["intent_lr"] = predict(feats.hybrid_matrix(data)).astype(np.float32)

    report = {"model": args.model, "variant": args.variant, "prototypes": len(rows),
              "intent_version": intents["version"], "notes": notes, "methods": {}}
    for method in scores["dev"]:
        entry = {}
        for fpr_name, fpr in (("fpr1", 0.01), ("fpr3", 0.03)):
            tau = threshold(scores["dev"][method][dev_keep], dev_y[dev_keep], fpr)
            entry[fpr_name] = {"threshold": tau}
            for name in ("dev", "test", "redteam"):
                entry[fpr_name][name] = summarize(scores[name][method], sets[name], name, tau)
            entry[fpr_name]["demo"] = [
                {"id": m["content_id"], "score": round(float(s), 4), "flagged": bool(s > tau)}
                for m, s in zip(sets["demo"]["meta"], scores["demo"][method])]
        entry["auc"] = {name: auc(scores[name][method], labels_of(sets[name])) for name in ("dev", "test", "redteam")}
        report["methods"][method] = entry

    if args.baseline:
        report["baseline"] = {}
        for name in ("test", "redteam", "demo"):
            base = baseline_scores(args.baseline, name, sets[name])
            if base is None:
                continue
            report["baseline"][name] = {"missing": base["missing"]}
            for which in ("rules", "shadow_classifier"):
                report["baseline"][name][which] = summarize(base[which], sets[name], name, 0.5) if name != "demo" else \
                    [{"id": m["content_id"], "flagged": bool(s > 0.5)} for m, s in zip(sets[name]["meta"], base[which])]

    report["demo_explanations"] = [
        {"id": m["content_id"], **(explain(sets["demo"], i, feats) or {})} for i, m in enumerate(sets["demo"]["meta"])]
    # Diagnostics for the zero-training margin at the dev 1% threshold.
    tau = report["methods"]["proto_margin"]["fpr1"]["threshold"]
    red = sets["redteam"]
    drivers = Counter()
    with open(args.output / "redteam_margin_flags.jsonl", "w", encoding="utf-8") as stream:
        for i, meta in enumerate(red["meta"]):
            if scores["redteam"]["proto_margin"][i] > tau:
                info = explain(red, i, feats)
                drivers[(meta["label"], info["top_intent"])] += 1
                stream.write(json.dumps({"label": meta["label"], "category": meta["category"], **info},
                                        ensure_ascii=False) + "\n")
    report["redteam_margin_drivers"] = {f"{k[0]}|{k[1]}": v for k, v in sorted(drivers.items())}
    with open(args.output / "metrics.json", "w", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=1)
    np.savez(args.output / "scores.npz", **{f"{name}__{method}": values
                                            for name, by_method in scores.items()
                                            for method, values in by_method.items()})

    print(f"model={args.model} variant={args.variant} prototypes={len(rows)} notes={notes}")
    header = f"{'method':18} {'op':5} {'dev R/F':>13} {'test R/F':>13} {'redteam R/F':>13} {'AUC dev/test/red':>20} demo(A,B,C)"
    print(header)
    for method, entry in report["methods"].items():
        for op in ("fpr1", "fpr3"):
            e = entry[op]
            cells = [f"{100 * e[n]['recall']:5.1f}/{100 * e[n]['fpr']:5.1f}" for n in ("dev", "test", "redteam")]
            a = entry["auc"]
            demo = "".join("X" if d["flagged"] else "." for d in e["demo"])
            print(f"{method:18} {op:5} {cells[0]:>13} {cells[1]:>13} {cells[2]:>13} "
                  f"{a['dev']:.3f}/{a['test']:.3f}/{a['redteam']:.3f} {demo}")
    for name, base in report.get("baseline", {}).items():
        if name == "demo":
            print("baseline demo", {k: "".join("X" if d["flagged"] else "." for d in v) for k, v in base.items() if k != "missing"})
            continue
        for which in ("rules", "shadow_classifier"):
            b = base[which]
            print(f"baseline {name:8} {which:18} recall={100 * b['recall']:.1f}% fpr={100 * b['fpr']:.1f}% missing={base['missing']}")


if __name__ == "__main__":
    main()
