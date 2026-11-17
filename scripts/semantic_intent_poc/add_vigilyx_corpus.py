#!/usr/bin/env python3
"""Add the VIGILYX-Training-Data corpus to a k-fold experiment (runs on 77).

Input is render_records.py JSON output (`--history both`). The text is the
current email's subject and body, including the quoted chain the renderer adds
to replies: that is what the engine sees. business_context, the history array,
target and provenance never reach the text. Cleaning is prepare_ft_data.clean(),
so the corpus is preprocessed like the frozen split.

Identity: people and most organisations are canonical tokens that the renderer
fills with fictional names chosen without reading the label. Real institutions
(provenance.entities and `render.orgs` of kind real, read from --corpus) stay
verbatim: the model has to tell genuine mail from impersonation by what the
mail asks for, not by which institution it names. --org-report lists every real
institution in the text with its label counts; one that appears under a single
label teaches nothing about telling its genuine mail from fakes.

Unlike the train-only supplements, corpus records take part in the folds.
thread_family_id, pair_id, source_group and template_family_id are joined
(union-find), together with exact duplicate texts, so a pair, its paraphrases
and records derived from one source always share a fold. Each group gets a
test fold and inner-dev flag from kfold_assign.bucket(). The base assignment is
copied unchanged, so existing records keep their folds.

Writes --output/{train,dev,test}.jsonl (base files, with corpus rows appended
to train; build_kfold.py pools all three), --assign-out, and --types-out (base
notice types plus corpus id -> "vtd:<domain>" for the per-type report).

With --rows-out only the corpus rows are written, for the counterfactual check:
render with another seed and `--name-pool heldout` (people the training text
never named) and pass --swap-real-orgs SALT to replace every real institution
by another real institution of the same type from the corpus (bank for bank),
chosen by a hash of SALT, thread_family_id and the name, never by the label.
Fold models then score these rows; a decision that flips was driven by names.
"""

import argparse
import collections
import hashlib
import json
from pathlib import Path
import re

from kfold_assign import bucket
from prepare_ft_data import clean

LABELS = {"malicious": 1, "benign": 0}
GROUP_FIELDS = ("thread_family_id", "pair_id", "source_group", "template_family_id")
# Institution type for the counterfactual swap: longest matching suffix, else script.
ZH_SUFFIXES = sorted((
    "股份有限公司", "有限责任公司", "有限公司", "分公司", "集团", "银行", "商城", "大学", "学院", "研究生院",
    "中心", "平台", "工会", "学报", "论坛", "支付", "邮箱", "部", "处", "局"), key=len, reverse=True)
CJK = re.compile("[一-鿿]")


def real_names(canonical):
    names = {e["name"] for e in (canonical.get("provenance") or {}).get("entities") or []
             if isinstance(e, dict) and isinstance(e.get("name"), str)}
    orgs = (canonical.get("render") or {}).get("orgs") or {}
    names |= {o["name"] for o in orgs.values() if isinstance(o, dict) and o.get("kind") == "real"
              and isinstance(o.get("name"), str)}
    return sorted((n for n in names if len(n.strip()) >= 2), key=len, reverse=True)


def org_type(name):
    if not CJK.search(name):
        return "latin"
    core = name.strip("《》")
    return next((suffix for suffix in ZH_SUFFIXES if core.endswith(suffix) and len(core) > len(suffix)), "zh")


def corpus_rows(rendered, canonical, swap_salt=None):
    """Return (rows, {real name: [malicious, benign]} over names present in the text)."""
    by_id = {record["id"]: record for record in canonical}
    seen = collections.defaultdict(lambda: [0, 0])
    texts = []
    for record in rendered:
        source = by_id[record.get("rendering", {}).get("source_id") or record["id"]]
        email = record["input"]["current_email"]
        subject, body = email.get("subject") or "", email.get("body") or ""
        present = [n for n in real_names(source) if n in subject or n in body]
        for name in present:
            seen[name][0 if source["target"]["label"] == "malicious" else 1] += 1
        texts.append((record, source, subject, body, present))
    pool = collections.defaultdict(list)
    for name in sorted(seen):
        pool[org_type(name)].append(name)
    rows = []
    for record, source, subject, body, present in texts:
        if swap_salt is not None:
            # Two passes through placeholders, so a swap never feeds another (A->B, B->C).
            marks = {}
            for i, name in enumerate(present):
                others = [n for n in pool[org_type(name)] if n != name and name not in n and n not in name]
                if not others:
                    continue
                digest = int(hashlib.sha256(("%s\x1f%s\x1f%s" % (swap_salt, record["thread_family_id"], name))
                                            .encode()).hexdigest()[:12], 16)
                mark = "\x00%d\x00" % i
                marks[mark] = others[digest % len(others)]
                subject, body = subject.replace(name, mark), body.replace(name, mark)
            for mark, replacement in marks.items():
                subject, body = subject.replace(mark, replacement), body.replace(mark, replacement)
        rows.append({"id": "vtd:" + source["id"],
                     "text": (clean(subject, False) + "\n" + clean(body, False)).strip(),
                     "label": LABELS[source["target"]["label"]],
                     "group": "VIGILYX-Corpus/" + source["language"]})
    if len({row["id"] for row in rows}) != len(rows):
        raise SystemExit("duplicate corpus ids")
    return rows, seen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rendered", required=True, type=Path, help="render_records.py --history both output")
    parser.add_argument("--corpus", required=True, type=Path, help="canonical corpus.json (real institution names)")
    parser.add_argument("--org-report", type=Path, help="write real institutions in the text with label counts")
    parser.add_argument("--rows-out", type=Path, help="write corpus rows only (counterfactual rendering)")
    parser.add_argument("--swap-real-orgs", metavar="SALT", help="with --rows-out: swap real institutions by type")
    parser.add_argument("--base-data", type=Path, help="prepare_ft_data.py train output")
    parser.add_argument("--base-assign", type=Path, help="kfold_assign.py output")
    parser.add_argument("--base-types", type=Path, help="notice_types.json of the base experiment")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--assign-out", type=Path)
    parser.add_argument("--types-out", type=Path)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", default="vigilyx-semantic-kfold-v1")
    args = parser.parse_args()
    if args.swap_real_orgs is not None and not args.rows_out:
        parser.error("--swap-real-orgs is for the counterfactual rows only; training text keeps real names")
    rendered = json.loads(args.rendered.read_text(encoding="utf-8"))
    canonical = json.loads(args.corpus.read_text(encoding="utf-8"))
    rows, seen = corpus_rows(rendered, canonical, args.swap_real_orgs)
    summary = {"corpus_rows": len(rows), "real_institutions_in_text": len(seen),
               "single_label_institutions": sum(1 for m, b in seen.values() if not (m and b))}
    if args.org_report:
        report = {name: {"malicious": m, "benign": b, "type": org_type(name)}
                  for name, (m, b) in sorted(seen.items(), key=lambda kv: -sum(kv[1]))}
        args.org_report.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    if args.rows_out:
        with open(args.rows_out, "x", encoding="utf-8") as out:
            for row in rows:
                out.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(json.dumps(summary, ensure_ascii=False))
        return
    if not all((args.base_data, args.base_assign, args.output, args.assign_out, args.types_out)):
        parser.error("--base-data, --base-assign, --output, --assign-out and --types-out are required")
    assignment = json.loads(args.base_assign.read_text(encoding="utf-8"))
    types = json.loads(args.base_types.read_text(encoding="utf-8")) if args.base_types else {}
    collisions = [row["id"] for row in rows if row["id"] in assignment]
    if collisions:
        raise SystemExit("corpus ids collide with the base assignment: %s" % collisions[:5])

    parent = {}

    def find(key):
        parent.setdefault(key, key)
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    for record, row in zip(rendered, rows):
        keys = ["%s:%s" % (field, record[field]) for field in GROUP_FIELDS if record.get(field)]
        keys.append("text:" + row["text"])
        for key in keys[1:]:
            parent[find(key)] = find(keys[0])
    representative = {}
    for key in list(parent):
        root = find(key)
        representative[root] = min(representative.get(root, key), key)

    counts = collections.Counter()
    labels_by_group = collections.defaultdict(set)
    for record, row in zip(rendered, rows):
        group = "vtd:" + representative[find("%s:%s" % (GROUP_FIELDS[0], record[GROUP_FIELDS[0]]))]
        fold = bucket(args.seed, "fold", group, args.folds)
        inner_dev = int(bucket(args.seed, "dev", group, 8) == 0)
        assignment[row["id"]] = [fold, inner_dev]
        types[row["id"]] = "vtd:" + record["domain"]
        labels_by_group[group].add(row["label"])
        counts["fold%d/%s" % (fold, "malicious" if row["label"] else "benign")] += 1
        counts["inner_dev"] += inner_dev

    args.output.mkdir(parents=True)
    for name in ("train", "dev", "test"):
        with open(args.output / f"{name}.jsonl", "x", encoding="utf-8") as out:
            out.write((args.base_data / f"{name}.jsonl").read_text(encoding="utf-8"))
            if name == "train":
                for row in rows:
                    out.write(json.dumps(row, ensure_ascii=False) + "\n")
    args.assign_out.write_text(json.dumps(assignment), encoding="utf-8")
    args.types_out.write_text(json.dumps(types, ensure_ascii=False), encoding="utf-8")
    sizes = collections.Counter(len(v) for v in labels_by_group.values())
    summary.update({"groups": len(labels_by_group), "mixed_label_groups": sizes.get(2, 0),
                    "counts": dict(sorted(counts.items()))})
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
