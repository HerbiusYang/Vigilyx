#!/usr/bin/env python3
"""Split the frozen E-PhishLLM + Fraud-R1 corpus for the semantic text classifier.

Input is the output directory of prepare_semantic_corpora.py. The split is a
deterministic hash of a seed-level group, so every Fraud-R1 record id (all
rounds, raw and generated text, Chinese and English translations) and every
exact-duplicate content lands on one side only.

* By default Chinese texts are test-only: they are never written to train or
  dev, and the Chinese rows of train/dev groups are dropped so a translation
  of a training seed cannot be scored as unseen. With `--chinese grouped`
  they follow their group like every other language; the test split is the
  same either way.
* `--synthetic` adds the output of generate_semantic_synthetic_benign.py.
  A synthetic group is one notice type in one language, so dev and test hold
  notice types the model never saw.
* Commercial spam is neither a positive nor a benign control; by default it
  is kept in test for reporting only. With `--spam by-round` it is labelled
  per Fraud-R1 round and follows its group: the raw brand marketing text, its
  polished rewrite (`generated`) and `round2` (marketing pressure, no account
  threat) are benign; `round3`/`round4` add account threats, penalties and
  lockouts and are malicious. Each record then gives a marketing/fraud pair.
* Generator placeholders are removed from every split so the model cannot
  learn them: `<<link>>`-style markers occur only in malicious E-PhishLLM
  rows, and capitalized bracket slots such as `[Agent]` or `[Your Name]`
  mark Fraud-R1 dialogues, which have no benign counterpart.

Output records keep the semantic_external_harness schema. Python 3.9 compatible.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

PLACEHOLDER = re.compile(r"<<[^<>\n]{1,64}>>|\[[A-Z][^\[\]\n]{0,40}\]")
CHINESE = {"Chinese", "zh-cn", "zh"}
SPLITS = (("train", 70), ("dev", 80), ("test", 100))
SPAM_BENIGN_ROUNDS = {"raw", "generated", "round2"}


def digest(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def group_key(source):
    if "notice_type" in source:
        return "synthetic:%s" % source["notice_type"]
    if source["dataset"] == "Fraud-R1":
        return "fraud:%s" % source["record_id"]
    return "ephish:%d" % source["record_index"]


def relabel_spam(sources):
    """Fraud-R1 commercial spam labelled by round (`--spam by-round`)."""
    return [dict(source, label="benign" if source.get("variant") in SPAM_BENIGN_ROUNDS else "malicious")
            if source["label"] == "spam" else source for source in sources]


def split_for(seed, group):
    bucket = int(digest(("%s\x1f%s" % (seed, group)).encode())[:8], 16) % 100
    return next(name for name, upper in SPLITS if bucket < upper)


def prepare(corpus, output, seed, chinese_policy, synthetic, spam_policy="test-only"):
    manifest = json.loads((corpus / "manifest.json").read_text())
    cases_path = corpus / "cases.jsonl"
    if digest(cases_path.read_bytes()) != manifest["corpus_sha256"]:
        raise ValueError("prepared corpus no longer matches its manifest")
    cases = [json.loads(line) for line in cases_path.open() if line.strip()]
    synthetic_sha256 = None
    if synthetic is not None:
        synthetic_manifest = json.loads((synthetic / "manifest.json").read_text())
        synthetic_path = synthetic / "cases.jsonl"
        synthetic_sha256 = digest(synthetic_path.read_bytes())
        if synthetic_sha256 != synthetic_manifest["cases_sha256"]:
            raise ValueError("synthetic corpus no longer matches its manifest")
        known = {case["content_id"] for case in cases}
        extra = [json.loads(line) for line in synthetic_path.open() if line.strip()]
        if any(case["content_id"] in known for case in extra):
            raise ValueError("synthetic content collides with the research corpus")
        cases += extra

    # Union-find: an exact-duplicate content joins all of its source groups.
    parent = {}

    def find(key):
        parent.setdefault(key, key)
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    for case in cases:
        keys = [group_key(source) for source in case["sources"]]
        find(keys[0])
        for key in keys[1:]:
            parent[find(key)] = find(keys[0])
    representative = {}
    for key in list(parent):
        root = find(key)
        representative[root] = min(representative.get(root, key), key)

    output.mkdir(parents=True)
    streams = {name: (output / ("%s.jsonl" % name)).open("xb") for name, _ in SPLITS}
    counts = Counter()
    excluded = Counter()
    removed = Counter()
    for case in cases:
        sources = case["sources"]
        relabelled = False
        if spam_policy == "by-round" and any(source["label"] == "spam" for source in sources):
            sources, relabelled = relabel_spam(sources), True
        labels = {source["label"] for source in sources}
        if len(labels) != 1:
            raise ValueError("conflicting labels: %s" % case["content_id"])
        label = labels.pop()
        split = split_for(seed, representative[find(group_key(sources[0]))])
        chinese = any(source["language"] in CHINESE for source in sources)
        if chinese and split != "test" and chinese_policy == "test-only":
            excluded["chinese_outside_test"] += 1
            continue
        if label == "spam" and split != "test":
            excluded["spam_outside_test"] += 1
            continue
        record = dict(case)
        if relabelled:
            record["sources"] = sources
        for field in ("subject", "body"):
            if record[field] is not None:
                found = PLACEHOLDER.findall(record[field])
                if found:
                    removed["%s/%s" % (sources[0]["dataset"], label)] += len(found)
                    record[field] = PLACEHOLDER.sub(" ", record[field])
        if not record["body"].strip():
            excluded["empty_after_placeholder_removal"] += 1
            continue
        record["classifier_split"] = split
        streams[split].write(encoded(record) + b"\n")
        for source in sources:
            counts["%s/%s/%s/%s" % (split, source["dataset"], source["language"], label)] += 1
        counts["%s/unique_contents" % split] += 1
    for stream in streams.values():
        stream.close()

    result = {
        "schema_version": 1,
        "seed": seed,
        "input_corpus_sha256": manifest["corpus_sha256"],
        "split_upper_percent": dict(SPLITS),
        "group_rule": "Fraud-R1 record_id across languages, rounds and variants; E-PhishLLM record index; exact duplicates joined",
        "chinese_policy": "test only; Chinese rows of train/dev groups dropped" if chinese_policy == "test-only"
        else "grouped with the other languages of the same seed",
        "synthetic_sha256": synthetic_sha256,
        "spam_policy": "test only, reported separately" if spam_policy == "test-only"
        else "by round: raw/generated/round2 benign, round3/round4 malicious; follows its group",
        "placeholders_removed": dict(sorted(removed.items())),
        "excluded": dict(sorted(excluded.items())),
        "counts": dict(sorted(counts.items())),
        "files": {name: digest((output / ("%s.jsonl" % name)).read_bytes()) for name, _ in SPLITS},
    }
    with (output / "manifest.json").open("x") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({key: result[key] for key in ("placeholders_removed", "excluded", "files")}, indent=2))
    for split, _ in SPLITS:
        print(split, result["counts"]["%s/unique_contents" % split])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--seed", default="vigilyx-semantic-classifier-v1")
    parser.add_argument("--chinese", choices=("test-only", "grouped"), default="test-only")
    parser.add_argument("--synthetic", type=Path)
    parser.add_argument("--spam", choices=("test-only", "by-round"), default="test-only")
    args = parser.parse_args()
    prepare(args.corpus, args.output, args.seed, args.chinese, args.synthetic, args.spam)
