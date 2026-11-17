#!/usr/bin/env python3
"""Shortcut probes for the VIGILYX corpus rows (training server, stdlib only).

Input is add_vigilyx_corpus.py output rows (id, text, label, group). Each probe
keeps the row id, so score_counterfactual.py scores it with the fold model that
held the record out and compares the decision with the original one. The label
never changes, so any flip is a shortcut:

* quote_add: malicious rows without a quoted chain get a "回复:"/"Re:" subject
  and a quoted chain copied from a benign row of another group (a hijacked
  thread). A flip means the quoted chain alone reads as benign.
* quote_strip: benign rows with a quoted chain lose it. A flip means the model
  needs the chain to call the mail benign.
* benign_edit: Chinese benign rows get one innocuous sentence using words that
  are malicious-skewed in the corpus (改成, 删掉, 去掉, 就说). A flip means the
  word, not the request, decided the result. The sentence goes after the first
  body line so every member's head window sees it, and is cleaned like the
  training text (NFKC: full-width commas become ASCII, as in the corpus).

Choices come from a hash of the row id, never from the label.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

from prepare_ft_data import clean

QUOTE_START = re.compile(
    r"\n_{10,}\n|\n-{3,}\s*(?:原始邮件|Original Message)\s*-{3,}|\n(?:> ?)?在 [^\n]{5,80}写道[:：]"
    r"|\n(?:> ?)?On [^\n]{5,160}wrote:|\n(?:发件人|From)[:：][^\n]*\n(?:发送时间|Sent|Date)[:：]|\n>")
REPLY_PREFIX = re.compile(r"^(?:回复|答复|转发|Re|RE|Fw|FW|Fwd)\s*[:：]")
CJK = re.compile("[一-鿿]")
BENIGN_EDITS = (
    "另外，周会时间改成周三下午三点，会议室不变。",
    "上次附件里重复的那一页我已经删掉了，其他内容没动。",
    "文件名里多余的空格我去掉了，方便大家检索。",
    "客户问起的话，就说样品周五寄出，物流单号到时再发。",
    "表格第三列的标题改成“到货日期”，便于和仓库对账。",
)


def pick(row_id, salt, n):
    return int(hashlib.sha256(("%s\x1f%s" % (salt, row_id)).encode()).hexdigest()[:12], 16) % n


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", required=True, type=Path, help="corpus rows (add_vigilyx_corpus.py)")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    rows = [json.loads(line) for line in open(args.rows, encoding="utf-8") if line.strip()]
    chains = {}
    for row in rows:
        match = QUOTE_START.search(row["text"])
        if row["label"] == 0 and match:
            chains.setdefault(row["group"], []).append(row["text"][match.start():])
    probes = {"quote_add": [], "quote_strip": [], "benign_edit": []}
    for row in rows:
        text, match = row["text"], QUOTE_START.search(row["text"])
        subject, _, body = text.partition("\n")
        if row["label"] == 1 and not match:
            zh = bool(CJK.search(subject))
            pool = [c for group, cs in sorted(chains.items()) if group == row["group"] for c in cs] or \
                [c for cs in chains.values() for c in cs]
            chain = pool[pick(row["id"], "chain", len(pool))]
            if not REPLY_PREFIX.match(subject):
                subject = ("回复: " if zh else "Re: ") + subject
            probes["quote_add"].append(dict(row, text=subject + "\n" + body.rstrip() + chain))
        elif row["label"] == 0 and match:
            stripped = text[:match.start()].rstrip()
            if len(stripped) >= 20:
                probes["quote_strip"].append(dict(row, text=stripped))
        if row["label"] == 0 and CJK.search(text) and "\n" in body:
            first, _, rest = body.partition("\n")
            sentence = clean(BENIGN_EDITS[pick(row["id"], "edit", len(BENIGN_EDITS))], False)
            probes["benign_edit"].append(dict(row, text=subject + "\n" + first + sentence + "\n" + rest))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, items in probes.items():
        with open(args.output_dir / ("probe_%s.jsonl" % name), "x", encoding="utf-8") as out:
            for item in items:
                out.write(json.dumps(item, ensure_ascii=False) + "\n")
    print(json.dumps({name: len(items) for name, items in probes.items()}))


if __name__ == "__main__":
    main()
