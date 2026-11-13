#!/usr/bin/env python3
"""Check identity masking: fixed cases must hold, then corpus-level placeholder rates.

usage: check_masking.py [CORPUS_JSONL ...]   (prints rates per dataset/label)
"""

import collections
import json
import random
import re
import sys

from poc_text import normalize

MASKED = [
    ("请拨打 400-123-4567 或 13800138000 联系客服", ["(phone)", "(phone)"]),
    ("致电热线95588咨询", ["(phone)"]),
    ("Call +1 (800) 555-0199 or 202-555-0143 now", ["(phone)", "(phone)"]),
    ("座机 0755-12345678", ["(phone)"]),
    ("访问 hongfuapp.com 或 wx.mail.qq.com 下载", ["(domain)", "(domain)"]),
    ("服务器 203.0.113.50 异常", ["(ip)"]),
    ("身份证号 11010519491231002X，卡号 6222 0200 1234 5678", ["(number)", "(number)"]),
    ("订单号 2024110512345678 已发货", ["(number)"]),
    ("备案编号：JDFC-ICP-20241105，商户 MCC_5815_0217，账户 NL09RABO0123456789", ["(code)", "(code)", "(code)"]),
    ("编号JDFC-ICP-20241105已登记，账户NL09RABO0123456789冻结", ["(code)", "(code)"]),
    ("王总，李经理说张伟先生明天到，小王你先准备", ["(name)", "(name)", "(name)", "(name)"]),
    ("Dear John Smith, Mr. Rossi asked Frau Müller", ["(name)", "(name)", "(name)"]),
    ("联系 support@example.com 或打开 https://example.com/a?b=c", ["(email)", "(link)"]),
]
KEPT = [
    "请于2024-11-15前支付15,500.00元",
    "附件 invoice.pdf 和 setup.exe 请查收",
    "本周总结已发，总部会议改到周三，总额 300 万元",
    "高级经理和金融专员参加培训",
    "版本 7.26.3 已发布，COVID 防控通知",
    "24小时内未验证将冻结账户",
]


def main():
    failures = 0
    for text, expected in MASKED:
        out = normalize(text)
        found = re.findall(r"\((?:phone|domain|ip|number|code|name|email|link)\)", out)
        if sorted(found) != sorted(expected):
            failures += 1
            print("MASK FAIL:", text, "->", out)
    for text in KEPT:
        out = normalize(text)
        if "(" in out and out != text:
            failures += 1
            print("KEEP FAIL:", text, "->", out)
    print(f"fixed cases: {len(MASKED) + len(KEPT) - failures}/{len(MASKED) + len(KEPT)} ok")

    placeholder = re.compile(r"\((phone|domain|ip|number|code|name|email|link)\)")
    rng = random.Random(7)
    for path in sys.argv[1:]:
        rates = collections.defaultdict(collections.Counter)
        examples = []
        for line in open(path, encoding="utf-8"):
            record = json.loads(line)
            source = record["sources"][0]
            key = "%s/%s" % ("synthetic" if "notice_type" in source else source["dataset"], source["label"])
            text = normalize((record.get("subject") or "") + "\n" + (record.get("body") or ""))
            rates[key]["emails"] += 1
            for kind in set(placeholder.findall(text)):
                rates[key][kind] += 1
            if "train" in path and placeholder.search(text) and rng.random() < 0.002:
                examples.append(text[:240].replace("\n", " "))
        print("==", path)
        for key, counter in sorted(rates.items()):
            n = counter.pop("emails")
            print(f"  {key:28} n={n:6}", " ".join(f"{k}={100 * v / n:.0f}%" for k, v in counter.most_common()))
        for example in examples[:6]:
            print("  e.g.", example)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
