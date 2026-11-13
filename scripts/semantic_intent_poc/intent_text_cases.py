#!/usr/bin/env python3
"""Golden cases for the Rust port of the intent-model preprocessing.

Runs hand-written inputs (no dataset text) through the Python originals,
poc_text.normalize and prepare_ft_data.clean, and writes
crates/vigilyx-engine/src/semantic/intent_text_cases.json. Run it in the PoC
toolbox image (the Python that prepared the training data), e.g. on 77:
  run_step.sh text_cases 1 -- python3 intent_text_cases.py --output /work/out/intent_text_cases.json
Inputs cover every identity rule and the places where Python `re` differs
from Rust regex (\\s, \\w, \\b, strip()).
"""

import argparse
import json
from pathlib import Path

from prepare_ft_data import clean

CASES = [
    (None, "服务器 10.1.2.3 和 192.168.0.256.1 不同，版本 1.2.3"),
    (None, "身份证 11010519491231002X，另一个110105194912310021号"),
    ("订单通知", "订单号 JDFC-ICP-20241105 与 ab12-cd34，编号JDFC-ICP-20241105已签署"),
    (None, "tracking A1B2C3D4E5 and ABCDEFGH1234, but not ABCDEFGHIJ or 12345678"),
    (None, "联系 +86 138-1234-5678 或 13912345678，号码138 1234 5678"),
    (None, "热线 400-820-1234，800 123 4567"),
    (None, "请拨打95588或客服：10086咨询，致电 12315"),
    (None, "Call +44 20 7946 0958 or +1 (415) 555-0123 today"),
    (None, "US (415) 555-0123, 1-800-555-0199 and 212.555.0147"),
    (None, "座机(010)12345678 或 0755-87654321"),
    (None, "卡号 6222 0212 3456 7890 123，另 6222-0212-3456-7890"),
    (None, "账号 1234567890123，金额 1,234,567.89 元，数字 12345678."),
    (None, "visit secure-login.com or EXAMPLE.TOP now; not a.b@c and mail.example.co.uk"),
    (None, "Open https://evil.top/x?a=1 or www.foo.cn/bar or HTTP://Up.Case/Path now"),
    (None, "contact a.b+c@mail.example.co.uk. or müller@beispiel.de"),
    (None, "王总、李经理好，张总结了会议，陈老师，总部和总额不受影响"),
    (None, "刘德华先生，赵敏女士，周杰小姐"),
    (None, "小王，你好！老李您好 小张\n小刘"),
    (None, "Mrs Smith and Mr. John Brown met Dr Jane and Prof. Anna-Lena O'Neil"),
    ("Dear Alice Wong, urgent", "Dear John Smith,\nHello Anna: Hi team, Liebe Frau Müller!"),
    (None, "pass\u200bword re\u00adset \ufeffBOM\u2060joined\u180espace"),
    (None, "Cafe\u0301 a\u0308bc e\u20dd x\u1ab0y"),
    (None, "\uff21\uff22\uff23\uff11\uff12\uff13\u3000\u5168\u89d2\uff0c\uff28\uff45\uff4c\uff4c\uff4f"),
    (None, "line\x1cone\x1ftwo  \x1c\nnext\x1d"),
    (None, "\u212aelvin.com and \u017ftore.com"),
    ("  Subject \t line  ", "a\r\n\r\n  b \t c\n\n\n"),
    (None, "x\u00a0\u00a0y\u3000z\u2003w\u202fv"),
    (None, ""),
    (None, "   \n \t \n"),
    (None, "\u093ehttps://x.top/a and \u203fwww.y.top and \u00b2https://z.top"),
    (None, "word_https://u.top a1https://v.top"),
    ("【华岳银行】账户安全提醒", "尊敬的客户：您的账户将于24小时内冻结，请访问 https://hy-bank.top/verify 并输入验证码。"),
    ("Your account", "Hello,\nWe noticed a sign-in from 203.0.113.7. If this wasn't you, reply to support@bank-help.com."),
    (None, "Grüße aus München, Ihre Rechnung Nr. RE-2024-0042 über 1.250,00 EUR an IBAN DE89370400440532013000."),
    (None, "Gentile Mario Rossi, la fattura FT2024/118 è disponibile su www.esempio.it/fatture"),
    (None, "电话:13800138000,电话：021-62345678，热线95533"),
    (None, "Mixed 中文English123混排 test@例子.com 和 a@b.cn"),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    rows = []
    for subject, body in CASES:
        expected = (clean(subject or "", False, True) + "\n" + clean(body or "", False, True)).strip()
        rows.append({"subject": subject, "body": body, "expected": expected})
    args.output.write_text(json.dumps(rows, ensure_ascii=True, indent=1) + "\n", encoding="utf-8")
    print(len(rows), "cases")


if __name__ == "__main__":
    main()
