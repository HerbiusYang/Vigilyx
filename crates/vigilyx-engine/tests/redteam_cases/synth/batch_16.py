#!/usr/bin/env python3
"""Batch 16: gray HTML pairs (bank/reset/docusign/bill/boarding fake vs real)."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def H(disp, frm, to, subj):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Tue, 08 Sep 2026 09:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b16@synth.example>\r\n"
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\n"
            "Content-Type: text/html; charset=utf-8\r\n\r\n")
def E(n, hdr, body, label, family, tech, note="", lang="zh", expected=None, ambiguous=False, borderline=""):
    W(n, (hdr + "\r\n" + body).encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": expected or ("block" if label == "malicious" else "deliver"),
        "engine_status": "not_evaluated", "synthetic": True, "batch": 16,
        "format": "html", "note": note, "ambiguous": ambiguous, "borderline": borderline})

E("gray_0061_bank_tx_fake.eml",
  H("建设银行", "message@ccb-notify2.example", "me@personal.example", "您有一笔异常交易待确认"),
  "<html><body><p>您尾号 6688 的账户发生一笔 2,860.00 元交易（境外）。</p>"
  "<p><a href='https://ccb-tx-confirm.example.vip/ok' style='background:#0066b3;color:#fff;"
  "padding:10px 28px;text-decoration:none'>确认是否本人</a></p>"
  "<p style='font-size:12px'>未确认将临时冻结账户。</p></body></html>",
  "malicious", "account_phishing", ["bank_tx_fake_button"], "假动账+确认按钮",
  "zh", "block", True, "真动账通知从不带'确认'按钮（真假对：gray_0062）")

E("gray_0062_bank_tx_real2.eml",
  H("建设银行", "messages@ccb.example", "me@personal.example", "您尾号6688的账户完成一笔交易"),
  "<html><body><p>您尾号 6688 的账户于 14:22 完成一笔消费 286.00 元（线上商户）。</p>"
  "<p style='font-size:12px'>如非本人请致电 95533。本邮件不含链接与按钮。</p></body></html>",
  "benign", "ham_personal", ["bank_tx_real_nobutton"], "真动账无按钮",
  "zh", "deliver", True, "与 gray_0061 同题材；真件=纯通知+电话渠道")

E("gray_0063_reset_fake.eml",
  H("账号中心", "no-reply@accounts-svc2.example", "me@personal.example", "密码重置请求"),
  "<html><body><p>我们收到了您的密码重置请求，请点击完成：</p>"
  "<p><a href='https://accounts-svc2-reset.example.info/rst/7f3b' style='color:#fff;background:#333;"
  "padding:10px 28px;text-decoration:none'>重置密码</a></p>"
  "<p style='font-size:12px'>如非本人操作请忽略本邮件。</p></body></html>",
  "malicious", "credential_harvest", ["reset_fake_link"], "假重置（话术几乎完美）",
  "zh", "block", True, "密码重置是真假最难分的一对；判别在发件域与链接域一致性")

E("gray_0064_reset_real2.eml",
  H("账号中心", "no-reply@accounts.svc.example", "me@personal.example", "重置密码请求（30分钟内有效）"),
  "<html><body><p>我们收到了您的密码重置请求。</p>"
  "<p><a href='https://accounts.svc.example/reset/rt_9d41ce' style='color:#fff;background:#333;"
  "padding:10px 28px;text-decoration:none'>重置密码</a></p>"
  "<p style='font-size:12px'>链接 30 分钟有效、一次性。非本人操作请忽略并尽快改密。</p></body></html>",
  "benign", "ham_business", ["reset_real_link"], "真重置（域一致+时效声明）",
  "zh", "deliver", True, "与 gray_0063 唯一可靠差异=发件域/链接域一致性，语义模型必须学会看域名")

E("gray_0065_docusign_fake2.eml",
  H("DocuSign", "dse@dsecc-notify.example", "finance@corp.internal", "Please sign: Payment Instruction Update"),
  "<html><body><p><b>CFO Office</b> sent you a document to sign:</p>"
  "<p style='border-left:3px solid #999;padding-left:12px'>Payment_Instruction_2026.pdf</p>"
  "<a href='https://dsecc-sign-view.example.co/e/2f71' style='background:#ffc72c;color:#000;"
  "padding:10px 28px;text-decoration:none'>REVIEW DOCUMENT</a></body></html>",
  "malicious", "credential_harvest", ["docusign_fake2"], "假签署（敏感文件名）",
  "zh", "block", True, "DocuSign 仿冒与真件（gray_0066）视觉几乎一致")

E("gray_0066_docusign_real.eml",
  H("DocuSign", "dse_noreply@docusign.example", "legal@corp.internal", "Please sign: NDA - ACME Corp"),
  "<html><body><p><b>Legal Dept</b> sent you a document to sign:</p>"
  "<p style='border-left:3px solid #999;padding-left:12px'>NDA_ACME_2026.pdf</p>"
  "<a href='https://docusign.example/envelope/9a55c2' style='background:#ffc72c;color:#000;"
  "padding:10px 28px;text-decoration:none'>REVIEW DOCUMENT</a>"
  "<p style='font-size:11px'>Envelope ID 9a55c2 | DocuSign Official</p></body></html>",
  "benign", "ham_business", ["docusign_real"], "真 DocuSign（官方域+Envelope ID）",
  "zh", "deliver", True, "同形对照；真件域名=发件域，附 Envelope ID 可回查")

E("gray_0067_cloud_bill_fake.eml",
  H("阿里云", "bill@aliyun-notify2.example", "ops@corp.internal", "您的云账单已出（欠费预警）"),
  "<html><body><p>本月账单 ¥12,408.50，账户余额不足即将停机。</p>"
  "<p><a href='https://aliyun-recharge2.example.info/pay' style='background:#ff6a00;color:#fff;"
  "padding:10px 28px;text-decoration:none'>立即充值</a></p>"
  "<p style='font-size:12px'>停机后数据保留 15 天。</p></body></html>",
  "malicious", "account_phishing", ["cloud_bill_fake_recharge"], "假云账单充值",
  "zh", "block", True, "云厂商真有欠费预警（gray_0068），假件差异在充值域")

E("gray_0068_cloud_bill_real.eml",
  H("阿里云", "noreply@aliyun.example", "ops@corp.internal", "您的账户余额低于预警线"),
  "<html><body><p>当前余额 ¥3,120.40，低于预警线。可在控制台-费用中心充值。</p>"
  "<p><a href='https://expense.aliyun-example.com/recharge' style='color:#ff6a00'>前往费用中心</a></p>"
  "<p style='font-size:12px'>本邮件由系统发出；阿里云不会索要账户密码。</p></body></html>",
  "benign", "ham_business", ["cloud_bill_real_console"], "真云欠费（官方费用中心域）",
  "zh", "deliver", True, "真件引导到控制台而非独立支付页")

E("gray_0069_boarding_fake.eml",
  H("中国国航", "service@air-china-2.example", "me@personal.example", "航班取消：CA1858（补办退改）"),
  "<html><body><p>很抱歉，您的 CA1858 已取消。可免费改签或退款：</p>"
  "<p><a href='https://ca-rebook-refund.example.vip/h' style='background:#e10c19;color:#fff;"
  "padding:10px 28px;text-decoration:none'>办理退改</a></p>"
  "<p style='font-size:12px'>需核对银行卡信息。</p></body></html>",
  "malicious", "pii_harvest", ["boarding_fake_refund_card"], "假退改收卡",
  "zh", "block", True, "真退改只在官方 App/官网，不收新卡号")

E("gray_0070_boarding_real2.eml",
  H("中国国航", "checkin@air-china.example", "me@personal.example", "航班变动提醒：CA1858 提前至 07:40"),
  "<html><body><p>您的 CA1858 起飞时间提前至 07:40，值机开放中。</p>"
  "<a href='https://www.air-china-example.com/checkin/CA1858' style='color:#e10c19'>在线值机</a>"
  "<p style='font-size:12px'>改签请在官方渠道办理；国航不收取退改服务费外的任何费用。</p></body></html>",
  "benign", "ham_personal", ["boarding_real_change"], "真航班变动（官方域）",
  "zh", "deliver", True, "与 gray_0069 对照；真变动的'动作'都在官方域内完成")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch16 written: {len(LABELS)} samples")
