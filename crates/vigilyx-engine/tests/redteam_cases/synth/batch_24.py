#!/usr/bin/env python3
"""Batch 24: BEC/finance variants + real business-finance mail."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def HD(disp, frm, to, subj, extra="", ct="text/plain; charset=utf-8"):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Thu, 17 Sep 2026 09:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b24@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\nContent-Type: {ct}\r\n\r\n")
def E(n, raw, label, family, tech, note="", lang="zh", fmt="plain"):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 24,
        "format": fmt, "note": note})

E("mal_0386_lc_amend.eml",
  HD("单证中心", "dc@trade-finance5.example", "trade@corp.internal", "信用证修改书 MT707 确认")
  + "修改书需在线确认：https://dc-qr5.example.org/m\r\n（网银管理员+U盾口令）\r\n",
  "malicious", "bec", ["lc_amendment_collect"], "信用证收 U 盾口令")
E("mal_0387_tail_urgency.eml",
  HD("总经理", "gm@mail-exec5.example", "treasury@corp.internal", "尾款今天必须到（我在机场）")
  + "账户用对方昨晚发的新资料，先付后补流程。\r\n",
  "malicious", "bec", ["tail_payment_airport"], "机场高压话术")
E("mal_0388_tax_agent2.eml",
  HD("税务筹划", "ch@tax-plan5.example", "finance@corp.internal", "留抵退税加速（内部渠道）")
  + "加速需提供申报账号密码，详情加微信 tax-886。\r\n",
  "malicious", "bec", ["vat_refund_wechat"], "退税灰产引流")
E("mal_0389_wire_proof.eml",
  HD("司库", "tk@treasury-relay5.example", "bank-rel@corp.internal", "水单与账务不符（重发凭证）")
  + "请以本邮件附件水单为准重新核对（对方账户已变更）：\r\n户名：XX贸易；卡号：6225 3390 8812 0077\r\n",
  "malicious", "bec", ["fake_wire_receipt_swap"], "假水单调包账户")
E("mal_0390_payroll_out.eml",
  HD("人力资源", "hr@payroll-outs5.example", "finance@corp.internal", "工资代发外包切换（首月）")
  + "首月需将工资表与员工卡信息发我邮箱加密压缩包，密码另发短信。\r\n",
  "malicious", "pii_harvest", ["payroll_outsource_collect"], "代发外包收全员卡信息")
E("mal_0391_dup_invoice.eml",
  HD("对账", "dz@vendor-relay5.example", "ap@corp.internal", "发票重开（旧作废，请按新金额付）")
  + "旧发票税率开错已作废，新票金额 48,300，收款账户同步变更：\r\n6225 0091 2280 6611\r\n",
  "malicious", "bec", ["invoice_reopen_swap"], "重开发票夹带换账户")
E("mal_0392_bill_discount.eml",
  HD("票据中介", "pj@bill-discount5.example", "treasury@corp.internal", "商票贴现询价（当日放款）")
  + "询价单与背书扫描发我邮箱，放款前收 1% 手续费至 6225 0091 7711 2200。\r\n",
  "malicious", "bec", ["bill_discount_scam"], "票据贴现灰产")
E("mal_0393_cross_border.eml",
  HD("跨境结算", "kj@fx-relay5.example", "trade@corp.internal", "SWIFT 收款人名称更正（退回重汇）")
  + "名称更正后请汇至：BENEF: PACIFIC TRD; IBAN: GB50TSTB00000000000000\r\n本周末前到账。\r\n",
  "malicious", "bec", ["swift_beneficiary_swap"], "跨境改收款人")
E("mal_0394_guarantee.eml",
  HD("保函服务", "bh@guarantee5.example", "bd@corp.internal", "履约保函加急出函（缴费激活）")
  + "激活费 3,000 元缴至：6225 0091 4400 9982\r\n出函后抵扣保费。\r\n",
  "malicious", "bec", ["guarantee_activation_fee"], "保函激活费骗局")
E("mal_0395_rent_loan.eml",
  HD("租房金融", "zfd@rental-fin5.example", "me@personal.example", "押金转租金贷（利率 6%）")
  + "签约链接：https://zfd-qy5.example.vip/s\r\n（身份证+银行卡+人脸）\r\n",
  "malicious", "pii_harvest", ["rental_loan_face"], "租金贷收全套")
E("mal_0396_invest_inner.eml",
  HD("财富内参", "nz@wealth-inner5.example", "cfo@corp.internal", "Pre-IPO 份额（老股转让）")
  + "份额确认：https://nz-qr5.example.vip/s\r\n（合格投资者核验：金融资产证明上传）\r\n",
  "malicious", "pii_harvest", ["preipo_share_lure"], "内参话术")
E("mal_0397_invoice_tax2.eml",
  HD("开票中心", "kp@fapiao-svc5.example", "tax@corp.internal", "数电票额度调整确认")
  + "确认额度：https://kp-ed5.example.info/c\r\n（税号+法定代表人身份证号）\r\n",
  "malicious", "pii_harvest", ["einvoice_limit_collect"], "数电票话术")
E("mal_0398_escrow_fee.eml",
  HD("资金监管", "jg@escrow5.example", "legal@corp.internal", "监管账户开户（律师见证费先行）")
  + "见证费 2,000 至 6225 0091 6600 1122，开户后抵扣。\r\n",
  "malicious", "bec", ["escrow_witness_fee"], "监管账户前期费")
E("mal_0399_dunning_swap.eml",
  HD("应收", "ys@vendor-relay5.example", "ap@corp.internal", "逾期利息通知（账户变更）")
  + "滞纳金按日万分之五；本月起回款账户调整为：\r\n6225 0091 9080 3344\r\n",
  "malicious", "bec", ["dunning_account_swap"], "催款夹带换账户")
E("mal_0400_charity_donate.eml",
  HD("公益基金", "gy@fund-relay5.example", "all@corp.internal", "配捐活动（企业 1:1）")
  + "捐赠通道：https://gy-pj5.example.info/d\r\n（需银行卡直捐，抵扣凭证回邮）\r\n",
  "malicious", "pii_harvest", ["matching_donation_card"], "配捐收卡")
E("mal_0401_loan_pre.eml",
  HD("信贷中心", "xd@loan-pre5.example", "me@personal.example", "预授信 30 万（利率 3.6%）")
  + "激活预授信需缴纳保证金 2%：https://xd-jh5.example.vip/p\r\n",
  "malicious", "bec", ["preapproved_loan_fee"], "预授信贷款")
E("mal_0402_forex_gains.eml",
  HD("外汇服务", "wh@fx-gains5.example", "me@personal.example", "结汇优惠（额度内部价）")
  + "内部价登记：https://wh-jh5.example.vip/r\r\n（身份证+银行卡+手机服务密码）\r\n",
  "malicious", "credential_harvest", ["fx_service_password"], "")

E("ham_0346_lc_real.eml",
  HD("单证中心", "dc@bank.example", "trade@corp.internal", "信用证通知已至（柜台领取）")
  + "MT700 已至，网银-单证可查。\r\n银行不通过邮件链接修改单证。\r\n",
  "benign", "ham_business", ["lc_real_bank_channel"], "与信用证钓鱼同形")
E("ham_0347_payroll_real2.eml",
  HD("人力资源", "hr@corp.internal", "finance@corp.internal", "9月工资发放完成")
  + "代发明细见财务系统，无异常。\r\n",
  "benign", "ham_business", ["payroll_real_done"], "与代发外包对照")
E("ham_0348_invoice_recv.eml",
  HD("应收", "ys@vendor.example", "ap@corp.internal", "发票已收到（编号 FP-9912）")
  + "已入待认证，月底统一勾选。\r\n",
  "benign", "ham_business", ["invoice_real_receipt"], "")
E("ham_0349_dunning_real2.eml",
  HD("应收", "ys@vendor.example", "ap@corp.internal", "账款逾期提醒（账户不变）")
  + "逾期 12 天，金额 21,400。账户按合同原账户。\r\n",
  "benign", "ham_business", ["dunning_real_no_change"], "与催款调包对照：明确账户不变")
E("ham_0350_wire_ok.eml",
  HD("司库", "tk@corp.internal", "trade@corp.internal", "汇款已到账确认")
  + "水单见附件，与合同账户一致。\r\n",
  "benign", "ham_business", ["wire_real_confirm"], "")
E("ham_0351_guarantee_real.eml",
  HD("保函服务", "bh@bank.example", "bd@corp.internal", "履约保函已出具")
  + "保函正本柜台领取，电子核验码短信。\r\n",
  "benign", "ham_business", ["guarantee_real_offline"], "真保函线下领取")
E("ham_0352_budget_real.eml",
  HD("财务-预算", "budget@corp.internal", "leads@corp.internal", "Q4 预算确认截止")
  + "门户-预算系统内确认。\r\n",
  "benign", "ham_business", ["budget_real_portal"], "")
E("ham_0353_tax_real2.eml",
  HD("财务-税务", "tax@corp.internal", "all@corp.internal", "留抵退税申请已提交")
  + "进度以电子税务局为准，官方渠道办理。\r\n",
  "benign", "ham_business", ["vat_real_official"], "与退税灰产对照")
E("ham_0354_donate_real2.eml",
  HD("公益基金", "fo@charity.example", "all@corp.internal", "年度配捐公示")
  + "配捐总额与流向见官网公示。\r\n不通过邮件收卡。\r\n",
  "benign", "ham_business", ["charity_real_public"], "与配捐钓鱼同形")
E("ham_0355_loan_real.eml",
  HD("信贷中心", "xd@bank.example", "me@personal.example", "贷款还款日提醒")
  + "月供 4,321 元，储蓄卡代扣。\r\n本邮件无链接。\r\n",
  "benign", "ham_personal", ["loan_real_nolink"], "与预授信对照")
E("ham_0356_fx_real2.eml",
  HD("外汇服务", "wh@bank.example", "finance@corp.internal", "结汇牌价（9/17 9:15）")
  + "USD/CNY 7.1080，窗口 14:00-16:00。\r\n",
  "benign", "ham_business", ["fx_real_quote"], "")
E("ham_0357_gm_real.eml",
  HD("总经理", "gm@corp.internal", "treasury@corp.internal", "尾款安排（按流程）")
  + "按合同原账户付，流程别省。\r\n",
  "benign", "ham_business", ["gm_real_follow_process"], "与机场高压话术对照：真高管反而强调流程")
E("ham_0358_bill_real.eml",
  HD("票据", "pj@bank.example", "treasury@corp.internal", "票据到期托收")
  + "到期票已托收，款项 T+1 入账。\r\n",
  "benign", "ham_business", ["bill_real_bank"], "与票据中介对照")
E("ham_0359_charity_receipt2.eml",
  HD("公益基金", "fo@charity.example", "me@personal.example", "捐赠收据已开具")
  + "电子收据见附件，可抵扣个税。\r\n",
  "benign", "ham_personal", ["receipt_real_attached"], "")
E("ham_0360_taxi_receipt.eml",
  HD("出行平台", "cx@ride.example", "me@personal.example", "行程发票已开具（3 张）")
  + "电子发票见附件。\r\n",
  "benign", "ham_personal", ["taxi_real_invoice"], "")
E("ham_0361_esop_real2.eml",
  HD("股权平台", "esop@corp.internal", "staff@corp.internal", "行权窗口开放（系统内操作）")
  + "门户-股权-行权，规则见手册。\r\n",
  "benign", "ham_business", ["esop_real_portal"], "与 ESOP 钓鱼同形")
E("ham_0362_audit_fee.eml",
  HD("会计所", "audit@cpa.example", "finance@corp.internal", "审计费用发票（Q3）")
  + "发票见附件，对公原账户。\r\n",
  "benign", "ham_business", ["audit_fee_real"], "")
E("ham_0363_insurance_claim_ok.eml",
  HD("理赔", "lp@insurance.example", "me@personal.example", "理赔款已支付")
  + "3,800 元已付至您预留账户，凭证见 App。\r\n",
  "benign", "ham_personal", ["claim_real_paid"], "理赔到账通知")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch24 written: {len(LABELS)} samples")
