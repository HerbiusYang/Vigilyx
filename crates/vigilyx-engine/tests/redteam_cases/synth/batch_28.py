#!/usr/bin/env python3
"""Batch 28: B2B/supply-chain lures + real B2B notices."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def HD(disp, frm, to, subj):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Mon, 21 Sep 2026 09:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b28@synth.example>\r\n"
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
def E(n, raw, label, family, tech, note=""):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": "zh", "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 28, "note": note})

E("mal_0461_sample_send.eml", HD("业务", "yw@sample-svc9.example", "purchase@corp.internal", "样品已寄出（运费到付）")
  + "样品到付运费请支付：https://yw-yf9.example.info/p\r\n（对公+经办人验证）\r\n",
  "malicious", "bec", ["sample_cod_pay"], "样品到付话术")
E("mal_0462_factory_audit.eml", HD("验厂中心", "yc@audit-svc9.example", "qa@corp.internal", "验厂预约需缴纳诚意金")
  + "诚意金 2,000：https://yc-cx9.example.vip/d\r\n通过后抵审核费。\r\n",
  "malicious", "bec", ["audit_deposit"], "验厂诚意金")
E("mal_0463_coa.eml", HD("质量文档", "zl@coa-svc9.example", "qa@corp.internal", "COA 证书补发（验证收件人）")
  + "补发验证：https://zl-bf9.example.info/v\r\n（邮箱+密码）\r\n",
  "malicious", "credential_harvest", ["coa_verify_password"], "COA 收密码")
E("mal_0464_customs2.eml",
  HD("报关行", "hg@customs-relay9.example", "trade@corp.internal", "报关单退单（重新申报）")
  + "重新申报需验证：https://hg-cs9.example.info/r\r\n（报关单号+对公账户）\r\n",
  "malicious", "bec", ["auto"], "b28fix")
E("mal_0465_origin_cert.eml", HD("产地证", "cd@co-svc9.example", "trade@corp.internal", "CO 产地证领取（年费）")
  + "年费缴纳：https://cd-nf9.example.vip/f\r\n（对公账户+U盾口令）\r\n",
  "malicious", "bec", ["co_annual_ukey"], "产地证收 U 盾")
E("mal_0466_telex.eml", HD("货代", "hd@forwarder-relay9.example", "trade@corp.internal", "电放费支付（放货前）")
  + "电放费 USD120：https://hd-df9.example.info/pay\r\n",
  "malicious", "bec", ["telex_release_fee"], "电放费")
E("mal_0467_quote2.eml", HD("运价", "yj@freight-quote9.example", "trade@corp.internal", "旺季运价锁定（24h）")
  + "锁定保证金：https://yj-bs9.example.vip/l\r\n",
  "malicious", "bec", ["freight_lock_deposit"], "运价锁定")
E("mal_0468_vendor_kyc2.eml", HD("采购中心", "cg@vendor-kyc9.example", "vendor@corp.internal", "供应商 KYC 年审（附件回传）")
  + "回传：营业执照+法人身份证+对公账户至本邮箱加密包。\r\n",
  "malicious", "pii_harvest", ["kyc_reply_collect"], "回收式 KYC")
E("mal_0469_biz_dev.eml", HD("商务", "sw@bizdev-relay9.example", "bd@corp.internal", "合作框架（电子签）")
  + "签署链接：https://sw-qs9.example.info/s\r\n（手机号+身份证号实名）\r\n",
  "malicious", "pii_harvest", ["esign_b2b_collect"], "B2B 电子签实名")
E("mal_0470_material_price.eml", HD("原料行情", "yl@material-svc9.example", "purchase@corp.internal", "绝版低价（余单甩卖）")
  + "余单 3 吨，定金 50%：6225 0091 5511 0093\r\n",
  "malicious", "bec", ["leftover_stock_deposit"], "余单甩卖")
E("mal_0471_qc_report2.eml", HD("质检", "zj@qc-relay9.example", "qa@corp.internal", "质检报告可查（扫码）")
  + "扫码查询：见附件图片二维码\r\n",
  "malicious", "quishing", ["qc_qr_lure"], "质检扫码")
E("mal_0472_expo_visitor2.eml",
  HD("展会", "zh@expo-relay9.example", "bd@corp.internal", "展商证件补办")
  + "补办：https://zh-bb9.example.info/e\r\n（营业执照+法人身份证）\r\n",
  "malicious", "pii_harvest", ["auto"], "b28fix")
E("mal_0473_contract_seal.eml", HD("印章服务", "yz@seal-svc9.example", "legal@corp.internal", "电子印章续期（年检）")
  + "年检：https://yz-nj9.example.info/y\r\n（统一社会信用代码+法人身份证）\r\n",
  "malicious", "pii_harvest", ["eseal_annual"], "电子印章年检")
E("mal_0474_tender_doc.eml", HD("标书服务", "bs@bid-doc9.example", "bd@corp.internal", "标书代做（中标率 90%）")
  + "定金 3,000：https://bs-dj9.example.vip/a\r\n",
  "malicious", "bec", ["bid_doc_scam"], "标书代做灰产")
E("mal_0475_import_duty.eml", HD("关税", "gs@duty-relay9.example", "trade@corp.internal", "归类补税通知")
  + "补税通道：https://gs-bs9.example.info/t\r\n（报关单号+对公账户）\r\n",
  "malicious", "bec", ["duty_reclassify"], "归类补税")
E("mal_0476_logistics_claim2.eml", HD("货损", "hs@claim-relay9.example", "trade@corp.internal", "货损理赔（邮件提交）")
  + "提交：装箱单+发票+银行账户至本邮箱。\r\n",
  "malicious", "pii_harvest", ["cargo_claim_reply"], "理赔回收式")
E("mal_0477_free_sample.eml",
  HD("免费样品", "mf@free-sample9.example", "purchase@corp.internal", "免费样品申领（付邮）")
  + "付邮 25 元：https://mf-yf9.example.vip/p\r\n",
  "malicious", "social_trust", ["auto"], "b28fix")
E("mal_0478_channel_fee.eml", HD("渠道", "qd@channel-svc9.example", "sales@corp.internal", "代理权定金（区域独占）")
  + "定金 20,000：https://qd-dj9.example.vip/d\r\n",
  "malicious", "bec", ["agency_deposit"], "代理定金")
E("mal_0479_einvoice_b2b.eml", HD("开票", "kp@invoice-b2b9.example", "ap@corp.internal", "发票信息变更确认")
  + "确认：https://kp-qr9.example.info/c\r\n（税号+开户行+账号）\r\n",
  "malicious", "pii_harvest", ["invoice_info_change"], "开票信息变更")
E("mal_0480_service_renew2.eml", HD("服务续约", "fw@renew-svc9.example", "it@corp.internal", "维保续约优惠（最后）")
  + "续约：https://fw-xy9.example.vip/r\r\n（对公+经办人身份证）\r\n",
  "malicious", "pii_harvest", ["maintenance_renew_docs"], "维保续约收件")

E("ham_0421_sample_ok.eml", HD("业务", "yw@vendor.example", "purchase@corp.internal", "样品已签收")
  + "谢谢安排，测试反馈本周回。\r\n",
  "benign", "ham_business", ["sample_real_ack"], "与样品话术同形")
E("ham_0422_coa_real.eml", HD("质量文档", "zl@vendor.example", "qa@corp.internal", "COA 已随货发出")
  + "纸质版随货，电子版见附件。\r\n",
  "benign", "ham_business", ["coa_real_attached"], "与 COA 钓鱼同形")
E("ham_0423_customs_real2.eml", HD("报关行", "hg@forwarder.example", "trade@corp.internal", "报关已放行")
  + "放行信息在单一窗口查询。\r\n",
  "benign", "ham_business", ["customs_real_release"], "")
E("ham_0424_telex_real.eml", HD("货代", "hd@forwarder.example", "trade@corp.internal", "电放已执行")
  + "收货人可提货，费用月结。\r\n",
  "benign", "ham_business", ["telex_real_done"], "与电放费钓鱼同形：月结不单付")
E("ham_0425_quote_real2.eml", HD("运价", "yj@forwarder.example", "trade@corp.internal", "下周舱位与运价")
  + "美西 USD3200/40HQ，有效期 7 天。\r\n",
  "benign", "ham_business", ["quote_real_validity"], "")
E("ham_0426_kyc_real2.eml", HD("采购中心", "cg@corp.internal", "vendor@example-corp.example", "KYC 年审（系统内）")
  + "供应商门户内更新，附件邮箱不受理。\r\n",
  "benign", "ham_business", ["kyc_real_portal"], "与回收式 KYC 对照")
E("ham_0427_esign_real2.eml", HD("电子签", "legal@corp.internal", "partner@vendor.example", "合同已发起签署")
  + "对方将收到平台官方邮件，我司不走自定义签署链接。\r\n",
  "benign", "ham_business", ["esign_real_platform"], "")
E("ham_0428_qc_real2.eml", HD("质检", "zj@vendor.example", "qa@corp.internal", "本周质检汇总")
  + "合格率 99.2%，明细见附件 Excel（无宏）。\r\n",
  "benign", "ham_business", ["qc_real_no_macro"], "明确无宏")
E("ham_0429_bid_win.eml", HD("政采平台", "notify@ccgp.example", "bd@corp.internal", "中标公告（智慧停车）")
  + "公示 7 日，合同签订见平台指引。\r\n",
  "benign", "ham_business", ["bid_real_win"], "")
E("ham_0430_contract_done.eml", HD("法务", "legal@corp.internal", "bd@corp.internal", "合同用印完成")
  + "纸质正本两份已寄。\r\n",
  "benign", "ham_business", ["contract_real_sealed"], "")
E("ham_0431_invoice_match.eml",
  HD("对账", "dz@vendor.example", "ap@corp.internal", "11月对账无差异")
  + "双方账目一致，无未达项。\r\n",
  "benign", "ham_business", ["auto"], "b28fix")
E("ham_0432_ship_doc.eml", HD("单证", "dz@forwarder.example", "trade@corp.internal", "全套单证已出")
  + "提单/箱单/发票扫描件见附件。\r\n",
  "benign", "ham_business", ["docs_real_attached"], "")
E("ham_0433_warehouse.eml", HD("仓储", "cc@3pl.example", "trade@corp.internal", "入库单 W-8842（本月）")
  + "明细见附件。\r\n",
  "benign", "ham_business", ["warehouse_real_inbound"], "")
E("ham_0434_return_ok.eml", HD("售后", "sh@vendor.example", "trade@corp.internal", "退换货已完成（换新）")
  + "新批次已发出。\r\n",
  "benign", "ham_business", ["rma_real_done"], "")
E("ham_0435_aging_test.eml", HD("实验室", "sys@lab.example", "qa@corp.internal", "老化测试报告（3 周期）")
  + "报告见附件 PDF。\r\n",
  "benign", "ham_business", ["aging_real_report"], "")
E("ham_0436_patent_grant.eml", HD("代理所", "li@agency.example", "ip@corp.internal", "专利授权通知书到达")
  + "缴登印费请确认（所内系统）。\r\n",
  "benign", "ham_business", ["patent_real_grant"], "与假代理同形（真所走所内系统）")
E("ham_0437_supplier_visit2.eml", HD("行政", "xz@corp.internal", "bd@corp.internal", "供应商来访（周四 10:00）")
  + "已备 3F 会议室。\r\n",
  "benign", "ham_business", ["visit_real_room"], "")
E("ham_0438_tender_qa.eml", HD("政采平台", "notify@ccgp.example", "bd@corp.internal", "答疑补遗文件发布")
  + "平台内下载。\r\n",
  "benign", "ham_business", ["qa_real_platform"], "")
E("ham_0439_annual_meet.eml", HD("市场", "mkt@corp.internal", "partners@list.example", "合作伙伴大会（12月）")
  + "邀请函纸质版寄出，回执表随函。\r\n",
  "benign", "ham_business", ["annual_real_invitation"], "")
E("ham_0440_credit_ok.eml", HD("资信", "zx@credit-bureau.example", "finance@corp.internal", "资信报告已交付")
  + "报告见附件（加密，密码短信）。\r\n",
  "benign", "ham_business", ["credit_real_delivered"], "真加密件密码走短信")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch28 written: {len(LABELS)} samples")
