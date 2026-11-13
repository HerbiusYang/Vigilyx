#!/usr/bin/env python3
"""Batch 32: HR-lifecycle/legal/bidding lures + real notices (all-new scenarios)."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def HD(disp, frm, to, subj, extra="", ct="text/plain; charset=utf-8"):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Sat, 26 Sep 2026 09:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b32@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\nContent-Type: {ct}\r\n\r\n")
def E(n, raw, label, family, tech, note="", lang="zh", fmt="plain", expected=None, ambiguous=False, borderline=""):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": expected or ("block" if label == "malicious" else "deliver"),
        "engine_status": "not_evaluated", "synthetic": True, "batch": 32,
        "format": fmt, "note": note, "ambiguous": ambiguous, "borderline": borderline})

E("mal_0551_probation.eml",
  HD("人事系统", "ehr@hr-svc24.example", "newhire@corp.internal", "试用期考核资料补交（影响转正）")
  + "补交：https://ehr-bj24.example.info/u\r\n（学历原件扫描+前雇主证明人电话+身份证）\r\n",
  "malicious", "pii_harvest", ["probation_docs_collect"], "试用期收全套背景材料")
E("mal_0552_transfer_order.eml",
  HD("人力资源", "hr@hr-relay24.example", "employee@corp.internal", "调岗通知（三日内确认）")
  + "调岗需重新签订岗位协议并核验身份：\r\nhttps://hr-dg24.example.org/c\r\n（工号+身份证+人脸）\r\n",
  "malicious", "pii_harvest", ["transfer_face_verify"], "调岗收人脸")
E("mal_0553_noncompete.eml",
  HD("法务-离职事务", "fl@hr-legal24.example", "leaver@corp.internal", "竞业限制义务提醒（保证金）")
  + "激活竞业补偿需先缴履约保证金 5,000：\r\n6225 0091 7700 3311\r\n（离职结算中返还）\r\n",
  "malicious", "bec", ["noncompete_deposit_scam"], "竞业保证金骗局")
E("mal_0554_option_buyback.eml",
  HD("股权事务", "gq@esop-relay24.example", "leaver@corp.internal", "期权回购协议（电子签+缴费）")
  + "回购需缴个税代缴款：https://gq-hg24.example.vip/p\r\n（身份证+银行卡）\r\n",
  "malicious", "pii_harvest", ["option_buyback_tax"], "期权回购收税")
E("mal_0555_patent_warning.eml",
  HD("知识产权律所", "lv@ip-warning24.example", "legal@corp.internal", "专利侵权警告函（附权利要求对照）")
  + "和解窗口 7 日：缴纳许可费 120,000 至 6225 0091 8830 5566，\r\n否则申请诉前禁令。\r\n",
  "malicious", "bec", ["patent_warning_fee"], "假侵权警告函收许可费")
E("mal_0556_tm_opposition.eml",
  HD("商标代理", "dl@tm-oppose24.example", "legal@corp.internal", "商标被提异议（答辩费）")
  + "答辩费 3,500：https://dl-db24.example.info/pay\r\n",
  "malicious", "bec", ["trademark_opposition_fee"], "异议答辩费")
E("mal_0557_arbitration.eml",
  HD("仲裁委", "zc@arb-notice24.example", "legal@corp.internal", "仲裁通知送达（网上确认）")
  + "确认送达：https://zc-qs24.example.org/c\r\n（统一社会信用代码+法定代表人身份证）\r\n",
  "malicious", "pii_harvest", ["fake_arbitration"], "假仲裁收法人证件")
E("mal_0558_lawyer_collect.eml",
  HD("律师事务所", "lv@debt-law24.example", "finance@corp.internal", "律师函催收（最后通牒）")
  + "欠款 218,400 于 9/30 前付至：6225 0091 6677 2200（律所监管户）。\r\n",
  "malicious", "bec", ["auto"], "b32fix")
E("mal_0559_bid_collusion.eml",
  HD("同行", "th@peer-relay24.example", "bd@corp.internal", "下周那个标（喝茶聊聊）")
  + "三家围一圈，价你出，中标分点辛苦费。\r\n细节面谈，本邮件勿转发。\r\n",
  "malicious", "bec", ["bid_collusion_invite"], "围标邀约（灰产）", "zh", "plain", "review", True,
  "违法围标内容明确，但无钓鱼要素；分类上属合规风险而非网络钓鱼，标 review 供人工")
E("mal_0560_expert_draw.eml",
  HD("评标专家系统", "pb@bid-expert24.example", "expert@corp.internal", "评标专家抽取通知（明日）")
  + "确认参评并领取专家费押金：https://pb-qr24.example.info/j\r\n（身份证+银行卡）\r\n",
  "malicious", "pii_harvest", ["expert_draw_deposit"], "评标抽取收押金")
E("mal_0561_perform_bond.eml",
  HD("保函服务", "bh@bid-bond24.example", "bd@corp.internal", "履约保函加急（手续费先行）")
  + "手续费 4,200 至 6225 0091 2244 9900，出函后抵扣。\r\n",
  "malicious", "bec", ["performance_bond_fee"], "履约保函费")
E("mal_0562_protest.eml",
  HD("异议受理", "yy@bid-protest24.example", "bd@corp.internal", "质疑文件补正（缴纳处理费）")
  + "补正+处理费 800：https://yy-bz24.example.info/f\r\n",
  "malicious", "bec", ["bid_protest_fee"], "质疑处理费")
E("mal_0563_labor_arb.eml",
  HD("劳动仲裁", "ld@labor-arb24.example", "hr@corp.internal", "员工仲裁申请副本（签收）")
  + "签收确认：https://ld-qs24.example.org/r\r\n（公司法人身份证+手机号）\r\n",
  "malicious", "pii_harvest", ["auto"], "b32fix")
E("mal_0564_notary.eml",
  HD("公证处", "gz@notary-svc24.example", "legal@corp.internal", "文件公证预约（预付费）")
  + "公证费 600 预付：https://gz-yf24.example.vip/p\r\n（经办人身份证+手机）\r\n",
  "malicious", "pii_harvest", ["notary_prepay"], "公证预付")
E("mal_0565_judicial_sale.eml",
  HD("司法拍卖", "sf@judicial-auction24.example", "me@personal.example", "法拍房保证金（尾号同号优先）")
  + "保证金 50 万缴纳：https://sf-bz24.example.info/d\r\n（银行卡+密码）\r\n",
  "malicious", "credential_harvest", ["judicial_auction_deposit"], "法拍保证金")
E("mal_0566_credit_repair_b.eml",
  HD("企业信用", "xy@biz-credit24.example", "legal@corp.internal", "行政处罚信用修复（代办）")
  + "修复费 8,000：https://xy-xf24.example.vip/r\r\n（统一社会信用代码+法人身份证）\r\n",
  "malicious", "pii_harvest", ["credit_repair_biz"], "信用修复代办")
E("mal_0567_antitrust.eml",
  HD("反垄断合规", "fl@antitrust-svc24.example", "legal@corp.internal", "经营者集中申报补正")
  + "补正材料：股权结构图+营业额清单，回传本邮箱。\r\n",
  "malicious", "pii_harvest", ["auto"], "b32fix")
E("mal_0568_export_ctrl.eml",
  HD("出口管制", "ck@export-ctrl24.example", "trade@corp.internal", "两用物项许可年审")
  + "年审：https://ck-ns24.example.org/y\r\n（ECCN 清单+最终用户证明）\r\n",
  "malicious", "pii_harvest", ["export_control_docs"], "出口管制收清单")
E("mal_0569_data_export.eml",
  HD("数据出境", "sj@data-export24.example", "dpo@corp.internal", "数据出境安全评估补正（评估机构）")
  + "补正材料发本邮箱：数据出境目录+ receiver 信息。\r\n",
  "malicious", "pii_harvest", ["data_export_exfil"], "假评估机构收出境数据目录")
E("mal_0570_sanctions.eml",
  HD("制裁合规", "zc@sanctions-svc24.example", "trade@corp.internal", "OFAC SDN 名单匹配预警")
  + "命中排查需提供交易对手全套 KYC 至本邮箱。\r\n",
  "malicious", "pii_harvest", ["auto"], "b32fix")
E("ham_0486_probation_ok.eml",
  HD("人事系统", "ehr@corp.internal", "newhire@corp.internal", "试用期转正评估已启动")
  + "评估在 HR 系统内进行，无需提交任何材料。\r\n",
  "benign", "ham_business", ["probation_real_system"], "与试用期钓鱼同形")
E("ham_0487_transfer_real.eml",
  HD("人力资源", "hr@corp.internal", "employee@corp.internal", "调岗沟通（无强制）")
  + "如无意愿可回复说明，岗位协议纸质签署。\r\n",
  "benign", "ham_business", ["transfer_real_offline"], "")
E("ham_0488_noncompete_real.eml",
  HD("法务", "legal@corp.internal", "leaver@corp.internal", "竞业限制启动通知（补偿随发）")
  + "补偿金按月随发至工资卡，无需缴纳任何费用。\r\n",
  "benign", "ham_business", ["noncompete_real_compensated"], "真竞业：补偿随发、零缴费")
E("ham_0489_option_real2.eml",
  HD("股权事务", "esop@corp.internal", "leaver@corp.internal", "回购协议（系统内签署）")
  + "门户-股权签署，税由公司代扣。\r\n",
  "benign", "ham_business", ["option_real_system"], "")
E("ham_0490_patent_real2.eml",
  HD("知识产权律所", "lv@ip-firm.example", "legal@corp.internal", "自由实施分析报告交付")
  + "报告见附件 PDF。\r\n",
  "benign", "ham_business", ["auto"], "b32fix")
E("ham_0491_arb_real.eml",
  HD("仲裁委", "sj@arb.example", "legal@corp.internal", "案件受理通知（平台送达）")
  + "材料在仲裁平台查收（短信验证码登录）。\r\n",
  "benign", "ham_business", ["arb_real_platform"], "与假仲裁同形")
E("ham_0492_lawyer_real.eml",
  HD("律所", "lv@law.example", "finance@corp.internal", "催收律师函（附委托书）")
  + "函件见附件，异议回函或走司法程序。\r\n",
  "benign", "ham_business", ["lawyer_real_letter"], "真律师函：函件+委托书，不收款")
E("ham_0493_expert_real.eml",
  HD("评标专家系统", "pb@ccgp.example", "expert@corp.internal", "抽取通知（确认参评）")
  + "平台内确认，专家费评标后平台发放。\r\n不收取任何押金。\r\n",
  "benign", "ham_business", ["expert_real_platform_fee"], "与押金钓鱼同形")
E("ham_0494_bond_real2.eml",
  HD("银行", "bh@bank.example", "bd@corp.internal", "履约保函开立成功")
  + "正本柜台领取。\r\n",
  "benign", "ham_business", ["bond_real_issued"], "")
E("ham_0495_notary_real.eml",
  HD("公证处", "gz@notary.example", "legal@corp.internal", "预约成功（到付）")
  + "周三 10:00 带公章到场，费用现场缴纳。\r\n",
  "benign", "ham_business", ["auto"], "b32fix")
E("ham_0496_auction_real.eml",
  HD("司法拍卖", "sf@court.example", "me@personal.example", "法拍竞买公告（官方平台）")
  + "保证金经淘宝/京东司法拍卖平台缴纳，勿信代缴。\r\n",
  "benign", "ham_personal", ["auction_real_platform"], "真法拍：平台缴保证金")
E("ham_0497_credit_real3.eml",
  HD("信用中国", "xy@creditchina.example", "legal@corp.internal", "行政处罚信息公示到期")
  + "公示期满自动修复，无需代办。\r\n",
  "benign", "ham_business", ["credit_real_automatic"], "真信用修复：自动+反代办提示")
E("ham_0498_antitrust_real.eml",
  HD("法务", "legal@corp.internal", "bd@corp.internal", "经营者集中申报完成")
  + "回执见附件。\r\n",
  "benign", "ham_business", ["antitrust_real_done"], "")
E("ham_0499_export_real.eml",
  HD("出口管制", "ck@moc.example", "trade@corp.internal", "许可申请已受理")
  + "受理号 EX-2026-8842，进度系统内查。\r\n",
  "benign", "ham_business", ["auto"], "b32fix")
E("ham_0500_data_export_real.eml",
  HD("网信", "wx@cac.example", "dpo@corp.internal", "出境评估材料签收")
  + "材料经官方申报系统提交，进度系统内查。\r\n",
  "benign", "ham_business", ["dataexport_real_system"], "与假评估机构对照：只走申报系统")
E("ham_0501_sanctions_real.eml",
  HD("合规", "hg@corp.internal", "trade@corp.internal", "季度制裁筛查报告")
  + "零命中，报告见附件。\r\n",
  "benign", "ham_business", ["sanctions_real_report"], "")
E("ham_0502_union_real2.eml",
  HD("工会", "union@corp.internal", "staff@corp.internal", "职工代表大会决议公示")
  + "决议清单见内网公示栏。\r\n",
  "benign", "ham_business", ["union_real_public"], "")
E("ham_0503_training_law.eml",
  HD("法务", "legal@corp.internal", "all@corp.internal", "新《公司法》要点培训")
  + "周四 15:00，录播后挂知识库。\r\n",
  "benign", "ham_business", ["law_training_real"], "")
E("ham_0504_dpo_real.eml",
  HD("DPO", "dpo@corp.internal", "rd@corp.internal", "个人信息保护审计排期")
  + "贵部门 10 月第二周，自查表内网下发。\r\n",
  "benign", "ham_business", ["auto"], "b32fix")
E("ham_0505_policy_real2.eml",
  HD("合规", "hg@corp.internal", "all@corp.internal", "举报渠道公示（合规热线）")
  + "热线 6000 与邮箱 compliance@，本邮件为年度例行公示。\r\n",
  "benign", "ham_business", ["hotline_real_public"], "")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch32 written: {len(LABELS)} samples")
