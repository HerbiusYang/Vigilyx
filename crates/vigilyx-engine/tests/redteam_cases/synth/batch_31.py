#!/usr/bin/env python3
"""Batch 31: fund/futures/asset-mgmt/payment lures + finance gray pairs."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def HD(disp, frm, to, subj, extra="", ct="text/plain; charset=utf-8"):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Thu, 24 Sep 2026 09:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b31@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\nContent-Type: {ct}\r\n\r\n")
def E(n, raw, label, family, tech, note="", lang="zh", fmt="plain", expected=None, ambiguous=False, borderline=""):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": expected or ("block" if label == "malicious" else "deliver"),
        "engine_status": "not_evaluated", "synthetic": True, "batch": 31,
        "format": fmt, "note": note, "ambiguous": ambiguous, "borderline": borderline})

E("mal_0531_pe_requal.eml",
  HD("私募登记", "sm@pe-svc22.example", "investor@personal.example", "合格投资者资格年审（资产证明）")
  + "年审上传：https://sm-ns22.example.org/u\r\n（金融资产证明+收入流水+身份证）\r\n",
  "malicious", "pii_harvest", ["pe_requalification_docs"], "私募年审收资产证明")
E("mal_0532_nav_alert.eml",
  HD("基金风控", "fk@fund-risk22.example", "investor@personal.example", "持仓产品净值触发预警线")
  + "查看持仓处置建议：https://fk-ck22.example.info/v\r\n（基金账号+密码）\r\n",
  "malicious", "account_phishing", ["auto"], "b31fix")
E("mal_0533_redeem_halt.eml",
  HD("产品公告", "gg@fund-product22.example", "investor@personal.example", "巨额赎回顺延，可走快速通道")
  + "快速通道：https://gg-ks22.example.vip/f\r\n（份额确认+银行卡）\r\n",
  "malicious", "pii_harvest", ["massive_redemption_fastlane"], "巨额赎回快速通道")
E("mal_0534_income_transfer.eml",
  HD("收益权转让", "sy@income-right22.example", "investor@personal.example", "收益权转让要约（溢价 8%）")
  + "签约回款账户确认：https://sy-qr22.example.info/s\r\n（银行卡+密码）\r\n",
  "malicious", "credential_harvest", ["income_right_transfer"], "收益权转让")
E("mal_0535_tot_ladder.eml",
  HD("资管计划", "zg@tot-svc22.example", "cfo@corp.internal", "TOT 层级产品补录（监管报送）")
  + "补录材料：产品结构图+底层资产清单+出资人明细，回传本邮箱加密包。\r\n",
  "malicious", "bec", ["auto"], "b31fix")
E("mal_0536_license_annual.eml",
  HD("支付清算", "zf@pay-license22.example", "finance@corp.internal", "支付业务许可证年检（备付金核查）")
  + "年检资料：https://zf-nj22.example.info/y\r\n（备付金账户+法务联系人身份证）\r\n",
  "malicious", "pii_harvest", ["payment_license_check"], "支付牌照年检")
E("mal_0537_merchant_net.eml",
  HD("商户服务", "shj@pay-merchant22.example", "merchant@corp.internal", "商户入网复核（结算卡变更）")
  + "复核：https://shj-fk22.example.org/c\r\n（新结算卡+确认打款金额）\r\n",
  "malicious", "pii_harvest", ["merchant_settle_change"], "结算卡变更")
E("mal_0538_usdt_freeze.eml",
  HD("链上合规", "lh@chain-compliance22.example", "me@personal.example", "USDT 地址涉案冻结（解冻申请）")
  + "解冻需缴纳保证金：TCxxxxxxxx（TRC20）\r\n",
  "malicious", "social_trust", ["usdt_freeze_deposit"], "链上保证金")
E("mal_0539_stable_kyc.eml",
  HD("稳定币", "wb@stable-svc22.example", "me@personal.example", "合规升级：重新 KYC")
  + "重新 KYC：https://wb-kyc22.example.vip/k\r\n（护照+地址证明+银行卡）\r\n",
  "malicious", "pii_harvest", ["auto"], "b31fix")
E("mal_0540_trust_pay.eml",
  HD("信托兑付", "xt@trust-pay22.example", "investor@personal.example", "信托计划兑付账户确认")
  + "确认：https://xt-qr22.example.info/d\r\n（打款卡号+身份证）\r\n",
  "malicious", "pii_harvest", ["trust_payment_confirm"], "信托兑付")
E("mal_0541_bond_dist.eml",
  HD("债券分销", "zq@bond-dist22.example", "treasury@corp.internal", "新债分销追加额度（今日）")
  + "追加打款：6225 0091 5522 8810\r\n（备注产品代码）\r\n",
  "malicious", "bec", ["bond_distribution_swap"], "新债分销收打款")
E("mal_0542_repo_rate.eml",
  HD("银行间市场", "yjj@interbank22.example", "treasury@corp.internal", "质押式回购结算失败需补款")
  + "补款：https://yjj-bk22.example.info/p\r\n（清算账户+U盾）\r\n",
  "malicious", "bec", ["interbank_repo_fail"], "银行间回购补款")
E("mal_0543_insurance_am.eml",
  HD("保险资管", "bx@iam-svc22.example", "finance@corp.internal", "资管产品到期续投（合同电子签）")
  + "签署：https://bx-qs22.example.info/s\r\n（经办人身份证+人脸）\r\n",
  "malicious", "pii_harvest", ["auto"], "b31fix")
E("mal_0544_family_office.eml",
  HD("家族办公室", "jz@fo-svc22.example", "cfo@corp.internal", "家族信托架构调整（税务居民身份）")
  + "身份资料：https://jz-sf22.example.vip/u\r\n（全家护照+税号）\r\n",
  "malicious", "pii_harvest", ["family_office_collect"], "家办收全家证件")
E("mal_0545_qdii2.eml",
  HD("QDII 额度", "qd@qdii-svc22.example", "treasury@corp.internal", "QDII 额度赎回期（今日申报）")
  + "申报：https://qd-sb22.example.info/a\r\n（外汇账户+经办人）\r\n",
  "malicious", "pii_harvest", ["qdii_quota_lure"], "QDII 额度")
E("mal_0546_hedge_dd.eml",
  HD("对冲尽调", "dc@hedge-dd22.example", "fund@corp.internal", "FOF 尽调资料清单（附件回传）")
  + "回传：策略说明+规模证明+估值表 至本邮箱。\r\n",
  "malicious", "pii_harvest", ["fof_dd_reply"], "FOF 尽调回收式")
E("mal_0547_prime_broker.eml",
  HD("PB 业务", "pb@prime-broker22.example", "quant@corp.internal", "主经纪商账户安全策略更新")
  + "策略生效需重新绑定令牌：https://pb-bd22.example.info/t\r\n（交易账号+密码）\r\n",
  "malicious", "credential_harvest", ["auto"], "b31fix")
E("mal_0548_dark_pool.eml",
  HD("大宗交易", "dz@block-trade22.example", "fund@corp.internal", "大宗折价机会（对手方已就位）")
  + "意向锁价定金 5%：6225 0091 9900 1177\r\n",
  "malicious", "bec", ["block_trade_deposit"], "大宗锁价定金")
E("mal_0549_algo_bait.eml",
  HD("算法接入", "sf@algo-connect22.example", "quant@corp.internal", "策略托管环境（VPN 配置+密钥）")
  + "配置包：https://sf-pz22.example.info/cfg.ovpn\r\n",
  "malicious", "malware_attachment", ["algo_vpn_config"], "算法托管 ovpn 配置")
E("mal_0550_credit_bond.eml",
  HD("信用债", "xy@bond-credit22.example", "fund@corp.internal", "持仓债券估值调整通知（回售选择权）")
  + "回售登记：https://xy-hs22.example.info/r\r\n（托管账号+密码）\r\n",
  "malicious", "credential_harvest", ["bond_putback"], "债券回售")

E("ham_0471_pe_real.eml",
  HD("私募登记", "dj@amac.example", "investor@personal.example", "合格投资者程序提示")
  + "认定材料在募集机构现场签署，协会不收取任何电子材料。\r\n",
  "benign", "ham_personal", ["pe_real_offline"], "与私募年审钓鱼同形（线下认定）")
E("ham_0472_redeem_real.eml",
  HD("产品公告", "gg@fund.example", "investor@personal.example", "巨额赎回顺延公告")
  + "当日赎回按比例确认，其余顺延。公告见官网披露栏。\r\n",
  "benign", "ham_personal", ["auto"], "b31fix")
E("ham_0473_merchant_real.eml",
  HD("商户服务", "shj@pay.example", "merchant@corp.internal", "结算延迟说明（通道维护）")
  + "今日结算延至明晨，账户不变。\r\n",
  "benign", "ham_business", ["settle_real_delay"], "与入网复核同形")
E("ham_0474_trust_real.eml",
  HD("信托", "xt@trust.example", "investor@personal.example", "信托计划分配公告")
  + "分配款将划付至预留账户。\r\n",
  "benign", "ham_personal", ["auto"], "b31fix")
E("ham_0475_interbank_real.eml",
  HD("银行间市场", "yjj@bank.example", "treasury@corp.internal", "日终结算正常")
  + "无失败指令。\r\n",
  "benign", "ham_business", ["interbank_real_clean"], "")
E("ham_0476_qdii_real.eml",
  HD("QDII", "qd@bank.example", "treasury@corp.internal", "额度使用月报")
  + "已用 62%，明细见网银。\r\n",
  "benign", "ham_business", ["qdii_real_report"], "")
E("ham_0477_research_report.eml",
  HD("第三方研究", "yj@research.example", "fund@corp.internal", "月度策略（订阅版）")
  + "报告见附件，密码已发短信。\r\n",
  "benign", "ham_business", ["research_real_zip_sms"], "真订阅研报密码走短信")
E("ham_0478_valuation_real.eml",
  HD("估值外包", "gz@admin.example", "fund@corp.internal", "日估值表（9/23）")
  + "估值表见附件 Excel。\r\n",
  "benign", "ham_business", ["valuation_real_daily"], "真日估值表（内部域附件）")
E("ham_0479_trade_conf_real.eml",
  HD("交易确认", "qr@broker.example", "fund@corp.internal", "成交回报（组合X）")
  + "当日成交明细见附件 CSV。\r\n",
  "benign", "ham_business", ["auto"], "b31fix")
E("ham_0480_compliance_real.eml",
  HD("合规", "hg@corp.internal", "all@corp.internal", "异常交易监控规则更新培训")
  + "培训录播在内部学习平台。\r\n",
  "benign", "ham_business", ["compliance_training_real"], "")
E("ham_0481_audit_custody.eml",
  HD("托管行", "tg@custody.example", "fund@corp.internal", "托管户对账（9月）")
  + "对账单见附件，差异回签。\r\n",
  "benign", "ham_business", ["auto"], "b31fix")
E("ham_0482_insurance_real2.eml",
  HD("保险", "bx@insure.example", "me@personal.example", "保单贷款可贷额度")
  + "可贷 3.2 万，App 内申请。\r\n",
  "benign", "ham_personal", ["policy_loan_real"], "")
E("ham_0483_gold_real.eml",
  HD("积存金", "jj@bank.example", "me@personal.example", "本月积存已扣款")
  + "按均价 588.2/g 积存 1 克。\r\n",
  "benign", "ham_personal", ["gold_real_monthly"], "")
E("ham_0484_forex_trade.eml",
  HD("外汇宝", "wh@bank.example", "me@personal.example", "挂单成交提醒")
  + "USD/CNY 7.102 挂单已成交。\r\n",
  "benign", "ham_personal", ["auto"], "b31fix")
E("ham_0485_broker_app.eml",
  HD("证券服务", "svc@broker.example", "investor@personal.example", "App 新版发布")
  + "应用商店更新，控件随包升级。\r\n我司不在邮件中提供任何下载。\r\n",
  "benign", "ham_personal", ["app_real_store"], "与控件 exe 钓鱼同形（商店分发）")

# ---- 金融灰区对照 ----
E("gray_0101_margin_pair_fake.eml",
  HD("融资融券", "rz@broker-m22.example", "investor@personal.example", "维持担保比例 132%（今日追保）")
  + "追保专户：6225 0091 4400 8823（XX 保证金专户）\r\n当日到账视为完成。\r\n",
  "malicious", "bec", ["margin_direct_transfer"], "假追保：直接给转账账户",
  "zh", "plain", "block", True, "真追保永远走 App 内银证转账，绝无'专户'直转；话术与真件几乎一致")
E("gray_0102_margin_pair_real.eml",
  HD("融资融券", "rz@broker.example", "investor@personal.example", "维持担保比例 132%（预警）")
  + "请于 App 内银证转账追加担保物或自行减仓。\r\n"
  "我司不指定任何收款账户。\r\n",
  "benign", "ham_personal", ["margin_real_app_transfer"],
  "zh", "plain", "deliver", True, "与 gray_0101 对照：动作在 App 内 vs 外部转账")
E("gray_0103_deposit_fake2.eml",
  HD("银行", "yh@ebank-relay23.example", "me@personal.example", "大额存单额度保留（今日）")
  + "缴款保留：https://yh-bl23.example.info/c\r\n（银行卡+U盾口令）\r\n",
  "malicious", "credential_harvest", ["cd_reserve_ukey"], "大额存单收 U 盾",
  "zh", "plain", "block", True, "真大额存单在手机银行直接购买")
E("gray_0104_deposit_real2.eml",
  HD("银行", "yh@bank.example", "me@personal.example", "大额存单起息日提醒")
  + "9/25 起息，可在手机银行查看。\r\n",
  "benign", "ham_personal", ["auto"], "b31fix", "zh", "plain", "deliver", True, "同形对照")
E("gray_0105_advisor_fake2.eml",
  HD("投顾", "tg@advisor-m23.example", "investor@personal.example", "策略组调仓（先缴服务费）")
  + "补缴 2,980 至 6225 0091 2200 7734。\r\n",
  "malicious", "bec", ["advisor_prepay_swap"], "投顾补缴",
  "zh", "plain", "block", True, "真投顾费用从证券账户扣，不外部转账")
E("gray_0106_advisor_real2.eml",
  HD("投顾", "tg@broker.example", "investor@personal.example", "服务费代扣成功")
  + "2,980 已从证券账户扣收。\r\n",
  "benign", "ham_personal", ["auto"], "b31fix", "zh", "plain", "deliver", True, "同形对照")
E("gray_0107_ipo_fake2.eml",
  HD("新股", "sg@broker-m23.example", "investor@personal.example", "中签弃购警告（缴款链接）")
  + "缴款：https://sg-jk23.example.vip/p\r\n（股东账户+密码）\r\n",
  "malicious", "credential_harvest", ["ipo_fake_link"],
  "zh", "plain", "block", True, "真中签只提醒备款，从不给缴款链接")
E("gray_0108_ctrl_fake2.eml",
  HD("交易服务", "jy@broker-m23.example", "investor@personal.example", "安全控件过期（邮件附件版）")
  + "控件安装包安装包见附件。\r\n",
  "malicious", "malware_attachment", ["auto"], "b31fix", "zh", "plain", "block", True, "同形对照")
E("gray_0109_ctrl_real2.eml",
  HD("交易服务", "jy@broker.example", "investor@personal.example", "安全控件随 App 更新")
  + "请通过官方应用商店升级，历史安装包已停用。\r\n",
  "benign", "ham_personal", ["ctrl_real_store"],
  "zh", "plain", "deliver", True, "与 gray_0108 对照：券商真控件只在商店/官网，永不走邮件附件")
E("gray_0110_fund_fake2.eml",
  HD("基金", "jj@fund-m23.example", "investor@personal.example", "持仓基金清盘预警（快速赎回）")
  + "快速赎回：https://jj-hs23.example.vip/r\r\n（银行卡+密码）\r\n",
  "malicious", "credential_harvest", ["fund_liquidation_lure"],
  "zh", "plain", "block", True, "真清盘公告走官网/披露平台，赎回在 App 内")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch31 written: {len(LABELS)} samples")
