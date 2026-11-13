#!/usr/bin/env python3
"""Batch 30: securities/brokerage lures (professional terminology) + real notices."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def HD(disp, frm, to, subj, extra="", ct="text/plain; charset=utf-8"):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Wed, 23 Sep 2026 09:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b30@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\nContent-Type: {ct}\r\n\r\n")
def ATT(hdr, t, fn, ct, b64):
    return (hdr + "Content-Type: multipart/mixed; boundary=\"BS\"\r\n\r\n"
            f"--BS\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{t}\r\n"
            f"--BS\r\nContent-Type: {ct}\r\nContent-Disposition: attachment; filename=\"{fn}\"\r\n"
            f"Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--BS--\r\n")
def E(n, raw, label, family, tech, note="", lang="zh", fmt="plain", expected=None, ambiguous=False, borderline=""):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": expected or ("block" if label == "malicious" else "deliver"),
        "engine_status": "not_evaluated", "synthetic": True, "batch": 30,
        "format": fmt, "note": note, "ambiguous": ambiguous, "borderline": borderline})

# ---- 券商/交易恶意 ----
E("mal_0511_dormant_act.eml",
  HD("账户服务", "kh@broker-svc21.example", "investor@personal.example", "您的证券账户已进入休眠名单")
  + "根据登记结算公司规定，三年无交易的账户将转入休眠。\r\n"
  "激活确认（今日内）：https://kh-jh21.example.info/a\r\n（股东账号+身份证号+交易密码）\r\n",
  "malicious", "account_phishing", ["dormant_account_lure", "collect_trade_password"], "休眠激活收交易密码")
E("mal_0512_allot_pay.eml",
  HD("新股申购", "sg@broker-ipo21.example", "investor@personal.example", "中签缴款提醒（明日扣款失败视为弃购）")
  + "您中签新股 500 股，缴款需确认三方存管：\r\n"
  "https://sg-jk21.example.vip/c\r\n（银行卡号+取款密码确认）\r\n",
  "malicious", "credential_harvest", ["ipo_payment_collect", "withdraw_password"], "中签缴款收取款密码")
E("mal_0513_margin_call.eml",
  HD("融资融券", "rz@broker-margin21.example", "investor@personal.example", "维持担保比例 128%，请于今日收盘前追加担保")
  + "追保直付通道：https://rz-zb21.example.info/p\r\n（银证转账+银行卡密码）\r\n"
  "未追加将于明日上午强制平仓。\r\n",
  "malicious", "credential_harvest", ["margin_call_urgency", "bank_password"], "追保话术收银行卡密码")
E("mal_0514_gem_perm.eml",
  HD("适当性管理", "sd@broker-perm21.example", "investor@personal.example", "创业板权限需重新签署风险揭示书")
  + "线上重签：https://sd-cq21.example.org/s\r\n（股东账号+身份证+人脸）\r\n"
  "未重签将限制交易。\r\n",
  "malicious", "pii_harvest", ["gem_repermission_face"], "权限重签收人脸")
E("mal_0515_abnormal_freeze.eml",
  HD("风控中心", "fk@broker-risk21.example", "investor@personal.example", "账户触发异常交易监控（临时冻结）")
  + "解除冻结需核验：https://fk-jc21.example.info/u\r\n（交易密码+身份证）\r\n",
  "malicious", "account_phishing", ["auto"], "b30fix")
E("mal_0516_client_ctrl.eml",
  HD("交易服务", "jy@broker-client21.example", "investor@personal.example", "交易客户端安全控件更新（必装）")
  + "不更新将无法登录交易。\r\n"
  "控件包：https://jy-kj21.example.info/setup.exe\r\n",
  "malicious", "malware_attachment", ["trading_control_update_exe"], "交易控件 exe 直链——券商钓鱼经典")
E("mal_0512b_bond_sub.eml",
  HD("可转债", "zz@broker-bond21.example", "investor@personal.example", "配号成功，缴款链接")
  + "可转债 AA+ 债缴款：https://zz-jk21.example.vip/b\r\n（股东账号+密码）\r\n",
  "malicious", "credential_harvest", ["convertible_bond_pay"], "可转债缴款")
E("mal_0517_advisor_renew.eml",
  HD("投顾服务", "tg@advisor-svc21.example", "investor@personal.example", "投顾服务到期（不续费将清出策略组）")
  + "续费直付：https://tg-xf21.example.vip/r\r\n（服务密码+银行卡）\r\n",
  "malicious", "credential_harvest", ["advisor_renew_collect"], "投顾续费")
E("mal_0518_level2.eml",
  HD("行情服务", "hq@level2-svc21.example", "investor@personal.example", "Level-2 行情权益暂停（账户核验失败）")
  + "重新核验：https://hq-hy21.example.info/v\r\n（交易账号+密码）\r\n",
  "malicious", "credential_harvest", ["level2_reauth"], "行情核验")
E("mal_0519_third_deposit.eml",
  HD("银证业务", "yz@bank-svc21.example", "investor@personal.example", "三方存管账户变更确认")
  + "确认新三方存管：https://yz-qr21.example.info/c\r\n（原卡号+新卡号+取款密码）\r\n",
  "malicious", "credential_harvest", ["auto"], "b30fix")
E("mal_0520_csrc_inquiry.eml",
  HD("上市公司证券部", "ir@listed-co-relay21.example", "cfo@corp.internal", "证监会问询函转发（需财务数据）")
  + "问询函要求 9/26 前回复，所需底稿清单见附件，数据请回传加密包：\r\n"
  "（密码另发）\r\n",
  "malicious", "pii_harvest", ["fake_csrc_inquiry", "reply_exfil"], "假问询函收财务底稿", "zh", "plain", "review", True,
  "上市公司确实会因问询函催数据——'回传加密包'渠道异常是弱线索，应复核")
E("mal_0521_insider_probe.eml",
  HD("合规监察", "jc@exchange-svc21.example", "exec@corp.internal", "内幕交易线索协查通知")
  + "涉及贵司 9 月公告前交易，需配合调查并提交说明：\r\n"
  "https://jc-xc21.example.org/d\r\n（高管名单+交易账户）\r\n",
  "malicious", "pii_harvest", ["fake_insider_probe"], "假内幕交易协查（恐吓高管）")
E("mal_0522_algo_whitelist.eml",
  HD("量化服务", "lh@quant-svc21.example", "quant@corp.internal", "算法交易白名单审核未通过")
  + "重新提交：https://lh-sc21.example.info/f\r\n（交易系统账号+密码）\r\n",
  "malicious", "credential_harvest", ["algo_whitelist_lure"], "量化白名单")
E("mal_0523_hk_connect.eml",
  HD("港股通", "ggt@broker-hk21.example", "investor@personal.example", "港股通权限年度确认")
  + "确认：https://ggt-qr21.example.info/y\r\n（股东账号+交易密码）\r\n",
  "malicious", "credential_harvest", ["auto"], "b30fix")
E("mal_0524_research_desk.eml",
  HD("研究所", "yjs@sell-side21.example", "fund@corp.internal", "限免研报（机构认证）")
  + "机构认证（工牌+邮箱+密码）：https://yjs-rz21.example.info/v\r\n",
  "malicious", "credential_harvest", ["research_access_collect"], "研报权限收凭据")
E("mal_0525_ipohk.eml",
  HD("孖展认购", "mj@hk-ipo21.example", "investor@personal.example", "IPO 孖展额度确认（今日截止）")
  + "确认：https://mj-qr21.example.vip/c\r\n（券商账户+密码+银行卡后三位）\r\n",
  "malicious", "credential_harvest", ["hk_margin_ipo"], "港股孖展")
E("mal_0526_transfer_delay.eml",
  HD("清算服务", "qs@clearing-svc21.example", "treasury@corp.internal", "清算头寸差异需平账")
  + "差异 48,000 需今日平账：\r\n收款：6225 0091 3311 8820\r\n（附差异明细回执）\r\n",
  "malicious", "bec", ["fake_clearing_difference"], "假清算差异平账")
E("mal_0527_fund_dd.eml",
  HD("TA登记", "ta@fund-ta21.example", "investor@personal.example", "基金账户身份信息过期")
  + "更新：https://ta-gx21.example.info/u\r\n（身份证+银行卡+预留手机）\r\n",
  "malicious", "pii_harvest", ["ta_identity_expire"], "TA登记过期")
E("mal_0528_wealth_vip.eml",
  HD("私行专属", "sz@private-bank21.example", "cfo@corp.internal", "专属额度（固收+，额度 500 万）")
  + "额度锁定：https://sz-sd21.example.vip/l\r\n（合格投资者核验+大额转账验证）\r\n",
  "malicious", "account_phishing", ["private_bank_quota"], "私行额度")
E("mal_0529_option_exec.eml",
  HD("期权经营机构", "qq@option-svc21.example", "investor@personal.example", "期权行权日提醒（资金不足）")
  + "行权资金补足：https://qq-bz21.example.info/f\r\n（期权账户+银行密码）\r\n",
  "malicious", "credential_harvest", ["auto"], "b30fix")
E("mal_0530_fut_margin.eml",
  HD("期货风控", "qh@futures-risk21.example", "investor@personal.example", "保证金率触警，账户存在强平风险")
  + "追加入金：https://qh-zj21.example.info/d\r\n（期货账户+银行密码）\r\n",
  "malicious", "credential_harvest", ["futures_margin_bank_password"], "期货追保收银行密码")

# ---- 券商 ham ----
E("ham_0456_ipo_pay_real.eml",
  HD("证券服务", "svc@broker.example", "investor@personal.example", "中签缴款提示")
  + "已从中签信息看，缴款日 9/24，请确保 16:00 前主账户有足额资金，\r\n"
  "系统自动扣款。操作请在官方 App 内完成，我司不发缴款链接。\r\n",
  "benign", "ham_personal", ["ipo_real_autodeduct"], "真中签：自动扣款+无链接")
E("ham_0457_margin_real.eml",
  HD("融资融券", "rz@broker.example", "investor@personal.example", "维持担保比例提醒")
  + "当前 155%，低于预警线 160%。可通过普通卖出或银证转账追加，\r\n"
  "均在交易 App 内操作；我司不会索要密码。\r\n",
  "benign", "ham_personal", ["margin_real_app_only"], "真追保：App 内操作+不索密码")
E("ham_0458_monthly_stmt.eml",
  HD("对账单", "dz@broker.example", "investor@personal.example", "9月度对账单")
  + "对账单在 App-我的-对账单查看。\r\n",
  "benign", "ham_personal", ["stmt_real_app"], "")
E("ham_0459_commission_real.eml",
  HD("客户服务", "kh@broker.example", "investor@personal.example", "佣金率调整已生效")
  + "按约调至万 2.5，App 内可查。\r\n",
  "benign", "ham_personal", ["commission_real_done"], "")
E("ham_0460_fund_confirm_real.eml",
  HD("基金销售", "xs@fund.example", "investor@personal.example", "申购确认单（T+1）")
  + "确认份额见附件 PDF。\r\n",
  "benign", "ham_personal", ["auto"], "b30fix")
E("ham_0461_dividend_real.eml",
  HD("基金公告", "gg@fund.example", "investor@personal.example", "分红公告：每份 0.021 元")
  + "红利再投默认，App 内可改。\r\n",
  "benign", "ham_personal", ["dividend_real_notice"], "")
E("ham_0462_struct_mature.eml",
  HD("理财", "lc@bank.example", "me@personal.example", "结构性存款到期兑付")
  + "本金+收益已入关联账户，明细见回单。\r\n",
  "benign", "ham_personal", ["struct_real_mature"], "")
E("ham_0463_research_real.eml",
  HD("研究所", "yjs@sell-side.example", "fund@corp.internal", "晨会纪要（9/23）")
  + "观点与个股逻辑见附件 PDF。\r\n退订回 TD。\r\n",
  "benign", "ham_business", ["research_real_attachment"], "真研报走附件")
E("ham_0464_strategy_conf.eml",
  HD("策略会", "clh@sell-side.example", "fund@corp.internal", "四季度策略会（10/15）")
  + "线下席位确认回复本邮件，线上链接会前一日短信发送。\r\n",
  "benign", "ham_business", ["strategy_conf_real"], "真策略会：链接走短信")
E("ham_0465_fut_real.eml",
  HD("期货风控", "qh@futures.example", "investor@personal.example", "交割月持仓提示")
  + "请于最后交易日前自行移仓，App 内操作。\r\n",
  "benign", "ham_personal", ["auto"], "b30fix")
E("ham_0466_clearing_real.eml",
  HD("清算", "qs@bank.example", "treasury@corp.internal", "日终清算无异常")
  + "各账户头寸一致。\r\n",
  "benign", "ham_business", ["clearing_real_clean"], "与假清算差异对照")
E("ham_0467_pay_settle.eml",
  HD("支付", "zj@pay.example", "merchant@corp.internal", "T+1 结算到账")
  + "昨日交易款已结算至预留账户。\r\n",
  "benign", "ham_business", ["settle_real_done"], "")
E("ham_0468_csrc_real.eml",
  HD("证监会", "fw@csrc.example", "cfo@corp.internal", "问询函回复已签收")
  + "已签收，回复将依规披露。\r\n本邮件无附件无链接。\r\n",
  "benign", "ham_business", ["csrc_real_receipt"], "与假问询函同形：真监管收发都走平台")
E("ham_0469_exchange_real.eml",
  HD("交易所", "tz@exchange.example", "ir@corp.internal", "监管工作函已电子送达")
  + "请于公司业务平台查收（CA 登录）。\r\n",
  "benign", "ham_business", ["auto"], "b30fix")
E("ham_0470_travel_finance.eml",
  HD("差旅", "travel@corp.internal", "finance@corp.internal", "出差备用金规则更新")
  + "海外出差备用金上限调整，财务频道见。\r\n",
  "benign", "ham_business", ["travel_fund_real"], "")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch30 written: {len(LABELS)} samples")
