#!/usr/bin/env python3
"""Batch 13: individually authored (10 mal + 10 ham + 10 gray pairs)."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def H(disp, frm, to, subj, extra=""):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Sat, 05 Sep 2026 10:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b13@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\n")
P = "Content-Type: text/plain; charset=utf-8\r\n\r\n"
def E(n, raw, label, family, tech, note="", lang="zh", expected=None, ambiguous=False, borderline=""):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": expected or ("block" if label == "malicious" else "deliver"),
        "engine_status": "not_evaluated", "synthetic": True, "batch": 13,
        "note": note, "ambiguous": ambiguous, "borderline": borderline})

E("mal_0211_insurance_lapse.eml",
  (H("保单服务", "bd@insure-lapse.example", "me@personal.example", "保单宽限期最后3天") + P +
   "您的保单进入宽限期最后 3 天，未补缴将失效。\r\n"
   "续期账户变更确认：https://insure-cont.example.info/x\r\n"
   "（保单号+身份证+新银行卡）\r\n").encode(),
  "malicious", "account_phishing", ["policy_lapse_change"], "以失效恐吓改收款账户")

E("mal_0212_court_notice.eml",
  (H("诉讼服务", "ss@court-notify.example", "legal@corp.internal", "传票送达失败（二次）") + P +
   "您涉及的案件传票二次送达失败，今日未确认将缺席审理：\r\n"
   "确认送达（身份证+手机号）：https://court-cs.example.org/d\r\n").encode(),
  "malicious", "social_trust", ["fake_court_summons"], "法院传票恐吓")

E("mal_0213_audit_penalty.eml",
  (H("税务稽查", "jc@tax-check.example", "finance@corp.internal", "稽查事项告知（限时陈述）") + P +
   "贵司被列入稽查对象，需 3 日内提交陈述申辩材料：\r\n"
   "https://jc-sc.example.org/up\r\n"
   "（统一社会信用代码+经办人身份证+对公账户）\r\n").encode(),
  "malicious", "pii_harvest", ["audit_penalty_collect"], "稽查恐吓财务")

E("mal_0214_data_breach.eml",
  (H("泄露通知", "notice@breach-alert.example", "me@personal.example", "您的信息出现在泄露库中") + P +
   "监测到您的邮箱+密码出现在新泄露库，立即检查泄露详情并改密：\r\n"
   "https://breach-check.example.info/q\r\n"
   "（邮箱+常用密码查询）\r\n").encode(),
  "malicious", "credential_harvest", ["breach_check_collect"], "以泄露为饵收常用密码")

E("mal_0215_password_check.eml",
  (H("安全中心", "pw@safe-check.example", "me@personal.example", "您的密码强度过低") + P +
   "检测到您在多平台使用相同弱密码，安全评分 32 分。\r\n"
   "一键体检（输入常用密码比对泄露库）：https://pw-tj.example.vip/s\r\n").encode(),
  "malicious", "credential_harvest", ["password_score_collect"], "")

E("mal_0216_family_group.eml",
  (H("家族群", "qun@family-reun.example", "me@personal.example", "家谱修订（登记信息）") + P +
   "族谱新修，请登记全家身份信息：\r\n"
   "https://jiapu-reg.example.info/f\r\n"
   "（姓名+身份证号+生辰）\r\n").encode(),
  "malicious", "pii_harvest", ["genealogy_collect"], "熟人文化话术")

E("mal_0217_charity_run.eml",
  (H("公益跑", "run@charity-sport.example", "me@personal.example", "公益名额保留（捐步换配捐）") + P +
   "您的公益跑名额保留至明日，确认需绑定收款账户（配捐返还）：\r\n"
   "https://run-peidu.example.club/b\r\n").encode(),
  "malicious", "pii_harvest", ["charity_bind_card"], "以配捐返绑卡")

E("mal_0218_photobook.eml",
  (H("云相册", "xc@photo-album.example", "me@personal.example", "家人共享相册邀请（3日有效）") + P +
   "接受邀请查看共享相册（需登录）：\r\n"
   "https://album-inv.example.info/j\r\n"
   "（手机号+云服务密码）\r\n").encode(),
  "malicious", "credential_harvest", ["album_inv_collect"], "")

E("mal_0219_car_wash_card.eml",
  (H("洗车行", "card@wash-svc.example", "driver@personal.example", "储值卡迁移（老系统停用）") + P +
   "老卡余额需迁移到新系统：\r\n"
   "https://wash-migrate.example.info/m\r\n"
   "（卡号+手机号+支付密码）\r\n").encode(),
  "malicious", "credential_harvest", ["card_migrate_pay_password"], "")

E("mal_0220_metro_eml",
  (H("地铁服务", "dt@metro-svc.example", "commuter@personal.example", "乘车码异常（风控）") + P +
   "您的乘车码触发风控，解除需核验：\r\n"
   "https://metro-jc.example.org/v\r\n"
   "（手机号+支付密码）\r\n").encode(),
  "malicious", "credential_harvest", ["metro_risk_password"], "")

E("ham_0211_policy_real.eml",
  (H("保单服务", "svc@insure.example", "me@personal.example", "宽限期提醒（续期方式说明）") + P +
   "您的保单 9/12 进入宽限期。续期请在官方 App 或柜面办理，\r\n"
   "本邮件不含链接；我们不会要求变更收款账户。\r\n").encode(),
  "benign", "ham_personal", ["policy_real_notice"], "真宽限提醒自带渠道纪律")

E("ham_0212_court_real.eml",
  (H("法院电子送达", "eticket@court.example", "legal@corp.internal", "电子送达成功回执") + P +
   "（2026）杭01民初8842号 传票已电子送达成功。\r\n"
   "回执在法院送达平台查看（短信附验证码），本邮件无链接。\r\n").encode(),
  "benign", "ham_business", ["court_real_delivery"], "真送达无链接+独立验证码渠道")

E("ham_0213_tax_real.eml",
  (H("税务局", "ns@tax-gov.example", "finance@corp.internal", "电子税务局：事项提醒") + P +
   "贵司有一项待办（汇算清缴确认），请登录电子税务局办理。\r\n"
   "官方渠道：APP 或办税服务厅，谨防虚假稽查通知。\r\n").encode(),
  "benign", "ham_business", ["tax_real_todo"], "与假稽查同形+官方渠道声明")

E("ham_0214_breach_real.eml",
  (H("安全提醒", "sec@pwd-mgr.example", "me@personal.example", "密码管家：1 个站点泄露提醒") + P +
   "您保存的某站点凭据出现在公开泄露库，建议在站内改密。\r\n"
   "我们永远不会索要您的密码明文。\r\n").encode(),
  "benign", "ham_business", ["pwdmgr_real_alert"], "与假泄露查询同形（永不收明文）")

E("ham_0215_family_real.eml",
  (H("大伯", "bo@family.example", "me@personal.example", "过年族谱那事") + P +
   "族里说清明把谱修了，你的支脉信息我按你爸记忆填的，\r\n"
   "回头你电话里对一遍就行。\r\n").encode(),
  "benign", "ham_personal", ["family_genealogy_real"], "真族谱修订走电话核对")

E("ham_0216_charity_real.eml",
  (H("基金会", "fo@charity.example", "me@personal.example", "月捐扣款回执（9月）") + P +
   "9 月月捐 30 元已扣款成功，发票可在官网自助开具。\r\n"
   "如需暂停请在官网账户内操作。\r\n").encode(),
  "benign", "ham_personal", ["charity_real_receipt"], "")

E("ham_0217_album_real.eml",
  (H("云相册", "share@photos.example", "me@personal.example", "「2024 云南」已与你共享") + P +
   "家人向你共享了相册，在相册 App-共享栏查看。\r\n"
   "邀请也在 App 内接受，无需另行登录。\r\n").encode(),
  "benign", "ham_personal", ["album_real_share"], "与假相册邀请同形（App 内闭环）")

E("ham_0218_wash_real.eml",
  (H("洗车行", "card@wash-svc.example", "driver@personal.example", "系统升级：余额自动转入") + P +
   "会员系统升级，余额已自动平移，无需操作。\r\n"
   "旧卡可继续刷。\r\n").encode(),
  "benign", "ham_personal", ["wash_real_auto"], "与假迁移同形（自动平移不索密码）")

E("ham_0219_metro_real.eml",
  (H("地铁服务", "dt@metro.example", "commuter@personal.example", "月度行程账单") + P +
   "8 月共 44 次，通勤优惠已自动抵扣。\r\n"
   "账单详情在官方 App 查看。\r\n").encode(),
  "benign", "ham_personal", ["metro_real_bill"], "")

E("ham_0220_run_real.eml",
  (H("公益跑", "run@charity.example", "me@personal.example", "捐步配捐公示") + P +
   "上月配捐总额与流向已公示在官网，\r\n"
   "配捐直达基金会对公账户，不涉及个人返还。\r\n").encode(),
  "benign", "ham_personal", ["run_real_public"], "")

# ---- gray pairs ----
E("gray_0051_supply_fake.eml",
  (H("PyPI Security", "sec@pypi-sec.example", "dev@corp.internal", "Malicious package in your requirements") + P +
   "Your requirements.txt pins a typosquatted package. Remediation wizard:\r\n"
   "https://pypi-fix.example.info/wiz (sign in with your PyPI credentials)\r\n").encode(),
  "malicious", "credential_harvest", ["fake_pypi_wizard"], "收 PyPI 凭据", "en",
  "block", True, "供应链告警真假同形；真平台向导在官方域内且不重收凭据")

E("gray_0052_supply_real.eml",
  (H("PyPI", "noreply@pypi.example", "dev@corp.internal", "Security notice: typosquat detected") + P +
   "A dependency you follow was removed for typosquatting.\r\n"
   "Review your lockfile at https://pypi.example/manage (existing session only).\r\n").encode(),
  "benign", "ham_business", ["pypi_real_notice"], "官方域+已有会话", "en",
  "deliver", True, "真通告用官方域、不索新凭据、只读性质")

E("gray_0053_edr_fake.eml",
  (H("终端安全", "edr@sec-endpoint2.example", "staff@corp.internal", "隔离通知：检测到键盘记录行为") + P +
   "您的终端已被隔离。自解通道（域账号+动态码）：\r\n"
   "https://edr2-relieve.example.info/u\r\n"
   "超时将通知主管。\r\n").encode(),
  "malicious", "credential_harvest", ["edr_fake_relief"], "恐吓+收域凭据", "zh",
  "block", True, "假 EDR；真企业 EDR 从不让用户自助'解隔离'")

E("gray_0054_edr_real.eml",
  (H("终端安全", "edr@corp.internal", "staff@corp.internal", "隔离说明：您的终端已由 SOC 接管处置") + P +
   "您的终端检测到风险已自动隔离，SOC 正在处置，\r\n"
   "请勿自行操作，IT 会在 30 分钟内联系您。\r\n").encode(),
  "benign", "ham_business", ["edr_real_soc_owned"], "真处置是接管而非自助", "zh",
  "deliver", True, "真 EDR 通知的标志：明确处置主体与时间窗，无任何'操作入口'")

E("gray_0055_bid_fake.eml",
  (H("采购中心", "cg@bid-supp.example", "bd@corp.internal", "入围通知：缴纳入围保证金 2 万") + P +
   "贵司已入围，需今日缴纳入围保证金 20,000 至指定账户：\r\n"
   "户名：XX 采购代理；卡号：6225 0091 2233 4455\r\n"
   "（对公转账，备注项目名）\r\n").encode(),
  "malicious", "bec", ["bid_fake_account"], "直接给个人格式卡号", "zh",
  "block", True, "招投标钓鱼的变体：'入围费'；真平台走保证金托管不出个人卡号")

E("gray_0056_bid_real2.eml",
  (H("政采云", "notify@zcy.example", "bd@corp.internal", "保证金退还公示（项目 G-2026-114）") + P +
   "贵司保证金已按原路径退回，1-3 工作日到账。\r\n"
   "退款进度在平台-我的保证金查询。\r\n").encode(),
  "benign", "ham_business", ["bid_real_refund"], "原路退回+平台查询", "zh",
  "deliver", True, "真保证金流：原路退回，绝不出现新卡号")

E("gray_0057_kyc_fake.eml",
  (H("银行", "kh@bank-kyc.example", "finance@corp.internal", "单位账户年检（KYC 材料更新）") + P +
   "按反洗钱要求更新开户资料，请在线提交：\r\n"
   "https://kyc-bank.example.org/u\r\n"
   "（法人身份证+对公账户+网银管理员密码）\r\n").encode(),
  "malicious", "credential_harvest", ["kyc_collect"], "以 KYC 收网银密码", "zh",
  "block", True, "银行 KYC 真实存在；但绝不会索要网银管理员密码")

E("gray_0058_kyc_real.eml",
  (H("银行客户经理", "li@bank.example", "finance@corp.internal", "账户年检：下周二上门") + P +
   "年检材料清单已发您邮箱（纸质）：执照、法人证、开户许可。\r\n"
   "我们周二 10:00 上门收取，带回行内办理。\r\n").encode(),
  "benign", "ham_business", ["kyc_real_offline"], "真年检走线下客户经理", "zh",
  "deliver", True, "真 KYC 的渠道纪律：纸质+上门，不搞在线收密")

E("gray_0059_invoice_tax_fake.eml",
  (H("税务代开", "dk@fp-dai.example", "freelancer@personal.example", "劳务发票代开（税费代缴）") + P +
   "代开劳务发票 6,000 元档，税费 480 由我们代缴，\r\n"
   "先付税费后出票：https://fp-dai.example.vip/k\r\n").encode(),
  "malicious", "bec", ["invoice_prepay"], "先付后出票", "zh",
  "block", True, "个人代开场景真假混杂（真代开在税务大厅或官方电子税务局）")

E("gray_0060_invoice_tax_real.eml",
  (H("电子税务局", "svc@etax.example", "freelancer@personal.example", "代开发票开具成功") + P +
   "您代开的劳务发票已开具，文件在电子税务局-我的发票下载。\r\n"
   "税费已同步申报，本邮件为通知，不含缴费链接。\r\n").encode(),
  "benign", "ham_business", ["etax_real_issue"], "官方签发+无支付链接", "zh",
  "deliver", True, "真代开是先申报后出票、全在官方端闭环")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch13 written: {len(LABELS)} samples")
