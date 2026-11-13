#!/usr/bin/env python3
"""Batch 7: gray-zone samples. Each carries `ambiguous: true`, a one-line
`borderline` note, and expected in {block, deliver, review} where review =
should land in quarantine/human triage, not auto-decided."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def H(disp, frm, to, subj, extra=""):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Sun, 30 Aug 2026 15:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b7@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\n")
P = "Content-Type: text/plain; charset=utf-8\r\n\r\n"
def E(n, raw, label, family, tech, expected, borderline, lang="zh"):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": expected, "engine_status": "not_evaluated",
        "synthetic": True, "ambiguous": True, "batch": 7, "borderline": borderline})

# ---------- mal-leaning gray ----------
E("gray_0001_sub_renew.eml",
  (H("订阅服务", "billing@stream-svc.example", "me@personal.example", "您的订阅已续费成功 ¥258") + P +
   "您的年度订阅已续费成功。如非本人操作，请立即点此取消并申请退款：\r\n"
   "https://sub-cancel-help.example.vip/refund\r\n").encode(),
  "malicious", "account_phishing", ["post_fact_refund_lure"], "block",
  "事后型钓鱼：先制造\"已扣费\"恐慌再给退款入口；真实商户也有类似模板")

E("gray_0002_interview_docs.eml",
  (H("招聘-初筛", "hr@startup-hire.example", "candidate@mail.example", "初筛通过，请补交证件材料") + P +
   "恭喜进入二面前置材料环节，请回复本邮件附上：\r\n"
   "身份证正反面、学历证书扫描件、近期生活照一张。\r\n"
   "材料仅 HR 可见。\r\n").encode(),
  "malicious", "pii_harvest", ["reply_pii_job"], "review",
  "与真实入职流程同形；回复式收集证件照本身即高危，应转人工确认招聘真实性")

E("gray_0003_groupbuy_person.eml",
  (H("行政-小李", "xiaoli.personal@163.example", "staff@corp.internal", "部门中秋礼盒最后统计") + P +
   "礼盒 188/份，走我个人代收（微信/支付宝都行），\r\n"
   "转账后回我邮箱登记份数，明天截止统一下单。\r\n").encode(),
  "malicious", "social_trust", ["personal_account_collect"], "review",
  "可能是真同事也可能是冒名；个人邮箱+个人收款是明确危险信号，但话术完全日常")

E("gray_0004_fund_channel.eml",
  (H("财富管家", "advisor@wealth-desk.example", "cfo@corp.internal", "一期产品临时退出通道（内部）") + P +
   "老客户专属：本期年化 8.2%，额度 30 万内 T+0 退出，\r\n"
   "通道今晚关闭：https://wealth-inner.example.vip/door\r\n").encode(),
  "malicious", "account_phishing", ["yield_promise_door"], "block",
  "收益承诺+限时通道是典型投资诈骗，但话术比俗套钓鱼更像正规理财营销")

E("gray_0005_cod_fee.eml",
  (H("快件", "notice@parcel-cod.example", "me@personal.example", "您有待付快递 39 元（今日退回）") + P +
   "包裹已到小区驿站三天，到付 39 元未结。\r\n"
   "缴纳入口：https://parcel-cod-pay.example.info/a\r\n"
   "今日未付将退回发件方。\r\n").encode(),
  "malicious", "account_phishing", ["cod_small_amount"], "block",
  "小额到付钓鱼；金额小到很多人不假思索就付")

E("gray_0006_points_fake.eml",
  (H("积分服务", "jf@carrier-points.example", "me@personal.example", "积分即将清零") + P +
   "您有 15600 积分将于月底清零，可兑话费/油卡：\r\n"
   "https://carrier-points-dh.example.co/ex\r\n").encode(),
  "malicious", "account_phishing", ["points_lookalike_domain"], "block",
  "运营商积分话术完全正规，唯一破绽在域名——需要域名知识才能判别的灰")

E("gray_0007_headhunt_bg.eml",
  (H("猎头-Vivian", "vivian@top-search.example", "me@personal.example", "职位匹配，附背景登记表") + P +
   "岗位匹配度很高，方便的话填一下背景登记表（含身份证号与现薪），\r\n"
   "回传我这边推给客户。表在附件区 Excel。\r\n").encode(),
  "malicious", "pii_harvest", ["headhunt_pii_form"], "review",
  "猎头行业确实这么干；收集身份证号于邮件流仍是 PII 风险")

E("gray_0008_keynote_fee.eml",
  (H("会议组委会", "committee@global-forum.example", "research@corp.internal", "特邀报告邀请（注册确认）") + P +
   "诚挚邀请您作特邀报告。确认出席需完成注册缴费（特邀 480 美元）：\r\n"
   "https://forum-reg.example.org/pay\r\n"
   "缴费后发出正式邀请函。\r\n").encode(),
  "malicious", "account_phishing", ["invite_then_fee"], "block",
  "真实存在的学术会议诈骗模式：先给荣誉感再收费")

E("gray_0009_domain_squat.eml",
  (H("品牌保护", "watch@brand-monitor.example", "legal@corp.internal", "监测到贵司关联域名被抢注") + P +
   "我们监测到 corp-internal.net 被第三方注册，建议贵司优先维权申赎。\r\n"
   "处理入口：https://brand-watch-act.example.info/case\r\n"
   "（错过申赎期将进入公开拍卖）\r\n").encode(),
  "malicious", "social_trust", ["domain_squat_pressure"], "block",
  "域名服务推销/骗局混合体；制造恐慌但全程不出现典型钓鱼词")

E("gray_0010_invoice_agent.eml",
  (H("开票服务", "kf@fapiao-svc.example", "tax@corp.internal", "税点优惠代开（可验票）") + P +
   "品目齐全、可验真、税点 1.5 起。\r\n"
   "长期合作加微信 kp-88866（备注行业）。\r\n").encode(),
  "malicious", "bec", ["invoice_fraud_spam"], "block",
  "虚开发票灰产：不是钓鱼但明确违法，业务上必须拦")

E("gray_0011_deposit_job.eml",
  (H("数据标注派单", "dan@label-work.example", "student@mail.example", "派单成功，需缴物料保证金 99") + P +
   "已为您派单 200 条/日。开工前缴物料保证金 99 元，\r\n"
   "满月全退：https://label-deposit.example.vip/pay\r\n").encode(),
  "malicious", "pii_harvest", ["job_deposit"], "block",
  "兼职骗局标准形态；对受害者而言与真实派单平台观感一致")

E("gray_0012_prize_tax.eml",
  (H("活动中心", "act@lucky-draw.example", "me@personal.example", "中奖资格已锁定，需缴押金解冻") + P +
   "您抽中的手机已锁定，海关扣押需缴 800 元押金解冻，\r\n"
   "到账后随奖品返还：https://lucky-unlock.example.club/g\r\n").encode(),
  "malicious", "social_trust", ["prize_deposit"], "block",
  "老式但仍然有效的中奖骗局")

E("gray_0013_charity_code.eml",
  (H("互助小组", "help@flood-relief.example", "all@corp.internal", "灾区旧物+捐款募集（同事转发）") + P +
   "受灾区同学所托转发：接收旧衣与捐款，\r\n"
   "捐款二维码见图（个人收款码，备注村名），明细周日公示。\r\n").encode(),
  "malicious", "social_trust", ["charity_personal_qr"], "review",
  "可能是真实互助；邮件渠道个人收款码+灾情紧迫感无法静态判定，应人工核实")

E("gray_0014_it_password.eml",
  (H("运维-张工", "zhang.ops@partner.example", "it@corp.internal", "迁移需要你的账号密码（临时）") + P +
   "今晚做邮件迁移，需要你把域账号密码发我邮箱走批量通道，\r\n"
   "明早迁移完你再改密。配合一下，赶窗口。\r\n").encode(),
  "malicious", "credential_harvest", ["ask_password_direct"], "block",
   "任何真实 IT 都不该索要明文密码；话术却完全像内部协作")

E("gray_0015_vendor_hijack.eml",
  (H("华信贸易-应收", "ap@hongxin-trade.example", "ap@corp.internal", "Re: 9月货款安排",
     "In-Reply-To: <po-2026-203@corp.internal>\r\nReferences: <po-2026-203@corp.internal>\r\n") + P +
   "王会计：9 月货款按合同 12 日付，金额不变。\r\n"
   "另：我们开户行网点迁址，收款账号启用新的，新账号今晚发你邮箱，\r\n"
   "付款前电话和我们财务再对一遍。\r\n").encode(),
  "malicious", "bec", ["vendor_hijack_new_account"], "review",
  "供应商账户劫持的标准形态：正文完全正常的真实往来，唯一危险信号是'今晚发新账号'+要求电话确认被自己抵消；静态不可判定，必须复核")

E("gray_0016_ceo_fake.eml",
  (H("陈总", "chen.ceo@mail-priv.example", "ea@corp.internal", "在吗，处理个事") + P +
   "在吗？我在外面开会。有笔保密事项需要你先个人垫付，\r\n"
   "金额不大但很急，回我邮箱，别走公司流程。\r\n").encode(),
  "malicious", "bec", ["ceo_impostor_advance"], "review",
  "假 CEO；同形对照见 gray_0031——两封静态特征几乎一致，靠发件域与垫付细节区分")

E("gray_0017_tm_fake.eml",
  (H("知产代理", "agent@ip-quick.example", "legal@corp.internal", "贵司商标面临驳回风险（今日答复）") + P +
   "监测到贵司核心商标被提无效宣告，今日为答复最后一日。\r\n"
   "加急通道：https://ip-urgent.example.co/act\r\n"
   "错过将丧失在先权利。\r\n").encode(),
  "malicious", "account_phishing", ["tm_pressure_deadline"], "block",
  "同形对照见 gray_0032；假代理用期限恐慌，真代理也会催期限")

E("gray_0018_apc_fake.eml",
  (H("期刊部", "apc@jsc-ind.example", "research@corp.internal", "Article accepted - APC settlement") + P +
   "Your manuscript JSI-2026-1147 is accepted. APC 1,850 USD settles the issue slot:\r\n"
   "https://jsc-ind-pay.example.org/apc\r\n"
   "Slot released on payment.\r\n").encode(),
  "malicious", "account_phishing", ["apc_fake_journal"], "block", "同形对照见 gray_0033；掠夺性期刊与真期刊同形")

E("gray_0019_claim_ok.eml",
  (H("理赔中心", "ok@claim-fast.example", "me@personal.example", "您的理赔已批复 3,800 元") + P +
   "理赔已批复。为完成打款，请添加专员企业微信核对收款信息，\r\n"
   "专员号见页面：https://claim-svc-add.example.info/kefu\r\n").encode(),
  "malicious", "pii_harvest", ["claim_add_contact"], "block",
  "理赔话术+引流私域，真理赔公司有时也加企微——引流方式本身是灰")

E("gray_0020_video_cancel.eml",
  (H("视频会员", "svc@vdo-mall.example", "me@personal.example", "自动续费将扣 45 元，取消请点") + P +
   "您的连续包月将于明晚扣费。如需取消：\r\n"
   "https://vdo-cancel-help.example.vip/stop\r\n"
   "（旧入口已停用）\r\n").encode(),
  "malicious", "account_phishing", ["cancel_page_lure"], "block",
  "取消入口钓鱼；用户主动想取消时警惕性最低")

# ---------- benign-leaning gray ----------
E("gray_0021_promo_renew.eml",
  (H("会员俱乐部", "club@vendor.example", "me@personal.example", "续费 5 折今日 24 点截止") + P +
   "老会员回馈：续费年卡 5 折，今日 24:00 截止。\r\n"
   "https://vendor.example/club/renew\r\n"
   "退订本类邮件点页脚。\r\n").encode(),
  "benign", "ham_business", ["marketing_urgency_official_domain"], "deliver",
  "紧迫感+链接+扣费话术俱全，但域名与发件一致、有退订——典型营销误报样本")

E("gray_0022_bank_antiphish.eml",
  (H("安全中心", "security@bank.example", "me@personal.example", "近期假冒我行钓鱼增多，请留意") + P +
   "尊敬的客户：近期发现假冒我行的\"账户异常\"短信与邮件。\r\n"
   "我行不会以邮件索要密码验证码。可疑信息请转发 security@bank.example。\r\n"
   "本邮件不含任何链接。\r\n").encode(),
  "benign", "ham_business", ["antiphish_advisory_no_link"], "deliver",
  "内容全是钓鱼词汇的防钓鱼提醒；规则引擎最易误伤的一类")

E("gray_0023_saas_expiry.eml",
  (H("SaaS Billing", "billing@saas-vendor.example", "ops@corp.internal", "Workspace expires in 7 days") + P +
   "Your workspace expires Sep 6. Renew in the console to avoid suspension:\r\n"
   "https://console.saas-vendor.example/billing\r\n"
   "This is the final automated reminder.\r\n").encode(),
  "benign", "ham_business", ["saas_expiry_button"], "deliver",
  "到期+最后提醒+登录按钮，钓鱼三件套齐全但全是真商务邮件标配")

E("gray_0024_hr_contact.eml",
  (H("人资系统", "ehr@corp.internal", "staff@corp.internal", "请更新您的紧急联系人信息") + P +
   "年度信息核对：请登录门户-个人-紧急联系人更新。\r\n"
   "https://portal.corp.internal/ehr/contact\r\n"
   "未更新不影响工资发放。\r\n").encode(),
  "benign", "ham_business", ["hr_info_update"], "deliver",
  "\"更新信息+登录\"与钓鱼同形，但内网域名与宽松期限是良性信号")

E("gray_0025_zoom_invite.eml",
  (H("日程助手", "no-reply@cal.example", "team@corp.internal", "邀请：架构评审 @ 周四") + P +
   "外部访客发起的视频会议邀请已同步。\r\n"
   "加入链接：https://cal.example/j/984-221-775\r\n"
   "已附加到你的日历。\r\n").encode(),
  "benign", "ham_business", ["external_meet_link"], "deliver",
  "外部会议链接是投毒高发载体，但这封是标准日历流")

E("gray_0026_redpacket.eml",
  (H("商城", "m@shop-app.example", "me@personal.example", "您有 50 元红包今日过期") + P +
   "打开 App 首页领取，也可在\"我的-资产\"查看。\r\n"
   "https://shop-app.example/r/50\r\n").encode(),
  "benign", "ham_business", ["redpacket_expiry"], "deliver",
  "过期红包与钓鱼的\"限时\"同构；真商城也天天发")

E("gray_0027_headhunt_real.eml",
  (H("猎头-Vivian", "vivian@ksearch.example", "me@personal.example", "JD：平台架构师（杭州/远程）") + P +
   "客户是出海电商独角兽，P8，预算给到 120。\r\n"
   "JD 见附件 PDF，感兴趣回个时间我约聊。\r\n").encode(),
  "benign", "ham_business", ["headhunt_real_jd"], "deliver",
  "与 gray_0007 同为猎头邮件，此封不索要证件信息——对照价值在于信息索取行为而非身份")

E("gray_0028_school_fee.eml",
  (H("财务处", "cwc@school.example", "parent@mail.example", "学费缴纳（对公账户，勿信个人码）") + P +
   "本学期学费 12,800 元，请汇入学校对公账户（见纸质通知盖章页）。\r\n"
   "学校不会使用个人收款码。缴费后凭回执开发票。\r\n").encode(),
  "benign", "ham_business", ["school_fee_corporate_account"], "deliver",
  "涉款邮件但走对公+明确反诈提示；与个人码类形成对照")

E("gray_0029_landlord_rent.eml",
  (H("房东", "landlord@personal.example", "tenant@personal.example", "9月房租记得转") + P +
   "这个月还是老卡号，押金条我月底给你。\r\n"
   "空调加氟的 150 从房租里扣就行。\r\n").encode(),
  "benign", "ham_personal", ["landlord_normal_rent"], "deliver",
  "个人间转账零安全特征，却是亿万租房者的日常")

E("gray_0030_it_mirror.eml",
  (H("IT应急", "emergency@corp-mirror.example", "it@corp.internal", "门户故障，临时镜像入口") + P +
   "主门户数据库故障，临时入口（外部镜像域，HTTPS）：\r\n"
   "https://mirror-login.corp-mirror.example/\r\n"
   "恢复后公告。仅本次事件使用。\r\n").encode(),
  "benign", "ham_business", ["emergency_mirror_domain"], "review",
  "真实 IT 应急时确实会开外部镜像域；与钓鱼无法静态区分——正确的期望动作是复核而非直接放行")

E("gray_0031_ceo_real.eml",
  (H("陈总", "chen.ceo@corp.internal", "ea@corp.internal", "在吗，处理个事") + P +
   "在吗？我在外面开会。接待用的伴手礼先用你的备用金垫一下，\r\n"
   "回我邮箱，回来我签单给你销账。\r\n").encode(),
  "benign", "ham_business", ["ceo_real_advance_legit_process"], "review",
  "真 CEO、真内部域，但\"垫付\"行为本身就该触发复核流程；与 gray_0016 同形对照——理想系统对两封都复核，人再放行")

E("gray_0032_tm_real.eml",
  (H("代理所", "li@zhuanli-agency.example", "legal@corp.internal", "商标无效答辩：本周五举证截止") + P +
   "贵司商标被提无效宣告，答辩举证期本周五截止。\r\n"
   "证据清单我已列好（见共享盘合同目录），确认后我提交。\r\n"
   "代理费发票随后开出。\r\n").encode(),
  "benign", "ham_business", ["tm_real_agency"], "deliver",
  "与 gray_0017 同形；真代理不索要登录、材料走共享盘、提发票——细节决定黑白")

E("gray_0033_apc_real.eml",
  (H("期刊部", "apc@j-sci.example", "research@corp.internal", "APC invoice for JSI-1147") + P +
   "Invoice APA-8842 attached for your accepted article (APC 1,850 USD).\r\n"
   "Pay via your institution's library portal; do not use links in email.\r\n"
   "We never request payment through email links.\r\n").encode(),
  "benign", "ham_business", ["apc_real_no_link"], "deliver", "en",
  "与 gray_0018 同形；真期刊明确\"不用邮件链接缴费\"——防伪声明是关键判别特征")

E("gray_0034_amazon_order.eml",
  (H("Amazon.cn", "ship-confirm@amazon.example", "me@personal.example", "您的订单已发货：滤芯x2") + P +
   "订单 402-88xxxx 已发货，预计周三到。\r\n"
   "查看订单：https://www.amazon.example/gp/your-account/orders\r\n"
   "（本邮件不索要任何账户信息）\r\n").encode(),
  "benign", "ham_business", ["ecom_order_confirm"], "deliver",
  "订单确认是钓鱼仿冒第一大户，真件的特征是纯通知不索信息")

E("gray_0035_2fa_reset.eml",
  (H("账户安全", "sec@saas-vendor.example", "ops@corp.internal", "Your verification code") + P +
   "Someone just requested a password reset. Code: 447 019.\r\n"
   "Not you? Ignore or contact support. We will never ask for this code.\r\n").encode(),
  "benign", "ham_business", ["own_2fa_code"], "deliver", "en",
  "验证码邮件被仿冒的概率极高，但真件就是长这样；上下文（本人是否触发）决定黑白")

E("gray_0036_bank_callback.eml",
  (H("风控中心", "risk@bank.example", "finance@corp.internal", "今日大额交易电话核实安排") + P +
   "贵司今日两笔大额转账将触发电话核实，请保持财务预留电话畅通。\r\n"
   "我行外呼显示 955XX，不会索要密码与验证码。\r\n").encode(),
  "benign", "ham_business", ["bank_callback_notice"], "deliver",
  "TOAD 的影子（打电话）但这是银行真流程，且声明不索密")

E("gray_0037_hr_salaryfix.eml",
  (H("薪酬", "pay@corp.internal", "wei.hua@corp.internal", "9月工资卡号更正确认") + P +
   "你提交的更正已受理：尾号 6688 → 尾号 0912。\r\n"
   "回复\"确认\"即可生效，无需提供完整卡号。\r\n").encode(),
  "benign", "ham_business", ["salary_fix_confirm_tail_only"], "deliver",
  "涉薪涉卡但系统只确认尾号、不收全号——合规设计本身就是判别特征")

E("gray_0038_milktea.eml",
  (H("行政-小李", "xiaoli@corp.internal", "staff@corp.internal", "下午茶拼单（垫付制）") + P +
   "奶茶拼单接龙，我先垫付，喝的下班前现金或转账给我都行，\r\n"
   "不收手续费。\r\n").encode(),
  "benign", "ham_business", ["office_groupbuy_advance"], "review",
  "内部域+垫付小额，正常办公日常；与 gray_0003（个人邮箱+预收全款）构成一对——收款时机与金额是分界线")

E("gray_0039_property_fee.eml",
  (H("物业服务中心", "pmu@community.example", "owner@list.example", "三季度物业费缴纳通知") + P +
   "物业费按季度汇入物业对公账户（账号见单元门公示栏盖章件），\r\n"
   "也可前台 POS。逾期按合同计违约金。\r\n").encode(),
  "benign", "ham_business", ["property_corporate_fee"], "deliver",
  "催缴+违约金的压力话术，但渠道全线下对公")

E("gray_0040_secondhand_deposit.eml",
  (H("买家", "buyer@personal.example", "me@personal.example", "鱼缸我定了，转你 100 定金") + P +
   "定金先转你，周六自取付尾款。地址发我一下。\r\n"
   "到时候帮你搭把手搬下楼。\r\n").encode(),
  "benign", "ham_personal", ["secondhand_normal_deposit"], "deliver",
  "陌生个人间转账+定金，电商语境高危特征全占，但这就是闲置交易的常态")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch7 written: {len(LABELS)} gray samples")
