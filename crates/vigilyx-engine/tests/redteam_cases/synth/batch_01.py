#!/usr/bin/env python3
"""Batch 1: 20 malicious + 20 benign, each email authored individually by the
LLM (no template interpolation). This script only writes the authored bytes
to disk and records the labels."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
def W(name, raw: bytes):
    open(os.path.join(ROOT, "synth", name), "wb").write(raw)
def H(frm_disp, frm, to, subj, extra=""):
    b = base64.b64encode(frm_disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Mon, 24 Aug 2026 09:{11+len(LABELS)%40:02d}:00 +0800\r\n"
            f"Message-ID: <{LABELS.__len__():04d}-b1@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\n")
P = "Content-Type: text/plain; charset=utf-8\r\n\r\n"
M = "Content-Type: text/html; charset=utf-8\r\n\r\n"
LABELS = []
def E(name, raw, label, family, lang, tech, note=""):
    W(name, raw); LABELS.append({"file": f"synth/{name}", "case_id": name[:-4],
        "label": label, "family": family, "language": lang, "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 1, "note": note})

E("mal_0001_mailbox_quota.eml",
  (H("邮箱管理员", "postmaster@mail-service.example", "chen.jie@corp.internal",
     "您的邮箱已超出配额") + P +
   "陈杰 您好：\r\n\r\n"
   "监控显示您的邮箱当前占用 9.8G / 10G，今日起将暂停收件。\r\n"
   "请在今天内完成容量核验与扩容登记，核验地址：\r\n"
   "https://mail-quota-center.example.info/verify\r\n\r\n"
   "邮箱管理员（系统代发）\r\n").encode(),
  "malicious", "account_phishing", "zh", ["quota_lure", "domain_link"], "邮箱容量话术")

E("mal_0002_pwd_expiry_notice.eml",
  (H("信息技术部", "it-notice@partner.example", "all-staff@corp.internal",
     "关于统一身份密码到期换发的通知") + P +
   "各部门：\r\n\r\n"
   "经核查，您名下的统一身份账号密码将于 48 小时后到期。\r\n"
   "到期未换发的账号将被停用，影响门禁、OA 与邮箱登录。\r\n"
   "请前往换发入口完成修改：http://203.0.113.77/sso/renew\r\n\r\n"
   "信息技术部（代章）\r\n").encode(),
  "malicious", "account_phishing", "zh", ["pwd_expiry", "ip_url"], "公文口吻")

E("mal_0003异地登录提醒.eml".replace("异地登录提醒","abnormal_login_alert"),
  (H("安全中心", "alert@id-protect.example", "liu.yang@corp.internal",
     "检测到新的登录地点") + P +
   "刘洋，你好：\r\n\r\n"
   "你的账号今天凌晨在陌生设备上有一次成功登录。\r\n"
   "如果不是你本人操作，请尽快确认账号归属并重置凭证：\r\n"
   "http://203.0.113.60/confirm/identity\r\n\r\n"
   "—— 安全中心自动告警\r\n").encode(),
  "malicious", "account_phishing", "zh", ["abnormal_login", "ip_url"], "口语化口吻")

E("mal_0004_realname_annual.eml",
  (H("客户服务中心", "service@acct-center.example", "zhao.qian@corp.internal",
     "【最后提醒】实名信息年度核验") + P +
   "尊敬的用户：\r\n\r\n"
   "您登记的实名信息已进入年度核验期，系统将在 24 小时后关闭核验通道。\r\n"
   "逾期未核验的账户将转入冻结名单，影响收发与关联业务。\r\n"
   "核验入口：https://realname-check.example.ru/step2\r\n\r\n"
   "如有疑问可回信本邮箱（勿致电）。\r\n").encode(),
  "malicious", "account_phishing", "zh", ["realname_lure", "ru_tld"], "")

E("mal_0005_unusual_signin_en.eml",
  (H("Mail Security", "no-reply@acct-activity.example", "user@corp.internal",
     "New device signed in to your mailbox") + M +
   "<html><body><p>Hello,</p>"
   "<p>A new device just signed in to your mailbox from another city. "
   "If this wasn't you, secure the account now:</p>"
   "<p><a href='https://mail-activity-check.example.net/secure'>Review activity</a></p>"
   "<p>This notice will not be repeated.</p></body></html>").encode(),
  "malicious", "account_phishing", "en", ["new_device_lure", "html_button"], "")

E("mal_0006_payment_portal.eml",
  (H("财务共享中心", "fssc@pay-portal.example", "finance@corp.internal",
     "待办：供应商付款账户重新登记") + P +
   "财务同事见信好：\r\n\r\n"
   "平台升级后原登记的收款账户需要重新确认，否则本月付款批次将被挂起。\r\n"
   "请登录核对：https://pay-portal-uat.example.info/reconfirm\r\n\r\n"
   "（本邮件由付款平台发出，请勿转发）\r\n").encode(),
  "malicious", "bec", "zh", ["supplier_account_reconfirm"], "财务定向话术")

E("mal_0007_bank_maint.eml",
  (H("网上银行", "service@ebank-notice.example", "sun.mei@corp.internal",
     "系统升级期间请完成预留信息核对") + P +
   "尊敬的客户：\r\n\r\n"
   "为配合总行系统升级，请在本周五前完成预留信息核对，\r\n"
   "未核对账户升级后将无法办理转账业务。\r\n"
   "核对地址：http://198.51.100.77/ebank/check\r\n\r\n"
   "（请勿将本邮件转发他人）\r\n").encode(),
  "malicious", "account_phishing", "zh", ["bank_upgrade_lure", "ip_url"], "网银口吻")

E("mal_0004b_routine_check.eml",
  (H("运营支持", "ops@sys-support.example", "zhou.lin@corp.internal",
     "一项例行核验未通过") + P +
   "周琳 你好：\r\n\r\n"
   "你的一项例行核验没有通过，原因涉及账号基础信息完整性。\r\n"
   "为避免影响后续使用，请在工作日内完成一次补录：\r\n"
   "https://ops-checkin.example.org/repair\r\n\r\n"
   "本邮件由运营支持发出，超过三日未处理将自动升级。\r\n").encode(),
  "malicious", "account_phishing", "zh", ["paraphrase_no_stock_keywords"], "硬正样本：无关键词")

E("mal_0008_supplier_change.eml",
  (H("采购对接", "ap@hongxin-trade.example", "ap@corp.internal",
     "收款账户变更说明（华信贸易）") + P +
   "您好：\r\n\r\n"
   "因公司开户行网点撤并，自本月 20 日起货款请汇至：\r\n"
   "户名：华信国际贸易有限公司\r\n"
   "账号：6225 8817 3392 0041\r\n"
   "开户行：中信银行杭州分行营业部\r\n\r\n"
   "原账户同日作废，请更新应付资料并回复确认，谢谢。\r\n").encode(),
  "malicious", "bec", "zh", ["payment_change_detail"], "带完整收款信息")

E("mal_0009_ceo_wire_en.eml",
  (H("CEO Office", "exec.assistant@partner.example", "cfo@corp.internal",
     "Wire before close of business") + P +
   "Kevin,\n\nI need the retainers moved before the wire window closes today. New\n"
   "instructions are with the agents; have finance action it quietly and confirm\n"
   "back to this address only. No calls, I'm in back-to-back sessions.\n\n"
   "- D. Chen\n").encode(),
  "malicious", "bec", "en", ["ceo_wire_urgency"], "简短高压口吻")

E("mal_0010_giftcards.eml",
  (H("行政部-王琳", "wl-admin@partner.example", "admin@corp.internal",
     "帮我备一批卡") + P +
   "在吗？下午接待外宾要送礼，帮我准备 15 张 1000 面值的购物卡，\r\n"
   "买好把卡号密码拍给我，走行政备用金，回头补单子。\r\n").encode(),
  "malicious", "bec", "zh", ["giftcard_urgency"], "")

E("mal_0011_onboarding_pii.eml",
  (H("人事-招聘组", "hiring@partner.example", "candidate@mail.example",
     "入职材料补交通知（今日截止）") + P +
   "候选人你好：\r\n\r\n"
   "背调进入最后环节，请今日内回复本邮件并附上：\r\n"
   "1) 身份证正反面照片（手持）；2) 人脸动态视频（眨眼转头）；\r\n"
   "材料仅用于核验，逾期视为放弃入职。\r\n").encode(),
  "malicious", "pii_harvest", "zh", ["reply_pii_id_face"], "")

E("mal_0012_refund_hotline.eml",
  (H("客服中心", "support@refund-ops.example", "wu.juan@corp.internal",
     "您申请的退款已受理，请致电确认") + P +
   "吴娟 您好：\r\n\r\n"
   "您上月提交的退款申请已进入终审，需本人致电确认收款信息。\r\n"
   "专线：400-812-6657（工作时段）。超过 24 小时未确认将自动撤销。\r\n").encode(),
  "malicious", "toad", "zh", ["refund_hotline"], "")

E("mal_0013_membership_deduct.eml",
  (H("会员服务", "vip@club-notice.example", "gao.feng@corp.internal",
     "会员即将自动扣费，如需关闭请来电") + P +
   "高枫 您好：\r\n\r\n"
   "您开通的年度会员将于明晚自动续费 299 元。\r\n"
   "如需关闭请本人致电客服专线：400-6231-882，其他渠道无法受理。\r\n").encode(),
  "malicious", "toad", "zh", ["auto_deduct_hotline"], "")

E("mal_0014_qr_invoice.eml",
  (H("开票助手", "invoice@tax-svc.example", "tax@corp.internal",
     "电子发票已开具，扫码查验") + P +
   "您好：本期服务费电子发票已开具，请使用微信扫描下方二维码查验并保存。\r\n"
   "二维码 7 日内有效。\r\n").encode(),
  "malicious", "quishing", "zh", ["qr_invoice_lure"], "正文无链接纯引导扫码")

E("mal_0015_signin_qr.eml",
  (H("培训中心", "train@academy.example", "hr@corp.internal",
     "周四培训签到改扫码") + M +
   "<html><body><p>各位：本周四《数据合规》培训签到改为扫码签到，"
   "到场后扫描屏幕下方二维码完成登记，未签到按缺席处理。</p>"
   "<p><img src='https://cdn-academy.example/signin.png' alt='签到二维码'></p>"
   "</body></html>").encode(),
  "malicious", "quishing", "zh", ["qr_signin_lure", "img_alt"], "")

E("mal_0016_training_form.eml",
  (H("培训系统", "learn@academy-sys.example", "all@corp.internal",
     "补训登录（账号为工号）") + M +
   "<html><body><p>本年度信息安全补训已开启，请使用工号+域密码登录完成学习：</p>"
   "<form action='https://learn-portal.example.co/session'><input name='uid' placeholder='工号'>"
   "<input type='password' name='pwd' placeholder='域密码'><button>进入学习</button></form>"
   "</body></html>").encode(),
  "malicious", "credential_harvest", "zh", ["body_form_password"], "正则表单+域密码话术")

E("mal_0017_social_query.eml",
  (H("社保查询", "shebao@city-hr.example", "he.peng@corp.internal",
     "个人社保账户查询入口变更") + M +
   "<html><body><p>因系统迁移，个人社保查询需重新绑定账号：</p>"
   "<form action='http://203.0.113.99/bind'><input name='idno' placeholder='身份证号'>"
   "<input type='password' name='pwd' placeholder='查询密码'><button>绑定</button></form>"
   "</body></html>").encode(),
  "malicious", "credential_harvest", "zh", ["body_form_idno_password", "ip_action"], "")

E("mal_0018_freeze_400.eml",
  (H("风控中心", "risk@acct-guard.example", "yan.li@corp.internal",
     "账户异常，建议尽快处理") + P +
   "严丽 您好：\r\n\r\n"
   "系统连续三次校验失败，您的账户已进入保护性冻结流程。\r\n"
   "如需今日解除：① 登录 https://guard-unlock.example.net/appeal；② 或致电 400-221-9083。\r\n"
   "为保障您的资金安全，请勿告知他人验证码。\r\n").encode(),
  "malicious", "account_phishing", "zh", ["freeze_appeal", "hotline"], "")

E("mal_0019_reimburse_card.eml",
  (H("薪酬组", "payroll@partner.example", "xu.rui@corp.internal",
     "工资卡信息核对（本月生效）") + P +
   "徐瑞 你好：\r\n\r\n"
   "财务要求本月重新核对工资卡，请直接回复本邮件：\r\n"
   "姓名 / 身份证号 / 银行卡号 / 预留手机号。\r\n"
   "今晚 20:00 前回复的并入本月批次，逾期顺延。\r\n").encode(),
  "malicious", "pii_harvest", "zh", ["reply_bank_card_collect"], "回收式 PII 收割")

E("mal_0020_vendor_confirm.eml",
  (H("采购部", "purchasing@partner.example", "warehouse@corp.internal",
     "新供应商首单确认") + P +
   "仓储同事：\r\n\r\n"
   "新供应商（远东实业）首单走临时结算，收款资料以其邮件为准，\r\n"
   "我已让对方把账户发你邮箱，收到后先付 30% 定金，流程回头补。\r\n\r\n"
   "采购部 老周\r\n").encode(),
  "malicious", "bec", "zh", ["first_order_temp_settlement"], "口头流程违规型 BEC")

E("ham_0001_meeting_move.eml",
  (H("李伟", "li.wei@corp.internal", "dev-team@corp.internal",
     "架构评审改到周四上午") + P +
   "各位：架构评审从周三挪到周四 10:00，还是老地方 3F-301。\r\n"
   "这次重点过存储层的分库方案，相关同学提前把材料挂到共享盘。\r\n"
   "有冲突的直接回我。\r\n").encode(),
  "benign", "ham_business", "zh", ["internal_meeting"], "")

E("ham_0002_weekly_dev.eml",
  (H("张敏", "zhang.min@corp.internal", "pmo@corp.internal",
     "数据治理第35周周报") + P +
   "本周：元数据采集覆盖到 82%，血缘解析在两个遗留系统上卡住；\r\n"
   "风险：上游接口 9 月初变更，需要提前对齐；\r\n"
   "下周：完成血缘兜底规则，出一份口径对照表。\r\n"
   "明细见 /projects/datagov/week35。\r\n").encode(),
  "benign", "ham_business", "zh", ["weekly_report"], "")

E("ham_0003_portal_migration.eml",
  (H("行政服务台", "admin-desk@corp.internal", "all-staff@corp.internal",
     "用章申请入口迁移公告") + P +
   "全体同事：\r\n\r\n"
   "9 月 1 日起用章申请迁移到内部门户（https://portal.corp.internal/seal），\r\n"
   "原 OA 入口保留至月底。纸质单同时停收。\r\n"
   "问题找行政台分机 8100。\r\n").encode(),
  "benign", "ham_business", "zh", ["internal_portal_link"], "")

E("ham_0004_leave_ok.eml",
  (H("人资系统", "hr-sys@corp.internal", "ma.chao@corp.internal",
     "您的年假申请已通过") + P +
   "马超：你的 10 月 8-12 日年假已批准，余额还剩 3 天。\r\n"
   "假期值班表已抄送你组内，离京注意报备。\r\n"
   "本邮件由系统发送，无需回复。\r\n").encode(),
  "benign", "ham_business", "zh", ["approval_notice"], "")

E("ham_0005_plan_change.eml",
  (H("王芳", "wang.fang@corp.internal", "product@corp.internal",
     "门户升级排期顺延一周") + P +
   "产品同学：因依赖的网关发布窗口调整，门户升级整体顺延一周，\r\n"
   "灰度从 9/14 挪到 9/21，联调计划不变。\r\n"
   "对外口径我先顶着，内部按新时间走。\r\n").encode(),
  "benign", "ham_business", "zh", ["schedule_change"], "")

E("ham_0006_invoice_mailed.eml",
  (H("计费中心", "billing@vendor.example", "ap@corp.internal",
     "8月SaaS服务费发票寄出") + P +
   "您好：8 月 SaaS 服务费增值税专用发票已按合同抬头开具，\r\n"
   "顺丰 SF1388xxxx 已揽收，预计后天送达。\r\n"
   "电子底联已同步发至贵司税务邮箱，对账如有差异回信即可。\r\n").encode(),
  "benign", "ham_business", "zh", ["legit_invoice"], "")

E("ham_0007_bank_stmt.eml",
  (H("客户服务", "service@bank.example", "finance@corp.internal",
     "8月对账单可查询") + P +
   "尊敬的客户：您单位账户 8 月对账单已生成。\r\n"
   "请登录企业手机银行在\"账户-对账单\"栏目查询或下载。\r\n"
   "本行不会以任何形式索要密码、验证码；本邮件不含链接。\r\n").encode(),
  "benign", "ham_business", "zh", ["bank_statement_nolink"], "硬负样本")

E("ham_0008_reimburse_paid.eml",
  (H("财务共享", "fssc@corp.internal", "liu.qing@corp.internal",
     "差旅报销已打款") + P +
   "刘青：你 8 月华东行差旅报销 3,412.00 元已于今日打款至尾号 6688 卡，\r\n"
   "票据影像已归档。到账有异常回我，正常不用回复。\r\n").encode(),
  "benign", "ham_business", "zh", ["reimburse_paid"], "")

E("ham_0009_maint_window.eml",
  (H("NOC", "noc@corp.internal", "it-all@corp.internal",
     "周六核心交换例行维护") + P +
   "本周六 02:00-06:00 核心交换机固件升级，内网预计 2-3 次分钟级闪断，\r\n"
   "生产业务不涉及；专线与出口不中断。\r\n"
   "值班：6000。公告：https://portal.corp.internal/notice/2026-37\r\n").encode(),
  "benign", "ham_business", "zh", ["maintenance_internal_link"], "")

E("ham_0010_ci_ok.eml",
  (H("CI机器人", "ci-bot@corp.internal", "dev-team@corp.internal",
     "[OK] gateway #4821 main 构建通过") + P +
   "main 分支构建通过：单元 312/312，集成 44/44，耗时 6m40s。\r\n"
   "镜像 gateway:1.9.4-rc2 已推送制品库，可自助拉取。\r\n").encode(),
  "benign", "ham_business", "zh", ["ci_notice"], "")

E("ham_0011_monitor_recover.eml",
  (H("监控平台", "monitor@corp.internal", "duty@corp.internal",
     "[恢复] 订单接口超时告警已恢复") + P +
   "订单接口 P95 超时告警于 11:42 自动恢复，持续 6 分钟，\r\n"
   "初步归因上游缓存抖动，复盘稍后同步值班群。\r\n").encode(),
  "benign", "ham_business", "zh", ["monitor_recovery"], "")

E("ham_0012_own_code.eml",
  (H("统一认证平台", "noreply@sso.corp.internal", "du.nan@corp.internal",
     "登录验证码") + P +
   "您正在登录统一认证平台，验证码 517 392，10 分钟内有效。\r\n"
   "如非本人操作，请尽快修改密码。请勿转发本邮件。\r\n").encode(),
  "benign", "ham_business", "zh", ["own_verification_code"], "最强硬负样本")

E("ham_0013_parcel.eml",
  (H("驿站", "notice@station.example", "guo.tao@corp.internal",
     "包裹到站提醒") + P +
   "【驿站】您的京东包裹已到东门驿站A区，取件码 4-9-2063，\r\n"
   "营业到 21:00，三天未取退回网点。\r\n").encode(),
  "benign", "ham_business", "zh", ["parcel_pickup"], "")

E("ham_0014_ticket.eml",
  (H("商旅平台", "travel@corp-partner.example", "qian.yu@corp.internal",
     "出票成功：CA1858") + P +
   "钱瑜：9/26 CA1858 杭州-北京已出票，08:15 起飞，值机口 D14。\r\n"
   "行程单与发票已发到你的附件区。退改请走平台，勿直接航司。\r\n").encode(),
  "benign", "ham_business", "zh", ["travel_ticket"], "")

E("ham_0015_family.eml",
  (H("妈妈", "mom@family.example", "me@personal.example",
     "十一的票订好了吗") + P +
   "订好把车次发我，让你爸去接。被子晒好了，你那屋换了新枕芯。\r\n"
   "带娃的东西别买，家里都有。就想吃你说的那个蛋糕，回来做。\r\n").encode(),
  "benign", "ham_personal", "zh", ["family"], "")

E("ham_0016_roommate.eml",
  (H("室友小柯", "ke@personal.example", "me@personal.example",
     "物业费这季我来交") + P +
   "水电燃气结到 9 月底了，物业费这季我一起交，你把上半年那笔转我就行。\r\n"
   "热水器有点响，师傅周四来看，那天有人在家吗？\r\n").encode(),
  "benign", "ham_personal", "zh", ["roommate"], "")

E("ham_0017_cfp_en.eml",
  (H("ACSAC 2026", "cfp@acsac.example", "research@corp.internal",
     "Second deadline reminder") + P +
   "Dear authors,\n\nSecond (final) reminder: full papers due Sep 30, AoE via\n"
   "https://acsac2026.example/submit. Rebuttal window opens Oct 14.\n\n"
   "Program chairs\n").encode(),
  "benign", "ham_business", "en", ["cfp_deadline_link"], "")

E("ham_0018_newsletter.eml",
  (H("企业通讯", "newsletter@corp-union.example", "all-staff@corp.internal",
     "企业通讯 2026年9月刊") + P +
   "【外部邮件】本期看点：中秋游园会报名、食堂二期档口开业、\r\n"
   "班车 3 号线加密班次、体检补检安排。\r\n"
   "全文：https://portal.corp.internal/newsletter/2026-09\r\n"
   "退订回复 TD。\r\n").encode(),
  "benign", "ham_business", "zh", ["banner_newsletter_link"], "带横幅硬负样本")

E("ham_0019_contract_return.eml",
  (H("法务-合作方", "legal@vendor.example", "legal@corp.internal",
     "框架协议盖章版已回寄") + P +
   "您好：两份盖章版已顺丰回寄（运单见附件短信），请注意查收。\r\n"
   "电子扫描件同步发过，归档以纸质为准。下季度对账联系人不变。\r\n").encode(),
  "benign", "ham_business", "zh", ["contract_return"], "")

E("ham_0020_club_signup.eml",
  (H("工会", "union@corp.internal", "all-staff@corp.internal",
     "羽毛球活动报名（周五截止）") + P +
   "本学期羽毛球活动恢复，每周三 19:00 滨江馆，费用工会承担，\r\n"
   "器材自备。想参加的回复本邮件登记，周五下班截止。\r\n").encode(),
  "benign", "ham_business", "zh", ["club_signup"], "")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS:
        f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch1 written: {len(LABELS)} samples")
