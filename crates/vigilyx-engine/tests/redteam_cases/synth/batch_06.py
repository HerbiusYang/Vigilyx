#!/usr/bin/env python3
"""Batch 6: government/academic/investment lures + workplace ham."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def H(disp, frm, to, subj, extra=""):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Sat, 29 Aug 2026 10:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b6@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\n")
P = "Content-Type: text/plain; charset=utf-8\r\n\r\n"
M = "Content-Type: text/html; charset=utf-8\r\n\r\n"
def E(n, raw, label, family, lang, tech, note=""):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 6, "note": note})

E("mal_0101_tax_app.eml",
  (H("税务服务", "svc@tax-mobile.example", "finance@corp.internal", "个税 App 版本过低，影响申报") + P +
   "检测到您使用的个税 App 版本过低，年度汇算功能受限。\r\n"
   "请通过校验通道更新并核验身份：https://tax-mobile-fix.example.org/up\r\n").encode(),
  "malicious", "account_phishing", "zh", ["tax_app_lure"], "")

E("mal_0102_big_transfer.eml",
  (H("网银安全", "sec@bank-verify.example", "finance@corp.internal", "大额转账待核实（今日有效）") + P +
   "您账户有一笔大额转账待核实，为保障资金安全请致电核实专线：\r\n"
   "400-771-6290。未核实转账将被退回并冻结 24 小时。\r\n").encode(),
  "malicious", "toad", "zh", ["big_transfer_hotline"], "财务定向 TOAD")

E("mal_0103_claim_face.eml",
  (H("理赔中心", "claim@insure-pay.example", "me@personal.example", "理赔需人脸核身") + P +
   "您的理赔申请进入核身环节，请按短信链接完成人脸核身，\r\n"
   "或致电理赔专线由人工引导：400-6620-115。\r\n"
   "链接有效期 30 分钟。\r\n").encode(),
  "malicious", "pii_harvest", "zh", ["claim_face_hotline"], "")

E("mal_0104_degree_check.eml",
  (H("学信服务", "svc@chsi-notice.example", "hr@corp.internal", "学历校验未通过（复核通道）") + P +
   "候选人授权的学历在线校验未通过，如需复核请使用复核通道：\r\n"
   "https://chsi-review.example.edu.cn/recheck\r\n"
   "复核需上传候选人身份证正反面。\r\n").encode(),
  "malicious", "account_phishing", "zh", ["degree_check_lure"], "HR 定向")

E("mal_0105_parttime.eml",
  (H("兼职运营", "job@part-time.example", "student@mail.example", "线上兼职：日结 300 起") + P +
   "手机即可操作，今日名额 20 人。\r\n"
   "报名登记（需姓名+手机+银行卡）：https://pt-reg.example.vip/join\r\n"
   "首单佣金当晚结算。\r\n").encode(),
  "malicious", "pii_harvest", "zh", ["parttime_collect"], "刷单定式")

E("mal_0106_draw.eml",
  (H("会员日", "act@shop-fest.example", "user@corp.internal", "抽奖码已生成，待激活") + P +
   "您的会员日抽奖码已生成，激活后可抽：\r\n"
   "https://act-draw.example.club/active\r\n"
   "奖品保留 48 小时。\r\n").encode(),
  "malicious", "account_phishing", "zh", ["draw_activate"], "")

E("mal_0107_slow_charge.eml",
  (H("话费慢充", "svc@charge-8x.example", "me@personal.example", "话费充值 95 折（72h 到账）") + P +
   "充值地址：https://charge-slow.example.info/pay\r\n"
   "今日订单明日凌晨统一到账，客服微信见页面。\r\n").encode(),
  "malicious", "account_phishing", "zh", ["slow_charge"], "")

E("mal_0108_unsubscribe_call.eml",
  (H("会员服务", "vip@auto-sub.example", "me@personal.example", "会员自动续费前提醒") + P +
   "您开通的连续包月服务将于明晚扣费 25 元。\r\n"
   "退订仅支持客服专线：400-8810-226，线上渠道已关闭。\r\n").encode(),
  "malicious", "toad", "zh", ["unsubscribe_hotline"], "退订只能打电话")

E("mal_0109_mail_move.eml",
  (H("邮件迁移", "move@mail-trans.example", "it@corp.internal", "邮箱系统搬迁通知") + P +
   "旧邮箱本周五停用，历史邮件请自行搬迁移导：\r\n"
   "迁移工具（需旧邮箱密码登录）：https://mail-mover.example.net/import\r\n").encode(),
  "malicious", "credential_harvest", "zh", ["mail_migration_collect"], "以迁移为名收密码")

E("mal_0110_icp_check.eml",
  (H("备案中心", "icp@beian-notice.example", "webmaster@corp.internal", "网站备案信息核验通知") + P +
   "按年度核验要求，贵单位备案信息需在 9 月 15 日前完成在线核验，\r\n"
   "逾期将注销备案并关闭站点：https://beian-check.example.com/verify\r\n").encode(),
  "malicious", "account_phishing", "zh", ["icp_verify"], "站长定向")

E("mal_0111_server_expire.eml",
  (H("云服务", "ops@cloud-host.example", "webmaster@corp.internal", "服务器 3 日后到期释放") + P +
   "您的云服务器将于 3 日后到期并释放数据。\r\n"
   "保留数据请登录控制台完成续费校验：\r\n"
   "https://cloud-renew-check.example.info/login\r\n").encode(),
  "malicious", "account_phishing", "zh", ["server_expire"], "")

E("mal_0112_trademark.eml",
  (H("知识产权代理", "agent@ip-agency.example", "legal@corp.internal", "商标初审驳回，可申诉（截止周五）") + P +
   "贵司商标在第 9 类初审驳回，申诉窗口截至本周五。\r\n"
   "申诉材料入口：https://tm-appeal.example.co/deny\r\n"
   "逾期视为放弃。\r\n").encode(),
  "malicious", "account_phishing", "zh", ["trademark_denied"], "法务定向")

E("mal_0113_apc.eml",
  (H("期刊编辑部", "editor@sci-index.example", "research@corp.internal", "稿件进入排版，请缴纳版面费") + P +
   "您的稿件已进入排版，请于 3 日内缴纳版面费 3200 元锁定刊期：\r\n"
   "https://apc-pay.example.org/fee\r\n"
   "逾期顺延至下期。\r\n").encode(),
  "malicious", "account_phishing", "zh", ["apc_fee"], "学术定向")

E("mal_0114_conf_reg.eml",
  (H("会议秘书处", "reg@conf-2026.example", "research@corp.internal", "注册费早鸟价今日截止") + P +
   "早鸟注册价今日 24:00 截止，逾期上浮 30%：\r\n"
   "https://conf-early.example.info/register\r\n"
   "缴费后凭回执开发票。\r\n").encode(),
  "malicious", "account_phishing", "zh", ["conf_early_fee"], "")

E("mal_0115_private_equity.eml",
  (H("投顾-王总", "advisor@private-fund.example", "cfo@corp.internal", "老产品有个临时额度（内部）") + P +
   "上一期产品的临时退出通道开两天，只在内部页操作：\r\n"
   "https://fund-exit.example.vip/door\r\n"
   "额度小，先到先得，勿外传。\r\n").encode(),
  "malicious", "account_phishing", "zh", ["private_fund_door"], "高管定向")

E("mal_0116_nft.eml",
  (H("数字藏品", "drop@nft-mint.example", "user@corp.internal", "限定款申购白名单生效") + P +
   "您的白名单已生效，申购窗口 2 小时：\r\n"
   "https://mint-gate.example.club/whitelist\r\n"
   "超时资格作废。\r\n").encode(),
  "malicious", "account_phishing", "zh", ["nft_whitelist"], "")

E("mal_0117_livestream.eml",
  (H("直播福利", "gift@live-rebate.example", "me@personal.example", "打赏返现活动（最后一天）") + P +
   "活动最后一天：打赏满 500 返 150，返现登记：\r\n"
   "https://live-rebate.example.vip/back\r\n"
   "需填写收款卡号与手机验证码。\r\n").encode(),
  "malicious", "pii_harvest", "zh", ["rebate_collect"], "")

E("mal_0118_express_claim2.eml",
  (H("理赔", "lipei@kd-svc.example", "me@personal.example", "丢件理赔待确认收卡信息") + P +
   "您的丢件理赔已批复，回复本邮件提供收款卡号与持卡人身份证号，\r\n"
   "财务直付，三个工作日到账。\r\n").encode(),
  "malicious", "pii_harvest", "zh", ["claim_reply_card"], "")

E("mal_0119_points.eml",
  (H("积分商城", "point@svc-mall.example", "me@personal.example", "积分即将清零，可兑好礼") + P +
   "您的 8640 积分将于月底清零，兑换通道：\r\n"
   "https://point-exchange.example.info/s\r\n"
   "需核验手机服务密码完成抵扣。\r\n").encode(),
  "malicious", "credential_harvest", "zh", ["points_service_pwd"], "以兑换收服务密码")

E("mal_0120_carrier_realname.eml",
  (H("运营商服务", "svc@sim-realname.example", "me@personal.example", "SIM 卡实名信息待补登记") + P +
   "按规定未完成实名补登记的号码将限制呼出。\r\n"
   "补登记：https://sim-fix.example.org/real\r\n"
   "需上传身份证与活体照片。\r\n").encode(),
  "malicious", "pii_harvest", "zh", ["carrier_realname_upload"], "")

E("ham_0101_budget.eml",
  (H("财务-预算", "budget@corp.internal", "leads@corp.internal", "Q4 预算占位提醒") + P +
   "Q4 预算下周三锁版，还没提交占位的组抓紧，\r\n"
   "平台入口：https://portal.corp.internal/budget/q4\r\n"
   "超支需走专项。\r\n").encode(),
  "benign", "ham_business", "zh", ["budget_deadline"], "")

E("ham_0102_expense_faq.eml",
  (H("财务共享", "fssc@corp.internal", "all-staff@corp.internal", "报销高频问题（8月版）") + P +
   "本月 FAQ 更新：1) 电子发票需带验真截图；2) 拼车发票按人均拆分；\r\n"
   "3) 境外小票需翻译件。其余见门户-财务-FAQ。\r\n").encode(),
  "benign", "ham_business", "zh", ["expense_faq"], "")

E("ham_0103_attend_appeal.eml",
  (H("考勤系统", "att@corp.internal", "lu.meng@corp.internal", "你的打卡异常申诉已通过") + P +
   "8/19 漏打卡申诉通过，已修正为正常出勤。\r\n"
   "后续记得手机端补签，系统自动记录。\r\n").encode(),
  "benign", "ham_business", "zh", ["appeal_ok"], "")

E("ham_0104_supplies.eml",
  (H("行政-库房", "storage@corp.internal", "floor3@corp.internal", "办公用品领用开放（周二）") + P +
   "周二上午库房开放领用，新品：升降支架、护腰垫。\r\n"
   "带工牌领，人多的东西先到先得。\r\n").encode(),
  "benign", "ham_business", "zh", ["supplies"], "")

E("ham_0105_toner.eml",
  (H("IT服务台", "helpdesk@corp.internal", "floor5@corp.internal", "打印耗材已到货") + P +
   "5F 的硒纸耗材已补充到货，A4 纸在老位置。\r\n"
   "卡纸仍请报修，勿自行拆.\r\n").encode(),
  "benign", "ham_business", "zh", ["toner"], "")

E("ham_0106_outing_vote.eml",
  (H("工会", "union@corp.internal", "all-staff@corp.internal", "秋游目的地投票（今晚截止）") + P +
   "候选：莫干山、千岛湖、径山骑行。投票走工会小程序，\r\n"
   "今晚 22:00 截止，多数决。\r\n").encode(),
  "benign", "ham_business", "zh", ["outing_vote"], "")

E("ham_0107_wiki_conflict.eml",
  (H("知识库", "wiki-bot@corp.internal", "dev-team@corp.internal", "编辑冲突：发布手册第4节") + P +
   "老许与你同时编辑了第 4 节，系统保留了先提交版本，\r\n"
   "你的改动在\"冲突副本\"页签，请手工合并。\r\n").encode(),
  "benign", "ham_business", "zh", ["wiki_conflict"], "")

E("ham_0108_git_gc.eml",
  (H("代码平台", "git@corp.internal", "dev-team@corp.internal", "大仓库清理提醒（>2G）") + P +
   "vigilyx 仓库已 2.3G，主要是历史二进制。本周窗口做一次 history 清理，\r\n"
   "期间只读两小时，请提前推送。\r\n").encode(),
  "benign", "ham_business", "zh", ["repo_gc"], "")

E("ham_0109_meal_allow.eml",
  (H("行政", "admin@corp.internal", "oncall@corp.internal", "值班餐补申领方式更新") + P +
   "值班餐补改为次月自动随薪发放，无需再提交申请，\r\n"
   "本月起执行。\r\n").encode(),
  "benign", "ham_business", "zh", ["meal_allowance"], "")

E("ham_0110_bonus_note.eml",
  (H("薪酬", "pay@corp.internal", "staff@corp.internal", "项目奖金随 9 月薪发放") + P +
   "上半年项目奖金并入 9 月薪一起发放，税按年终奖口径单独计。\r\n"
   "明细见工资条备注列。\r\n").encode(),
  "benign", "ham_business", "zh", ["bonus_notice"], "")

E("ham_0111_checkup_slot.eml",
  (H("行政-健康", "health@corp.internal", "all-staff@corp.internal", "年度体检排期（9/9-9/20）") + P +
   "排期已出，按部门分日；改期在门户健康频道自助换，\r\n"
   "空腹项目记得早晨别吃。\r\n").encode(),
  "benign", "ham_business", "zh", ["checkup_slot"], "")

E("ham_0112_vaccine_bus.eml",
  (H("行政-健康", "health@corp.internal", "all-staff@corp.internal", "流感疫苗班车（自愿）") + P +
   "9/16 下午疫苗车进园区，自愿接种，工号登记，\r\n"
   "接种后留观 30 分钟。孕妇与过敏体质不建议。\r\n").encode(),
  "benign", "ham_business", "zh", ["vaccine_bus"], "")

E("ham_0113_mind_talk.eml",
  (H("工会-心理", "eap@corp.internal", "all-staff@corp.internal", "EAP 讲座：睡眠与压力") + P +
   "周四 18:30 报告厅，EAP 顾问讲睡眠与压力管理，可匿名提问。\r\n"
   "报名不做名单公示。\r\n").encode(),
  "benign", "ham_business", "zh", ["eap_talk"], "")

E("ham_0114_bookclub.eml",
  (H("读书会", "books@corp.internal", "club@corp.internal", "九月共读：《事实》") + P +
   "九月共读《事实》，月底线上聊。书在知识库有电子版。\r\n"
   "领读人还缺一位，想上的吱声。\r\n").encode(),
  "benign", "ham_business", "zh", ["bookclub"], "")

E("ham_0115_running.eml",
  (H("跑团", "run@corp.internal", "run@corp.internal", "本周六滨江 10K 慢摇") + P +
   "周六 7:00 滨江跑道集合，配速 6 分半，雨取消。\r\n"
   "新手有 5K 陪跑组。\r\n").encode(),
  "benign", "ham_business", "zh", ["running_club"], "")

E("ham_0116_badminton.eml",
  (H("羽毛球社", "bdm@corp.internal", "club@corp.internal", "季循环赛第3轮赛程") + P +
   "第 3 轮赛程已发布群公告，场地照旧周三晚。\r\n"
   "轮空的帮忙记分。\r\n").encode(),
  "benign", "ham_business", "zh", ["badminton"], "")

E("ham_0117_boardgame.eml",
  (H("桌游社", "board@corp.internal", "club@corp.internal", "周五桌游夜：新到的德策") + P +
   "新到两盒德策，周五 19:00 茶水间开桌，新手可教。\r\n"
   "报名接龙。\r\n").encode(),
  "benign", "ham_business", "zh", ["boardgame"], "")

E("ham_0118_photo.eml",
  (H("行政台", "admin-desk@corp.internal", "all-staff@corp.internal", "部门合影时间（下周三）") + P +
   "下周三 10:00 中庭拍部门合影，工装不强制，\r\n"
   "拍完的图年底年会用。\r\n").encode(),
  "benign", "ham_business", "zh", ["group_photo"], "")

E("ham_0119_badge_design.eml",
  (H("品牌部", "brand@corp.internal", "all-staff@corp.internal", "新版工牌样式征集意见") + P +
   "新版工牌三种方案在门户投票，截止周五，\r\n"
   "采纳方案的提议人送周边。\r\n").encode(),
  "benign", "ham_business", "zh", ["badge_design"], "")

E("ham_0120_holiday_sec.eml",
  (H("安全环保部", "safety@corp.internal", "all-staff@corp.internal", "节前安全自查通知") + P +
   "放假前最后一天下班：拔插排、关窗、锁柜。\r\n"
   "值班表已发，紧急联系分机 6000。\r\n").encode(),
  "benign", "ham_business", "zh", ["holiday_security"], "")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch6 written: {len(LABELS)} samples")
