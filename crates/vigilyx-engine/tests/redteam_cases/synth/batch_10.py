#!/usr/bin/env python3
"""Batch 10: gov/medical/student lures + HR ham + 10 gray (5 real/fake pairs)."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def H(disp, frm, to, subj, extra=""):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Wed, 02 Sep 2026 11:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b10@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\n")
P = "Content-Type: text/plain; charset=utf-8\r\n\r\n"
def E(n, raw, label, family, tech, note="", expected=None, ambiguous=False, borderline=""):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": "zh", "techniques": tech,
        "expected": expected or ("block" if label == "malicious" else "deliver"),
        "engine_status": "not_evaluated", "synthetic": True, "batch": 10,
        "note": note, "ambiguous": ambiguous, "borderline": borderline})

E("mal_0161_card_risk.eml",
  (H("风控中心", "risk@card-safe.example", "me@personal.example", "银行卡存在异常交易，需解锁") + P +
   "检测到夜间异常交易两笔，卡片已临时冻结。\r\n"
   "解锁验证：https://card-unlock.example.info/u\r\n"
   "（卡号+取款密码+手机验证码）\r\n").encode(),
  "malicious", "credential_harvest", ["card_unlock_collect"], "收三要素")

E("mal_0162_medical_stop.eml",
  (H("医保中心", "yb@insure-city.example", "me@personal.example", "医保卡将停用（信息待更新）") + P +
   "医保系统升级，未更新个人信息（身份证号+手机号）的卡将停用：\r\n"
   "https://yb-update.example.org/up\r\n").encode(),
  "malicious", "pii_harvest", ["medical_stop_update"], "")

E("mal_0163_fund_draw.eml",
  (H("公积金", "gjj@fund-svc.example", "employee@corp.internal", "公积金租房提取（新流程）") + P +
   "租房提取迁移到线上：\r\n"
   "https://gjj-draw.example.info/zf\r\n"
   "需身份证号+银行卡+公积金密码。\r\n").encode(),
  "malicious", "credential_harvest", ["fund_draw_collect"], "")

E("mal_0164_vehicle_check.eml",
  (H("车管服务", "dmv@vehicle-svc.example", "driver@personal.example", "车辆年检到期（逾期罚分）") + P +
   "您的车辆年检 9/15 到期，逾期将记 3 分：\r\n"
   "预约检测（需行驶证号+身份证）：\r\n"
   "https://dmv-book.example.org/yj\r\n").encode(),
  "malicious", "pii_harvest", ["vehicle_check_collect"], "")

E("mal_0165_license_study.eml",
  (H("交管服务", "jiaoguan@study-svc.example", "driver@personal.example", "记分满 9 分，需在线学习") + P +
   "本周期记分达 9 分，须完成在线学习减免：\r\n"
   "https://jg-study.example.info/x\r\n"
   "（驾驶证号+档案编号登录）\r\n").encode(),
  "malicious", "credential_harvest", ["license_study_collect"], "")

E("mal_0166_tuition_defer.eml",
  (H("资助中心", "zz@edu-aid.example", "student@mail.example", "学费缓交申请（本批截止）") + P +
   "家庭困难可申请缓交，需提交家长收入证明与银行卡流水：\r\n"
   "https://aid-apply.example.org/hj\r\n"
   "材料直传审核老师。\r\n").encode(),
  "malicious", "pii_harvest", ["tuition_defer_collect"], "")

E("mal_0167_scholarship.eml",
  (H("学工部", "xgb@sch-svc.example", "student@mail.example", "奖学金发放信息核对") + P +
   "国家励志奖学金发放前需核对银行卡：\r\n"
   "https://sch-check.example.info/f\r\n"
   "（学号+身份证号+银行卡号）\r\n").encode(),
  "malicious", "pii_harvest", ["scholarship_collect"], "学生定向")

E("mal_0168_diploma.eml",
  (H("教务处", "jwc@edu-admin.example", "alumni@mail.example", "毕业证明书补办（校友通道）") + P +
   "校友补办需核验身份（毕业证号+身份证正反面）：\r\n"
   "https://jwc-alumni.example.org/bb\r\n"
   "20 个工作日出证。\r\n").encode(),
  "malicious", "pii_harvest", ["diploma_collect"], "")

E("mal_0169_cet.eml",
  (H("成绩查询", "cj@cet-svc.example", "student@mail.example", "四六级成绩提前查（内部通道）") + P +
   "内部通道提前 3 天查分：\r\n"
   "https://cet-early.example.info/q\r\n"
   "（准考证号+身份证号）\r\n").encode(),
  "malicious", "pii_harvest", ["score_query_collect"], "")

E("mal_0170_roll_change.eml",
  (H("教务处", "jwc@edu-svc.example", "student@mail.example", "学籍异动手续补办通知") + P +
   "您的休学复学手续缺少一项材料，请补交：\r\n"
   "https://jwc-fix.example.org/yd\r\n"
   "（教务系统账号密码登录上传）\r\n").encode(),
  "malicious", "credential_harvest", ["roll_fix_collect"], "")

E("ham_0161_perf_start.eml",
  (H("人资", "hr@corp.internal", "all-staff@corp.internal", "年度绩效评估启动") + P +
   "自评通道已开（门户-绩效-2026），9/20 截止。\r\n"
   "今年自评与 360 互评并行，权重不变。\r\n").encode(),
  "benign", "ham_business", ["perf_start"], "")

E("ham_0162_calibrate.eml",
  (H("人资-BP", "hrbp@corp.internal", "leads@corp.internal", "绩效校准会（各部门 30 分钟）") + P +
   "校准会排期已出，各部门 30 分钟，带初评结果来。\r\n"
   "强制比例今年取消。\r\n").encode(),
  "benign", "ham_business", ["calibration"], "")

E("ham_0163_refer_paid.eml",
  (H("人资", "hr@corp.internal", "staff@corp.internal", "你的内推奖金已发放") + P +
   "你推荐的候选人过保，内推奖金 4,000 元随本月薪发放，\r\n"
   "个税已代扣，明细见工资条备注。\r\n").encode(),
  "benign", "ham_business", ["refer_paid"], "")

E("ham_0164_learn_hours.eml",
  (H("培训平台", "learn@corp.internal", "staff@corp.internal", "年度学时完成情况") + P +
   "您已完成 18/20 学时，剩余 2 学时可在任意必修课补齐，\r\n"
   "12/31 截止。\r\n").encode(),
  "benign", "ham_business", ["learn_hours"], "")

E("ham_0165_instructor.eml",
  (H("培训平台", "learn@corp.internal", "leads@corp.internal", "内部讲师招募（新激励）") + P +
   "内部讲师课酬上调至 800/课时，开发课程另计。\r\n"
   "报名走培训平台-讲师通道。\r\n").encode(),
  "benign", "ham_business", ["instructor_recruit"], "")

E("ham_0166_english.eml",
  (H("工会", "union@corp.internal", "all-staff@corp.internal", "英语角恢复（每周四）") + P +
   "外教带领，主题聊天，19:00 茶水间，免费。\r\n"
   "水平不限，敢说就行。\r\n").encode(),
  "benign", "ham_business", ["english_corner"], "")

E("ham_0167_gym_class.eml",
  (H("健身房", "no-reply@gym.example", "me@personal.example", "本周团课表（新增冥想）") + P +
   "新增周三晚冥想课，其余不变。预约在小程序，\r\n"
   "会员免费。\r\n").encode(),
  "benign", "ham_personal", ["gym_class"], "")

E("ham_0168_eap_book.eml",
  (H("EAP", "eap@corp.internal", "staff@corp.internal", "心理咨询预约通道（保密）") + P +
   "预约走 EAP 平台，第三方保密，公司侧不可见名单。\r\n"
   "每人每年 6 次免费。\r\n").encode(),
  "benign", "ham_business", ["eap_booking"], "")

E("ham_0169_blood.eml",
  (H("工会", "union@corp.internal", "all-staff@corp.internal", "血站献血车进园区（10/15）") + P +
   "献血车 10/15 进园区，上午时段，献血后补休半天，\r\n"
   "报名工会小程序，体检标准现场告知。\r\n").encode(),
  "benign", "ham_business", ["blood_donation"], "")

E("ham_0170_clinic_day.eml",
  (H("行政-健康", "health@corp.internal", "campus@corp.internal", "园区义诊（骨科/口腔）") + P +
   "周四义诊进园区，骨科与口腔，免费咨询，\r\n"
   "带既往片子可优先看。\r\n").encode(),
  "benign", "ham_business", ["free_clinic"], "")

# ---- gray pairs ----
E("gray_0041_refund_scam.eml",
  (H("退费专班", "zf@edu-refund2.example", "parent@mail.example", "学费退回登记（政策窗口）") + P +
   "按新政策可退部分学费，登记银行卡与孩子身份证号：\r\n"
   "https://refund2-apply.example.vip/d\r\n"
   "窗口仅三天。\r\n").encode(),
  "malicious", "pii_harvest", ["refund_window_collect"], None,
  "与 gray_0042 同题材；三天窗口+收完整证件号为骗", True,
  "真退费也存在（政策性退费）；区分点在收件渠道与信息范围")

E("gray_0042_refund_real.eml",
  (H("机构服务", "service@edu-org.example", "parent@mail.example", "退费进度：已进入核算") + P +
   "您的退费申请已进入核算，款项原路退回支付账户，\r\n"
   "预计 5-7 个工作日。无需提供任何卡号，\r\n"
   "有疑问请在 App 内联系客服。\r\n").encode(),
  "benign", "ham_business", ["refund_real_original_path"], None,
  "原路退回+明确不索卡号是真实退费的标准形态", True,
  "退费题材真假同形；真件永不索要新卡号")

E("gray_0043_appleid_fake2.eml",
  (H("Apple Support", "id@verify-apple-id.example", "me@personal.example", "Verify your Apple ID") + P.encode() if False else
   (H("Apple Support", "id@verify-apple-id.example", "me@personal.example", "Verify your Apple ID") + P +
   "Your Apple ID was used on a new device. Confirm your password to keep access:\r\n"
   "https://verify-appleid.example.co/signin\r\n").encode()),
  "malicious", "account_phishing", ["appleid_password_page"], None,
  "真 Apple 永不在邮件里要密码——本封页面直接收密码", True,
  "Apple 钓鱼高发；判别点是是否索要凭据（真件只给状态通知）")

E("gray_0044_apple_receipt.eml",
  (H("Apple", "no_reply@email.apple.example", "me@personal.example", "您的收据：iCloud 50G") + P +
   "订单 WKQ88H412：iCloud 50G 月度 ¥21。\r\n"
   "订阅管理请在设备设置内操作；苹果不会邮件索要任何信息。\r\n").encode(),
  "benign", "ham_business", ["apple_receipt_real"], None,
  "与 gray_0043 对照；真件纯通知+反诈声明", True,
  "订阅扣费恐慌是钓鱼常用杠杆，真收据只做通知")

E("gray_0045_fee_fake.eml",
  (H("工会", "union-pay@corp-union-fee.example", "staff@corp.internal", "会费补缴（线上通道）") + P +
   "2026 会费线上补缴通道：\r\n"
   "https://union-fee2.example.net/pay\r\n"
   "未缴影响年度福利。\r\n").encode(),
  "malicious", "account_phishing", ["fee_external_domain"], None,
  "仿内部工会但用外部域+独立收银", True,
  "会费真实存在；真件走内网或工资代扣，不会跳外部支付页")

E("gray_0046_fee_real.eml",
  (H("工会", "union@corp.internal", "staff@corp.internal", "会费改为工资代扣（无需操作）") + P +
   "自 10 月起会费随薪代扣（2 元/月），无需线上缴纳，\r\n"
   "历史欠缴不补收。退出工会的回邮件即可。\r\n").encode(),
  "benign", "ham_business", ["fee_payroll_deduct"], None,
  "与 gray_0045 对照；代扣+无需操作+可退出是真实流程特征", True,
  "涉及缴费但真实流程不制造任何'需立即操作'的动作")

E("gray_0047_esign_fake.eml",
  (H("e签宝", "notice@esign-quick.example", "legal@corp.internal", "合同待签署：战略合作协议") + P +
   "对方发来协议待签，点击进入签署（需手机号+身份证号实名）：\r\n"
   "https://esign-q.example.info/s\r\n"
   "3 日内有效。\r\n").encode(),
  "malicious", "pii_harvest", ["esign_collect"], "review",
  "假电子签：以实名索取证件号", True,
  "电子签平台确实需要实名——真假区分靠平台域名与是否走公司统一签署入口")

E("gray_0048_esign_real.eml",
  (H("法务", "legal@corp.internal", "contract@corp.internal", "电子签署任务已下发（内部平台）") + P +
   "两份 NDA 已下发到内网签署平台（门户-法务-待签），\r\n"
   "外部协作者会收到平台官方域名的邀请，\r\n"
   "任何索要证件号的'签署'都不是我们的流程。\r\n").encode(),
  "benign", "ham_business", ["esign_real_internal"], None,
  "与 gray_0047 对照；真流程指明平台入口并带防伪提示", True,
  "签署类真假同形，真件的特征是入口明确+主动防伪提示")

E("gray_0049_annual_report_fake.eml",
  (H("市场监管", "wj@gs-nb2026.example", "legal@corp.internal", "年报补报最后通知（今日）") + P +
   "贵司 2025 年报尚未公示，今日为补报最后期限：\r\n"
   "http://203.0.113.88/nb\r\n"
   "逾期列入异常名录。\r\n").encode(),
  "malicious", "account_phishing", ["annual_report_ip"], None,
  "年报话术完全真实，但真入口是官方域名而非裸 IP", True,
  "政务话术+IP 入口是组合破绽；仅看话术无法判别")

E("gray_0050_audit_real2.eml",
  (H("会计师事务所", "audit@cpa-firm.example", "finance@corp.internal", "年审资料清单（9/14进场）") + P +
   "清单见附件目录：银行流水、合同台账、纳税申报表。\r\n"
   "资料通过贵司门户共享给我们项目组账号，\r\n"
   "请勿通过邮件传输凭证类文件。\r\n").encode(),
  "benign", "ham_business", ["audit_real_no_transfer"], None,
  "真实会计所；明确不走邮件传凭证本身就是安全特征", True,
  "审计邮件是钓鱼仿冒热点，真件反而强调传输渠道纪律")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch10 written: {len(LABELS)} samples")
