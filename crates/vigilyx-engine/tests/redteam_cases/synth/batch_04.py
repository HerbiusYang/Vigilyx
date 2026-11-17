#!/usr/bin/env python3
"""Batch 4: individually authored (gov/travel/consumer lures + daily ham)."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def H(disp, frm, to, subj, extra=""):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Thu, 27 Aug 2026 09:{15+len(LABELS)%44:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b4@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\n")
P = "Content-Type: text/plain; charset=utf-8\r\n\r\n"
M = "Content-Type: text/html; charset=utf-8\r\n\r\n"
def ATT(t, fn, ct, b64):
    return ("Content-Type: multipart/mixed; boundary=\"BS\"\r\n\r\n"
            f"--BS\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{t}\r\n"
            f"--BS\r\nContent-Type: {ct}\r\nContent-Disposition: attachment; filename=\"{fn}\"\r\n"
            f"Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--BS--\r\n")
def B64(s): return base64.b64encode(s.encode()).decode()
def E(n, raw, label, family, lang, tech, note=""):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 4, "note": note})

E("mal_0061_access_control.eml",
  (H("智慧园区", "iac@park-sys.example", "employee@corp.internal", "门禁权限即将回收") + P +
   "您好：因组织架构同步，您在 2 号楼的门禁权限将于本周五回收。\r\n"
   "如仍需通行，请在回收前完成一次权限续期登记：\r\n"
   "https://iac-park.example.info/renew\r\n").encode(),
  "malicious", "account_phishing", "zh", ["access_control_lure"], "门禁话术")

E("mal_0062_vpn_cert.eml",
  (H("网络服务", "vpn@net-ops.example", "remote@corp.internal", "VPN 接入证书到期提醒（72小时）") + P +
   "您当前的 VPN 接入证书将在 72 小时后失效，届时无法远程办公。\r\n"
   "请提前换发：https://vpn-cert-renew.example.net/apply\r\n"
   "（换发需使用域账号登录，请勿使用公共网络操作）\r\n").encode(),
  "malicious", "account_phishing", "zh", ["vpn_cert_lure"], "远程办公定向")

E("mal_0063_im_reauth.eml",
  (H("协同办公", "support@im-suite.example", "staff@corp.internal", "客户端需重新完成实名绑定") + P +
   "接监管要求，协同办公客户端需在月底前重新实名。\r\n"
   "未实名的账号将无法收发工作消息与文档。\r\n"
   "绑定入口：https://im-verify.example.org/bind\r\n").encode(),
  "malicious", "account_phishing", "zh", ["im_reauth_lure"], "IM 实名话术")

E("mal_0064_legal_person_cert.eml",
  (H("数字证书服务", "ca@legal-cert.example", "legal@corp.internal", "法人一证通数字证书年检通知") + P +
   "贵单位法人一证通数字证书已进入年检期。\r\n"
   "未按期年检的证书将暂停使用，影响税务与社保申报。\r\n"
   "年检地址：https://ca-annual.example.ru/inspect\r\n").encode(),
  "malicious", "account_phishing", "zh", ["legal_person_cert"], "政务证书年检话术")

E("mal_0065_biz_license.eml",
  (H("市场监管提示", "notice@credit-srv.example", "legal@corp.internal", "电子营业执照年报填写提醒") + P +
   "经比对，贵单位 2025 年度电子营业执照年报信息尚不完整。\r\n"
   "请于本月底前补报，逾期将列入经营异常名录：\r\n"
   "http://203.0.113.77/annual/report\r\n").encode(),
  "malicious", "account_phishing", "zh", ["biz_license_annual", "ip_url"], "公文体")

E("mal_0066_parcel_fee.eml",
  (H("快件服务", "depot@express-svc.example", "user@corp.internal", "快件滞留第3天，即将收取仓储费") + P +
   "您的快件在网点滞留超过 72 小时，明日起按 2 元/天收取仓储费。\r\n"
   "确认改派或自取请点：https://express-arrange.example.info/reschedule\r\n").encode(),
  "malicious", "account_phishing", "zh", ["parcel_fee_pressure"], "")

E("mal_0067_etc_abnormal.eml",
  (H(" ETC服务", "etc@highway-notice.example", "driver@personal.example", "【ETC】通行费扣款异常提醒") + P +
   "您名下车辆 8 月通行费存在一笔扣款异常，为避免列入黑名单，\r\n"
   "请今日内核实补缴：https://etc-pay-fix.example.co/verify\r\n").encode(),
  "malicious", "account_phishing", "zh", ["etc_lure"], "车主定向")

E("mal_0068_fund_bind.eml",
  (H("公积金中心", "gjj@fund-city.example", "employee@corp.internal", "公积金账户关联失效告知") + P +
   "因系统升级，您的公积金账户与银行卡的关联关系失效，\r\n"
   "提取与贷款功能暂停，请重新关联：\r\n"
   "https://fund-rebind.example.org/card\r\n").encode(),
  "malicious", "account_phishing", "zh", ["fund_rebind"], "")

E("mal_0069_cloud_purge.eml",
  (H("云盘运营", "drive@cloud-svc.example", "user@corp.internal", "账号活跃度不足，30 日后清理") + P +
   "您的云盘已连续 180 天未完成安全校验，按规则将于 30 日后进入清理队列。\r\n"
   "保留数据请完成校验：https://drive-keep.example.net/check\r\n").encode(),
  "malicious", "account_phishing", "zh", ["cloud_purge_lure"], "")

E("mal_0070_exam_confirm.eml",
  (H("考试中心", "reg@exam-svc.example", "student@mail.example", "报名信息最后确认（今日 24:00 截止）") + P +
   "您的考试报名信息存在一项待确认项，今日 24:00 后不可修改。\r\n"
   "确认入口：https://exam-confirm.example.info/final\r\n"
   "未确认视为放弃本次报考。\r\n").encode(),
  "malicious", "account_phishing", "zh", ["exam_deadline"], "考生定向")

E("mal_0071_hospital_refund.eml",
  (H("门诊服务", "reg@hospital-notice.example", "patient@personal.example", "挂号退费需电话核实") + P +
   "您 8 月的挂号退费申请已审核通过，退费前需本人致电核实身份。\r\n"
   "退费专线：400-861-2273（仅工作日 14:00-16:00）。\r\n").encode(),
  "malicious", "toad", "zh", ["hospital_refund_hotline"], "")

E("mal_0072_flight_change.eml",
  (H("行程服务", "trip@air-notify.example", "traveler@personal.example", "您的航班可免费改签一次") + P +
   "受运力调整影响，您 9/12 的航班可免费改签一次，\r\n"
   "改签须今日内在线确认：https://trip-change.example.club/swap\r\n"
   "逾期恢复收费改签。\r\n").encode(),
  "malicious", "account_phishing", "zh", ["flight_change"], "旅客定向")

E("mal_0073_sample_fee.eml",
  (H("采购-李工", "li@supplier-mold.example", "purchase@corp.internal", "样品费先付，模具费月底") + P +
   "王工：打样排期出来了，样品费 8,600 先付才能排产，\r\n"
   "账户以我邮件里发的那份为准（财务户名换了），收据后补。\r\n"
   "模具费月底一起走，别走系统，赶时间。\r\n").encode(),
  "malicious", "bec", "zh", ["sample_fee_bypass_process"], "绕流程话术")

E("mal_0074_mold_split.eml",
  (H("财务-共享", "ap-share@partner.example", "treasury@corp.internal", "模具款拆两笔支付的通知") + P +
   "按与供应商最新约定，模具款拆两笔：首笔 60% 付新账户，尾款 40% 付原账户。\r\n"
   "新账户资料在其邮件里，今天先出首笔。\r\n").encode(),
  "malicious", "bec", "zh", ["split_payment_new_account"], "")

E("mal_0075_deposit_return.eml",
  (H("房东", "landlord@rental.example", "tenant@personal.example", "押金退还，麻烦发下银行卡") + P +
   "小周：房子验收没问题，押金这周退你。\r\n"
   "把银行卡号、开户行和预留手机号发我邮箱，另外拍一张手持身份证照片,\r\n"
   "中介要走个流程。\r\n").encode(),
  "malicious", "pii_harvest", "zh", ["deposit_pii_collect"], "生活场景 PII")

E("mal_0076_lottery_verify.eml",
  (H("活动运营", "prize@shop-anniv.example", "user@corp.internal", "您有一份周年礼待核实") + P +
   "恭喜您在门店周年活动中被抽中，礼品保留至本周日。\r\n"
   "核实领取资格（需实名+手机号）：https://prize-claim.example.vip/go\r\n").encode(),
  "malicious", "account_phishing", "zh", ["lottery_claim"], "")

E("mal_0077_parking_qr.eml",
  (H("停车场", "pm@parking-svc.example", "driver@personal.example", "月卡续费改为扫码") + P +
   "本月起月卡续费取消柜台，请扫码自助续费（支持优惠券）：\r\n"
   "二维码见附件图片，7 日内有效。\r\n").encode(),
  "malicious", "quishing", "zh", ["parking_qr_lure"], "无链接引导扫码")

E("mal_0078_dining_qr.eml",
  (H("餐饮服务", "vip@food-court.example", "employee@corp.internal", "餐补余额迁移，扫码激活") + P +
   "旧餐补系统下线，余额需迁移到新档口系统。\r\n"
   "在食堂扫描海报二维码完成激活，余额 30 日后清零。\r\n").encode(),
  "malicious", "quishing", "zh", ["canteen_qr_lure"], "员工福利定向")

E("mal_0079_mailbox_expand_form.eml",
  (H("邮箱服务", "quota@mail-admin.example", "staff@corp.internal", "容量升级申请（需验证）") + M +
   "<html><body><p>申请邮箱容量升级到 20G，请验证域账号：</p>"
   "<form action='https://mail-expand.example.info/apply'>"
   "<input name='account' placeholder='邮箱账号'><input type='password' name='pwd' placeholder='密码'>"
   "<button>提交申请</button></form></body></html>").encode(),
  "malicious", "credential_harvest", "zh", ["body_form_password"], "")

E("mal_0080_vpn_form.eml",
  (H("远程接入", "vpn@corp-gateway.example", "remote@corp.internal", "新 VPN 控制台首次登录") + M +
   "<html><body><p>VPN 控制台已更换，首次登录需验证：</p>"
   "<form action='http://203.0.113.60/vpn'><input name='user' placeholder='域账号'>"
   "<input type='password' name='pass' placeholder='域密码'><button>登录</button></form>"
   "</body></html>").encode(),
  "malicious", "credential_harvest", "zh", ["body_form_password", "ip_action"], "")

E("ham_0061_meeting_shift.eml",
  (H("产品-苏黎", "su.li@corp.internal", "proj@corp.internal", "评审挪到周五下午三点") + P +
   "各位：评审改周五 15:00，架构那页我又改了一版，\r\n"
   "会上直接过差异，不用预读。冲突的单独找我。\r\n").encode(),
  "benign", "ham_business", "zh", ["meeting_shift"], "")

E("ham_0062_travel_policy.eml",
  (H("财务共享", "fssc@corp.internal", "all-staff@corp.internal", "差旅标准微调（9月执行）") + P +
   "9 月起经济舱折扣舱位放开到全价 75 折以内可自订；\r\n"
   "住宿标准不变。旧流程里\"HR 审批\"一步取消。\r\n"
   "详见门户-制度-差旅。\r\n").encode(),
  "benign", "ham_business", "zh", ["policy_update"], "")

E("ham_0063_desk_move.eml",
  (H("行政台", "admin-desk@corp.internal", "dev-team@corp.internal", "工位调整：3F 东区下周一") + P +
   "下周一 3F 东区工位重排，个人物品周五下班前收纳到纸箱贴工号，\r\n"
   "周一上午到场认领新位。显示器不用搬。\r\n").encode(),
  "benign", "ham_business", "zh", ["desk_move"], "")

E("ham_0064_badge_extend.eml",
  (H("门禁中心", "badge@corp.internal", "contractor@corp.internal", "外包工牌延期已办好") + P +
   "您的工牌有效期已延至 12/31，无需换卡。\r\n"
   "权限范围不变，加班时段自动放行。\r\n").encode(),
  "benign", "ham_business", "zh", ["badge_extend"], "")

E("ham_0065_internal_transfer.eml",
  (H("人资-BP", "hrbp@corp.internal", "all-staff@corp.internal", "平台工程组内部转岗开放（2 名）") + P +
   "平台工程组开放 2 个内部转岗名额，方向是网关与发布系统，\r\n"
   "P6 起，要求在岗满一年。感兴趣的本周五前发简历给 BP 邮箱。\r\n").encode(),
  "benign", "ham_business", "zh", ["internal_transfer"], "")

E("ham_0066_advisor_reply.eml",
  (H("导师-郑老师", "zheng@univ.example", "student@univ.example", "Re: 大论文第四章") + P +
   "第四章实验部分说服力不够，补一组消融；\r\n"
   "4.2 节的公式编号乱了，图 4-3 重画。周五组会讲进展。\r\n").encode(),
  "benign", "ham_business", "zh", ["advisor_reply"], "")

E("ham_0067_grad_admit.eml",
  (H("研究生院", "yjs@univ.example", "applicant@personal.example", "硕士生拟录取通知（公示版）") + P +
   "恭喜进入拟录取名单，公示期 10 个工作日。\r\n"
   "调档函与政审表将以纸质寄出，请保持电话畅通。\r\n"
   "本邮件无附件无链接。\r\n").encode(),
  "benign", "ham_business", "zh", ["grad_admit"], "")

E("ham_0068_ecom_ship.eml",
  (H("店铺发货", "ship@myshop.example", "buyer@personal.example", "您的订单已发货") + P +
   "亲爱的顾客：您的订单（蓝牙耳机 x1）已发货，中通 7831 xxxx，\r\n"
   "预计后天到。有问题随时回信，小店感谢支持。\r\n").encode(),
  "benign", "ham_business", "zh", ["ecom_ship"], "")

E("ham_0069_fishtank.eml",
  (H("老韩", "han@personal.example", "me@personal.example", "鱼缸你要就周六来搬") + P +
   "鱼缸带架子底滤都在，水泵上个月刚换。你周六上午来，\r\n"
   "两个人抬得动，顺路把你那套书还我。\r\n").encode(),
  "benign", "ham_personal", "zh", ["secondhand"], "")

E("ham_0070_pet_vaccine.eml",
  (H("宠颐生宠物医院", "svc@petclinic.example", "me@personal.example", "疫苗加强针到期提醒") + P +
   "糖豆（猫）的狂犬疫苗将于 9/10 到期，可预约周间下午。\r\n"
   "到院需出示上次的免疫本。\r\n").encode(),
  "benign", "ham_personal", "zh", ["pet_vaccine"], "")

E("ham_0071_driving_school.eml",
  (H("驾校-张教练", "coach@driving.example", "me@personal.example", "科目三练车改周五") + P +
   "周五下午考场清场，正好练三条线，14:00 驾校门口集合。\r\n"
   "带身份证，穿软底鞋。\r\n").encode(),
  "benign", "ham_personal", "zh", ["driving_school"], "")

E("ham_0072_health_report.eml",
  (H("体检中心", "report@checkup.example", "me@personal.example", "您的体检报告已生成") + P +
   "今年报告已出，两项随访建议（详见纸质报告第 3 页）。\r\n"
   "纸质版已寄出，线上复查请在小程序登录本人档案。\r\n").encode(),
  "benign", "ham_personal", "zh", ["health_report"], "")

E("ham_0073_kindergarten.eml",
  (H("中二班-陈老师", "teacher@kg.example", "parent@mail.example", "本周亲子作业与着装") + P +
   "本周主题是树叶贴画，周一带三片不同的叶子；\r\n"
   "周三有体能课穿运动鞋。图书角还差两名义工家长。\r\n").encode(),
  "benign", "ham_personal", "zh", ["kindergarten"], "")

E("ham_0074_group_buy.eml",
  (H("团长-莉莉", "lily@community.example", "neighbors@list.example", "周四海鲜团到货") + P +
   "明晚 7 点南门取货，带袋子。帝王蟹只剩两份要的说一声。\r\n"
   "没付款的接龙里补一下。\r\n").encode(),
  "benign", "ham_personal", "zh", ["group_buy"], "")

E("ham_0075_apple_receipt.eml",
  (H("Apple", "no_reply@email.apple.example", "me@personal.example", "您的收据") + P +
   "文档编号 1782xxxx。App Store 购买：云盘 2T 月度订阅 ¥68。\r\n"
   "如非本人操作可在设备上查看订阅管理。\r\n").encode(),
  "benign", "ham_business", "zh", ["apple_receipt"], "硬负样本：订阅扣款")

E("ham_0076_domain_renew.eml",
  (H("注册商", "support@registrar.example", "webmaster@personal.example", "域名 30 天后到期") + P +
   "example.dev 将于 30 天后到期，请及时续费避免释放。\r\n"
   "登录控制台操作；本邮件不含直接支付链接。\r\n").encode(),
  "benign", "ham_business", "zh", ["domain_renewal"], "")

E("ham_0077_gha_action.eml",
  (H("GitHub Actions", "actions@github.example", "dev@corp.internal", "[ci] workflow run failed: e2e") + P +
   "e2e (chrome) run #2214 failed at step \"login spec\" (exit 1).\r\n"
   "Log: https://git.corp.internal/vigilyx/actions/runs/2214\r\n"
   "Re-run or bisect at the link above.\r\n").encode(),
  "benign", "ham_business", "zh", ["ci_failed"], "失败告警也是良性")

E("ham_0078_figma_comment.eml",
  (H("Figma", "notify@figma.example", "design@corp.internal", "珂珂 评论了你的设计稿") + P +
   "@你：设置页的信息架构图 12 框，第二层建议合并。\r\n"
   "打开文件回复：https://figma.corp.internal/file/board-settings\r\n").encode(),
  "benign", "ham_business", "zh", ["figma_comment"], "")

E("ham_0079_backup_done.eml",
  (H("备份系统", "backup@corp.internal", "ops@corp.internal", "[OK] 夜间全量备份完成") + P +
   "全量 2.1T 完成 03:12，校验通过，快照保留 14 份。\r\n"
   "异地副本延迟 40 分钟同步完成。\r\n").encode(),
  "benign", "ham_business", "zh", ["backup_ok"], "")

E("ham_0080_cert_expiry.eml",
  (H("证书巡检", "certbot@corp.internal", "ops@corp.internal", "api.corp.internal 证书 14 天后到期") + P +
   "ACME 自动续期上次失败（DNS 超时），请手工触发：\r\n"
   "运维手册 runbook 第 7 节。逾期影响小程序端接口。\r\n").encode(),
  "benign", "ham_business", "zh", ["cert_expiry"], "")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch4 written: {len(LABELS)} samples")
