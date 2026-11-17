#!/usr/bin/env python3
"""Batch 8: individually authored (tax/esop/wedding/edu lures + workplace ham)."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def H(disp, frm, to, subj, extra=""):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Mon, 31 Aug 2026 09:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b8@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\n")
P = "Content-Type: text/plain; charset=utf-8\r\n\r\n"
def ATT(t, fn, ct, b64):
    return ("Content-Type: multipart/mixed; boundary=\"BS\"\r\n\r\n"
            f"--BS\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{t}\r\n"
            f"--BS\r\nContent-Type: {ct}\r\nContent-Disposition: attachment; filename=\"{fn}\"\r\n"
            f"Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--BS--\r\n")
def B64(s): return base64.b64encode(s.encode()).decode()
def E(n, raw, label, family, tech, note=""):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": "zh", "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 8, "note": note})

E("mal_0121_wecom_invite.eml",
  (H("协作平台", "invite@wecom-svc.example", "staff@corp.internal", "您被邀请加入新工作群「管理层通报」") + P +
   "点击加入群聊，加入后可见历史通报：\r\n"
   "https://wecom-inv.example.info/join\r\n"
   "邀请 24 小时内有效。\r\n").encode(),
  "malicious", "account_phishing", ["im_group_invite"], "仿协作平台邀请")

E("mal_0122_red_invoice.eml",
  (H("税务服务", "svc@tax-swap.example", "tax@corp.internal", "红字发票信息表待确认（今日闭环）") + P +
   "您上月开具的发票被受票方冲红，需今日确认红字信息表：\r\n"
   "https://tax-red.example.org/confirm\r\n"
   "逾期将转异常凭证并影响申报。\r\n").encode(),
  "malicious", "account_phishing", ["tax_red_invoice"], "财务定向")

E("mal_0123_labor_contract.eml",
  (H("人事系统", "ehr@sign-flow.example", "newhire@corp.internal", "电子劳动合同待签署（3日有效）") + P +
   "您的劳动合同已生成，请在线签署：\r\n"
   "https://ehr-sign.example.net/ct\r\n"
   "（需实名+人脸核身后方可签署）\r\n").encode(),
  "malicious", "account_phishing", ["contract_sign_face"], "签署+人脸收集")

E("mal_0124_esop_window.eml",
  (H("股权平台", "esop@option-svc.example", "staff@corp.internal", "行权窗口开启（本周截止）") + P +
   "本期行权窗口截至本周五，逾期顺延半年。\r\n"
   "行权操作（需域账号）：https://esop-act.example.ru/ex\r\n").encode(),
  "malicious", "account_phishing", ["esop_window_lure"], "员工股权定向")

E("mal_0125_wedding_card.eml",
  (H("小明&小红", "invite@our-wed.example", "friends@list.example", "我们的婚礼请帖")
   + ATT("诚邀您参加我们的婚礼，详情见附件电子请帖。",
         "婚礼请帖.html", "text/html",
         B64("<html><head><meta http-equiv='refresh' content='0;url=https://wed-gift-pay.example.vip/rsvp'></head>"
             "<body>打开请帖…</body></html>"))),
  "malicious", "redirect_attachment", ["wedding_htm_refresh"], "婚礼请帖载体")

E("mal_0126_course_refund.eml",
  (H("退费中心", "refund@edu-payback.example", "parent@mail.example", "您的培训费用可申请退回") + P +
   "按政策部分培训费用可协商退回，登记后 3-5 日到账：\r\n"
   "https://edu-refund.example.vip/apply\r\n"
   "需填写监护人银行卡与孩子学籍号。\r\n").encode(),
  "malicious", "pii_harvest", ["course_refund_collect"], "教育退费骗局")

E("mal_0127_train_refund_call.eml",
  (H("课程顾问", "kf@kecheng-svc.example", "parent@mail.example", "退费事宜请专线联系") + P +
   "您的退费申请已受理，专员回访请接听：400-6900-117。\r\n"
   "需按语音提示输入银行卡号完成退款登记。\r\n").encode(),
  "malicious", "toad", ["refund_ivr_card"], "电话 IVR 收卡号")

E("mal_0128_appleid_alert.eml",
  (H("Apple", "no_replyid@apple-id-verify.example", "me@personal.example", "您的 Apple ID 在新设备登录") + P +
   "检测到您的 Apple ID 在济南的 iPhone 登录。如非本人，请立即验证：\r\n"
   "https://apple-id-check.example.co/verify\r\n"
   "24 小时内未验证将冻结 ID。\r\n").encode(),
  "malicious", "account_phishing", ["appleid_lure"], "高发仿冒")

E("mal_0129_icloud_full.eml",
  (H("iCloud", "noreply@icloud-store.example", "me@personal.example", "存储空间已满，备份暂停") + P +
   "iCloud 免费空间已满，iCloud 照片备份已暂停。\r\n"
   "升级或清理：https://icloud-space-up.example.info/m\r\n").encode(),
  "malicious", "account_phishing", ["icloud_space"], "")

E("mal_0130_wechat_unlock.eml",
  (H("微信服务", "help@wx-unlock.example", "me@personal.example", "账号辅助解封邀请") + P +
   "好友申请您协助解封账号，点击查看协助流程：\r\n"
   "https://wx-help-unlock.example.vip/a\r\n"
   "（需登录并人脸验证）\r\n").encode(),
  "malicious", "account_phishing", ["wechat_unlock_face"], "解封骗局")

E("mal_0131_live_margin.eml",
  (H("直播带货", "settle@live-shop.example", "merchant@corp.internal", "保证金未缴，橱窗即将关闭") + P +
   "新规要求补缴带货保证金 2,000 元，否则橱窗下架：\r\n"
   "https://live-margin.example.club/pay\r\n"
   "今日内有效。\r\n").encode(),
  "malicious", "account_phishing", ["live_margin"], "商家定向")

E("mal_0132_exam_link.eml",
  (H("招聘笔试", "exam@hire-test.example", "candidate@mail.example", "在线笔试链接（90分钟）") + P +
   "笔试链接（含屏幕监控授权）：https://hire-exam.example.org/go\r\n"
   "需身份证号+手机号登录，开考后不可暂停。\r\n").encode(),
  "malicious", "pii_harvest", ["exam_login_collect"], "")

E("mal_0133_intern_cert.eml",
  (H("就业指导", "svc@career-edu.example", "student@mail.example", "实习证明申领（在校生）") + P +
   "申领实习证明需核验学籍：\r\n"
   "https://career-cert.example.info/st\r\n"
   "（学号+身份证号+教务系统密码）\r\n").encode(),
  "malicious", "credential_harvest", ["intern_cert_collect"], "收教务密码")

E("mal_0134_union_fee.eml",
  (H("工会", "fee@union-pay.example", "staff@corp.internal", "2026 会费补缴通知") + P +
   "系统显示您有两个季度会费未缴，影响福利资格。\r\n"
   "补缴：https://union-fee-pay.example.net/2026\r\n").encode(),
  "malicious", "account_phishing", ["union_fee_fake_domain"], "")

E("mal_0135_power_fee.eml",
  (H("物业缴费", "pm@elec-fee.example", "owner@personal.example", "电费预存不足，明日暂停供电") + P +
   "您户内预存电费余额不足 10 元，明日 9:00 起暂停供电。\r\n"
   "线上充值：https://elec-topup.example.info/cz\r\n").encode(),
  "malicious", "account_phishing", ["power_cutoff_pressure"], "")

E("mal_0136_campus_card.eml",
  (H("一卡通中心", "card@campus-svc.example", "student@mail.example", "校园卡充值通道维护通知") + P +
   "原充值通道维护，请使用临时通道充值（家长可代充）：\r\n"
   "https://campus-card-tmp.example.org/cz\r\n"
   "维护期 48 小时。\r\n").encode(),
  "malicious", "account_phishing", ["campus_card_tmp"], "家长代充话术")

E("mal_0137_lib_fine.eml",
  (H("图书馆", "fine@lib-city.example", "me@personal.example", "超期滞纳金未缴，暂停外借") + P +
   "您有 3 本书超期，滞纳金 6.4 元，未缴暂停外借权限：\r\n"
   "https://lib-pay-fine.example.co/pay\r\n").encode(),
  "malicious", "account_phishing", ["library_fine"], "小额滞纳金")

E("mal_0138_car_recall.eml",
  (H("客户关怀", "recall@auto-brand.example", "driver@personal.example", "您的车辆涉及召回范围") + P +
   "经备案，您的车辆在召回范围，请在线预约免费检修并登记银行卡（过路费返还）：\r\n"
   "https://auto-recall-book.example.info/r\r\n").encode(),
  "malicious", "pii_harvest", ["recall_card_collect"], "以召回收卡")

E("mal_0139_dividend.eml",
  (H("分红通知", "fh@insure-pay.example", "me@personal.example", "年度分红可领取（本月）") + P +
   "您的保单年度分红 1,240 元可领取，登录领取页：\r\n"
   "https://div-claim.example.vip/get\r\n"
   "（需保单号+身份证后六位）\r\n").encode(),
  "malicious", "account_phishing", ["dividend_claim"], "")

E("mal_0140_credit_limit.eml",
  (H("信用卡中心", "svc@card-limit.example", "me@personal.example", "临时额度即将失效，可申请转固定") + P +
   "您的临时额度 9 月 5 日失效，达标可转固定额度：\r\n"
   "https://limit-up.example.co/fix\r\n"
   "需验证卡号与 CVV。\r\n").encode(),
  "malicious", "credential_harvest", ["cvv_collect"], "收 CVV")

E("ham_0121_hackathon.eml",
  (H("创新办", "innovation@corp.internal", "all-staff@corp.internal", "内部黑客马拉松 10 月开跑") + P +
   "48 小时组队做小工具，主题自由。往届冠军做了会议室占位机器人。\r\n"
   "报名走创新办频道，9/20 截止。\r\n").encode(),
  "benign", "ham_business", ["hackathon"], "")

E("ham_0122_ip_talk.eml",
  (H("法务-知产", "ip@corp.internal", "all-staff@corp.internal", "知产讲座：开源协议合规") + P +
   "周三 16:00 报告厅，讲开源协议与商用边界，研发同学建议参加。\r\n"
   "课件会后挂知识库。\r\n").encode(),
  "benign", "ham_business", ["ip_talk"], "")

E("ham_0123_nda_sign.eml",
  (H("法务", "legal@corp.internal", "newhire@corp.internal", "保密协议电子签署（内部平台）") + P +
   "入职保密协议已推送到内网签署平台（门户-法务-待签），\r\n"
   "请在到岗一周内完成，纸质版无需。\r\n").encode(),
  "benign", "ham_business", ["internal_sign_platform"], "真实电子签署走内网")

E("ham_0124_weekly_tpl.eml",
  (H("PMO", "pmo@corp.internal", "leads@corp.internal", "周报模板更新（增加风险栏）") + P +
   "下月起周报模板增加\"依赖风险\"一栏，模板已更新到共享盘，\r\n"
   "老模板自动兼容。\r\n").encode(),
  "benign", "ham_business", ["weekly_template"], "")

E("ham_0125_okr.eml",
  (H("部门长-老许", "xu@corp.internal", "team-a@corp.internal", "Q4 OKR 对齐会改周二") + P +
   "对齐会改周二上午，各自把 O 带来，KR 现场掰扯。\r\n"
   "别写产出型 KR，写结果型的。\r\n").encode(),
  "benign", "ham_business", ["okr_meeting"], "")

E("ham_0126_mentor.eml",
  (H("人资-培训", "train@corp.internal", "team-a@corp.internal", "新人导师配对（9月批）") + P +
   "本批三位新人导师已配对：小蔺-后端、珂珂-设计、老许-平台。\r\n"
   "导师津贴按月随薪。\r\n").encode(),
  "benign", "ham_business", ["mentor_pairing"], "")

E("ham_0127_code_style.eml",
  (H("架构组", "arch@corp.internal", "dev-team@corp.internal", "Rust 代码规范 v1.2 生效") + P +
   "v1.2 主要变化：错误处理统一 thiserror、日志字段规范。CI 已挂 lint。\r\n"
   "存量代码不强制回改。\r\n").encode(),
  "benign", "ham_business", ["code_style"], "")

E("ham_0128_dep_upgrade.eml",
  (H("架构组", "arch@corp.internal", "dev-team@corp.internal", "tokio 升级评审（周三）") + P +
   "tokio 1.x 升级 PR 已挂，改动集中在定时器 API。\r\n"
   "周三过一遍，灰度计划附在 PR 描述。\r\n").encode(),
  "benign", "ham_business", ["dep_review"], "")

E("ham_0129_incident_review.eml",
  (H("SRE", "sre@corp.internal", "it-all@corp.internal", "8/30 支付抖动复盘会") + P +
   "影响 14 分钟，根因连接池配置。复盘周四 15:00，\r\n"
   "改进项三条已立项。\r\n").encode(),
  "benign", "ham_business", ["incident_review"], "")

E("ham_0130_sprint.eml",
  (H("产品-苏黎", "su.li@corp.internal", "proj@corp.internal", "第37迭代计划已发布") + P +
   "本迭代 21 个需求，灰度工具链占 6 个。\r\n"
   "排期看板已同步，锁版周四。\r\n").encode(),
  "benign", "ham_business", ["sprint_plan"], "")

E("ham_0131_customer_event.eml",
  (H("市场部", "marketing@corp.internal", "sales@corp.internal", "客户答谢会筹备分工") + P +
   "10/18 答谢会，场地已定。缺两位现场对接人，\r\n"
   "议程初稿在共享盘，周五评审。\r\n").encode(),
  "benign", "ham_business", ["customer_event"], "")

E("ham_0132_expo.eml",
  (H("市场部", "marketing@corp.internal", "pmo@corp.internal", "云栖展位物料清单确认") + P +
   "展位物料清单请今天确认（含两台演示机），\r\n"
   "物流周四提货，随行人员名单同步行政。\r\n").encode(),
  "benign", "ham_business", ["expo_logistics"], "")

E("ham_0133_tm_internal.eml",
  (H("法务-知产", "ip@corp.internal", "legal@corp.internal", "商标第9类续展（内部流程）") + P +
   "第 9 类商标明年 3 月到期，续展材料我这边准备，\r\n"
   "需要研发提供两个使用证据截图（带日期）。\r\n").encode(),
  "benign", "ham_business", ["tm_renew_internal"], "与假代理钓鱼同形（gray_0032 对照系）")

E("ham_0134_audit_entry.eml",
  (H("财务-审计", "audit@corp.internal", "finance@corp.internal", "年审进场安排（9/14-9/18）") + P +
   "会计师事务所 9/14 进场年审，需提前备好银行流水与合同台账。\r\n"
   "现场对接：小蔡。清单见财务频道。\r\n").encode(),
  "benign", "ham_business", ["real_audit_entry"], "与假集团审计钓鱼同形")

E("ham_0135_compliance_training.eml",
  (H("合规部", "compliance@corp.internal", "all-staff@corp.internal", "数据合规必修课（11月截止）") + P +
   "个保法专题必修课上线，门户-合规-必修。\r\n"
   "11/30 截止，计入考核。\r\n").encode(),
  "benign", "ham_business", ["compliance_course"], "")

E("ham_0136_pipl_check.eml",
  (H("合规部", "compliance@corp.internal", "rd-leads@corp.internal", "个保法自查清单（研发部分）") + P +
   "研发侧自查三件事：埋点脱敏、日志含 PII 排查、导出审批留痕。\r\n"
   "表单在合规频道，下周五回收。\r\n").encode(),
  "benign", "ham_business", ["pipl_check"], "")

E("ham_0137_vpn_upgrade.eml",
  (H("网络服务", "vpn@corp.internal", "remote@corp.internal", "VPN 客户端周四晚升级") + P +
   "周四 22:00 客户端强制升级，旧版本将无法登录。\r\n"
   "升级包在内网下载页，会议不影响。\r\n").encode(),
  "benign", "ham_business", ["vpn_upgrade"], "")

E("ham_0138_print_quota.eml",
  (H("行政", "admin@corp.internal", "all-staff@corp.internal", "打印配额调整（下月起）") + P +
   "黑白不限量取消，改为每月 200 页，超出走部门审批。\r\n"
   "彩色维持申请制。\r\n").encode(),
  "benign", "ham_business", ["print_quota"], "")

E("ham_0139_room_book.eml",
  (H("会议室系统", "room@corp.internal", "staff@corp.internal", "您预订的会议室变更通知") + P +
   "3F-301 周四 14:00 改为 5F-502（投影维护），日历已同步。\r\n"
   "如不需要请取消释放。\r\n").encode(),
  "benign", "ham_business", ["room_change"], "")

E("ham_0140_ac_temp.eml",
  (H("行政台", "admin-desk@corp.internal", "campus@corp.internal", "空调温度统一设定通知") + P +
   "响应限电，办公区空调统一 26 度，个人位风扇自便。\r\n"
   "下班前关灯关空调。\r\n").encode(),
  "benign", "ham_business", ["ac_temp"], "")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch8 written: {len(LABELS)} samples")
