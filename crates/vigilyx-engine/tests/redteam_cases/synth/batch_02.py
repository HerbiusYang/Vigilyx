#!/usr/bin/env python3
"""Batch 2: individually authored samples (redirect/identity/link-obs mal + ops ham)."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(name, raw): open(os.path.join(ROOT, "synth", name), "wb").write(raw)
def H(disp, frm, to, subj, extra=""):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Tue, 25 Aug 2026 10:{20+len(LABELS)%39:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b2@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\n")
P = "Content-Type: text/plain; charset=utf-8\r\n\r\n"
M = "Content-Type: text/html; charset=utf-8\r\n\r\n"
def ATT(text_part, fn, ct, payload_b64, cte="base64"):
    return ("Content-Type: multipart/mixed; boundary=\"BS\"\r\n\r\n"
            f"--BS\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{text_part}\r\n"
            f"--BS\r\nContent-Type: {ct}\r\nContent-Disposition: attachment; filename=\"{fn}\"\r\n"
            f"Content-Transfer-Encoding: {cte}\r\n\r\n{payload_b64}\r\n--BS--\r\n")
def B64(s): return base64.b64encode(s.encode()).decode()
def E(name, raw, label, family, lang, tech, note=""):
    W(name, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{name}", "case_id": name[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 2, "note": note})

# ---- malicious: attachment redirect family ----
E("mal_0022_attach_notice_html.eml",
  (H("电子公文", "doc@oa-notice.example", "office@corp.internal", "内部文件传阅")
   + ATT("各部门：传阅文件见附件，打开后按页面提示登录阅办。",
         "传阅文件.html", "text/html",
         B64("<html><head><meta http-equiv='refresh' content='0;url=https://oa-read.example.info/auth'></head>"
             "<body>正在打开阅办系统…</body></html>"))),
  "malicious", "redirect_attachment", "zh", ["attach_meta_refresh"], "公文话术+跳转")

E("mal_0023_attach_ics_pay.eml",
  (H("会议系统", "meeting@corp-partner.example", "exec@corp.internal", "董事会材料预审会")
   + ATT("会议详情见附件日历，请接受邀请。",
         "board.ics", "text/calendar",
         B64("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nSUMMARY:董事会预审\r\n"
             "ORGANIZER;CN=董事长办公室:mailto:board@partner.example\r\n"
             "URL:https://board-review.example.ru/login\r\n"
             "DESCRIPTION:材料已加密，点击链接用域账号解密查看\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"))),
  "malicious", "redirect_attachment", "zh", ["ics_url_domain_auth"], "日历+域账号解密话术")

E("mal_0024_attach_vcard.eml",
  (H("商务拓展", "bd@newmarket.example", "sales@corp.internal", "新客户对接人名片")
   + ATT("下周来访的客户对接信息见附件名片。",
         "客户对接人.vcf", "text/vcard",
         B64("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:采购总监-林\r\nORG:新程集团\r\n"
             "URL:https://supplier-portal.example.net/apply\r\nEND:VCARD\r\n"))),
  "malicious", "redirect_attachment", "zh", ["vcard_url"], "")

E("mal_0025_attach_url_shortcut.eml",
  (H("共享盘", "share@drv-notify.example", "rd@corp.internal", "共享盘迁移通知")
   + ATT("旧共享盘已迁移，请用附件快捷方式访问新版。",
         "共享盘.url", "application/internet-shortcut",
         B64("[InternetShortcut]\r\nURL=http://203.0.113.99/drive\r\n"))),
  "malicious", "redirect_attachment", "zh", ["url_shortcut_ip"], "")

E("mal_0026_attach_meta_doc.eml",
  (H("文档服务", "docs@colab-notice.example", "pmo@corp.internal", "协作文档分享：验收口径")
   + ATT("同事分享了一篇文档给你，打开即可评论。",
         "验收口径.html", "text/html",
         B64("<html><head><meta http-equiv='refresh' content='0;url=https://colab-doc.example.org/signin'></head>"
             "<body>跳转评论页…</body></html>"))),
  "malicious", "redirect_attachment", "zh", ["attach_meta_refresh"], "协作分享话术")

# ---- malicious: identity spoof family ----
E("mal_0027_disp_authority.eml",
  (H("信息技术部-网络安全组", "net-sec@partner.example", "it@corp.internal", "等保自查配合事项")
   + P +
   "各位：等保自查需要各部门配合提交一份系统清单，\r\n"
   "先回复本邮件确认收到，模板稍后发。事情不复杂但周五前要交。\r\n").encode(),
  "malicious", "identity_spoof", "zh", ["display_authority"], "显示名冒充内部权威")

E("mal_0028_ceo_homoglyph.eml",
  (H("董事长办公室", "b0ard@partner.example", "secretary@corp.internal", "在？")
   + P +
   "在？我在开评审，不方便打电话。\r\n"
   "刚接到通知需要临时处理一笔保密事项，你先回复确认在岗。\r\n").encode(),
  "malicious", "identity_spoof", "zh", ["ceo_urgency_no_keywords"], "")

E("mal_0029_fake_reply.eml",
  (H("采购-老周", "zhou@partner.example", "warehouse@corp.internal", "Re: 定金支付确认",
     "In-Reply-To: <po-2026-118@corp.internal>\r\nReferences: <po-2026-118@corp.internal>\r\n")
   + P +
   "按上午电话说的，定金先付，账户用他们邮件里发的那份，\r\n"
   "别在系统里走流程了，周五前到账就行。出问题我担着。\r\n").encode(),
  "malicious", "identity_spoof", "zh", ["fake_reply_bypass_process"], "假线程+绕流程")

E("mal_0030_forged_ar.eml",
  (H("邮件网关", "gateway@partner.example", "user@corp.internal", "被拦截邮件的放行申请",
     "Received: from gw.partner.example (gw.partner.example [198.51.100.9]) by mx.corp.internal; \r\n"
     "Authentication-Results: mx.corp.internal; spf=pass dkim=pass dmarc=pass\r\n")
   + P +
   "您有一封被误拦的外部来信，点击核对放行（需域账号登录）：\r\n"
   "https://release-gate.example.co/unlock\r\n").encode(),
  "malicious", "identity_spoof", "zh", ["forged_auth_results", "release_lure"], "伪造认证头+放行话术")

# ---- malicious: link obfuscation family ----
E("mal_0031_tab_entity.eml",
  (H("门户运营", "portal@corp-notices.example", "all@corp.internal", "门户统一认证升级")
   + M +
   "<html><body><p>门户本周启用新认证，点击进入绑定页完成一次绑定：</p>"
   "<p><a href='ht&Tab;tp://203.0.113.60/bind'>绑定入口</a></p></body></html>").encode(),
  "malicious", "link_obfuscation", "zh", ["named_tab_entity"], "")

E("mal_0032_base_relative.eml",
  (H("后勤服务", "logistics@facilities.example", "staff@corp.internal", "工牌补办入口")
   + "<html><head><base href='http://203.0.113.77/card/'></head><body>" \
     "<p>工牌补办线上化，点击提交：</p><p><a href='apply'>工牌补办</a></p></body></html>" \
     .join(["Content-Type: text/html; charset=utf-8\r\n\r\n", ""])[0:0] + 
   ("Content-Type: text/html; charset=utf-8\r\n\r\n"
    "<html><head><base href='http://203.0.113.77/card/'></head><body>"
    "<p>工牌补办线上化，点击提交：</p><p><a href='apply'>工牌补办</a></p></body></html>")).encode(),
  "malicious", "link_obfuscation", "zh", ["base_href_relative"], "")

E("mal_0033_greek_tld.eml",
  (H("期刊编辑部", "editor@j-sci.example", "research@corp.internal", "录用通知与校样")
   + P +
   "大作已通过外审，录用通知与校样文件见编辑部系统：\r\n"
   "j-sci-papers.c\u03bfm（浏览器打开，账号为投稿邮箱）\r\n").encode(),
  "malicious", "link_obfuscation", "zh", ["greek_omicron_bare_domain"], "学术录用话术")

E("mal_0034_open_redirect.eml",
  (H("文档中心", "docs@corp-share.example", "team@corp.internal", "季度材料共享")
   + M +
   "<html><body><p>季度材料已打包，在线查看：</p>"
   "<p><a href='https://docs.google.com/url?q=https://share-pack.example.info/login'>打开材料</a></p>"
   "</body></html>").encode(),
  "malicious", "link_obfuscation", "zh", ["trusted_open_redirect"], "")

# ---- malicious: sanitizer / structure / malware ----
E("mal_0035_banner_lure.eml",
  (H("系统退信", "mailer-daemon@relay.example", "user@corp.internal", "投递失败通知")
   + P +
   "【外部邮件】您的账户存在异常登录记录，请立即按提示核验，\r\n"
   "24 小时内未核验将暂停收件服务。\r\n").encode(),
  "malicious", "sanitizer_evasion", "zh", ["banner_prefix_inversion"], "")

E("mal_0036_dilution_long.eml",
  (H("企业服务", "svc@corp-life.example", "user@corp.internal", "员工福利平台月刊")
   + P +
   ("本月福利一览：电影票 5 折、洗车券包、体检加项套餐。\r\n" * 25) +
   "另：您的账户存在异常登录，请立即验证身份 http://203.0.113.60/v\r\n" +
   ("本月福利一览：电影票 5 折、洗车券包、体检加项套餐。\r\n" * 25)).encode(),
  "malicious", "structure_evasion", "zh", ["dilution"], "")

E("mal_0037_attach_exe_dbl.eml",
  (H("财务-应付", "ap@yy-supply.example", "ap@corp.internal", "对账单电子版")
   + ATT("8月对账单见附件，核对后回签。",
         "对账单.pdf.exe", "application/octet-stream",
         base64.b64encode(bytes([0x4D,0x5A,0x90,0x00]) + b"\x90"*128).decode())),
  "malicious", "malware_attachment", "zh", ["double_extension_exe"], "")

E("mal_0038_attach_docm.eml",
  (H("内控办公室", "audit@partner.example", "finance@corp.internal", "内控自查表（宏版）")
   + ATT("自查表需启用宏后填写，周五回收。",
         "内控自查表.docm", "application/vnd.ms-word.document.macroEnabled.12",
         base64.b64encode(b"PK\x03\x04" + b"\x00"*96).decode())),
  "malicious", "malware_attachment", "zh", ["macro_doc"], "")

E("mal_0039_qr_benefits.eml",
  (H("员工福利", "benefit@corp-perk.example", "all-staff@corp.internal", "中秋福利领取通道")
   + P +
   "今年中秋福利改为自选礼包，请扫码进入自选页，\r\n"
   "截止本月底，逾期视为放弃。\r\n").encode(),
  "malicious", "quishing", "zh", ["qr_benefits_lure"], "无链接纯扫码")

E("mal_0040_qr_meet.eml",
  (H("行政-会议室", "meetingroom@partner.example", "admin@corp.internal", "外部访客Wi-Fi已开通")
   + M +
   "<html><body><p>访客 Wi-Fi 已按你的申请开通，扫码连接（有效期 48 小时）：</p>"
   "<p><img src='https://wifi-qrcdn.example/v.png' alt='访客WiFi二维码'></p></body></html>").encode(),
  "malicious", "quishing", "zh", ["qr_wifi_lure"], "")

E("mal_0041_hr_form.eml",
  (H("人资系统", "ehr@hr-saas.example", "staff@corp.internal", "信息采集（薪资卡维护）")
   + M +
   "<html><body><p>因银行渠道升级，请补录薪资卡信息：</p>"
   "<form action='https://ehr-bank.example.net/save'><input name='name' placeholder='姓名'>"
   "<input name='card' placeholder='银行卡号'><input type='password' name='pwd' placeholder='查询密码'>"
   "<button>提交</button></form></body></html>").encode(),
  "malicious", "credential_harvest", "zh", ["body_form_bankcard"], "")

# ---- ham ----
E("ham_0021_oncall.eml",
  (H("值班表", "duty@corp.internal", "sre@corp.internal", "第36周值班轮换") + P +
   "下周值班：周二老许、周四小蔺，周末组合不变。\r\n"
   "交接要点写在值班本，重点盯支付链路的灰度。\r\n").encode(),
  "benign", "ham_business", "zh", ["oncall"], "")

E("ham_0022_review_request.eml",
  (H("陈曦", "chen.xi@corp.internal", "li.wei@corp.internal", "PR 评审：网关超时回退") + P +
   "老李，#5121 改了超时回退的层级，230 行，\r\n"
   "测试都绿了但我想让你把把方向，今天内看一眼就行。\r\n").encode(),
  "benign", "ham_business", "zh", ["code_review"], "")

E("ham_0023_doc_comment.eml",
  (H("知识库机器人", "wiki-bot@corp.internal", "dev-team@corp.internal", "你的文档有新评论") + P +
   "《灰度发布手册》新增 2 条评论：\r\n"
   "@王芳：第 3 步的回滚阈值建议改成百分比。\r\n"
   "@李伟：附件脚本在 mac 下路径要改。\r\n"
   "查看：https://portal.corp.internal/wiki/gray-release\r\n").encode(),
  "benign", "ham_business", "zh", ["doc_comment_internal_link"], "")

E("ham_0024_interview",
  (H("招聘-电话面", "hiring@corp.internal", "interviewer@corp.internal", "周四下午候选人安排") + P +
   "周四 14:00 / 15:00 两场后端电话面，简历已发你邮箱。\r\n"
   "面试链接走会议室系统，评价表今晚发。\r\n").encode(),
  "benign", "ham_business", "zh", ["interview_arrangement"], "")

E("ham_0025_club_badminton.eml",
  (H("工会-羽毛球", "union@corp.internal", "club@corp.internal", "周三场地确认") + P +
   "本周三 19:00-21:00 滨江馆 3 号场已定，AA 场地费每人 18，\r\n"
   "临时来不了的群里喊一声找人顶。\r\n").encode(),
  "benign", "ham_business", "zh", ["club"], "")

E("ham_0026_fire_drill.eml",
  (H("安全环保部", "safety@corp.internal", "all-staff@corp.internal", "周四消防疏散演练") + P +
   "周四 15:00 全楼疏散演练，听到广播后按就近楼梯撤到南广场集合，\r\n"
   "预计 25 分钟。工位断电、随身带工牌。\r\n").encode(),
  "benign", "ham_business", "zh", ["drill_notice"], "")

E("ham_0027_training_internal.eml",
  (H("培训平台", "learn@corp.internal", "all-staff@corp.internal", "年度必修课上线") + P +
   "2026 年度信息安全必修课已上线，10 月 31 日前完成。\r\n"
   "入口：https://portal.corp.internal/learn/mandatory\r\n"
   "进度计入部门考核。\r\n").encode(),
  "benign", "ham_business", "zh", ["internal_training_link"], "")

E("ham_0028_asset_return.eml",
  (H("资产管理", "asset@corp.internal", "leavers@corp.internal", "离职资产归还提醒") + P +
   "办理离职手续前请归还：笔记本、显示器、门禁卡与工牌。\r\n"
   "预约窗口：每周二/四下午，工单入口见门户首页。\r\n").encode(),
  "benign", "ham_business", "zh", ["asset_return"], "")

E("ham_0029_weather_alert.eml",
  (H("行政台", "admin-desk@corp.internal", "campus@corp.internal", "台风黄色预警：明日弹性办公") + P +
   "气象台发布台风黄色预警，明日全员弹性办公，班车停运一天。\r\n"
   "到岗同事注意南门积水点绕行。\r\n").encode(),
  "benign", "ham_business", "zh", ["weather_flexible"], "")

E("ham_0030_printer_fix.eml",
  (H("IT服务台", "helpdesk@corp.internal", "floor3@corp.internal", "3楼打印机已修复") + P +
   "3F 走廊打印机卡纸故障已处理，驱动重装如失败请走门户报修，\r\n"
   "勿自行拆纸盒。分机 8100。\r\n").encode(),
  "benign", "ham_business", "zh", ["it_fixed"], "")

E("ham_0031_partner_meet.eml",
  (H("客户成功", "cs@vendor.example", "sales@corp.internal", "9月季度会议题确认") + P.encode() if False else
   (H("客户成功", "cs@vendor.example", "sales@corp.internal", "9月季度会议题确认") + P +
   "Hi，9 月 QBR 想对齐三个议题：续约窗口、新模块灰度、明年预算口径。\r\n"
   "时间你们定，会议室我们带。议程草案见附件区文档。\r\n").encode()),
  "benign", "ham_business", "zh", ["qbr_external"], "")

E("ham_0032_freelance_invoice.eml",
  (H("自由译者-阿澄", "cheng@personal.example", "marketing@corp.internal", "8月翻译费结算") + P +
   "您好：8 月共 4 篇稿 12,600 字，按约定单价开票 3,150 元。\r\n"
   "发票这周寄出，请留意查收并安排付款。\r\n").encode(),
  "benign", "ham_business", "zh", ["freelance_invoice"], "")

E("ham_0033_school_notice.eml",
  (H("班主任-王老师", "teacher@school.example", "parents@list.example", "秋游回执与着装提醒") + P +
   "各位家长：周五秋游，请穿运动鞋、带水壶，回执单明早交。\r\n"
   "随行家长 2 名已满，感谢报名。\r\n").encode(),
  "benign", "ham_personal", "zh", ["school_notice"], "")

E("ham_0034_dentist.eml",
  (H("齿科诊所", "service@clinic.example", "me@personal.example", "预约确认：周四 18:30 洗牙") + P +
   "您的预约已确认。如需改期请提前一天致电前台，\r\n"
   "本次含抛光，约 40 分钟。\r\n").encode(),
  "benign", "ham_personal", "zh", ["clinic_confirm"], "")

E("ham_0035_gym.eml",
  (H("健身房", "no-reply@gym.example", "me@personal.example", "私教课到期提醒") + P +
   "您的 10 节私教包剩余 2 节，有效期至 9/30。\r\n"
   "续约优惠详询前台，勿回复本邮箱。\r\n").encode(),
  "benign", "ham_personal", "zh", ["gym_reminder"], "")

E("ham_0036_github_pr.eml",
  (H("GitHub", "notifications@github.example", "dev@corp.internal", "[vigilyx] PR #512: fix timeout") + P.encode() if False else
   (H("GitHub", "notifications@github.example", "dev@corp.internal", "[vigilyx] PR #512: fix timeout") + P +
   "chenxi opened PR #512 \"gateway: tiered timeout fallback\".\r\n"
   "+230 -18 across 6 files. CI green. Review requested: liwei.\r\n"
   "https://git.corp.internal/vigilyx/pull/512\r\n").encode()),
  "benign", "ham_business", "zh", ["github_notification"], "")

E("ham_0037_conf_reg.eml",
  (H("KCon 2026", "reg@kcon.example", "sec@corp.internal", "注册确认与日程") + P +
   "您的参会注册已确认（编号 KC-2026-08847）。\r\n"
   "日程与场馆指引：https://kcon2026.example/agenda\r\n"
   "凭二维码入场，已同步至您的日历。\r\n").encode(),
  "benign", "ham_business", "zh", ["conf_registration"], "")

E("ham_0038_tax_deadline.eml",
  (H("财务共享", "fssc@corp.internal", "all-staff@corp.internal", "专项附加扣除信息确认（10月截止）") + P +
   "各位：2026 年度个税专项附加扣除信息确认已开始，\r\n"
   "请于 10 月 31 日前在个税 APP 完成，操作指引见内网财务频道。\r\n"
   "本邮件不采集任何信息，谨防仿冒。\r\n").encode(),
  "benign", "ham_business", "zh", ["legit_tax_notice_antifraud"], "硬负样本：真实退税通知+防伪声明")

E("ham_0039_shuttle_change.eml",
  (H("行政-车队", "fleet@corp.internal", "campus@corp.internal", "班车2号线增开晚班") + P +
   "应加班需求，2 号线自下周一起增开 21:30 晚班，路线不变。\r\n"
   "实时位置仍用车队小程序查看。\r\n").encode(),
  "benign", "ham_business", "zh", ["shuttle"], "")

E("ham_0040_vacation_handover.eml",
  (H("杜楠", "du.nan@corp.internal", "team@corp.internal", "休假交接（9/8-9/14）") + P +
   "下周休年假，工单值守转给老许，发布权限在小蔺。\r\n"
   "两份在途单子的说明在共享盘 /handover/du/。急事打我备用号。\r\n").encode(),
  "benign", "ham_business", "zh", ["vacation_handover"], "")

E("ham_0041_meeting_min.eml",
  (H("PMO", "pmo@corp.internal", "proj@corp.internal", "门户升级第9次例会纪要") + P +
   "纪要已归档：灰度范围收敛到两域；回滚演练提前到 9/18；\r\n"
   "两项决议与责任人行内已有 @。有异议今天内回。\r\n").encode(),
  "benign", "ham_business", "zh", ["meeting_minutes"], "")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch2 written: {len(LABELS)} samples")
