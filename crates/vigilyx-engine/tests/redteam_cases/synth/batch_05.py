#!/usr/bin/env python3
"""Batch 5: i18n lures, hard positives, and extreme hard-negative ham."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def H(disp, frm, to, subj, extra=""):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Fri, 28 Aug 2026 14:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b5@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\n")
P = "Content-Type: text/plain; charset=utf-8\r\n\r\n"
M = "Content-Type: text/html; charset=utf-8\r\n\r\n"
def ATT(t, fn, ct, b64):
    return ("Content-Type: multipart/mixed; boundary=\"BS\"\r\n\r\n"
            f"--BS\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{t}\r\n"
            f"--BS\r\nContent-Type: {ct}\r\nContent-Disposition: attachment; filename=\"{fn}\"\r\n"
            f"Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--BS--\r\n")
def B64(s): return base64.b64encode(s.encode()).decode()
def E(n, raw, label, family, lang, tech, note="", enc="utf-8"):
    W(n, raw if isinstance(raw, bytes) else raw.encode(enc, errors="replace"))
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 5, "note": note})

E("mal_0081_ko_stop.eml",
  (H("계정관리", "id@kr-svc.example", "kim@corp.internal",
     "=?utf-8?B?" + base64.b64encode("계정 정지 안내".encode()).decode() + "?=")
   + P +
   "비정상적인 로그인 시도가 확인되었습니다. 24시간 이내에 본인 인증을\r\n"
   "완료하지 않으면 계정이 정지됩니다: https://kr-verify.example.kr/check\r\n"),
  "malicious", "account_phishing", "ko", ["ko_stop"], "韩文覆盖")

E("mal_0082_ja_bec.eml",
  (H("経理部", "keiri@partner.example", "bucho@corp.internal",
     "=?utf-8?B?" + base64.b64encode("振込先変更のお願い".encode()).decode() + "?=")
   + P +
   "取引先より振込先変更の連絡がありました。今月分は下記へお振込みください。\r\n"
   "三菱UFJ銀行 支店1234 口座 5678901 カ）トウキョウブッシ\r\n"
   "変更確認の返信は不要です。\r\n"),
  "malicious", "bec", "ja", ["ja_bank_change"], "日文 BEC")

E("mal_0083_ru_soft.eml",
  (H("Служба поддержки", "help@portal-ru.example", "orlov@corp.internal", "=?utf-8?B?0KHQldCf?=")
   + "Content-Type: text/plain; charset=windows-1251\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
   + "Добрый день. Часть настроек вашего профиля не прошла проверку.\r\n"
     "Актуализируйте их сегодня, чтобы избежать ограничений: https://ru-fix.example.su/update\r\n"),
  "malicious", "account_phishing", "ru", ["ru_soft_paraphrase"], "", "cp1251")

E("mal_0084_vi_bec.eml",
  (H("Kế toán", "acc@vn-supply.example", "ap@corp.internal", "Thay doi tai khoan thanh toan")
   + P +
   "Do thay doi ngan hang, tu tuan sau moi thanh toan cho tai khoan moi:\r\n"
   "VCB 0071 0009 87654 - CTY TNHH VIETTRADE. Xac nhan qua email nay.\r\n"),
  "malicious", "bec", "vi", ["vi_bank_change"], "")

E("mal_0085_cfo_display.eml",
  (H("财务总监-陈", "chen.cfo@partner.example", "gl@corp.internal", "内部划款（勿外传）") + P +
   "有笔内部划款需要走你渠道，先回复确认在线，细节我拉小群说。\r\n"
   "别在大会上提。\r\n").encode(),
  "malicious", "identity_spoof", "zh", ["cfo_display_secretive"], "")

E("mal_0086_hq_audit.eml",
  (H("集团审计部", "audit@holding-group.example", "finance@corp.internal", "审计资料线上调取通知") + P +
   "按集团年度审计安排，请各子公司财务于本周内完成资料线上授权：\r\n"
   "https://audit-holding.example.ru/grant（集团统一认证登录）\r\n"
   "逾期未授权的将列入审计发现项。\r\n").encode(),
  "malicious", "identity_spoof", "zh", ["hq_audit_authority"], "母公司名义")

E("mal_0087_courier_thread.eml",
  (H("顺急快递-工单", "cs@courier-svc.example", "user@corp.internal", "Re: 工单 2026-0991 处理中",
     "In-Reply-To: <wo-2026-0991@corp.internal>\r\n")
   + P +
   "您的工单我们跟进中，理赔需补充身份材料：\r\n"
   "点击补充（工单号登录）：https://courier-claim.example.info/case\r\n"
   "超时工单自动关闭。\r\n").encode(),
  "malicious", "identity_spoof", "zh", ["fake_reply_courier"], "假客服线程")

E("mal_0088_userinfo_new.eml",
  (H("门户", "portal@mail-gw.example", "staff@corp.internal", "登录态失效") + M +
   "<html><body><p>登录态已过期，重新登录：</p>"
   "<p><a href='https://portal.corp.internal@cred-gate.example.net/re?u=1'>重新登录</a></p>"
   "</body></html>").encode(),
  "malicious", "link_obfuscation", "zh", ["userinfo_url"], "")

E("mal_0089_ip_port.eml",
  (H("报表平台", "bi@corp-bi.example", "analyst@corp.internal", "报表平台迁移临时入口") + P +
   "新报表平台灰度入口（临时）：http://203.0.113.60:8081/bi\r\n"
   "用 BI 账号+密码登录，稳定后统一跳转。\r\n").encode(),
  "malicious", "link_obfuscation", "zh", ["ip_port_lure"], "内话术包装外部 IP")

E("mal_0090_data_uri_link.eml",
  (H("内网通知", "intra@corp-notices.example", "all@corp.internal", "通知内容（防爬）") + M +
   "<html><body><p>点击查看正文：</p>"
   "<p><a href='data:text/html;base64,PGh0bWw+PHNjcmlwdD5sb2NhdGlvbj0iaHR0cDovLzIwMy4wLjExMy42MC9kIjwvc2NyaXB0Pg=='>查看</a></p>"
   "</body></html>").encode(),
  "malicious", "link_obfuscation", "zh", ["data_uri_redirect"], "")

E("mal_0091_rtf_lure.eml",
  (H("合同管理", "contract@partner.example", "legal@corp.internal", "合同扫描件（RTF版）")
   + ATT("合同扫描件见附件，RTF 兼容旧系统。",
         "合同扫描件.rtf", "application/rtf",
         B64("{\\rtf1\\ansi verify your contract payment now: http://203.0.113.77/ct\\par}"))),
  "malicious", "redirect_attachment", "zh", ["rtf_text_lure"], "")

E("mal_0092_htm_docs_refresh.eml",
  (H("共享文档", "docs@collab-notice.example", "team@corp.internal", "需求文档共享（在线版）")
   + ATT("文档为在线版，打开附件进入。",
         "需求文档.html", "text/html",
         B64("<html><head><meta http-equiv='refresh' content='0;url=https://docs.google.com/forms/d/e/fake/viewform'></head><body>…</body></html>"))),
  "malicious", "redirect_attachment", "zh", ["attach_refresh_trusted"], "")

E("mal_0093_xlsm.eml",
  (H("数据中心", "data@partner.example", "analyst@corp.internal", "8月经营数据（宏版透视）")
   + ATT("打开时请启用宏以刷新透视表。",
         "经营数据.xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12",
         base64.b64encode(b"PK\x03\x04" + b"\x00"*64).decode())),
  "malicious", "malware_attachment", "zh", ["xlsm_macro"], "")

E("mal_0094_iso_tool.eml",
  (H("IT 支持", "it@tool-dl.example", "dev@corp.internal", "调试工具包（ISO 镜像）")
   + ATT("工具包为 ISO 镜像，挂载后运行 setup。",
         "toolkit.iso", "application/x-iso9660-image",
         base64.b64encode(b"\x00CD001" + b"\x00"*96).decode())),
  "malicious", "malware_attachment", "zh", ["iso_toolkit"], "")

E("mal_0095_autoreply_lure.eml",
  (H("自动回复", "auto@relay-notice.example", "user@corp.internal", "自动回复：无法送达") + P +
   "自动回复：您的账户存在异常登录，请立即按提示核验，\r\n"
   "24 小时内未核验将暂停收件服务。\r\n").encode(),
  "malicious", "sanitizer_evasion", "zh", ["auto_reply_prefix_inversion"], "")

E("mal_0096_dilution_news.eml",
  (H("内刊", "weekly@corp-mag.example", "user@corp.internal", "内刊第 92 期") + P +
   ("本期导读：封面故事、人物专栏、新品速览、食堂月度菜单。\r\n" * 30) +
   "附：您的账户存在异常登录，请立即验证 http://203.0.113.99/u\r\n" +
   ("本期导读：封面故事、人物专栏、新品速览、食堂月度菜单。\r\n" * 30)).encode(),
  "malicious", "structure_evasion", "zh", ["dilution"], "")

E("mal_0097_alt_diff.eml",
  (H("企业服务", "mag@corp-mag.example", "user@corp.internal", "企业通讯")
   + "Content-Type: multipart/alternative; boundary=\"BA\"\r\n\r\n"
     "--BA\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
     "您好，本期企业通讯已发布，请查收。\r\n"
     "--BA\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
     "<html><body><p>尊敬的用户：您的账户存在异常登录，请立即"
     "<a href='http://203.0.113.60/ok'>验证身份</a>，24小时内未验证将冻结账户。</p></body></html>\r\n"
     "--BA--\r\n").encode(),
  "malicious", "structure_evasion", "zh", ["alternative_differential"], "")

E("mal_0098_routine_todo.eml",
  (H("运营平台", "ops@biz-platform.example", "merchant@corp.internal", "巡检发现 1 项待办") + P +
   "系统例行巡检发现您有 1 项待办未处理，长时间未处理将影响功能使用，\r\n"
   "处理入口：https://ops-todo.example.net/item\r\n").encode(),
  "malicious", "account_phishing", "zh", ["paraphrase_routine_todo"], "硬正样本：无关键词")

E("mal_0099_wifi_portal.eml",
  (H("会议网络", "wifi@venue-net.example", "guest@corp.internal", "会场 Wi-Fi 认证") + M +
   "<html><body><p>连接会场 Wi-Fi 后请完成一次认证（手机号+服务密码）：</p>"
   "<form action='http://203.0.113.77/wifi'><input name='msisdn' placeholder='手机号'>"
   "<input type='password' name='svc' placeholder='服务密码'><button>连网</button></form>"
   "</body></html>").encode(),
  "malicious", "credential_harvest", "zh", ["wifi_portal_form", "ip_action"], "")

E("mal_0100_expense_form.eml",
  (H("报销平台", "bx@finance-saas.example", "staff@corp.internal", "报销卡信息补录") + M +
   "<html><body><p>因对公结算升级，请补录报销卡（姓名/卡号/取款密码）：</p>"
   "<form action='https://bx-card.example.co/save'><input name='nm'><input name='card'>"
   "<input type='password' name='pwd'><button>保存</button></form></body></html>").encode(),
  "malicious", "credential_harvest", "zh", ["expense_form_password"], "取款密码话术")

E("ham_0081_phish_drill.eml",
  (H("安全运营中心", "soc@corp.internal", "all-staff@corp.internal", "【预告】下周一全员钓鱼演练") + P +
   "各位：下周一我们将开展年度钓鱼演练，届时会有仿冒钓鱼邮件\r\n"
   "（主题涉及\"账户异常\"\"密码过期\"），请按培训口径处置：不点击、上报按钮。\r\n"
   "演练不记名，点击后的引导页有说明。 questions 联系 SOC。\r\n").encode(),
  "benign", "ham_business", "zh", ["phishing_drill_announcement"], "极硬负样本：内容即钓鱼话题")

E("ham_0082_pentest_window.eml",
  (H("安全部", "sec@corp.internal", "it-all@corp.internal", "授权渗透测试窗口（9/2-9/4）") + P +
   "红队将在 9/2-9/4 对网关与门户做授权渗透测试，期间可能出现\r\n"
   "告警与少量异常登录测试，均在授权范围（授权书编号 SEC-2026-31）。\r\n"
   "涉及系统的同事请勿自行处置，统一转 SOC。\r\n").encode(),
  "benign", "ham_business", "zh", ["authorized_pentest_window"], "极硬负样本：合法渗透授权")

E("ham_0083_code_freeze.eml",
  (H("发布组", "release@corp.internal", "dev-team@corp.internal", "国庆前代码冻结安排") + P +
   "9/26 起代码冻结，仅允许修复级别提交（需两人批准）。\r\n"
   "冻结期间 CI 保持绿线，解冻 10/8。\r\n").encode(),
  "benign", "ham_business", "zh", ["code_freeze"], "")

E("ham_0084_escalation.eml",
  (H("客服-升级", "cs-lead@corp.internal", "prod@corp.internal", "客户升级：订单延迟（内部）") + P +
   "KA 客户反馈 3 笔订单延迟超 48h，已在内部升级，\r\n"
   "请产研今天给出归因初稿，对外口径由客服统一。\r\n").encode(),
  "benign", "ham_business", "zh", ["internal_escalation"], "")

E("ham_0085_slow_query.eml",
  (H("DBA 平台", "dba@corp.internal", "dev@corp.internal", "[告警] 慢查询 TOP3（8/28）") + P +
   "orders 表全表扫描 3 次（>2s），索引建议见工单 DBA-1024。\r\n"
   "明晚窗口评估加索引。\r\n").encode(),
  "benign", "ham_business", "zh", ["slow_query_alert"], "")

E("ham_0086_disk_usage.eml",
  (H("资源巡检", "sizer@corp.internal", "ops@corp.internal", "[提醒] es-05 磁盘 87%") + P +
   "es-05 数据盘 87%，预计 4 天写满。扩容流程已发起，\r\n"
   "期间避免大索引重建。\r\n").encode(),
  "benign", "ham_business", "zh", ["disk_alert"], "")

E("ham_0087_slack_mention.eml",
  (H("协作平台", "notify@chat.corp.internal", "dev@corp.internal", "蔺柯 在 #gateway 提到了你") + P +
   "@你：超时回退那层我看了，边界条件再确认下？\r\n"
   "回复：https://chat.corp.internal/c/gateway/8812\r\n").encode(),
  "benign", "ham_business", "zh", ["chat_mention"], "")

E("ham_0088_minutes_confirm.eml",
  (H("PMO-小江", "jiang@corp.internal", "proj@corp.internal", "纪要待你确认（1 处修改）") + P +
   "昨天评审纪要第 5 条我按你会上说的改了，确认无误我归档。\r\n"
   "今天下班前回我即可。\r\n").encode(),
  "benign", "ham_business", "zh", ["minutes_confirm"], "")

E("ham_0089_welcome.eml",
  (H("团队", "team-a@corp.internal", "newhire@corp.internal", "欢迎入职！") + P +
   "欢迎加入！工位在 3F 东区，导师是老许。\r\n"
   "第一周主要熟悉环境和 runbook，下周带你过网关链路。\r\n").encode(),
  "benign", "ham_business", "zh", ["welcome"], "")

E("ham_0090_farewell.eml",
  (H("老许", "xu@corp.internal", "team-a@corp.internal", "最后一天，交接都在位了") + P +
   "今天最后一天，值班表、发布权限、两把机房钥匙都交给小蔺了。\r\n"
   "相册我建了个共享，大家随意取。后会有期！\r\n").encode(),
  "benign", "ham_business", "zh", ["farewell"], "")

E("ham_0091_outing_photos.eml",
  (H("工会", "union@corp.internal", "outing@corp.internal", "outing 照片已归档") + P +
   "照片 400+ 张已传共享盘 /outing/2026-08，含无人机版。\r\n"
   "有好看的单张自行截取，水印工具在群公告。\r\n").encode(),
  "benign", "ham_business", "zh", ["photos_archive"], "")

E("ham_0092_birthday.eml",
  (H("行政台", "admin-desk@corp.internal", "floor3@corp.internal", "本月寿星：李伟、王芳") + P +
   "周三 16:00 茶水间切蛋糕，本月寿星李伟、王芳。\r\n"
   "贺卡在行政台，路过的写两句。\r\n").encode(),
  "benign", "ham_business", "zh", ["birthday"], "")

E("ham_0093_delay_risk.eml",
  (H("项目-苏黎", "su.li@corp.internal", "pmo@corp.internal", "灰度计划延一周的风险报备") + P +
   "上游网关发布窗口变了，灰度顺延一周。对外承诺我没改，\r\n"
   "先内部报备，若周四前窗口恢复则按原计划。\r\n").encode(),
  "benign", "ham_business", "zh", ["delay_risk_report"], "")

E("ham_0094_vendor_visit.eml",
  (H("前台", "reception@corp.internal", "sales@corp.internal", "下周访客：供应商 3 人（周二）") + P +
   "周二 10:00 供应商来访 3 人，已备小会议室，\r\n"
   "访客 Wi-Fi 申请单在你们组助理那里。\r\n").encode(),
  "benign", "ham_business", "zh", ["visitor_notice"], "")

E("ham_0095_interview_feedback.eml",
  (H("面试官-老李", "li.wei@corp.internal", "hiring@corp.internal", "候选人反馈：两轮通过") + P +
   "两场面评都过了，系统设计稍弱但潜力可以，建议给 P5+。\r\n"
   "背调按标准流程走。\r\n").encode(),
  "benign", "ham_business", "zh", ["interview_feedback"], "")

E("ham_0096_patent_fee.eml",
  (H("法务-知产", "ip@corp.internal", "finance@corp.internal", "专利年费缴纳清单（10月）") + P +
   "10 月需缴年费专利 14 项，明细见法务频道表格，合计 3.8 万。\r\n"
   "请按流程走专项付款，明细我已核对。\r\n").encode(),
  "benign", "ham_business", "zh", ["patent_fee"], "")

E("ham_0097_title_change.eml",
  (H("应收-小蔡", "cai@vendor.example", "ap@corp.internal", "确认新发票抬头") + P +
   "我们更名后新抬头已启用：蓝汛数字科技有限公司。\r\n"
   "请回复确认后续按新抬头开票，旧抬头本月作废。\r\n").encode(),
  "benign", "ham_business", "zh", ["invoice_title_change"], "硬负样本：抬头变更真实场景")

E("ham_0098_api_joint.eml",
  (H("联调", "api@partner.example", "dev@corp.internal", "对账接口联调时间（9/3）") + P +
   "9/3 上午联调对账接口，测试环境 token 已发到对接群。\r\n"
   "沙箱地址不变，联调用例 12 条在共享文档。\r\n").encode(),
  "benign", "ham_business", "zh", ["api_joint_debug"], "")

E("ham_0099_book_due.eml",
  (H("图书馆", "lib@corp.internal", "dev@corp.internal", "借阅到期提醒（2 本）") + P +
   "《Designing Data-Intensive Applications》明日到期，\r\n"
   "内网续借入口：https://portal.corp.internal/lib\r\n"
   "逾期一天扣部门积分。\r\n").encode(),
  "benign", "ham_business", "zh", ["library_due"], "")

E("ham_0100_carwash.eml",
  (H("洗车行", "svc@carwash.example", "me@personal.example", "储值卡余额提醒") + P +
   "您的洗车卡余额 32 元（约 1 次），充值优惠见店内。\r\n"
   "本卡长期有效，谨防他人代充值诈骗。\r\n").encode(),
  "benign", "ham_personal", "zh", ["carwash_balance"], "带防骗提示的硬负样本")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch5 written: {len(LABELS)} samples")
