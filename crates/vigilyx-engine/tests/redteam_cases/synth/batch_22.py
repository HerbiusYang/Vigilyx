#!/usr/bin/env python3
"""Batch 22: enterprise-system lures + real internal system notices."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def HD(disp, frm, to, subj, ct="text/plain; charset=utf-8"):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Tue, 15 Sep 2026 09:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b22@synth.example>\r\n"
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\nContent-Type: {ct}\r\n\r\n")
def E(n, raw, label, family, tech, note="", lang="zh", fmt="plain"):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 22,
        "format": fmt, "note": note})

E("mal_0353_expense_card2.eml",
  HD("财务共享", "fssc@expense-svc3.example", "staff@corp.internal", "报销需先登记收款卡")
  + "新税控要求报销前登记收款卡：https://bx-dj3.example.info/r\r\n（卡号+预留手机+身份证号）\r\n",
  "malicious", "pii_harvest", ["expense_register_card"], "报销登记收卡")
E("mal_0354_onboard_health.eml",
  HD("入职体检", "tj@hire-health.example", "newhire@corp.internal", "体检报告直传通道")
  + "报告请直传核验通道（含化验单）：https://tj-sc3.example.org/u\r\n",
  "malicious", "pii_harvest", ["health_report_upload"], "医疗敏感数据收集")
E("mal_0355_vpn_freeze.eml",
  HD("网络服务", "vpn@net-ops3.example", "remote@corp.internal", "VPN 账号因'异地登录'冻结")
  + "解冻需重置密码并验证：https://vpn-jd3.example.info/f\r\n（域账号+旧密码+动态码）\r\n",
  "malicious", "credential_harvest", ["vpn_freeze_reauth"], "VPN 冻结话术")
E("mal_0356_badge_delay.eml",
  HD("门禁中心", "badge@card-svc3.example", "contractor@corp.internal", "外包工牌延期需核验")
  + "延期需核验身份（身份证+人脸）：https://card-yq3.example.info/e\r\n",
  "malicious", "pii_harvest", ["badge_face_verify"], "")
E("mal_0357_payslip_reset.eml",
  HD("薪酬平台", "pay@salary-svc3.example", "staff@corp.internal", "工资条初始密码待设置")
  + "设置工资条密码（与域密码一致以便记忆）：https://pay-mm3.example.org/i\r\n",
  "malicious", "credential_harvest", ["payslip_password_reuse"],
  "诱导密码复用")
E("mal_0358_attend_code.eml",
  HD("考勤系统", "att@hr-svc3.example", "staff@corp.internal", "补卡需短信核验")
  + "补卡核验（手机号+验证码）：https://att-hm3.example.info/c\r\n",
  "malicious", "pii_harvest", ["attend_sms_collect"], "")
E("mal_0359_oa_timeout.eml",
  HD("OA", "oa@flow-svc3.example", "manager@corp.internal", "待办单超时将自动驳回")
  + "处理入口（域账号登录）：https://oa-cl3.example.net/t\r\n",
  "malicious", "credential_harvest", ["oa_todo_login"], "")
E("mal_0360_sso_cookie.eml",
  HD("身份平台", "sso@idp-svc3.example", "staff@corp.internal", "登录Cookie 已失效（批量）")
  + "为同步会话请重新登录：https://sso-cl3.example.info/re\r\n（域账号+密码）\r\n",
  "malicious", "account_phishing", ["cookie_relogin"], "Cookie 失效话术")
E("mal_0361_forum_sync.eml",
  HD("内部论坛", "bbs@corp-relay3.example", "dev@corp.internal", "论坛账号与域账号合并")
  + "合并需输入域密码确认：https://bbs-hb3.example.info/m\r\n",
  "malicious", "credential_harvest", ["forum_password_merge"], "")
E("mal_0362_it_announce.eml",
  HD("IT 服务台", "itsm@help3.example", "it@corp.internal", "资产盘点确认（扫码）")
  + "资产标签扫码确认：https://it-pd3.example.info/a\r\n（需域账号授权相机）\r\n",
  "malicious", "credential_harvest", ["asset_scan_auth"], "")
E("mal_0363_license_renew3.eml",
  HD("软件资产", "sam@soft-asset3.example", "rd@corp.internal", "IDE 许可证续期（账号核验）")
  + "续期核验（邮箱+密码）：https://sam-xu3.example.org/l\r\n",
  "malicious", "credential_harvest", ["license_account_verify"], "")
E("mal_0364_meeting_rec.eml",
  HD("会议系统", "meet@vc-svc3.example", "leaders@corp.internal", "回放已生成（外部观众版）")
  + "外部观众版回放链接：https://vc-hf3.example.ru/play\r\n",
  "malicious", "link_obfuscation", ["playback_external_ru"], "俄域回放链接")
E("mal_0365_doc_share3.eml",
  HD("文档中心", "doc@share-svc3.example", "team@corp.internal", "制度汇编（修订版）")
  + "在线阅读（需登录）：https://doc-zd3.example.info/read\r\n",
  "malicious", "account_phishing", ["policy_doc_login"], "制度汇编话术")
E("mal_0366_train_cert.eml",
  HD("培训平台", "learn@edu-svc3.example", "staff@corp.internal", "学时证明可下载（实名核验）")
  + "证明下载需实名核验：https://learn-xs3.example.org/c\r\n（身份证+手机号）\r\n",
  "malicious", "pii_harvest", ["cert_download_pii"], "")
E("mal_0367_printer_scan.eml",
  HD("打印中心", "prt@device3.example", "admin@corp.internal", "扫描件待领取（HP-3F）")
  + "扫描件在线领取：https://prt-lq3.example.info/s\r\n",
  "malicious", "account_phishing", ["printer_scan_lure"], "打印机扫描件话术")
E("mal_0368_visitor_wifi.eml",
  HD("访客网络", "guest@wifi-svc3.example", "guest@corp.internal", "访客 Wi-Fi 密码已重置")
  + "新密码领取：https://guest-wf3.example.info/p\r\n（手机号+验证码）\r\n",
  "malicious", "account_phishing", ["guest_wifi_lure"], "访客 Wi-Fi 话术")
E("ham_0311_license_real.eml",
  HD("软件资产", "sam@corp.internal", "rd@corp.internal", "JetBrains 许可已续期")
  + "已按席位续期，激活直接用企业账号登录即可。\r\n",
  "benign", "ham_business", ["license_real_done"], "真续期已完成无需操作")
E("ham_0312_asset_done.eml",
  HD("IT 服务台", "itsm@corp.internal", "staff@corp.internal", "资产盘点已完成（您的 3 台已确认）")
  + "盘点通过，标签完整。\r\n",
  "benign", "ham_business", ["asset_real_done"], "")
E("ham_0313_forum_digest.eml",
  HD("内部论坛", "bbs@corp.internal", "dev@corp.internal", "本周热帖：三则")
  + "网关排障、新人指南、健身打卡。站内查看。\r\n",
  "benign", "ham_business", ["forum_real_digest"], "")
E("ham_0314_meet_rec_real.eml",
  HD("会议系统", "vc@corp.internal", "leaders@corp.internal", "回放已上传（内网）")
  + "回放在门户-会议-回放。\r\n",
  "benign", "ham_business", ["meet_real_internal"], "")
E("ham_0315_doc_new.eml",
  HD("文档中心", "doc@corp.internal", "all@corp.internal", "制度汇编修订版发布")
  + "见门户-制度。纸印发文走行政。\r\n",
  "benign", "ham_business", ["doc_real_portal"], "")
E("ham_0316_train_done.eml",
  HD("培训平台", "learn@corp.internal", "staff@corp.internal", "学时已达标（22/20）")
  + "证明在平台内自助下载。\r\n",
  "benign", "ham_business", ["train_real_done"], "")
E("ham_0317_printer_real.eml",
  HD("打印中心", "prt@corp.internal", "admin@corp.internal", "扫描件已投递您的邮箱")
  + "扫描件 PDF 见本邮件附件。\r\n",
  "benign", "ham_business", ["printer_real_attached"], "真扫描件直附")
E("ham_0318_guest_real.eml",
  HD("行政台", "admin-desk@corp.internal", "guest@corp.internal", "访客 Wi-Fi 密码")
  + "密码 GUEST-0926，当日有效。\r\n当面告知，不经邮件外发。\r\n",
  "benign", "ham_business", ["guest_real_sms"], "密码线下交付")
E("ham_0319_birthday_list.eml",
  HD("行政台", "admin-desk@corp.internal", "floor3@corp.internal", "Q4 寿星名单")
  + "李伟 10/3、王芳 11/7。蛋糕统一周五。\r\n",
  "benign", "ham_business", ["birthday_real_list"], "")
E("ham_0320_shuttle_real2.eml",
  HD("车队", "fleet@corp.internal", "campus@corp.internal", "明日雾天发车提前")
  + "大雾预警，早班车提前 20 分钟。\r\n",
  "benign", "ham_business", ["shuttle_real_fog"], "")
E("ham_0321_canteen_menu.eml",
  HD("食堂", "canteen@corp.internal", "campus@corp.internal", "本周菜单（中秋加餐）")
  + "周三加餐月饼与桂花酒酿。\r\n菜单看公众号。\r\n",
  "benign", "ham_business", ["canteen_real_menu"], "")
E("ham_0322_parking_real.eml",
  HD("物业", "pm@corp.internal", "staff@corp.internal", "地库 B2 消防改造（临时停车）")
  + "下周一 B2 封闭，临停改地面。\r\n",
  "benign", "ham_business", ["parking_real_notice"], "")
E("ham_0323_mail_quota_real.eml",
  HD("邮箱管理员", "postmaster@corp.internal", "heavy-user@corp.internal", "您的邮箱已达 80%")
  + "建议清理大附件；扩容走行政审批。\r\n系统不会发任何'校验链接'。\r\n",
  "benign", "ham_business", ["quota_real_internal"], "真配额提醒+反诈声明")
E("ham_0324_dns_change.eml",
  HD("网络服务", "dns@corp.internal", "it@corp.internal", "内网 DNS 周四切换")
  + "旧 DNS 保留一周，客户端自动。\r\n",
  "benign", "ham_business", ["dns_real_switch"], "")
E("ham_0325_idp_real.eml",
  HD("身份平台", "sso@corp.internal", "all@corp.internal", "登录异常自助排查上线")
  + "门户-身份-诊断可自助排查。\r\n平台不发'Cookie 失效'邮件。\r\n",
  "benign", "ham_business", ["idp_real_diag"], "与 Cookie 话术对照")
E("ham_0326_backup_alert_real.eml",
  HD("备份系统", "backup@corp.internal", "ops@corp.internal", "[告警] 备份窗口超时（非失败）")
  + "数据量上涨导致窗口超时 40 分钟，任务仍在跑。\r\n明晚调优分片。\r\n",
  "benign", "ham_business", ["backup_real_alert"], "")
E("ham_0327_cert_rot.eml",
  HD("证书巡检", "cert@corp.internal", "ops@corp.internal", "证书自动轮换成功")
  + "*.corp.internal 已轮换，无需操作。\r\n",
  "benign", "ham_business", ["cert_real_rotated"], "")
E("ham_0328_fw_rule.eml",
  HD("防火墙运营", "fw@corp.internal", "sec@corp.internal", "规则变更单 FW-991 已生效")
  + "按工单开通测试网段互访，有效期 7 天。\r\n",
  "benign", "ham_business", ["fw_real_change"], "")
E("ham_0329_wiki_hot.eml",
  HD("知识库", "wiki@corp.internal", "all@corp.internal", "本周编辑榜")
  + "小蔺 12 篇、老许 9 篇。感谢贡献。\r\n",
  "benign", "ham_business", ["wiki_real_board"], "")
E("ham_0330_club_fund.eml",
  HD("工会", "union@corp.internal", "clubs@corp.internal", "社团经费已拨付")
  + "各社团经费已到账，发票本季度内交。\r\n",
  "benign", "ham_business", ["club_real_fund"], "")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch22 written: {len(LABELS)} samples")
