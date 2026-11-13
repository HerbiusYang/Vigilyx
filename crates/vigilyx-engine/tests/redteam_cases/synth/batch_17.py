#!/usr/bin/env python3
"""Batch 17: APT-grade lures (spearphishing/supply-chain/multi-stage TTPs) +
look-alike benigns. Family=apt. No real actor attributions."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def HD(disp, frm, to, subj, extra="", ct="text/plain; charset=utf-8"):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Wed, 09 Sep 2026 08:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b17@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\nContent-Type: {ct}\r\n\r\n")
def ATT(hdr, t, fn, ct, payload_b64):
    return (hdr + "Content-Type: multipart/mixed; boundary=\"BS\"\r\n\r\n"
            f"--BS\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{t}\r\n"
            f"--BS\r\nContent-Type: {ct}\r\nContent-Disposition: attachment; filename=\"{fn}\"\r\n"
            f"Content-Transfer-Encoding: base64\r\n\r\n{payload_b64}\r\n--BS--\r\n")
def B(s): return base64.b64encode(s.encode() if isinstance(s, str) else s).decode()
def E(n, raw, label, family, tech, note="", lang="zh", fmt="plain",
      expected=None, ambiguous=False, borderline=""):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": expected or ("block" if label == "malicious" else "deliver"),
        "engine_status": "not_evaluated", "synthetic": True, "batch": 17,
        "format": fmt, "note": note, "ambiguous": ambiguous, "borderline": borderline})

# ---------------- APT malicious (25) ----------------
hdr = HD("议程委员会", "pc@blackhat-agenda.example", "sec-research@corp.internal",
         "Re: 议题初评意见（LZ-2026-1147）",
         "In-Reply-To: <cfp-1147@corp.internal>\r\n")
E("mal_0261_apt_conf_spear.eml",
  hdr + "您好：\r\n\r\n"
  "初评意见已出（偏向接收），委员会希望在终审前与您对齐 slide 篇幅。\r\n"
  "带批注的议程草案放在协作页：https://blackhat-agenda.example/draft/1147\r\n\r\n"
  "方便的话本周约 20 分钟电话。\r\n\r\nProgram Committee\r\n",
  "malicious", "apt", ["spearphish_conference", "lookalike_domain", "thread_context"],
  "话术零钓鱼词，域名近似官方议程站", "zh", "plain", "review",
  True, "定向会议话术+仿冒议程域；正文无任何可检关键词，只能靠域名信誉/线索关联")

hdr = HD("HR-Talent", "talent@rust-career.example", "dev@corp.internal",
         "Senior Rust Engineer (Remote, USD) — your tower-lsp work")
E("mal_0262_apt_job_spear.eml",
  hdr + "Hi,\n\n"
  "We came across your tower-lsp contributions; the overlay runtime role fits.\n"
  "Comp range and the case-study brief are here: https://rust-career.example/case/gw\n\n"
  "No rush — happy to answer questions first.\n\n"
  "— Talent, Meridian Labs",
  "malicious", "apt", ["spearphish_recruit", "targeted_recon_reference"],
  "点名真实开源项目增强可信", "en")

hdr = HD("采购-远东实业", "sales@yuandong-supply.example", "purchase@corp.internal",
         "Re: PO-2026-1148 交期与发票",
         "In-Reply-To: <po-2026-1148@corp.internal>\r\nReferences: <po-2026-1148@corp.internal>\r\n")
E("mal_0263_apt_thread_hijack.eml",
  ATT(hdr, "交期确认如上。发票最新版见附件（税率变更后重开），\r\n对账以本版为准。",
      "发票202609.iso", "application/x-iso9660-image",
      base64.b64encode(b"\x00CD001" + bytes(range(256))).decode()),
  "malicious", "apt", ["thread_hijack_partner_lookalike", "iso_container"],
  "仿合作方域名续真线程+ISO 容器载荷")

hdr = HD("IT 服务台", "servicedesk@corp-it-relay.example", "staff@corp.internal",
         "设备授权流程：会议室大屏登录")
E("mal_0264_apt_device_code.eml",
  hdr + "为把会议室大屏加入会议，请按以下步骤完成设备授权：\r\n\r\n"
  "1. 在任意设备打开 https://microsoft.com/devicelogin\r\n"
  "2. 输入代码：FJ9H2K\r\n"
  "3. 使用企业账号登录确认\r\n\r\n"
  "代码 15 分钟内有效。（本流程与官方一致，请勿转发）",
  "malicious", "apt", ["device_code_phishing", "legit_url_only"],
  "全程官方 URL，唯一攻击面是设备码", "zh", "plain", "block",
  False, "")

hdr = HD("TimesheetPro", "notifications@timesheetpro-sso.example", "staff@corp.internal",
         "TimesheetPro 请求访问您的邮箱与日历")
E("mal_0265_apt_oauth_consent.eml",
  hdr + "您的组织管理员启用了 TimesheetPro 工时集成。\r\n\r\n"
  "请完成一次授权以继续使用：\r\n"
  "https://login.timesheetpro-sso.example/consent?client=ts&scope=mail.read calendars\r\n\r\n"
  "授权后无需重复登录。撤回可在账户安全页操作。",
  "malicious", "apt", ["oauth_consent_phishing", "scope_grant"],
  "不收密码，直接收邮箱读权限")

hdr = HD("会议服务", "materials@conf-delivery.example", "research@corp.internal",
         "圆桌会议资料（离线版）")
E("mal_0266_apt_html_smuggling.eml",
  ATT(hdr, "离线版议程见附件，浏览器打开即可（无需联网）。",
      "agenda.html", "text/html",
      B("<html><body>loading…<script>const d=atob('PD9maWxlIGJpbmFyeT8+');"
        "const b=new Blob([d],{type:'application/octet-stream'});"
        "const a=document.createElement('a');a.href=URL.createObjectURL(b);"
        "a.download='agenda.iso';a.click();</script></body></html>")),
  "malicious", "apt", ["html_smuggling", "base64_blob_iso"],
  "附件 HTML 静态无恶意，打开后 JS 组装 ISO 落盘")

hdr = HD("会议服务", "materials@conf-delivery.example", "research@corp.internal",
         "圆桌会议资料（现场记录）")
E("mal_0267_apt_onenote.eml",
  ATT(hdr, "现场速记整理在 OneNote 页内，双击查看。",
      "notes.one", "application/onenote",
      base64.b64encode(b"\xE4\x52\x5A\xC8" + b"\x00"*96).decode()),
  "malicious", "apt", ["onenote_embedded_script"])

hdr = HD("法务", "contract@partner-relay4.example", "legal@corp.internal",
         "合同扫描件（RAR 压缩）")
E("mal_0268_apt_rar_symlink.eml",
  ATT(hdr, "扫描件打包如附件，解压到任意目录即可。",
      "合同扫描件.rar", "application/vnd.rar",
      base64.b64encode(b"Rar!\x1a\x07\x01\x00" + b"\x00"*80).decode()),
  "malicious", "apt", ["rar_symlink_traversal"],
  "RAR 符号链接/路径穿越（解压到启动目录）")

hdr = HD("会务组", "photo@roundtable-pics.example", "research@corp.internal",
         "现场照片（精修版）")
E("mal_0269_apt_stego_png.eml",
  ATT(hdr, "合影与讲台照在附件。", "现场照片.png", "image/png",
      base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00"*120 + b"PK\x03\x04" + b"\x00"*40).decode()),
  "malicious", "apt", ["polyglot_png_zip"],
  "PNG/ZIP 多态文件（文件尾附带压缩载荷）")

hdr = HD("会务组", "materials@roundtable-docs.example", "research@corp.internal",
         "资料合集快捷方式")
E("mal_0270_apt_lnk.eml",
  ATT(hdr, "资料合集已放到共享，附件是入口快捷方式。",
      "会议资料.lnk", "application/x-ms-shortcut",
      base64.b64encode(b"\x4c\x00\x00\x00\x01\x14\x02\x00" + b"\x00"*40 +
                       b"powershell -w hidden -enc AAAA" + b"\x00").decode()),
  "malicious", "apt", ["lnk_powershell_downloader"])

hdr = HD("财务共享", "fssc@partner-billing5.example", "finance@corp.internal",
         "Q3 财务包")
E("mal_0271_apt_iso_dual.eml",
  ATT(hdr, "Q3 报表包如附件，挂载后打开 index。", "Q3 financials.iso",
      "application/x-iso9660-image",
      base64.b64encode(b"\x00CD001" + b"\x00"*96).decode()),
  "malicious", "apt", ["iso_container", "english_corporate_thread"], "英文内文伪装",
  "en")

hdr = HD("研讨筹委", "secr@closed-door-rt.example", "policy@corp.internal",
         "闭门研讨：数据跨境新规（第4期）")
E("mal_0272_apt_roundtable.eml",
  hdr + "您好：\r\n\r\n"
  "第四期闭门研讨拟定 9/26 杭州，议题为数据跨境与合规审计实务。\r\n"
  "议程与阅读材料（需登录阅读）：https://closed-door-rt.example/issue4\r\n\r\n"
  "名额有限，回复确认即可保留。\r\n",
  "malicious", "apt", ["closed_door_invite", "clean_prose_no_keywords"],
  "行业闭门定向，零敏感词")

hdr = HD("网络服务", "vpn-config@corp-netcfg.example", "remote@corp.internal",
         "VPN 配置轮换（导入新配置）")
E("mal_0273_apt_vpn_config.eml",
  ATT(hdr, "新配置见附件，导入 OpenVPN 客户端后重启生效。",
      "corp-2026.ovpn", "application/x-openvpn-profile",
      B("client\r\nremote gw.evil-net.example 1194\r\nup /etc/hook.sh\r\n")),
  "malicious", "apt", ["vpn_profile_hook"],
  "ovpn 的 up 钩子执行脚本")

hdr = HD("区域CERT", "alert@cert-partner.example", "sec@corp.internal",
         "预警通报：针对行业的鱼叉活动（附IOC）")
E("mal_0274_apt_fake_cert.eml",
  ATT(hdr,
      "IOC 打包如附件，解压密码：Passw0rd2026\r\n\r\n"
      "通报正文：近期发现仿冒招聘的定向活动，样本与失陷指标见附件包。\r\n",
      "ioc_pack.zip", "application/zip",
      base64.b64encode(b"PK\x03\x04" + bytes(range(64))).decode()),
  "malicious", "apt", ["fake_cert_advisory", "password_protected_payload"],
  "以'带密码压缩包'伪装可信通报")

hdr = HD("期刊编辑部", "ms@j-systems.example", "research@corp.internal",
         "Review invitation: JSS-2026-1147")
E("mal_0275_apt_review_remote_template.eml",
  ATT(hdr, "Dear Dr.,\n\nPlease find the manuscript for review attached.\n",
      "manuscript.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      base64.b64encode(b"PK\x03\x04" + b"\x00\x00\x00\x00").decode()),
  "malicious", "apt", ["remote_template_injection"],
  "docx 远程模板注入（打开时拉取恶意模板）", "en")

hdr = HD("赵工", "zhao@partner-relay5.example", "eng@corp.internal",
         "Re: 图纸第3版",
         "In-Reply-To: <dwg-v3@corp.internal>\r\n")
E("mal_0276_apt_zero_text.eml",
  ATT(hdr, "见附件。", "第3版签字页.pdf", "application/pdf",
      base64.b64encode(b"%PDF-1.7" + b"\x00"*90).decode()),
  "malicious", "apt", ["minimal_reply_payload", "signed_thread"],
  "正文仅'见附件'，信任全部来自线程上下文")

hdr = HD("采购中心", "op@city-smart-rfp.example", "bd@corp.internal",
         "智慧城市二期需求调研表")
E("mal_0277_apt_xls_unc.eml",
  ATT(hdr, "调研表请于本周末前回填。", "需求调研表.xls", "application/vnd.ms-excel",
      base64.b64encode(b"\xd0\xcf\x11\xe0" + b"\x00\x00\x00\x00").decode()),
  "malicious", "apt", ["xls_unc_dde"],
  "老 XLS 内嵌 UNC/DDE 取回")

hdr = HD("系统检查", "check@corp-scan-relay.example", "it@corp.internal",
         "终端自检工具（双击运行）")
E("mal_0278_apt_hta.eml",
  ATT(hdr, "自检工具见附件，运行后将结果截图回复。",
      "check.hta", "application/hta",
      B("<script>new ActiveXObject('WScript.Shell').Run('powershell -enc AA');</script>")),
  "malicious", "apt", ["hta_downloader"])

hdr = HD("内刊", "letter@corp-weekly5.example", "staff@corp.internal",
         "本周内刊（第38期）")
E("mal_0279_apt_tds_style.eml",
  HD("内刊", "letter@corp-weekly5.example", "staff@corp.internal", "本周内刊（第38期）",
     "", "text/html; charset=utf-8")
  + "<html><body><h3>第 38 期目录</h3><ul><li>封面：效率工具</li><li>人物：值班十年</li></ul>"
  "<p>完整版：<a href='https://corp-weekly5.example/read/38'>阅读</a></p>"
  "<p style='font-size:11px'>如您在园区网络外，请使用备用入口 "
  "<a href='https://weekly-mirror-gate.example.info/38'>镜像阅读</a></p></body></html>",
  "malicious", "apt", ["tds_style_geo_fallback"],
  "主链真、镜像链假的分流手法", "zh", "html")

hdr = HD("会务", "cal@rt-calendar.example", "research@corp.internal",
         "邀请：第4期闭门研讨（9/26）")
E("mal_0280_apt_ics_alarm.eml",
  ATT(hdr, "日程见附件，添加后会前自动提醒。",
      "invite.ics", "text/calendar",
      B("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nSUMMARY:闭门研讨\r\n"
        "BEGIN:VALARM\r\nTRIGGER:-PT10M\r\nACTION:DISPLAY\r\n"
        "DESCRIPTION:会前请完成材料预读 https://rt-material.example.info/pre\r\n"
        "END:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")),
  "malicious", "apt", ["ics_valarm_lure"],
  "日历提醒文案诱导访问链接")

hdr = HD("IT 安全部", "security-key@corp-enroll.example", "leaders@corp.internal",
         "硬件密钥升级：扫码绑定新令牌")
E("mal_0281_apt_reverse_proxy_qr.eml",
  HD("IT 安全部", "security-key@corp-enroll.example", "leaders@corp.internal",
     "硬件密钥升级：扫码绑定新令牌", "", "text/html; charset=utf-8")
  + "<html><body><p>本季度为管理岗更换硬件密钥。请用企业微信扫码进入绑定页：</p>"
  "<p><img src='https://corp-enroll.example/q.png' alt='绑定二维码' width='170'></p>"
  "<p style='font-size:12px'>绑定过程需输入域账号完成核验。</p></body></html>",
  "malicious", "apt", ["reverse_proxy_sso_qr"], "反向代理仿 SSO 扫码", "zh", "html")

hdr = HD("Meridian Labs", "talent@rust-career.example", "dev@corp.internal",
         "Case study brief (24h window)")
E("mal_0282_apt_case_brief.eml",
  hdr + "Hi,\n\n"
  "Brief for the overlay runtime case study:\n"
  "- scope: a small timeout-fallback design doc\n"
  "- upload: https://rust-career.example/upload/gw\n\n"
  "Paid at standard consulting rate regardless of outcome.\n",
  "malicious", "apt", ["paid_case_brief_collect"], "付费案例降低戒心", "en")

hdr = HD("华信贸易-应收", "ap@hongxin-trade.example", "ap@corp.internal",
         "Re: 9月货款安排（账户变更）",
         "In-Reply-To: <po-2026-203@corp.internal>\r\n")
E("mal_0283_apt_supplier_bank_swap.eml",
  hdr + "王会计：9 月货款按合同 12 日付。\r\n"
  "因开户行迁址，本次起启用新账户（已随本邮件抄送财务备案）：\r\n"
  "户名：华信国际贸易有限公司；账号：6225 0091 4471 0082\r\n"
  "付款前请电话与我们财务复核（0571-88xx 转 8021）。\r\n",
  "malicious", "apt", ["supplier_bank_swap_on_real_thread"],
  "真线程+新账户+自查电话（电话也是攻击者）", "zh", "plain", "review",
  True, "静态完全不可判定（域名真、话术真、流程真），只能靠账户变更历史/对账异常检出")

hdr = HD("安全响应", "triage@corp-redteam-relay.example", "it@corp.internal",
         "红队演练：请勿处理本封（有效性验证）")
E("mal_0284_apt_fake_redteam.eml",
  hdr + "本封为红队演练有效性验证样本。\r\n"
  "如您看到本邮件，说明投递通道正常，请点击\"确认送达\"以完成统计：\r\n"
  "https://corp-redteam-relay.example/ack/it\r\n",
  "malicious", "apt", ["fake_redteam_ack"],
  "冒充红队利用'演练心理'诱导点击")

hdr = HD("Bug Bounty", "payout@bounty-pay.example", "sec-research@corp.internal",
         "Payout approved: SSRF-2026-8842 ($1,500)")
E("mal_0285_apt_bounty_payout.eml",
  hdr + "Hi,\n\n"
  "Your report SSRF-2026-8842 is accepted. To release the payout, verify your\r\n"
  "account at https://bounty-pay.example/claim/8842 (SSO or email login).\n",
  "malicious", "apt", ["bounty_payout_lure"], "盯防安全研究者的定向", "en")

# ---------------- look-alike ham (15) ----------------
E("ham_0261_conf_real.eml",
  HD("议程委员会", "pc@conf-official.example", "sec-research@corp.internal",
     "Re: 议题初评意见（议题 #1147）", "In-Reply-To: <cfp-1147@corp.internal>\r\n")
  + "您好：\r\n\r\n"
  "初评意见已出，终审前请根据批注调整 slide 篇幅（议程系统内可见）：\r\n"
  "https://conf-official.example/review/1147\r\n\r\n"
  "如需电话沟通请回复约时间。\r\n",
  "benign", "ham_business", ["conf_review_real_thread"], "与 APT 会议仿冒同形（官方域+真线程）")

E("ham_0262_recruiter_real.eml",
  HD("Talent - Meridian", "talent@meridianlabs.example", "dev@corp.internal",
     "Senior Rust Engineer — your tower-lsp work")
  + "Hi,\n\n"
  "Your tower-lsp writeup was a great read. We have a remote Rust role open;\n"
  "JD attached in the careers portal (no login needed to view):\n"
  "https://meridianlabs.example/careers/rust-senior\n\n"
  "Happy to chat first if you prefer.\n",
  "benign", "ham_business", ["recruiter_real_official_domain"], "", "en")

E("ham_0263_partner_thread_clean.eml",
  HD("采购-远东实业", "sales@yuandong.example", "purchase@corp.internal",
     "Re: PO-2026-1148 交期确认",
     "In-Reply-To: <po-2026-1148@corp.internal>\r\nReferences: <po-2026-1148@corp.internal>\r\n")
  + "交期确认 9/18，物流单发出后同步。\r\n发票按老规则月底统一开。\r\n",
  "benign", "ham_business", ["partner_thread_clean"],
  "与被劫持线程对照：无新附件、无账户变更")

E("ham_0264_devicecode_real.eml",
  HD("IT 服务台", "helpdesk@corp.internal", "facilities@corp.internal",
     "会议室大屏登录方式（设备授权）")
  + "会议室大屏无法键入密码，可用设备授权登录：\r\n"
  "1. 在电脑打开 https://login.microsoftonline.com/devicelogin\r\n"
  "2. 输入屏幕显示的代码\r\n"
  "注意：代码由大屏生成显示，不要接受任何人通过邮件发来的代码。\r\n",
  "benign", "ham_business", ["devicecode_real_from_screen"],
  "真设备码流程的要点：代码来自设备屏幕而非邮件")

E("ham_0265_oauth_real.eml",
  HD("IT 服务台", "helpdesk@corp.internal", "staff@corp.internal",
     "工时集成上线：TimesheetPro 授权指引")
  + "工时集成已上线，请在门户-应用中心完成一次授权（应用中心内点击\r\n"
  "TimesheetPro 即可，仅申请日历读写）。\r\n"
  "切勿通过邮件链接进行应用授权。\r\n",
  "benign", "ham_business", ["oauth_real_portal_only"],
  "真授权只走门户应用中心，强调防邮件链接")

E("ham_0266_cert_real_adv.eml",
  HD("安全运营中心", "soc@corp.internal", "it-all@corp.internal",
     "转发：区域CERT预警（含IOC）")
  + "转发同行 CERT 预警，IOC 原文链接：https://cert-official.example/2026-091\r\n"
  "本地样本已沙箱复测，网关规则已更新。\r\n"
  "（我们不会以附件分发样本，样本获取走内部样本库）\r\n",
  "benign", "ham_business", ["cert_real_no_attachment"],
  "真转发只给原文链接，不带密码压缩包")

E("ham_0267_journal_review_real.eml",
  HD("Journal Systems", "ms@j-systems.example", "research@corp.internal",
     "Review invitation: JSI-1147")
  + "Dear Dr.,\n\n"
  "You are invited to review manuscript JSI-1147. Accept/decline at the\r\n"
  "reviewer portal: https://jsi.example.org/reviewer/1147 (your existing account).\n",
  "benign", "ham_business", ["journal_real_portal"], "", "en")

E("ham_0268_supplier_invoice_clean.eml",
  HD("华信贸易-应收", "ap@hongxin-trade.example", "ap@corp.internal",
     "9月对账单（无变化）")
  + "9 月对账单已发贵司门户，合计与上月口径一致，无账户变更。\r\n"
  "核对差异回邮件即可。\r\n",
  "benign", "ham_business", ["supplier_no_change"], "与银行账户调包对照")

E("ham_0269_vpn_real.eml",
  HD("网络服务", "vpn@corp.internal", "remote@corp.internal",
     "VPN 配置轮换（门户下载）")
  + "新配置已发布，门户-VPN-配置下载（登录后自动导入客户端）。\r\n"
  "配置文件不会通过邮件附件分发。\r\n",
  "benign", "ham_business", ["vpn_real_portal"], "与 opn 附件投放对照")

E("ham_0270_conf_photo_real.eml",
  HD("会务组-小陈", "chen@conf-official.example", "research@corp.internal",
     "现场照片（网盘相册）")
  + "照片 300+ 张已传官方相册：https://conf-official.example/album/38\r\n"
  "含高清版，可直接下载。\r\n",
  "benign", "ham_business", ["conf_photo_real_album"], "与多态 PNG 附件对照")

E("ham_0271_rfp_real.eml",
  HD("政采平台", "notify@ccgp.example", "bd@corp.internal",
     "智慧城市二期：需求调研开始")
  + "调研表在平台内在线填写（统一身份登录），截止本周末。\r\n"
  "平台不会以附件形式下发调研表。\r\n",
  "benign", "ham_business", ["rfp_real_platform_only"], "与 xls 投放对照")

E("ham_0272_finance_zip_real.eml",
  HD("财务共享", "fssc@corp.internal", "gl@corp.internal",
     "银行回单（加密压缩包）")
  + "9 月回单打包如附件，解压密码已通过短信发到您预留手机。\r\n"
  "密码不经邮件传递，请勿转发附件。\r\n"
  + "Content-Type: multipart/mixed; boundary=\"BS\"\r\n\r\n"
  "--BS\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n见上。\r\n"
  "--BS\r\nContent-Type: application/zip\r\nContent-Disposition: attachment; filename=\"回单.zip\"\r\n"
  "Content-Transfer-Encoding: base64\r\n\r\n" + base64.b64encode(b"PK\x05\x06" + b"\x00"*18).decode()
  + "\r\n--BS--\r\n",
  "benign", "ham_business", ["zip_real_sms_password"],
  "真加密包：密码走短信、发件是内部域", "zh", "plain", "review", True,
  "压缩包内容为测试占位/无法提取文本，策略应展示检查不完整并交人工确认")

E("ham_0273_case_real.eml",
  HD("Meridian Labs", "talent@meridianlabs.example", "dev@corp.internal",
     "Re: Case study brief")
  + "Thanks — the brief is on the same careers page, no separate upload needed:\n"
  "https://meridianlabs.example/careers/case\n",
  "benign", "ham_business", ["case_real_same_domain"], "", "en")

E("ham_0274_redteam_real2.eml",
  HD("安全部-红队", "redteam@corp.internal", "it@corp.internal",
     "9月演练复盘摘要")
  + "9 月演练点击率 4.2%。复盘要点：长域名与'扫码'类点击率最高。\r\n"
  "样本与统计见内部平台（演练期间投放，事后公布链接，不做'确认送达'）。\r\n",
  "benign", "ham_business", ["redteam_real_no_ack_link"],
  "真红队复盘从不要求'确认送达'点击")

E("ham_0275_bounty_real.eml",
  HD("HackerOne", "noreply@hackerone.example", "sec-research@corp.internal",
     "Report #8842 resolved (bounty $1,500)")
  + "Your report is resolved. The bounty will arrive via your configured\r\n"
  "payout method; manage payouts only inside the platform:\r\n"
  "https://hackerone.example/user/payouts\n",
  "benign", "ham_business", ["bounty_real_in_platform"], "", "en")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch17 written: {len(LABELS)} samples")
