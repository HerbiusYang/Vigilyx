#!/usr/bin/env python3
"""Batch 34: hand-crafted stealth constructions. Each malicious sample hides
its payload behind exactly ONE tell; the note documents the design."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def HD(disp, frm, to, subj, extra="", ct="text/plain; charset=utf-8"):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Mon, 28 Sep 2026 08:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b34@synth.example>\r\n" + extra +
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
        "engine_status": "not_evaluated", "synthetic": True, "batch": 34,
        "format": fmt, "note": note, "ambiguous": ambiguous, "borderline": borderline})

# ---- 单一破绽系列：每个恶意只有一处可变因素 ----
E("mal_0594_one_char_domain.eml",
  HD("IT 服务台", "itsm@corp.interna1.example", "dev@corp.internal", "网关发布窗口变更通知",
     "Reply-To: itsm@corp.interna1.example\r\n")
  + "各位：因机房电力检修，网关发布窗口从周四 23:00 调整至周五 23:00，\r\n"
  "灰度比例不变，值班表顺延。具体见值班本。\r\n",
  "malicious", "apt", ["single_tell:domain_one_char(1 vs l)", "no_link_no_attachment"],
  "隐蔽设计：正文纯运维信息、零链接零附件；唯一破绽是 corp.interna1（数字1替换l）+Reply-To 同域。检测必须依赖域名比对而非内容",
  "zh", "plain", "review", True, "内容完全良性，域名才是攻击——无链接无附件，纯仿冒域试探")

E("mal_0595_replyto_split.eml",
  HD("王芳", "wang.fang@corp.internal", "treasury@corp.internal", "报销的单据我转给小蔡了",
     "Reply-To: wang.fang.cf@gmail-relay.example\r\n")
  + "她说缺一份发票原件照片，你直接回她邮箱就行，纸质的我这边补。\r\n",
  "malicious", "apt", ["single_tell:replyto_differs", "harvest_by_reply"],
  "隐蔽设计：From 完全真实（被冒充的同事）、正文家常；Reply-To 指向外部收集箱。回复即外泄",
  "zh", "plain", "block", True, "From/Reply-To 分离是唯一破绽；检测点=Reply-To 域与 From 域不一致")

E("mal_0596_http_internal.eml",
  HD("监控平台", "monitor@corp-observ.example", "sre@corp.internal", "P99 毛刺的 trace 已导出")
  + "trace 挂在临时面板：http://corp-observ.example:8080/t/8842\r\n"
  "（内网地址，半小时有效）\r\n",
  "malicious", "apt", ["single_tell:http_port_lure"],
  "隐蔽设计：运维口吻完美（P99/trace/面板/时效），唯一破绽是外部域+8080 端口冒充内网面板",
  "zh", "plain", "block", True, "内网话术包装外部地址；检测点=域名不在内网段清单")

E("mal_0597_doc_not_docx.eml",
  ATT(HD("采购-老周", "zhou@hongxin-trade.example", "purchase@corp.internal",
         "Re: PO-2026-1148 签字版（老格式）",
         "In-Reply-To: <po-2026-1148@corp.internal>\r\n"),
      "财务说系统旧只认 .doc，重转了一份。",
      "签字版.doc", "application/msword",
      base64.b64encode(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00"*64).decode()),
  "malicious", "apt", ["single_tell:legacy_doc_on_thread", "ole_payload"],
  "隐蔽设计：真线程+合理借口（旧系统）+正确 CTE；唯一破绽是旧版二进制格式。'借口合理性'是社工核心",
  "zh", "plain", "block", True, "OLE 宏载体；借口'对方系统旧'在 B2B 里真实存在——需沙箱而非规则")

E("mal_0598_date_math.eml",
  HD("总经办", "schedule@partner-relay30.example", "ea@corp.internal", "行程与材料（周三版）")
  + "周三 09:00 出发，材料我让助理整理在共享页，周二晚前看一遍：\r\n"
  "https://partner-materials.example/2026/w38\r\n"
  "页面要公司邮箱登录，忘了密码就先用邮箱注册一个。\r\n",
  "malicious", "apt", ["single_tell:soft_registration", "no_urgency_words"],
  "隐蔽设计：无任何紧迫词——期限由'周三出发'的日历算术暗示；'先注册一个'诱导凭据新建（重用密码）。语气是秘书的自然口语",
  "zh", "plain", "block", True, "零关键词+零紧迫词；检测点=外部域要求公司邮箱注册")

E("mal_0599_project_vocab.eml",
  HD("架构组-外部顾问", "cons@arch-advisory.example", "arch@corp.internal",
     "关于灰度回退阈值的一点补充")
  + "看了你们网关的回退逻辑，建议阈值做成可配的，我画了张时序图：\r\n"
  "https://arch-advisory.example/diagrams/fallback\r\n"
  "不急，周五评审前看就行。\r\n",
  "malicious", "apt", ["single_tell:advisor_link", "victim_vocab_mirroring"],
  "隐蔽设计：镜像受害者自己的项目词汇（网关/灰度/回退/评审），'不急'反紧迫话术。唯一破绽是顾问域",
  "zh", "plain", "block", True, "定向情报水准的话术；检测点=顾问域无历史往来记录")

E("mal_0600_half_info.eml",
  HD("李伟", "li.wei@corp.interna1.example", "dev@corp.internal", "Re: 值班交接（第三批）",
     "In-Reply-To: <duty-handover@corp.internal>\r\n")
  + "交接文档我放在老地方了，另外补了两条新链路的说明：\r\n"
  "入口今晚 8 点前有效。\r\n",
  "malicious", "apt", ["single_tell:domain_one_char", "vague_reference"],
  "隐蔽设计：'老地方'式模糊引用（无 URL 无附件名），唯一破绽仍是 interna1 域。收件人会自然回信问链接——攻击者再私发",
  "zh", "plain", "review", True, "两段式投放的第一封；内容零恶意，域名单字符差异是唯一线索")

E("mal_0601_positive_frame.eml",
  HD("薪福服务", "payroll@hr-saas26.example", "staff@corp.internal", "年度个税优惠确认（可省 2,400 元）")
  + "确认资格（身份证+银行卡）：https://payroll-saas26.example.info/c\r\n",
  "malicious", "subsidy_fraud", ["auto"], "b34fix")
E("mal_0602_silent_swap.eml",
  HD("华信贸易-应收", "ap@hongxin-trade.example", "ap@corp.internal",
     "Re: 10月货款（第2次）",
     "In-Reply-To: <po-2026-203@corp.internal>\r\nReferences: <po-2026-203@corp.internal>\r\n")
  + "上次说的新账户财务没批下来，10 月还是按老账户付，金额不变。\r\n"
  "老账户明天到期换新卡，新卡号我明早发这个邮箱。\r\n",
  "malicious", "apt", ["multi_stage:swap_later", "account_swap_stage2"],
  "隐蔽设计：本封完全无害（甚至'取消'了变更），为明天的'新卡号'邮件建立信任锚。单封检测必然放行",
  "zh", "plain", "review", True, "阶段化调包第一封：静态零恶意；需序列检测（同线程出现账户变更才回溯）")
E("mal_0603_cc_boss.eml",
  HD("人事-BP", "hrbp@corp-relay31.example", "leaver@corp.internal",
     "离职材料（抄送你的 leader）",
     "Cc: leader@corp.internal\r\n")
  + "离职证明和社保转移单在附件，签回执走链接：\r\n"
  "https://hrbp-exit31.example.info/sign\r\n",
  "malicious", "apt", ["single_tell:external_link", "cc_authority_pressure"],
  "隐蔽设计：抄送领导制造合规压力，正文例行公事。唯一破绽是签署链接外域",
  "zh", "plain", "block", True, "Cc 权威压制；检测点=人事流程链接应为内网域")
E("mal_0604_ticket_ref.eml",
  HD("IT服务台", "itsm@corp-relay32.example", "it@corp.internal", "[工单 #ITSM-7754] 附件是日志包")
  + "按工单描述收集的网关日志见附件（解压密码工单里）。\r\n",
  "malicious", "malware_attachment", ["single_tell:password_zip_payload", "ticket_authority"],
  "隐蔽设计：引用工单编号建立权威，密码'在工单里'制造合理拆分。唯一破绽在附件内",
  "zh", "plain", "block")
E("mal_0605_meet_poll.eml",
  HD("PMO", "pmo@corp-relay33.example", "proj@corp.internal", "评审时间二选一（投票）")
  + "周三 14:00 / 周四 16:00，投票页：\r\n"
  "https://pmo-poll33.example.info/v\r\n（用公司邮箱登录记名投票）\r\n",
  "malicious", "credential_harvest", ["single_tell:poll_login", "normal_business_frame"],
  "隐蔽设计：投票是最低威胁动作，'记名'给了收密码的完美理由。唯一破绽是投票站外域",
  "zh", "plain", "block")
E("mal_0606_forwarded_clean.eml",
  HD("张敏", "zhang.min@corp.internal", "dev@corp.internal", "Fw: 供应商接口文档")
  + "转给你，他们 API 的鉴权说明：\r\n\r\n"
  "---------- 转发邮件 ----------\r\n"
  "From: dev@vendor-api.example\r\n"
  "鉴权 token 每周轮换，新 token 获取页：https://vendor-api.example/token\r\n"
  "（用你们企业邮箱注册即可）\r\n",
  "malicious", "apt", ["single_tell:forwarded_lure", "forwarded_clean_hand"],
  "隐蔽设计：真同事转发+分隔线下是'供应商原文'——恶意藏在被转发段里，转发者是受害者。唯一破绽在转发段的注册链接",
  "zh", "plain", "block", True, "转发链里的投毒；检测需看转发内层的链接而非发件人")
E("mal_0607_ellipsis.eml",
  HD("财务共享", "fssc@corp-relay34.example", "gl@corp.internal", "9月凭证影像归档")
  + "影像已归档，目录结构见：\r\n"
  "\\\\fssc-archive34.example@8080\\sep\\ \r\n"
  "（WebDAV，域账号直接访问）\r\n",
  "malicious", "apt", ["single_tell:webdav_port", "unc_credential_leak"],
  "隐蔽设计：UNC/WebDAV 路径写法常见于内网，端口藏在 @ 后。唯一破绽是主机名非内网",
  "zh", "plain", "block")
E("mal_0608_signature_only.eml",
  HD("商务", "bd@partner-relay35.example", "sales@corp.internal", "好的，按这个来")
  + "收到，明天确认。\r\n\r\n--\r\n"
  "Michael Chen | 商务拓展\r\n"
  "文档中心：https://partner-relay35.example/docs\r\n",
  "malicious", "link_obfuscation", ["single_tell:signature_link", "minimal_body"],
  "隐蔽设计：正文三行字，恶意全在签名档'文档中心'链接。内容检测无可检物",
  "zh", "plain", "block")
E("mal_0609_unsub_once.eml",
  HD("行业周报", "news@sector-weekly.example", "research@corp.internal", "第 41 期：双碳与出海")
  + "本期导读三条：政策、案例、数据。\r\n"
  "全文：https://sector-weekly.example/41\r\n"
  "不想收了？一次性退订（需验证邮箱身份）：https://sector-weekly.example/unsub\r\n",
  "malicious", "account_phishing", ["single_tell:unsub_verify", "newsletter_cover"],
  "隐蔽设计：正文链接全部无害，'退订要验证邮箱身份'才是收凭据的入口。退订是最低戒心动作",
  "zh", "plain", "block")
E("mal_0610_font_hint.eml",
  HD("行政", "admin@corp-relay36.example", "all@corp.internal", "下周停车调整",
     "", "text/html; charset=utf-8")
  + "<html><body><p>地面车位改为预约制，详见内网门户。</p>"
  "<p style='opacity:0.02'>系统维护：全员需重新激活邮箱 https://corp-relay36.example/act</p>"
  "</body></html>",
  "malicious", "visual_lure", ["single_tell:opacity_0.02", "cover_notice"],
  "隐蔽设计：正文是真实行政通知（真话术），恶意藏在 2% 透明度的一行里——人眼几乎不可见",
  "zh", "html", "block")
E("mal_0611_dkim_pass_style.eml",
  HD("产品团队", "product@notion-mailer.example", "pm@corp.internal",
     "Your workspace was mentioned in 3 pages",
     "Feedback-ID: 8842:noc:m-w03:mc\r\nList-Unsubscribe: <https://notion-mailer.example/u>\r\n")
  + "Pages mentioning your workspace:\r\n"
  "- Q4 Roadmap | Friday notes | Vendor list\r\n"
  "View: https://notion-mailer.example/w/pm/mentions\r\n"
  "(Sign in with your SSO.)\r\n",
  "malicious", "apt", ["single_tell:sso_on_marketing_infra", "saas_spoof_full_headers"],
  "隐蔽设计：完整伪造 SaaS 营销头（Feedback-ID/List-Unsubscribe），连退订都齐——唯一破绽是域名非官方 not**ion**",
  "en", "plain", "block", True, "营销基建仿冒：头部特征全套正确，域名是唯一解")
E("mal_0612_numbered_ambiguity.eml",
  HD("稽核", "audit@bank-relay37.example", "treasury@corp.internal", "两点差异（昨日流水）")
  + "1) 14:22 笔金额不符\r\n2) 手续费口径\r\n"
  "明细已发你司对公邮箱备案用的地址，请核对后回签。\r\n",
  "malicious", "apt", ["single_tell:phantom_attachment", "reply_chain_init"],
  "隐蔽设计：'已发备案地址'是虚构引用（什么都没发），诱导回信确认'哪个地址'——回信即建立联系。零链接零附件",
  "zh", "plain", "review", True, "社会工程开信件：无任何可检对象，唯一防御是外发回复策略")

# ---- ham：与上述破绽类型一一对应的真件 ----
E("ham_0523_real_replyto_same.eml",
  HD("王芳", "wang.fang@corp.internal", "treasury@corp.internal", "报销的单据我转给小蔡了")
  + "她说缺一份发票原件照片，你直接回她邮箱就行，纸质的我这边补。\r\n",
  "benign", "ham_business", ["pair_of:mal_0595", "replyto_equals_from"],
  "与 mal_0595 唯一差异：无 Reply-To 头")
E("ham_0524_real_http_internal.eml",
  HD("监控平台", "monitor@corp.internal", "sre@corp.internal", "P99 毛刺的 trace 已导出")
  + "trace 挂在临时面板：http://trace.corp.internal:8080/t/8842\r\n"
  "（内网地址，半小时有效）\r\n",
  "benign", "ham_business", ["pair_of:mal_0596", "internal_domain"],
  "与 mal_0596 唯一差异：内网域")
E("ham_0525_real_docx.eml",
  ATT(HD("采购-老周", "zhou@hongxin-trade.example", "purchase@corp.internal",
         "Re: PO-2026-1148 签字版",
         "In-Reply-To: <po-2026-1148@corp.internal>\r\n"),
      "签字版转好了。",
      "签字版.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      base64.b64encode(b"PK\x03\x04" + b"\x00"*32).decode()),
  "benign", "ham_business", ["pair_of:mal_0597", "modern_format"],
  "与 mal_0597 差异：docx 现代格式", "zh", "plain", "review", True,
  "DOCX 内容为测试占位/无法提取文本，策略应展示检查不完整并交人工确认")
E("ham_0526_real_poll.eml",
  HD("PMO", "pmo@corp.internal", "proj@corp.internal", "评审时间二选一（投票）")
  + "周三 14:00 / 周四 16:00，门户-投票：\r\n"
  "https://portal.corp.internal/poll/gw-review\r\n",
  "benign", "ham_business", ["pair_of:mal_0605", "internal_poll"],
  "与 mal_0605 差异：内网投票")
E("ham_0527_real_signature.eml",
  HD("商务", "bd@partner.example", "sales@corp.internal", "好的，按这个来")
  + "收到，明天确认。\r\n\r\n--\r\n"
  "Michael Chen | 商务拓展\r\n"
  "官网：https://www.partner.example\r\n",
  "benign", "ham_business", ["pair_of:mal_0608", "signature_link_matches_domain"],
  "与 mal_0608 差异：签名链接=发件域主站")
E("ham_0528_real_unsub.eml",
  HD("行业周报", "news@sector-weekly.example", "research@corp.internal", "第 41 期：双碳与出海")
  + "本期导读三条：政策、案例、数据。\r\n"
  "全文：https://sector-weekly.example/41\r\n"
  "退订：https://sector-weekly.example/u?id=8842（一键，无需验证）\r\n",
  "benign", "ham_business", ["pair_of:mal_0609", "unsub_no_verify"],
  "与 mal_0609 差异：退订无需'验证身份'——真退订从不要密码")
E("ham_0529_real_mentions.eml",
  HD("Notion", "team@mgenius-mailer.example", "pm@corp.internal", "Your workspace was mentioned")
  + "Pages: Q4 Roadmap, Vendor list. View in-app.\r\n",
  "benign", "ham_business", ["auto"], "b34fix")
E("ham_0530_real_archive.eml",
  HD("财务共享", "fssc@corp.internal", "gl@corp.internal", "9月凭证影像归档")
  + "影像已归档：\\\\file.corp.internal\\fssc\\sep\\\r\n"
  "（域账号直接访问）\r\n",
  "benign", "ham_business", ["pair_of:mal_0607", "internal_unc"],
  "与 mal_0607 差异：真内网 UNC")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch34 written: {len(LABELS)} samples")
