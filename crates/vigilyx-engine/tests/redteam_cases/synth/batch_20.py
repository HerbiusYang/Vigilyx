#!/usr/bin/env python3
"""Batch 20: post-compromise internal lures, multilingual APT, undecidable grays."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def HD(disp, frm, to, subj, extra="", ct="text/plain; charset=utf-8"):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Sat, 12 Sep 2026 08:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b20@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\nContent-Type: {ct}\r\n\r\n")
def ATT(hdr, t, fn, ct, b64):
    return (hdr + "Content-Type: multipart/mixed; boundary=\"BS\"\r\n\r\n"
            f"--BS\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{t}\r\n"
            f"--BS\r\nContent-Type: {ct}\r\nContent-Disposition: attachment; filename=\"{fn}\"\r\n"
            f"Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--BS--\r\n")
def E(n, raw, label, family, tech, note="", lang="zh", fmt="plain",
      expected=None, ambiguous=False, borderline="", enc="utf-8"):
    W(n, raw if isinstance(raw, bytes) else raw.encode(enc, errors="replace"))
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": expected or ("block" if label == "malicious" else "deliver"),
        "engine_status": "not_evaluated", "synthetic": True, "batch": 20,
        "format": fmt, "note": note, "ambiguous": ambiguous, "borderline": borderline})

# ---- post-compromise internal lures (from REAL internal domains) ----
E("mal_0321_hijacked_mailbox.eml",
  HD("李伟-平台组", "li.wei@corp.internal", "dev-team@corp.internal",
     "邮箱迁移通知（今晚）")
  + "各位：IT 今晚统一迁移邮箱，收到本邮件的请先完成账号重新登录验证：\r\n"
  "https://mail-migrate-relay.example/verify\r\n"
  "（用域账号密码登录后等待迁移完成）\r\n",
  "malicious", "apt", ["internal_mailbox_hijack"],
  "发件域为真内部（信箱被劫持），唯一破绽是链接外域", "zh", "plain", "review",
  True, "同域发件=最高可信度；域名比对是唯一静态线索，必须复核")

E("mal_0322_meeting_link_swap.eml",
  HD("陈曦", "chen.xi@corp.internal", "leaders@corp.internal",
     "Re: 网关评审改线上（链接更新）",
     "In-Reply-To: <gw-review@corp.internal>\r\n")
  + "会议室被占了，改线上。用这个链接进：\r\n"
  "https://meet-relay-gw.example/j/arch\r\n"
  "（原来的链接作废）\r\n",
  "malicious", "apt", ["meeting_link_swap_internal_thread"],
  "真线程换会议链接（劫持后小动作）", "zh", "plain", "review",
  True, "换链接是劫持后常见动作；内域发件+外域会议链接=应复核")

E("mal_0323_archive_request.exfil.eml",
  HD("合规-张倩", "zhang.qian@corp.internal", "legal@corp.internal",
     "归档请求：客户合同（2019-2026）")
  + "审计需要 2019-2026 客户合同全文，打包发我邮箱或上传：\r\n"
  "https://corp-d365-relay.example/up/legal\r\n"
  "今晚要用，先发我一份。\r\n",
  "malicious", "apt", ["exfil_disguised_archive"],
  "以归档为名的数据外带", "zh", "plain", "review",
  True, "话术完全合规；异常在于'今晚+外链上传'，需 DLP 视角而非钓鱼视角")

# ---- multilingual APT ----
E("mal_0324_ru_gas.eml",
  HD("ООО Газпром контракт", "kontrakt@gaz-contract.example", "trade@corp.internal",
     "=?utf-8?B?" + base64.b64encode("Дополнение к контракту".encode()).decode() + "?=",
     "", "text/plain; charset=windows-1251")
  + "Добрый день. Направляем дополнение к контракту (приложение).\r\n"
  "Обсуждение условий: https://gaz-contract.example/sup\r\n",
  "malicious", "apt", ["ru_energy_contract", "cp1251"],
  "俄文能源合同话术", "ru", "plain", "block", False, "", "cp1251")

E("mal_0325_ja_trade.eml",
  HD("東京貿易株式会社", "eigyou@tokyo-boeki.example", "trade@corp.internal",
     "=?utf-8?B?" + base64.b64encode("新規サプライヤー登録のお願い".encode()).decode() + "?=")
  + "いつもお世話になっております。\r\n"
  "新規取引に伴う登録フォームのご案内：\r\n"
  "https://tokyo-boeki.example/entry\r\n"
  "ご確認のほどよろしくお願いいたします。\r\n",
  "malicious", "apt", ["ja_supplier_registration"], "日式商务敬语钓鱼")

E("mal_0326_ko_semiconductor.eml",
  HD("반도체 협력회", "collab@semi-kr.example", "rd@corp.internal",
     "=?utf-8?B?" + base64.b64encode("공정 데이터 협약서 안내".encode()).decode() + "?=")
  + "안녕하세요. 공정 데이터 협약 관련 서류가 업데이트되었습니다.\r\n"
  "확인: https://semi-kr.example/pact/2026\r\n",
  "malicious", "apt", ["ko_semiconductor_lure"], "半导体供应链韩文话术")

E("mal_0327_fr_intl.eml",
  HD("Division Affaires", "affaires@intl-ops.example", "hr@corp.internal",
     "Note diplomatique - verification requise")
  + "Bonjour,\n\n"
  "Une note concernant vos accréditations nécessite vérification:\n"
  "https://intl-ops.example/note/8842\r\n",
  "malicious", "apt", ["fr_intl_org_lure"], "国际组织法语话术", "fr")

E("mal_0328_hant_crossstrait.eml",
  HD("兩岸經貿協會", "svc@cross-strait.example", "trade@corp.internal", " ECFA關稅減免申請（第3批）")
  + "台端符合第3批關稅減免資格，請於期限內完成線上申請：\r\n"
  "https://cross-strait.example/apply/ecfa3\r\n"
  "（統一證號+大陸台胞證號碼）\r\n",
  "malicious", "apt", ["hant_crossstrait_lure"], "两岸经贸繁体话术", "zh-hant")

# ---- more vectors ----
E("mal_0329_cookie_export.eml",
  HD("IT 支持", "it@browser-sync-relay.example", "staff@corp.internal",
     "浏览器配置同步（迁移到新设备）")
  + "换机后浏览器配置可一键同步：\r\n"
  "导出工具（含登录态）：https://browser-sync-relay.example/export\r\n"
  "导出文件发回本邮箱即可完成同步。\r\n",
  "malicious", "apt", ["session_cookie_export_collect"], "收浏览器会话导出（绕过密码）")

E("mal_0330_ca_ukey.eml",
  HD("电子认证", "svc@ca-bid.example", "bd@corp.internal",
     "投标 CA 证书到期换发（Ukey 快递）")
  + "贵司投标 CA 证书 30 日后到期，换发需核验单位信息：\r\n"
  "https://ca-bid.example/renew（统一社会信用代码+经办人身份证号）\r\n"
  "新 Ukey 顺丰到付。\r\n",
  "malicious", "apt", ["bid_ca_renew_collect"], "投标 CA 话术收证件号")

E("mal_0331_legal_subpoena.eml",
  HD("律师事务所", "notice@law-desk15.example", "legal@corp.internal",
     "Legal Hold Notice - Litigation (Case No. 2026-88)")
  + "Dear Counsel,\n\n"
  "A preservation order applies to your client. Acknowledge receipt and verify\r\n"
  "authorized recipients: https://law-desk15.example/hold/88\r\n",
  "malicious", "apt", ["fake_legal_hold"], "假法律保全令", "en")

E("mal_0332_mfa_fatigue_pre.eml",
  HD("IT 安全部", "mfa@corp-relay16.example", "leaders@corp.internal",
     "MFA 升级：预授权确认")
  + "今晚 MFA 平滑升级，管理岗需提前完成'预授权'：\r\n"
  "点击确认（收到推送请选择'批准'）：\r\n"
  "https://corp-relay16.example/mfa-pre\r\n",
  "malicious", "apt", ["mfa_fatigue_preauth"],
  "为今晚的 MFA 疲劳轰炸做铺垫：先教用户'习惯点批准'")

E("mal_0333_printer_fw.eml",
  ATT(HD("设备管理", "fleet@printer-svc17.example", "admin@corp.internal",
         "打印机固件安全更新"),
      "固件包见附件（USB 或管理页导入）。",
      "LJ6000-fw.bin", "application/octet-stream",
      base64.b64encode(b"\x7fELF" + b"\x00"*40).decode()),
  "malicious", "apt", ["printer_firmware_elf"], "打印机固件 ELF 载荷")

E("mal_0334_game_engine.eml",
  HD("引擎合作", "partner@engine-labs.example", "dev@corp.internal",
     "联调 SDK（预览版）")
  + "Hi,\n\n"
  "Preview SDK attached in the shared drive; mount the image:\r\n"
  "https://engine-labs.example/sdk-preview.iso\r\n",
  "malicious", "apt", ["game_engine_sdk_iso"], "SDK 预览 ISO", "en")

E("mal_0335_exchange_vuln.eml",
  HD("产品安全", "psrt@mail-product.example", "it@corp.internal",
     "紧急：邮件服务器 RCE 补丁（带外分发）")
  + "因漏洞在野利用，补丁采取带外分发：\r\n"
  "https://mail-product-oob.example/patch/ex2609\r\n"
  "（管理凭据登录下载，切勿转发）\r\n",
  "malicious", "apt", ["fake_out_of_band_patch"], "带外补丁话术收管理员凭据")

# ---- undecidable gray pairs (10) ----
E("gray_0081_colleague_notice_real.eml",
  HD("李伟-平台组", "li.wei@corp.internal", "dev-team@corp.internal",
     "值班表更新（下周）")
  + "下周值班：周二老许、周四小蔺。交接写值班本。\r\n"
  "有问题群里说。\r\n",
  "benign", "ham_business", ["colleague_real_plain"],
  "与劫持信箱对照的干净内部信", "zh", "plain", "deliver", True,
  "同域同风格的内部信；真伪只能靠行为基线（发信时间/习惯）")

E("gray_0082_meet_real.eml",
  HD("陈曦", "chen.xi@corp.internal", "leaders@corp.internal",
     "Re: 网关评审改线上",
     "In-Reply-To: <gw-review@corp.internal>\r\n")
  + "会议室被占了，改线上。用老链接进：\r\n"
  "https://meet.corp.internal/j/arch\r\n",
  "benign", "ham_business", ["meet_real_internal_link"],
  "内域会议链接", "zh", "plain", "deliver", True,
  "与 mal_0322 逐字级对照：唯一差异是会议链接域")

E("gray_0083_law_real.eml",
  HD("法务-外部顾问", "counsel@law-firm.example", "legal@corp.internal",
     "Litigation hold acknowledgment (Case 2026-88)")
  + "Please acknowledge this hold by reply email (no link needed).\n"
  "Scope and custodians listed in the attached PDF (signature page 3).\n",
  "benign", "ham_business", ["legal_real_reply_ack"],
  "真保全令：回邮确认即可", "en", "plain", "deliver", True,
  "与 mal_0331 对照：真件不搞'链接核验'")

E("gray_0084_archive_real.eml",
  HD("审计-内勤", "audit.ops@corp.internal", "legal@corp.internal",
     "归档请求：客户合同（2019-2026）")
  + "年审需要 2019-2026 客户合同清单，请挂到内网共享盘\r\n"
  "/audit/2026/contracts/（权限已开）。\r\n",
  "benign", "ham_business", ["archive_real_internal_share"],
  "真归档走内网共享盘", "zh", "plain", "deliver", True,
  "与 mal_0323 对照：渠道（内网共享 vs 外链上传）是分界线")

E("gray_0085_ca_real.eml",
  HD("电子认证", "svc@cfca.example", "bd@corp.internal",
     "投标 CA 证书到期提醒")
  + "证书到期前 30 天可在业务系统内在线换发（Ukey 插入自动识别），\r\n"
  "我司不通过邮件链接办理换发。\r\n",
  "benign", "ham_business", ["ca_real_system_only"], "真 CA 只走业务系统", "zh",
  "plain", "deliver", True, "与 mal_0330 对照")

E("gray_0086_sdk_real.eml",
  HD("Engine Labs", "partner@engine-labs.example", "dev@corp.internal",
     "Re: 联调 SDK（预览版）")
  + "The preview SDK is on our partner portal (your existing credentials):\n"
  "https://partner.engine-labs.example/sdk/preview\n",
  "benign", "ham_business", ["sdk_real_portal_same_domain"],
  "域一致的合作门户", "en", "plain", "deliver", True,
  "与 mal_0334 对照：链接域是否与发件域同源")

E("gray_0087_patch_real.eml",
  HD("产品安全", "psrt@mail-product.example", "it@corp.internal",
     "安全公告：RCE 漏洞（官方更新通道）")
  + "补丁已进入官方更新通道（管理控制台-更新），\r\n"
  "我们不会带外分发安装包；收到此类邮件请上报 PSRT。\r\n",
  "benign", "ham_business", ["patch_real_console"],
  "真公告只指控制台", "zh", "plain", "deliver", True,
  "与 mal_0335 对照：'带外分发'本身就是危险信号")

E("gray_0088_mfa_real.eml",
  HD("IT 安全部", "security@corp.internal", "leaders@corp.internal",
     "MFA 升级说明（今晚自动）")
  + "今晚 MFA 自动升级，无需任何预操作。\r\n"
  "升级后首次登录会多一次验证；我们不会发'预授权'链接，\r\n"
  "收到推送请求请按日常习惯处理，异常请上报。\r\n",
  "benign", "ham_business", ["mfa_real_no_preauth"],
  "真 MFA 升级明确'无需预操作'", "zh", "plain", "deliver", True,
  "与 mal_0332 对照：真升级绝不教你'提前习惯批准'")

E("gray_0089_hant_real.eml",
  HD("兩岸經貿協會", "svc@cross-strait.example", "trade@corp.internal",
     "會員大會議程（紙本）")
  + "會員大會議程如附件，回執請郵寄或傳真至秘書處。\r\n"
  "本會不提供線上申請作業。\r\n",
  "benign", "ham_business", ["hant_real_offline_process"],
  "真协会走线下", "zh-hant", "plain", "deliver", True,
  "与 mal_0328 同域同语言对照；真件不做线上收证")

E("gray_0090_exch_real.eml",
  HD("微软产品安全", "security@ms-product.example", "it@corp.internal",
     "Exchange 安全更新（已发布）")
  + "The September SU is available via Microsoft Update / SU tool as usual.\r\n"
  "Microsoft never distributes patches as out-of-band downloads by email.\r\n",
  "benign", "ham_business", ["ms_real_update_channel"],
  "真厂商声明从不用邮件带外发补丁", "en", "plain", "deliver", True,
  "与 mal_0335 的英语版对照；判别句式是官方反诈声明")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch20 written: {len(LABELS)} samples")
