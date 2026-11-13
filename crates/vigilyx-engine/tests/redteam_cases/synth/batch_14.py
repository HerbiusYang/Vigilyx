#!/usr/bin/env python3
"""Batch 14: HTML threat mails (brand buttons/forms/hidden text) + HTML ham."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def H(disp, frm, to, subj):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Sun, 06 Sep 2026 09:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b14@synth.example>\r\n"
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\n"
            "Content-Type: text/html; charset=utf-8\r\n\r\n")
def E(n, hdr, body, label, family, tech, note="", lang="zh"):
    raw = hdr + "\r\n" + body
    W(n, raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 14,
        "format": "html", "note": note})

E("mal_0221_bank_button.eml",
  H("招商银行", "service@cmb-pay-notice.example", "me@personal.example", "【招商银行】您的账户存在异常交易"),
  "<html><body style='margin:0'><div style='max-width:600px;font-family:sans-serif'>"
  "<div style='background:#c7000b;color:#fff;padding:16px'>招商银行</div>"
  "<p style='padding:16px'>尊敬的客户，我们检测到您的账户在异地发生一笔异常交易，为保障资金安全已临时冻结。</p>"
  "<table cellpadding=0 cellspacing=0><tr><td style='background:#c7000b;border-radius:4px'>"
  "<a href='https://cmb-unlock-verify.example.info/unfreeze' style='color:#fff;display:block;padding:12px 32px;text-decoration:none'>立即解冻</a>"
  "</td></tr></table>"
  "<p style='color:#999;font-size:12px;padding:16px'>如非本人操作请忽略本邮件。</p></div></body></html>",
  "malicious", "account_phishing", ["html_brand_button", "bank_spoof"], "仿银行红头按钮")

E("mal_0222_m365_verify.eml",
  H("Microsoft 365", "no-reply@m365-secure.example", "staff@corp.internal", "Action required: validate your mailbox"),
  "<html><body style='font-family:Segoe UI,sans-serif'>"
  "<h2 style='color:#106ebe'>Microsoft 365</h2>"
  "<p>Your mailbox will be <b>permanently deleted in 48 hours</b> unless you re-validate it.</p>"
  "<p><a href='https://m365-validate-login.example.net/owa' "
  "style='background:#106ebe;color:#fff;padding:10px 24px;text-decoration:none'>Keep my mailbox</a></p>"
  "<hr><p style='font-size:11px;color:#888'>Microsoft Corporation | Privacy | Unsubscribe</p></body></html>",
  "malicious", "account_phishing", ["html_m365_spoof"], "仿 M365 删除威胁", "en")

E("mal_0223_login_card_form.eml",
  H("统一身份认证", "sso@corp-portal-gw.example", "staff@corp.internal", "登录态已失效，请重新认证"),
  "<html><body style='background:#f5f6f7'><div style='max-width:380px;margin:40px auto;"
  "background:#fff;border:1px solid #ddd;border-radius:8px;padding:24px;font-family:sans-serif'>"
  "<h3 style='margin-top:0'>企业统一认证</h3>"
  "<form action='https://sso-relay-example.example.co/session'>"
  "<input name='u' placeholder='企业邮箱' style='width:100%;padding:10px;margin:6px 0;border:1px solid #ccc'>"
  "<input type='password' name='p' placeholder='密码' style='width:100%;padding:10px;margin:6px 0;border:1px solid #ccc'>"
  "<button style='width:100%;padding:10px;background:#2f6fed;color:#fff;border:0'>登 录</button></form>"
  "<p style='font-size:12px;color:#999'>忘记密码？联系管理员</p></div></body></html>",
  "malicious", "credential_harvest", ["html_login_card_form"], "邮件内嵌登录卡片")

E("mal_0224_hidden_white_text.eml",
  H("每周精选", "digest@shop-weekly.example", "me@personal.example", "本周精选好物"),
  "<html><body><h2>本周精选</h2>"
  "<p>清仓好物低至 3 折，点击查看全部清单。</p>"
  "<div style='color:#ffffff;font-size:1px'>您的账户存在异常登录，请立即验证身份恢复 https://sec-restore.example.vip/r 24小时内未验证将冻结</div>"
  "<p><a href='https://weekly-deals.example.info/list'>查看清单</a></p>"
  "</body></html>",
  "malicious", "visual_lure", ["white_on_white_hidden"], "白字隐藏夹带钓鱼文")

E("mal_0225_invoice_button.eml",
  H("电子发票", "invoice@fp-delivery.example", "finance@corp.internal", "您的电子发票 IN2026-0912 已开具"),
  "<html><body style='font-family:sans-serif'>"
  "<p>您的发票已开具，金额 ¥4,280.00。</p>"
  "<p><a href='http://203.0.113.66/invoice/view?id=IN2026-0912' "
  "style='background:#0a7d38;color:#fff;padding:10px 28px;text-decoration:none'>查看并下载发票</a></p>"
  "<p style='font-size:12px;color:#888'>本邮件由系统发送，请勿回复。</p></body></html>",
  "malicious", "account_phishing", ["html_invoice_button_ip"], "发票按钮指向裸 IP")

E("mal_0226_parcel_button.eml",
  H("中通快递", "notify@zto-delivery.example", "me@personal.example", "包裹派送异常，请确认地址"),
  "<html><body style='font-family:sans-serif'>"
  "<p>您的包裹 <b>7831-6642-0091</b> 派送失败（地址不详）。</p>"
  "<p><a href='https://zto-readdress.example.info/fix' style='color:#009fe8'>修改派送地址（需支付 1 元信息费）</a></p>"
  "<p style='font-size:12px;color:#999'>两日内未确认将退回发件人。</p></body></html>",
  "malicious", "account_phishing", ["html_parcel_redirect_fee"], "小额信息费陷阱")

E("mal_0227_autosubmit_form.eml",
  H("OA 系统", "oa@corp-oa-notify.example", "staff@corp.internal", "您有一条待审批单据"),
  "<html><body onload=\"document.getElementById('f').submit()\">"
  "<p>单据 OA-2026-7788 待您审批，正在跳转…</p>"
  "<form id='f' action='https://oa-session-fix.example.net/d'></form>"
  "<p><a href='https://oa-session-fix.example.net/d'>如未自动跳转请点此</a></p></body></html>",
  "malicious", "credential_harvest", ["html_autosubmit"], "onload 自动提交跳转")

E("mal_0228_img_only_lure.eml",
  H("会员中心", "vip@club-mail.example", "me@personal.example", "您的专属权益即将到期"),
  "<html><body><p>尊贵的会员：</p>"
  "<p><img src='https://cdn-club-mail.example/p/expiry_banner.png' "
  "alt='您的账户存在异常登录，账户将于24小时后停用，请立即点击 https://club-safe-verify.example.vip/a 完成验证恢复'></p>"
  "<p>祝使用愉快。</p></body></html>",
  "malicious", "visual_lure", ["img_alt_carries_lure"], "诱导文案全在 img alt")

E("mal_0229_decoy_links.eml",
  H("IT 服务台", "helpdesk@corp-it-relay.example", "staff@corp.internal", "Wi-Fi 证书更新通知"),
  "<html><body><p>企业 Wi-Fi 根证书更新，请从以下任一入口更新：</p>"
  "<ul><li><a href='https://portal.corp.internal/it/wifi'>门户-IT 服务台</a></li>"
  "<li><a href='https://it-wiki.corp.internal/wifi2026'>知识库指引</a></li>"
  "<li><a href='https://wifi-cert-update.example.info/install'>快捷更新通道（推荐）</a></li></ul>"
  "<p>更新后无需重启。</p></body></html>",
  "malicious", "link_obfuscation", ["decoy_legit_links"], "两条真内网链接当掩护")

E("mal_0230_outlook_table_phish.eml",
  H("企业邮箱", "postmaster@mail-expire.example", "staff@corp.internal", "邮箱升级通知"),
  "<html><body><table cellpadding=8 style='border-collapse:collapse;font-family:sans-serif'>"
  "<tr><td colspan=2 style='background:#0072c6;color:#fff'>企业邮箱系统升级</td></tr>"
  "<tr><td>升级对象</td><td>全体员工</td></tr>"
  "<tr><td>截止时间</td><td>本周五 18:00</td></tr>"
  "<tr><td>未升级影响</td><td>停止收发</td></tr>"
  "<tr><td colspan=2><a href='https://mail-upgrade-portal.example.org/step1' "
  "style='background:#0072c6;color:#fff;padding:8px 20px;text-decoration:none'>开始升级</a></td></tr>"
  "</table></body></html>",
  "malicious", "account_phishing", ["html_outlook_style_table"], "Outlook 蓝表格风格")

E("mal_0231_countdown_urgency.eml",
  H("限时活动", "flash@mall-sec.example", "me@personal.example", "余额宝体验金 8 元今日过期"),
  "<html><body style='text-align:center'>"
  "<div style='font-size:28px;color:#d00'>仅剩 <span>05:59:12</span></div>"
  "<p>您的 8 元体验金即将过期，激活后可提现：</p>"
  "<a href='https://mall-activate-cash.example.vip/tiyan' style='color:#fff;background:#ff6700;"
  "padding:12px 40px;text-decoration:none;font-size:16px'>立即提现</a>"
  "</body></html>",
  "malicious", "account_phishing", ["html_countdown"], "倒计时紧迫样式")

E("mal_0232_docusign_fake.eml",
  H("DocuSign", "dse@docusign-envelope.example", "legal@corp.internal", "Completed: Sales Agreement - Please Review"),
  "<html><body style='font-family:sans-serif'>"
  "<p><b>李伟</b> has sent you a document to review and sign:</p>"
  "<p style='border-left:3px solid #999;padding-left:12px'>Sales Agreement 2026-Q4.pdf</p>"
  "<a href='https://docusign-review-doc.example.co/envelope/8f2a' "
  "style='background:#ffc72c;color:#000;padding:10px 28px;text-decoration:none'>REVIEW DOCUMENT</a>"
  "<p style='font-size:11px;color:#888'>You are receiving this because you are a DocuSign recipient.</p>"
  "</body></html>",
  "malicious", "credential_harvest", ["html_docusign_spoof"], "DocuSign 仿冒", "en")

E("mal_0233_dropbox_fake.eml",
  H("Dropbox", "no-reply@dropbox-share.example", "team@corp.internal", "王芳 shared \"Q4财务模型.xlsx\" with you"),
  "<html><body>"
  "<p><b>王芳</b> shared a file with you:</p>"
  "<p>📊 Q4财务模型.xlsx (2.4 MB)</p>"
  "<a href='https://dropbox-file-get.example.info/sh/q4model' "
  "style='background:#0061ff;color:#fff;padding:10px 30px;text-decoration:none'>Open</a>"
  "</body></html>",
  "malicious", "account_phishing", ["html_dropbox_spoof"], "网盘分享仿冒（内鬼话术）")

E("mal_0234_voicemail_fake.eml",
  H("Skype", "noreply@skype-voicemail.example", "staff@corp.internal", "New Voicemail from HR (0:42)"),
  "<html><body><p>You have 1 new voicemail:</p>"
  "<p><b>From:</b> HR &nbsp; <b>Duration:</b> 0:42</p>"
  "<a href='https://skype-vm-play.example.net/play?id=8842' "
  "style='background:#00aff0;color:#fff;padding:8px 22px;text-decoration:none'>▶ Play</a>"
  "</body></html>",
  "malicious", "credential_harvest", ["html_voicemail_lure"], "语音信箱仿冒", "en")

E("mal_0235_pwd_expiry_banner.eml",
  H("账号中心", "admin@acct-pwd.example", "staff@corp.internal", "密码过期警示（剩余 6 小时）"),
  "<html><body><div style='border:2px solid #e00;background:#fff0f0;padding:12px'>"
  "<b style='color:#e00'>⚠ 您的密码将在 6 小时后过期</b>"
  "<p>过期后所有关联系统（邮箱/VPN/OA）将同时锁定。</p>"
  "<a href='https://pwd-extend-now.example.org/ext' style='color:#0066cc'>立即续期密码 &rarr;</a>"
  "</div></body></html>",
  "malicious", "account_phishing", ["html_alert_banner"], "警示横幅样式")

E("mal_0236_qr_html.eml",
  H("微信支付", "pay@wxpay-notify.example", "me@personal.example", "收款码异常停用通知"),
  "<html><body><p>您的商户收款码因风控停用，扫码申诉恢复：</p>"
  "<p><img src='https://wxpay-appeal-cdn.example/q.png' alt='申诉二维码' width='180'></p>"
  "<p style='font-size:12px;color:#999'>微信支付 官方通知</p></body></html>",
  "malicious", "quishing", ["html_qr_appeal"], "收款码申诉扫码")

E("mal_0237_bilingual_split.eml",
  H("IT Center", "it@corp-bilingual.example", "staff@corp.internal", "Password Sync Required / 密码同步通知"),
  "<html><body><p>Your AD password is out of sync.</p>"
  "<p>您的域密码与邮箱密码不一致，将影响移动端登录。</p>"
  "<p><a href='https://ad-pwdsync-fix.example.info/sync'>Sync Now / 立即同步</a></p>"
  "</body></html>",
  "malicious", "account_phishing", ["html_bilingual"], "中英双语混合")

E("mal_0238_unicode_linktext.eml",
  H("网银", "ebank@bank-secure.example", "me@personal.example", "账户核实通知"),
  "<html><body><p>请点击下方官网链接完成账户核实：</p>"
  "<a href='https://ebank-verify-gate.example.vip/chk'>https://ebank.βαnk‑example.com</a>"
  "<p>（请认准官网地址）</p></body></html>",
  "malicious", "link_obfuscation", ["unicode_display_url"], "显示 URL 用希腊字母伪装")

E("mal_0239_survey_gift.eml",
  H("客户之声", "survey@svc-voice.example", "me@personal.example", "邀请您参与满意度调研（完成送 20 元话费）"),
  "<html><body><p>耽误您 1 分钟，完成即充 20 元话费：</p>"
  "<a href='https://voice-reward-claim.example.info/s' style='color:#fff;background:#52c41a;"
  "padding:10px 26px;text-decoration:none'>开始问卷</a>"
  "<p style='font-size:12px;color:#999'>话费 24h 内到账</p></body></html>",
  "malicious", "pii_harvest", ["survey_reward_collect"], "问卷送礼收手机号")

E("mal_0240_meeting_hijack.eml",
  H("日程助手", "cal@meet-invite2.example", "leaders@corp.internal", "董事会特别会议（今日 16:00）"),
  "<html><body><p><b>特别董事会</b> 今日 16:00 讨论组织调整，请提前进入会议室：</p>"
  "<a href='https://board-room-enter.example.ru/join' style='color:#fff;background:#722ed1;"
  "padding:10px 30px;text-decoration:none'>进入会议室</a>"
  "<p style='font-size:12px'>建议提前 5 分钟测试音频。</p></body></html>",
  "malicious", "account_phishing", ["html_meeting_room_lure"], "高管日程仿冒")

E("ham_0221_newsletter_full.eml",
  H("企业内刊", "newsletter@corp.example", "all-staff@corp.internal", "内刊 2026年9月：中秋专场"),
  "<html><body style='font-family:sans-serif'>"
  "<div style='background:#1a3c6e;color:#fff;padding:14px'>企业内刊 · 中秋专场</div>"
  "<h3>中秋游园会</h3><p>报名通道开启，含亲子区。</p>"
  "<h3>食堂二期</h3><p>粤式档口开业，烧腊 8 折首周。</p>"
  "<h3>班车</h3><p>3 号线加密班次表已更新。</p>"
  "<p><a href='https://portal.corp.internal/newsletter/2026-09' style='color:#1a3c6e'>阅读全文</a> | "
  "<a href='https://portal.corp.internal/newsletter/unsub' style='color:#888'>退订</a></p>"
  "</body></html>",
  "benign", "ham_business", ["html_newsletter_internal"], "真内刊 HTML")

E("ham_0222_order_confirm.eml",
  H("京东", "orders@jd.example", "me@personal.example", "订单已发货：图书 x2"),
  "<html><body><p>您的订单 <b>3022-8841</b> 已由京东快递揽收。</p>"
  "<p>预计 9/9 送达。<a href='https://order.jd.example/detail/3022-8841' style='color:#e3101e'>查看订单</a></p>"
  "<p style='font-size:12px;color:#999'>本邮件由系统发送，请勿回复；京东不会以任何形式索要密码。</p>"
  "</body></html>",
  "benign", "ham_business", ["html_order_real"], "真电商发货通知")

E("ham_0223_github_notify.eml",
  H("GitHub", "notifications@github.example", "dev@corp.internal", "[vigilyx] Review requested on #529"),
  "<html><body><p><b>zhangmin</b> requested your review on:</p>"
  "<p>gateway: tiered timeout fallback (#529)</p>"
  "<p><a href='https://github.example/vigilyx/gateway/pull/529' style='color:#0969da'>View it on GitHub</a></p>"
  "<hr><p style='font-size:11px;color:#888'>You're receiving this because you are a CODEOWNER.</p>"
  "</body></html>",
  "benign", "ham_business", ["html_github_real"], "", "en")

E("ham_0224_webinar_invite.eml",
  H("技术委员会", "tc@corp.internal", "dev@corp.internal", "线上分享：网关可观测性（周四 20:00）"),
  "<html><body><p>内部分享：网关可观测性实践。</p>"
  "<p>时间：周四 20:00 · 讲者：小蔺</p>"
  "<a href='https://meet.corp.internal/j/obs-talk' style='color:#fff;background:#2f6fed;"
  "padding:10px 28px;text-decoration:none'>加入会议</a>"
  "<p style='font-size:12px;color:#888'>回放会后入知识库。</p></body></html>",
  "benign", "ham_business", ["html_webinar_internal"], "内网会议按钮")

E("ham_0225_pwd_reset_real.eml",
  H("账号中心", "no-reply@accounts.svc.example", "me@personal.example", "重置密码请求（本人操作确认）"),
  "<html><body><p>我们收到了您的密码重置请求。</p>"
  "<p><a href='https://accounts.svc.example/reset/rt_7f3b9c' style='color:#fff;background:#333;"
  "padding:10px 28px;text-decoration:none'>重置密码</a></p>"
  "<p style='font-size:12px;color:#888'>链接 30 分钟内有效，仅可使用一次。若非本人操作请忽略并尽快改密。</p>"
  "</body></html>",
  "benign", "ham_business", ["html_reset_real_requested"], "用户本人触发的真重置（时效+一次性声明）")

E("ham_0226_ship_update.eml",
  H("顺丰速运", "sf-notice@sf.example", "me@personal.example", "快件已到达杭州转运中心"),
  "<html><body><p>运单 <b>SF1398xxxx8841</b> 当前状态：到达杭州转运中心。</p>"
  "<p>全程时效承诺不变。<a href='https://www.sf-example.com/track/SF1398' style='color:#dc1e32'>跟踪快件</a></p>"
  "</body></html>",
  "benign", "ham_personal", ["html_ship_real"], "")

E("ham_0227_event_reg.eml",
  H("活动行", "service@huodong.example", "me@personal.example", "报名成功：Rust 杭州线下 Meetup"),
  "<html><body><p>报名成功！Rust Meetup · 9/20 14:00 · 西湖区某园区。</p>"
  "<p>凭二维码入场：<img src='https://cdn.huodong.example/ticket/q_8841.png' alt='入场二维码' width='120'></p>"
  "<p style='font-size:12px'>二维码当日有效，勿转发。</p></body></html>",
  "benign", "ham_business", ["html_event_qr_real"], "真活动票二维码")

E("ham_0228_receipt_html.eml",
  H("App Store", "no_reply@email.apple.example", "me@personal.example", "您的收据来自 Apple"),
  "<html><body><p>文档编号：1998xxxx88。App Store 购买项目：</p>"
  "<table cellpadding=6 style='border-collapse:collapse'>"
  "<tr><td>TestFlight（Beta）</td><td>免费</td></tr></table>"
  "<p><a href='https://apps.apple.example/receipts' style='color:#06c'>查看收据</a></p>"
  "<p style='font-size:11px'>如非本人购买，请在设备上查看购买记录。</p></body></html>",
  "benign", "ham_business", ["html_apple_receipt_real"], "", "en")

E("ham_0229_saas_digest.eml",
  H("Figma", "notify@figma.example", "design@corp.internal", "Your weekly Figma digest"),
  "<html><body><p>This week in your team's files:</p>"
  "<ul><li>12 new comments</li><li>3 files updated</li><li>珂珂 mentioned you twice</li></ul>"
  "<a href='https://figma.example/digest/w36' style='color:#0fa958'>Open digest</a></body></html>",
  "benign", "ham_business", ["html_saas_digest"], "", "en")

E("ham_0230_docs_comment.eml",
  H("腾讯文档", "notify@docs.example", "team@corp.internal", "「灰度发布手册 v2」有 3 条新评论"),
  "<html><body><p>文档更新提醒：</p>"
  "<ul><li>王芳：第 3 步阈值建议改百分比</li><li>李伟：mac 路径需调整</li></ul>"
  "<a href='https://docs.example/d/gray-release-v2' style='color:#1e6fff'>查看文档</a></body></html>",
  "benign", "ham_business", ["html_docs_comment_real"], "")

E("ham_0231_flight_checkin.eml",
  H("中国国航", "checkin@air-china.example", "me@personal.example", "您的 CA1858 可办理值机"),
  "<html><body><p>CA1858 杭州-北京 9/12 08:15，现已开放值机。</p>"
  "<a href='https://www.air-china-example.com/checkin/CA1858' style='color:#e10c19'>在线值机</a>"
  "<p style='font-size:12px'>值机不收费；任何索取费用的'值机服务'均为假冒。</p></body></html>",
  "benign", "ham_personal", ["html_checkin_real"], "真值机+反诈声明")

E("ham_0232_subscription_notice.eml",
  H("云音乐", "service@music.example", "me@personal.example", "您的黑胶会员还有 7 天到期"),
  "<html><body><p>会员权益到期后将恢复免费模式，已下载歌曲保留。</p>"
  "<a href='https://music.example/vip/renew' style='color:#fff;background:#c20c0c;"
  "padding:10px 28px;text-decoration:none'>续费</a> &nbsp;"
  "<a href='https://music.example/vip/cancel' style='color:#888'>取消自动续费</a></body></html>",
  "benign", "ham_personal", ["html_subscription_real"], "真订阅通知（含取消入口）")

E("ham_0233_meeting_bot.eml",
  H("日程机器人", "calendar-bot@corp.internal", "team@corp.internal", "Reminder: 网关周会 15 分钟后开始"),
  "<html><body><p>⏰ 网关周会将于 15 分钟后开始（3F-301 + 线上）。</p>"
  "<a href='https://meet.corp.internal/j/gw-weekly' style='color:#fff;background:#00897b;"
  "padding:8px 22px;text-decoration:none'>加入</a></body></html>",
  "benign", "ham_business", ["html_meeting_reminder"], "")

E("ham_0234_forum_notify.eml",
  H("V2EX", "notify@v2ex.example", "me@personal.example", "您收藏的节点有新热帖"),
  "<html><body><p>「程序员」节点新热帖：</p>"
  "<p><a href='https://v2ex-example.com/t/1093841'>如何看待网关超时回退的分级设计</a></p>"
  "<p style='font-size:12px'>来自您的收藏节点订阅。</p></body></html>",
  "benign", "ham_personal", ["html_forum_real"], "")

E("ham_0235_estatement.eml",
  H("招商银行", "estatement@cmb.example", "me@personal.example", "您的8月电子账单已生成"),
  "<html><body><div style='background:#c7000b;color:#fff;padding:10px'>招商银行</div>"
  "<p>您尾号 6688 的信用卡 8 月账单已生成，应还 ¥2,140.55。</p>"
  "<p>请登录手机银行或官网查询，<b>本邮件不含链接</b>；我行不会索要卡号有效期与 CVV。</p>"
  "</body></html>",
  "benign", "ham_personal", ["html_bank_nolink_real"], "真银行 HTML 但主动声明无链接")

E("ham_0236_survey_real.eml",
  H("客户之声", "survey@svc.example", "me@personal.example", "邀请评价您本次的维修服务"),
  "<html><body><p>您 9/2 的空调维修已完成，愿意花 30 秒评价吗？</p>"
  "<a href='https://survey.svc.example/f/wb8842' style='color:#1677ff'>开始评价</a>"
  "<p style='font-size:12px'>仅用于服务改进，无任何奖励诱导。</p></body></html>",
  "benign", "ham_personal", ["html_survey_real"], "真问卷（无奖励诱导）")

E("ham_0237_team_update.eml",
  H("组织发展", "od@corp.internal", "all-staff@corp.internal", "平台工程组晋升公示"),
  "<html><body><p>三季度晋升公示（9/6-9/12）：</p>"
  "<table cellpadding=6 style='border-collapse:collapse'>"
  "<tr><td>蔺柯</td><td>高级工程师</td></tr><tr><td>陈曦</td><td>资深工程师</td></tr></table>"
  "<p>异议期邮箱 od@corp.internal。</p></body></html>",
  "benign", "ham_business", ["html_promotion_public"], "")

E("ham_0238_changelog.eml",
  H("发布组", "release@corp.internal", "dev@corp.internal", "网关 1.9.5 变更摘要"),
  "<html><body><ul><li>超时回退分级（#529）</li><li>修复内存泄漏 3 处（#531）</li>"
  "<li>熔断阈值可配（#533）</li></ul>"
  "<a href='https://portal.corp.internal/wiki/changelog/gw-1.9.5' style='color:#1a3c6e'>完整变更</a></body></html>",
  "benign", "ham_business", ["html_changelog"], "")

E("ham_0239_feedback_req.eml",
  H("员工体验", "survey@corp.internal", "staff@corp.internal", "内推流程体验反馈（3 题）"),
  "<html><body><p>最近用过内推系统吗？3 道题帮我们改进：</p>"
  "<a href='https://portal.corp.internal/survey/referral' style='color:#1677ff'>去填写</a>"
  "<p style='font-size:12px'>匿名，2 分钟。</p></body></html>",
  "benign", "ham_business", ["html_feedback_internal"], "")

E("ham_0240_alumni_news.eml",
  H("校友会", "xyh@univ.example", "alumni@mail.example", "校友通讯：秋季刊"),
  "<html><body><h3>秋季刊目录</h3><ul><li>院系动态</li><li>基金会年报</li><li>返校日安排</li></ul>"
  "<a href='https://xyh.univ-example.edu.cn/2026-autumn' style='color:#8b1a1a'>阅读全文</a></body></html>",
  "benign", "ham_personal", ["html_alumni_real"], "")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch14 written: {len(LABELS)} samples")
