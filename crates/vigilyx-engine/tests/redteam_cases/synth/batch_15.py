#!/usr/bin/env python3
"""Batch 15: advanced HTML threat techniques + transactional HTML ham."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def H(disp, frm, to, subj):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Mon, 07 Sep 2026 09:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b15@synth.example>\r\n"
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\n"
            "Content-Type: text/html; charset=utf-8\r\n\r\n")
def E(n, hdr, body, label, family, tech, note="", lang="zh"):
    W(n, (hdr + "\r\n" + body).encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 15,
        "format": "html", "note": note})

E("mal_0241_css_offscreen.eml",
  H("招聘平台", "hr@job-mail.example", "me@personal.example", "新职位匹配：高级后端（薪资面议）"),
  "<html><body><p>有 3 个新职位与您匹配，点击查看。</p>"
  "<div style='position:absolute;left:-9999px'>您的账号存在风险，请登录 https://job-sec-fix.example.vip/r 完成安全验证，否则简历将被隐藏</div>"
  "<p><a href='https://job-mail.example/jobs/match'>查看职位</a></p></body></html>",
  "malicious", "visual_lure", ["css_offscreen_hidden"], "CSS 移出屏隐藏")

E("mal_0242_tiny_font.eml",
  H("周报助手", "weekly@report-bot.example", "staff@corp.internal", "第37周周报已归档"),
  "<html><body><p>您的周报已自动归档，无需操作。</p>"
  "<p style='font-size:1px;color:#f8f8f8'>您的VPN证书即将过期，请立即更新 https://vpn-cert-now.example.info/renew 否则将无法远程办公</p>"
  "</body></html>",
  "malicious", "visual_lure", ["tiny_font_hidden"], "1px 字号隐藏")

E("mal_0243_table_login_form.eml",
  H("邮箱管理中心", "admin@mail-center.example", "staff@corp.internal", "邮箱容量已满 95%"),
  "<html><body><table cellpadding=10 style='border-collapse:collapse;font-family:sans-serif'>"
  "<tr><td style='background:#4a90d9;color:#fff' colspan=2>邮箱管理中心</td></tr>"
  "<tr><td>当前容量</td><td><div style='background:#eee'><div style='background:#d9534f;width:95%'>&nbsp;</div></div> 95%</td></tr>"
  "<tr><td colspan=2><form action='https://mail-center-expand.example.info/box'>"
  "<input name='email' placeholder='邮箱' style='padding:8px'> "
  "<input type='password' name='pwd' placeholder='密码' style='padding:8px'> "
  "<button style='padding:8px 16px'>一键扩容</button></form></td></tr></table></body></html>",
  "malicious", "credential_harvest", ["table_form_progress"], "进度条+表单组合")

E("mal_0244_iframe_login.eml",
  H("门户", "portal@corp-sso-gw.example", "staff@corp.internal", "门户维护完成，请重新绑定"),
  "<html><body><p>门户维护完成，为同步您的会话请重新绑定：</p>"
  "<iframe src='https://sso-bind-gate.example.org/rebind' width='100%' height='360'></iframe>"
  "</body></html>",
  "malicious", "credential_harvest", ["iframe_login_embed"], "iframe 内嵌假登录")

E("mal_0245_display_mismatch.eml",
  H("云文档", "doc@corp-share-gw.example", "team@corp.internal", "张敏分享了《季度OKR》给您"),
  "<html><body><p><b>张敏</b> 向您分享了文档。</p>"
  "<p><a href='https://share-doc-relay.example.net/v/okr-q4' style='color:#1a0dab'>https://docs.corp.internal/okr-q4</a></p>"
  "<p style='font-size:12px'>若无法打开请复制链接到浏览器。</p></body></html>",
  "malicious", "link_obfuscation", ["href_text_mismatch_html"], "显示内网链接实跳外部")

E("mal_0246_datauri_qr.eml",
  H("入职助手", "onboard@hr-saas2.example", "newhire@corp.internal", "入职材料提交（扫码进入）"),
  "<html><body><p>请扫码进入材料提交通道（需人脸核身）：</p>"
  "<p><img alt='入职通道二维码' width='170'></p>"
  "<p style='font-size:12px'>通道 24 小时有效。</p></body></html>",
  "malicious", "quishing", ["html_qr_placeholder_onboard"], "扫码收人脸")

E("mal_0247_fake_captcha.eml",
  H("安全验证", "robot@captcha-gate.example", "me@personal.example", "请完成人机验证以继续收件"),
  "<html><body style='text-align:center'><h3>安全验证</h3>"
  "<p>检测到异常流量，请完成验证：</p>"
  "<div style='border:1px solid #ccc;padding:16px;display:inline-block'>"
  "<form action='https://captcha-pass-gate.example.vip/v'>"
  "<input name='acct' placeholder='账号'> <input type='password' name='pwd' placeholder='密码'><br><br>"
  "<label><input type='checkbox' checked> 我不是机器人</label> "
  "<button>验证</button></form></div></body></html>",
  "malicious", "credential_harvest", ["fake_captcha_form"], "假人机验证收账密")

E("mal_0248_emoji_brand.eml",
  H("支付宝", "service@alipay-notify2.example", "me@personal.example", "账户存在异常登录风险"),
  "<html><body><p>💙 支付宝</p><p>检测到您的账户在陌生设备登录。</p>"
  "<p><a href='https://alipay-safe-check2.example.co/r' style='color:#1677ff'>立即核实 &gt;</a></p>"
  "<p style='font-size:11px'>© 支付宝 · 本邮件由系统发出</p></body></html>",
  "malicious", "account_phishing", ["emoji_brand_header"], "emoji 当品牌 logo")

E("mal_0249_fake_encrypted.eml",
  H("保密邮件", "secure@encrypt-mail.example", "legal@corp.internal", "您收到一封加密邮件（1 封）"),
  "<html><body><p>外部发来一封加密邮件，使用您的 <b>企业邮箱密码</b> 解密阅读：</p>"
  "<p><a href='https://enc-mail-read.example.info/open' style='background:#333;color:#fff;"
  "padding:10px 26px;text-decoration:none'>🔐 阅读加密邮件</a></p>"
  "<p style='font-size:12px'>邮件将在 7 天后销毁。</p></body></html>",
  "malicious", "credential_harvest", ["encrypted_mail_lure"], "假加密邮件收密码")

E("mal_0250_gdpr_footer.eml",
  H("Privacy Team", "privacy@rights-req.example", "me@personal.example", "Data subject request - action needed"),
  "<html><body><p>Under applicable data regulations you must confirm your identity to retain your account.</p>"
  "<p><a href='https://rights-confirm.example.org/v' style='background:#0057d8;color:#fff;padding:10px 26px;"
  "text-decoration:none'>Confirm identity</a></p>"
  "<p style='font-size:11px;color:#888'>You received this because you have an account. Unsubscribe | Terms | Privacy</p>"
  "</body></html>",
  "malicious", "account_phishing", ["fake_gdpr_footer"], "合规话术+规范页脚伪装", "en")

E("mal_0251_menu_multilink.eml",
  H("员工服务门户", "svc@portal-relay2.example", "staff@corp.internal", "门户功能导航更新"),
  "<html><body><p>门户导航更新，常用入口：</p>"
  "<p><a href='https://portal.corp.internal/it'>IT 服务</a> | "
  "<a href='https://portal.corp.internal/hr'>HR</a> | "
  "<a href='https://portal.corp.internal/fin'>财务</a> | "
  "<a href='https://portal-relay2.example.info/sso'>统一登录（新）</a></p>"
  "</body></html>",
  "malicious", "link_obfuscation", ["menu_real_plus_fake"], "三个真链接夹一个假")

E("mal_0252_entity_text.eml",
  H("账户安全", "sec@acct-safe2.example", "me@personal.example", "您的账户已被限制"),
  "<html><body><p>您的&#36134&#25143&#23384&#22312&#24322&#24120&#30331&#24405，请立即&#39564&#35777。</p>"
  "<p><a href='https://acct-verify2.example.vip/u'>验证入口</a></p></body></html>",
  "malicious", "account_phishing", ["numeric_entity_text"], "实体编码正文（浏览器解码显示）")

E("mal_0253_otp_form.eml",
  H("双因素认证", "otp@mfa-gate2.example", "staff@corp.internal", "MFA 验证码过期，请重新绑定"),
  "<html><body><p>您的 MFA 验证码多次失效，需重新绑定令牌：</p>"
  "<form action='https://mfa-rebind2.example.net/b'>"
  "<input name='acct' placeholder='域账号'> "
  "<input name='pwd' type='password' placeholder='密码'> "
  "<input name='otp' placeholder='当前 6 位验证码'> "
  "<button>重新绑定</button></form></body></html>",
  "malicious", "credential_harvest", ["otp_rebind_form"], "密码+OTP 一锅端")

E("mal_0254_ics_inline_html.eml",
  H("会议系统", "meet@boardroom2.example", "leaders@corp.internal", "预算会议改期：9/10 14:00"),
  "<html><body><p>预算会议改期至 9/10 14:00，请更新日历：</p>"
  "<p><a href='https://meet-cal-add2.example.ru/invite.ics' style='background:#722ed1;color:#fff;"
  "padding:10px 28px;text-decoration:none'>添加到日历</a></p></body></html>",
  "malicious", "redirect_attachment", ["ics_html_button"], "日历按钮走外部 ics")

E("mal_0255_escrow_table.eml",
  H("资金托管", "escrow@trade-secure.example", "trade@corp.internal", "买方款项已入托管，请确认收款账户"),
  "<html><body><p>买方货款 86,400 元已入托管，确认后 T+1 放款：</p>"
  "<table cellpadding=8 style='border:1px solid #ccc;border-collapse:collapse'>"
  "<tr><td>收款户名</td><td><input name='acct-name' value='杭州某科技有限公司'></td></tr>"
  "<tr><td>收款账号</td><td><input name='acct-no' placeholder='对公账号'></td></tr>"
  "<tr><td>开户行</td><td><input name='bank' placeholder='开户行'></td></tr></table>"
  "<p><a href='https://escrow-confirm2.example.info/ok' style='color:#fff;background:#52c41a;"
  "padding:10px 30px;text-decoration:none'>确认放款账户</a></p></body></html>",
  "malicious", "bec", ["fake_escrow_table"], "假托管改收款账户")

E("mal_0256_prefilled_form.eml",
  H("行政", "admin@corp-relay3.example", "wei.hua@corp.internal", "工牌补办申请（已预填）"),
  "<html><body><p>补办信息已预填，确认提交：</p>"
  "<form action='https://badge-confirm3.example.org/s'>"
  "<input name='emp' value='wei.hua@corp.internal' readonly> "
  "<input name='pwd' type='password' placeholder='域密码确认身份'> "
  "<button>提交</button></form></body></html>",
  "malicious", "credential_harvest", ["prefilled_targeted_form"], "预填收件人增强可信度")

E("mal_0257_unsub_trap.eml",
  H("会员俱乐部", "club@svc-mailer2.example", "me@personal.example", "感谢您的订阅（本期）"),
  "<html><body><p>本期会员刊：新品 5 折、积分翻倍。</p>"
  "<p style='font-size:11px'>不想再收到？<a href='https://club-unsub-now.example.vip/off'>一键退订</a> | "
  "<a href='https://club-mailer2.example/p'>偏好设置</a></p></body></html>",
  "malicious", "account_phishing", ["unsubscribe_trap"], "退订链接即钓鱼入口")

E("mal_0258_spaced_text.eml",
  H("客服中心", "cs@svc-center3.example", "me@personal.example", "订单退款已受理"),
  "<html><body><p style='letter-spacing:2px'>您的 订 单 退 款 已 受 理 ，请 点 击 确 认。</p>"
  "<p><a href='https://refund-ok3.example.info/c'>确 认 退 款</a></p></body></html>",
  "malicious", "account_phishing", ["letter_spaced_html"], "字间空格混淆")

E("mal_0259_reply_harvest_card.eml",
  H("中大奖通知", "prize@act-mailer4.example", "me@personal.example", "恭喜！您已获得扫地机器人一台"),
  "<html><body><div style='max-width:420px;border:1px solid #ffd700;border-radius:8px;padding:20px;text-align:center'>"
  "<p style='font-size:20px'>🎉 恭 喜 中 奖 🎉</p><p>奖品：扫地机器人 x1</p>"
  "<p style='font-size:13px'>领取方式：<b>回复本邮件</b>，附姓名+电话+详细地址+身份证照片</p>"
  "<p style='font-size:11px'>7 日内有效，逾期视为放弃</p></div></body></html>",
  "malicious", "pii_harvest", ["reply_harvest_card"], "中奖卡片回收式")

E("mal_0260_fake_doc_comment.eml",
  H("文档协作", "comment@doc-svc4.example", "pm@corp.internal", "3 位同事评论了《需求规格 v3》"),
  "<html><body><p><b>苏黎、王芳、李伟</b> 评论了文档：</p>"
  "<ul><li>苏黎：验收口径第 2 条…</li><li>王芳：接口示例…</li></ul>"
  "<p><a href='https://doc-reply4.example.net/d/r3' style='color:#1677ff'>查看并回复</a></p></body></html>",
  "malicious", "account_phishing", ["fake_doc_comment"], "假协作文档评论")

E("ham_0241_azure_bill.eml",
  H("Microsoft Azure", "azure-noreply@microsoft.example", "ops@corp.internal", "Your invoice is ready (09-2026)"),
  "<html><body><p>Your Azure invoice for September is ready.</p>"
  "<p><a href='https://portal.azure.example/#blade/invoice' style='color:#0067b8'>View in portal</a></p>"
  "<p style='font-size:11px'>You are receiving this because you are the account owner.</p></body></html>",
  "benign", "ham_business", ["azure_bill_real"], "", "en")

E("ham_0242_le_cert.eml",
  H("Let's Encrypt", "noreply@letsencrypt.example", "webmaster@corp.internal", "Certificate expiration notice"),
  "<html><body><p>Your certificate (portal.corp.internal) expires in 20 days.</p>"
  "<p>Renewal is automatic; no action is needed if ACME is healthy.</p>"
  "<p style='font-size:11px'>Expiry: 2026-09-27 | Series: prod-88</p></body></html>",
  "benign", "ham_business", ["le_cert_real"], "真到期通知（自动续期声明）", "en")

E("ham_0243_reschedule.eml",
  H("日程机器人", "cal-bot@corp.internal", "team@corp.internal", "变更：网关评审 → 周四 15:00"),
  "<html><body><p>架构评审改期 <b>周四 15:00</b>，地点不变。</p>"
  "<p><a href='https://meet.corp.internal/j/arch-review' style='color:#00897b'>更新会议链接</a></p>"
  "<p style='font-size:12px'>日历已自动同步。</p></body></html>",
  "benign", "ham_business", ["reschedule_real"], "")

E("ham_0244_club_signup2.eml",
  H("工会", "union@corp.internal", "staff@corp.internal", "中秋游园会报名开启"),
  "<html><body><p>游园会 9/24 14:00 南草坪，含亲子区与汉服打卡。</p>"
  "<a href='https://portal.corp.internal/union/park2026' style='color:#fff;background:#c7000b;"
  "padding:10px 30px;text-decoration:none'>报名</a>"
  "<p style='font-size:12px'>家属同报，截止 9/20。</p></body></html>",
  "benign", "ham_business", ["club_signup_html_real"], "")

E("ham_0245_food_order.eml",
  H("饿了么", "order@eleme.example", "me@personal.example", "订单已送达：轻食沙拉"),
  "<html><body><p>您的订单已送达，祝用餐愉快。</p>"
  "<a href='https://h5.eleme-example.com/order/8842' style='color:#0097ff'>评价本单</a></body></html>",
  "benign", "ham_personal", ["food_order_real"], "")

E("ham_0246_bank_alert_nolink.eml",
  H("建设银行", "messages@ccb.example", "me@personal.example", "您尾号6688的账户完成一笔交易"),
  "<html><body><p>您尾号 6688 的账户于 12:03 完成一笔消费 36.00 元（某某便利）。</p>"
  "<p style='font-size:12px'>如非本人交易请致电 95533。本邮件不含链接，我行不会索要验证码。</p>"
  "</body></html>",
  "benign", "ham_personal", ["bank_tx_nolink_real"], "真动账（纯文本无链接）")

E("ham_0247_boarding.eml",
  H("海南航空", "service@hnair.example", "me@personal.example", "值机提醒：HU7802 明日 07:55"),
  "<html><body><p>HU7802 杭州-三亚 明日 07:55，值机已开放。</p>"
  "<a href='https://www.hnair-example.com/checkin' style='color:#c8102e'>在线值机</a>"
  "<p style='font-size:12px'>值机免费，谨防收费值机诈骗。</p></body></html>",
  "benign", "ham_personal", ["boarding_real"], "")

E("ham_0248_hotel_conf.eml",
  H("亚朵", "booking@atour.example", "me@personal.example", "预订确认：杭州西湖店 9/12-9/13"),
  "<html><body><p>订单已确认，到店付 ¥429。</p>"
  "<p><a href='https://www.atour-example.com/order/9917' style='color:#0084ff'>订单详情</a></p>"
  "<p style='font-size:12px'>18:00 后到店请备注。</p></body></html>",
  "benign", "ham_personal", ["hotel_conf_real"], "")

E("ham_0249_kid_course.eml",
  H("少年得到", "svc@shaoniandedao.example", "parent@mail.example", "本周编程课更新：循环的魔法"),
  "<html><body><p>孩子本周的课程已更新，建议观看 20 分钟。</p>"
  "<a href='https://app.shaoniandedao-example.com/lesson/loop' style='color:#ff7a00'>去学习</a>"
  "<p style='font-size:12px'>学习报告每周日推送。</p></body></html>",
  "benign", "ham_personal", ["kid_course_real"], "")

E("ham_0250_report_ready.eml",
  H("浙一互联网医院", "notice@zyhospital.example", "me@personal.example", "您的检验报告已出具"),
  "<html><body><p>血常规报告已出具，请在小程序-我的报告中查看。</p>"
  "<p style='font-size:12px'>报告异常项请以医生解读为准；医院不会电话推销药品。</p></body></html>",
  "benign", "ham_personal", ["report_ready_real"], "")

E("ham_0251_gov_progress.eml",
  H("浙里办", "noreply@zjzwfw.example", "me@personal.example", "您的居住证办理进度更新"),
  "<html><body><p>您的居住证续签已进入制证环节（3/5）。</p>"
  "<a href='https://www.zjzwfw-example.gov.cn/my/progress' style='color:#1677ff'>查看进度</a>"
  "<p style='font-size:12px'>政务服务不收取任何加急费用。</p></body></html>",
  "benign", "ham_personal", ["gov_progress_real"], "")

E("ham_0252_customs_notice.eml",
  H(" EMS国际", "intl@ems.example", "me@personal.example", "国际件清关补税通知"),
  "<html><body><p>您的国际件（EE88xx…）需缴纳行邮税 52 元。</p>"
  "<a href='https://ems-intl-example.com/tax/pay?no=EE8842' style='color:#0f7a3d'>缴税通道</a>"
  "<p style='font-size:12px'>税额以海关文书为准。</p></body></html>",
  "benign", "ham_personal", ["customs_real"], "真清关补税（官方域）")

E("ham_0253_job_push.eml",
  H("BOSS直聘", "push@zhipin.example", "me@personal.example", "有 5 位新老板看过您"),
  "<html><body><p>本周 5 位老板查看了您的简历，其中 2 位发出沟通邀请。</p>"
  "<a href='https://www.zhipin-example.com/chat' style='color:#00beab'>查看邀请</a>"
  "<p style='font-size:12px'>退订 | 意见反馈</p></body></html>",
  "benign", "ham_personal", ["job_push_real"], "")

E("ham_0254_cloud_renew.eml",
  H("百度网盘", "service@pan.example", "me@personal.example", "超级会员还有 3 天到期"),
  "<html><body><p>会员到期后将限速。续费或取消自动续费均可在 App 内操作。</p>"
  "<p style='font-size:12px'>本邮件仅提醒，不含支付链接。</p></body></html>",
  "benign", "ham_personal", ["cloud_renew_nolink_real"], "真提醒（无支付链接版）")

E("ham_0255_blog_rss.eml",
  H("阮一峰周刊", "feed@ruanyifeng.example", "me@personal.example", "科技爱好者周刊第 800 期"),
  "<html><body><h3>周刊 800 期</h3><ul><li>工具：一个轻量网关</li><li>文章：超时设计漫谈</li></ul>"
  "<a href='https://www.ruanyifeng-example.com/blog/weekly/issue800' style='color:#333'>阅读全文</a>"
  "<p style='font-size:12px'>每周五发布 | <a href='https://www.ruanyifeng-example.com/unsub'>退订</a></p>"
  "</body></html>",
  "benign", "ham_personal", ["blog_rss_real"], "")

E("ham_0256_podcast.eml",
  H("小宇宙", "notify@xiaoyuzhou.example", "me@personal.example", "《商业就是这样》更新了"),
  "<html><body><p>EP.214 已更新：快递业的价格战。</p>"
  "<a href='https://xiaoyuzhou-example.com/p/8842' style='color:#1fb6ff'>收听</a></body></html>",
  "benign", "ham_personal", ["podcast_real"], "")

E("ham_0257_volunteer_shift.eml",
  H("社区志愿队", "zhiyuan@community.example", "me@personal.example", "周六旧物改造排班（已排您 14:00）"),
  "<html><body><p>周六活动排班：您在 14:00-16:00 引导组。</p>"
  "<p>如需调整请在群里换班，集合点会所门口。</p></body></html>",
  "benign", "ham_personal", ["volunteer_shift_real"], "")

E("ham_0258_vaccine2.eml",
  H("宠颐生", "svc@petclinic.example", "me@personal.example", "糖豆的第二针到了（9/18 前）"),
  "<html><body><p>猫三联第二针有效期至 9/18，可预约工作日下午。</p>"
  "<a href='https://petclinic-example.com/book/tangdou' style='color:#ff7a45'>预约</a></body></html>",
  "benign", "ham_personal", ["pet_vaccine2_real"], "")

E("ham_0259_etc_bill.eml",
  H("ETC服务", "etc@gszcpay.example", "driver@personal.example", "【ETC】9月通行费月结单"),
  "<html><body><p>9 月通行 18 次，扣费 142.50 元（记账日后结算）。</p>"
  "<p style='font-size:12px'>明细请查 ETC 小程序；扣费异常请走官方客服。</p></body></html>",
  "benign", "ham_personal", ["etc_bill_real"], "")

E("ham_0260_points_monthly.eml",
  H("航司会员", "ffp@airline.example", "me@personal.example", "9月里程月报"),
  "<html><body><p>本月新增 3,240 里程，当前 58,410。里程有效期滚动三年。</p>"
  "<a href='https://ffp.airline-example.com/statement' style='color:#003580'>查看月报</a></body></html>",
  "benign", "ham_personal", ["points_monthly_real"], "")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch15 written: {len(LABELS)} samples")
