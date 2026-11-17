#!/usr/bin/env python3
"""Batch 25: HTML/multiformat lures + transactional ham + closing gray pairs."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def HD(disp, frm, to, subj, extra="", ct="text/plain; charset=utf-8"):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Fri, 18 Sep 2026 09:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b25@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\nContent-Type: {ct}\r\n\r\n")
def E(n, raw, label, family, tech, note="", lang="zh", fmt="plain",
      expected=None, ambiguous=False, borderline=""):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": expected or ("block" if label == "malicious" else "deliver"),
        "engine_status": "not_evaluated", "synthetic": True, "batch": 25,
        "format": fmt, "note": note, "ambiguous": ambiguous, "borderline": borderline})

E("mal_0403_html_darkbtn.eml",
  HD("安全中心", "sec@dark-theme6.example", "me@personal.example", "账户安全提醒（深色版）", "", "text/html; charset=utf-8")
  + "<html><body style='background:#111;color:#eee'><p>检测到异常登录。</p>"
  "<a href='https://dark-sec-check6.example.vip/v' style='color:#0ff'>立即核查</a></body></html>",
  "malicious", "account_phishing", ["html_dark_theme"], "深色主题按钮", "zh", "html")
E("mal_0404_html_table_invoice.eml",
  HD("发票中心", "fp@invoice-html6.example", "finance@corp.internal", "增值税发票预览", "", "text/html; charset=utf-8")
  + "<html><body><table border=1 cellpadding=6><tr><th>品名</th><th>金额</th></tr>"
  "<tr><td>咨询服务</td><td>36,000.00</td></tr></table>"
  "<a href='https://fp-view6.example.info/d'>下载发票联</a></body></html>",
  "malicious", "account_phishing", ["html_table_invoice_button"], "表格发票+下载按钮", "zh", "html")
E("mal_0405_html_autofill.eml",
  HD("行政", "admin@corp-relay26.example", "staff@corp.internal", "个人信息表预填（确认）", "", "text/html; charset=utf-8")
  + "<html><body><form action='https://info-confirm26.example.info/s'>"
  "<input name='name' value='（您的姓名）'><input name='idno' value='（身份证）'>"
  "<input type='password' name='pwd' placeholder='域密码核验'><button>确认提交</button></form></body></html>",
  "malicious", "credential_harvest", ["html_prefill_pii_form"], "预填信息表+域密码", "zh", "html")
E("mal_0406_html_redirect_btn.eml",
  HD("门户", "portal@corp-relay27.example", "staff@corp.internal", "单点登录跳转修复", "", "text/html; charset=utf-8")
  + "<html><body><p>点击下方按钮完成跳转（自动链式跳转 3 次）：</p>"
  "<a href='https://r1-relay27.example.info/x'>重新进入门户</a></body></html>",
  "malicious", "link_obfuscation", ["html_chain_redirect_button"], "链式跳转按钮", "zh", "html")
E("mal_0407_html_imgbtn.eml",
  HD("会员", "vip@club-relay28.example", "me@personal.example", "礼包到账（点击图领取）", "", "text/html; charset=utf-8")
  + "<html><body><p>礼包已到账。</p><a href='https://club-gift28.example.vip/g'><img src='https://cdn-club28.example/btn.png' alt='领取礼包'></a></body></html>",
  "malicious", "account_phishing", ['html_image_button'], "图片按钮", "zh", "html")
E("mal_0408_html_details.eml",
  HD("公告", "gg@notice-relay29.example", "staff@corp.internal", "福利调整说明", "", "text/html; charset=utf-8")
  + "<html><body><details><summary>点击展开详情</summary>"
  "<p>根据最新核对结果，您需完成身份补录：https://gg-bulu29.example.info/f</p>"
  "</details></body></html>",
  "malicious", "account_phishing", ["html_details_fold_lure"], "折叠详情藏链接", "zh", "html")
E("mal_0409_html_sig_link.eml",
  HD("企业服务", "svc@svc-relay30.example", "staff@corp.internal", "服务满意度回访", "", "text/html; charset=utf-8")
  + "<html><body><p>感谢使用本服务。</p>"
  "<p style='font-family:serif'>张经理 | 企业服务热线<br>"
  "<a href='https://sig-svc30.example.info/x' style='color:#888;text-decoration:none'>官网</a></p></body></html>",
  "malicious", "link_obfuscation", ["html_signature_link"], "签名档灰链", "zh", "html")
E("mal_0410_html_footer_micro.eml",
  HD("资讯", "zx@news-relay31.example", "me@personal.example", "今日资讯速览", "", "text/html; charset=utf-8")
  + "<html><body><p>今日十条速览已更新。</p><p style='font-size:11px;color:#bbb'><a href='https://zx-nl31.example.info/x' style='color:#bbb'>退订/管理</a></p></body></html>",
  "malicious", "visual_lure", ['html_footer_micro_link'], "页脚微链", "zh", "html")
E("mal_0411_ko_bank2.eml",
  HD("은행", "sv@kr-bank6.example", "kim@corp.internal",
     "=?utf-8?B?" + base64.b64encode("계좌 서비스 중지 안내".encode()).decode() + "?=")
  + "서비스 유지를 위해 본인 인증이 필요합니다: https://kr-bank-v6.example.co/v\r\n",
  "malicious", "account_phishing", ["ko_bank_verify"], "韩文银行", "ko")
E("mal_0412_ja_kuroneko.eml",
  HD("ヤマト運輸", "info@tky-taqbin6.example", "tanaka@corp.internal",
     "=?utf-8?B?" + base64.b64encode("再配達のお願い".encode()).decode() + "?=")
  + "ご不在のため持ち帰りました。再配達はこちら：https://tky-sai6.example.info/r\r\n",
  "malicious", "account_phishing", ["ja_redelivery"], "日文再配送", "ja")
E("mal_0413_ru_gov.eml",
  HD("Госуслуги", "info@gos-uslugi6.example", "ivanov@corp.internal", "Уведомление")
  + "Для продления регистрации подтвердите данные: https://gos-u6.example.org/p\r\n",
  "malicious", "account_phishing", ["ru_gosuslugi"], "俄政务", "ru")
E("mal_0414_hant_bank2.eml",
  HD("網上銀行", "cs@hk-easybank.example", "ho@corp.internal", "帳戶風控提醒")
  + "您嘅帳戶觸發風控，請即登入核實：https://hk-fk6.example.hk/v\r\n",
  "malicious", "account_phishing", ["hant_bank_risk"], "繁体银行", "zh-hant")
E("mal_0415_yue_express2.eml",
  HD("順豐", "sf@hk-sf6.example", "ho@corp.internal", "包裹待領（3日）")
  + "你嘅包裹喺驿站等緊你，改派或自取：https://hk-sfp6.example.info/g\r\n",
  "malicious", "account_phishing", ["yue_parcel"], "粤语快递", "zh-yue")
E("mal_0416_ar_trade.eml",
  HD("شركة التجارة", "svc@ar-trade6.example", "trade@corp.internal", "تحديث الحساب", "")
  + "تحديث بيانات الحساب: https://ar-v6.example.org/u\r\n",
  "malicious", "account_phishing", ['ar_trade'], "阿文商务", "ar", "plain")
E("mal_0417_de_industrie.eml",
  HD("Industrie Verband", "info@de-verband6.example", "trade@corp.internal", "Zollabfertigung aktualisiert")
  + "Bitte aktualisieren Sie Ihre Zolldaten: https://de-zoll6.example.org/u\r\n",
  "malicious", "account_phishing", ["de_customs"], "德语报关", "de")
E("mal_0418_es_banco.eml",
  HD("Banco", "sv@es-banco6.example", "trade@corp.internal", "Actualización requerida", "")
  + "Actualice su cuenta: https://es-v6.example.org/c\r\n",
  "malicious", "account_phishing", ['es_bank'], "西语银行", "es", "plain")
E("mal_0419_pt_servico.eml",
  HD("Serviço Online", "sv@pt-svc6.example", "trade@corp.internal", "Verificação de conta")
  + "Verifique sua conta: https://pt-v6.example.org/c\r\n",
  "malicious", "account_phishing", ["pt_verify"], "葡语核验", "pt")
E("mal_0420_th_bank2.eml",
  HD("ธนาคาร", "sv@th-bank6.example", "somchai@corp.internal", "แจ้งเตือนบัญชี", "")
  + "ยืนยันบัญชี: https://th-v6.example.co/v\r\n",
  "malicious", "account_phishing", ['th_bank'], "泰语银行", "th", "plain")
E("ham_0364_gdpr_ok.eml",
  HD("隐私服务", "privacy@svc.example", "me@personal.example", "数据删除请求已处理")
  + "请求已处理，30 日内生效。\r\n",
  "benign", "ham_business", ["gdpr_real_done"], "真隐私请求回执")
E("ham_0365_unsub_ok.eml",
  HD("订阅中心", "list@svc.example", "me@personal.example", "退订成功")
  + "已退订周刊类邮件，交易类通知保留。\r\n",
  "benign", "ham_business", ["unsub_real_confirmed"], "真退订确认")
E("ham_0366_double_optin.eml",
  HD("订阅确认", "confirm@svc.example", "me@personal.example", "请确认您的订阅（双确认）")
  + "点击确认订阅（我们采用双重确认制）：https://svc.example/confirm/ab12\r\n"
  "不点击不会订阅。\r\n",
  "benign", "ham_business", ["double_optin_real"], "真双确认（灰区对照的良性半边）")
E("ham_0367_login_alert.eml",
  HD("账号安全", "sec@svc.example", "me@personal.example", "新设备登录提醒")
  + "您的账号刚在新设备登录（Chrome/Windows）。\r\n"
  "如是本人可忽略；修改密码请在官网操作，本邮件无链接。\r\n",
  "benign", "ham_business", ["login_alert_real_nolink"], "真登录提醒（无链接版）")
E("ham_0368_pw_changed.eml",
  HD("账号中心", "no-reply@svc.example", "me@personal.example", "密码修改成功", "")
  + "密码已于 14:20 修改成功。如非本人请立即通过官网找回。\r\n本邮件无链接。\r\n",
  "benign", "ham_business", ['pw_changed_real'], "密码修改成功通知", "zh", "plain")
E("ham_0369_order_shipped2.eml",
  HD("商城", "orders@shop.example", "me@personal.example", "订单已发货（两件）")
  + "空气炸锅与滤芯已发货，分别两个包裹。\r\n",
  "benign", "ham_personal", ["order_real_split"], "")
E("ham_0370_flight_ok2.eml",
  HD("航司", "svc@air.example", "me@personal.example", "值机成功（已选座 32K）", "")
  + "登机牌在 App-行程。\r\n",
  "benign", "ham_personal", ['checkin_real_seat'], "值机成功", "zh", "plain")
E("ham_0371_hotel_pre.eml",
  HD("酒店", "svc@atour.example", "me@personal.example", "入住前提醒（到店付）")
  + "入住 14:00 后，携带身份证原件。\r\n",
  "benign", "ham_personal", ["hotel_real_pre"], "")
E("ham_0372_class_remind.eml",
  HD("少年宫", "svc@children.example", "parent@mail.example", "周六绘画课调课通知")
  + "调至周日 10:00，材料自备画板。\r\n",
  "benign", "ham_personal", ["class_real_reschedule"], "")
E("ham_0373_pet_grooming.eml",
  HD("宠物店", "svc@pet.example", "me@personal.example", "洗护预约确认（周六 14:00）")
  + "糖豆洗澡+修毛，准时到。\r\n",
  "benign", "ham_personal", ["pet_real_booked"], "")
E("ham_0374_car_maint.eml",
  HD("4S店", "svc@auto.example", "driver@personal.example", "保养提醒（1万公里）")
  + "建议预约小保养，工时费门店公示。\r\n",
  "benign", "ham_personal", ["car_real_maint"], "")
E("ham_0375_water_bill.eml",
  HD("水务", "sf@city-water.example", "owner@personal.example", "10月水费账单可查", "")
  + "账单 42.6 元，代扣账户自动扣。\r\n",
  "benign", "ham_personal", ['water_real_bill'], "水费账单", "zh", "plain")
E("ham_0376_gas_check.eml",
  HD("燃气", "rq@city-gas.example", "owner@personal.example", "入户安检预约（下周）")
  + "工作人员穿工装带证件，可拒查并致电 95xxx 核实。\r\n",
  "benign", "ham_personal", ["gas_real_check"], "真安检自带防伪指引")
E("ham_0377_broadband_real2.eml",
  HD("宽带", "kd@telecom.example", "me@personal.example", "合约到期续约提醒")
  + "到期后自动转标准资费，续约营业厅或 App。\r\n",
  "benign", "ham_personal", ["broadband_real_renew"], "")
E("ham_0378_interview_remind2.eml",
  HD("招聘", "hr@corp.internal", "candidate@mail.example", "面试提醒（周三 14:00）")
  + "线上会议链接在日历邀请里（企业域）。\r\n",
  "benign", "ham_business", ["interview_real_calendar"], "")
E("ham_0379_offboard.eml",
  HD("人资", "hr@corp.internal", "leaver@corp.internal", "离职清单进度（3/5）", "")
  + "已完成资产、门禁、邮箱转移；待办：社保、证明。\r\n",
  "benign", "ham_business", ['offboard_real_progress'], "离职清单", "zh", "plain")
E("ham_0380_club_fund2.eml",
  HD("工会", "union@corp.internal", "club@corp.internal", "羽毛球社场地续订成功")
  + "周三档期续到年底。\r\n",
  "benign", "ham_business", ["club_real_renewed"], "")

E("gray_0091_optin_fake.eml",
  HD("订阅确认", "confirm@svc-relay32.example", "me@personal.example", "请确认您的订阅")
  + "点击确认：https://svc-relay32.example/c/xy99\r\n"
  "（不点击将保留订阅并计费）\r\n",
  "malicious", "account_phishing", ["optin_fake_billing_pressure"],
  "假双确认+计费恐吓", "zh", "plain", "block", True,
  "与 ham_0366 同形；真双确认从不说'不点击将计费'")
E("gray_0092_voip_alert_fake.eml",
  HD("语音信箱", "vm@voip-relay33.example", "staff@corp.internal", "未接来电：IT 部门 (0:12)")
  + "在线试听：https://voip-play33.example.info/p\r\n",
  "malicious", "credential_harvest", ["voip_fake_play"],
  "假语音信箱", "zh", "plain", "block", True, "企业语音信箱真件极少经邮件给外链")
E("gray_0093_saas_trial_fake.eml",
  HD("SaaS Billing", "billing@saas-relay34.example", "ops@corp.internal", "Trial ending - card required", "")
  + "Your trial ends in 2 days. Add your card now to keep data:\r\nhttps://saas-relay34.example/card\r\n",
  "malicious", "credential_harvest", ['trial_card_collect'], "试用到期收卡", "en", "plain", "block", True, "同形对照")
E("gray_0094_saas_trial_real.eml",
  HD("SaaS Billing", "billing@saas-vendor.example", "ops@corp.internal", "Trial ending soon")
  + "Add a payment method in the console (existing login):\r\nhttps://console.saas-vendor.example/billing\r\n",
  "benign", "ham_business", ["trial_real_console"],
  "真试用提醒走控制台", "en", "plain", "deliver", True, "与 gray_0093 对照：卡信息只在控制台填")
E("gray_0095_hr_survey_fake.eml",
  HD("人资", "hr@corp-hr-relay35.example", "staff@corp.internal", "匿名调研（福利）")
  + "问卷：https://hr-wj35.example.info/q\r\n（需域账号登录以保证匿名）\r\n",
  "malicious", "credential_harvest", ["survey_domain_login_fake"],
  "假匿名调研收域账号", "zh", "plain", "block", True, "'登录保证匿名'自相矛盾——逻辑破绽")
E("gray_0096_hr_survey_real.eml",
  HD("人资", "hr@corp.internal", "staff@corp.internal", "匿名调研开启（无链接）", "")
  + "问卷下周发内网链接，结果匿名直达第三方平台。\r\n",
  "benign", "ham_business", ['survey_real_internal_no_link'], "真匿名调研", "zh", "plain", "deliver", True, "同形对照")
E("gray_0097_it_survey_real2.eml",
  HD("员工体验", "survey@corp.internal", "all@corp.internal", "IT 服务满意度（匿名）")
  + "门户-调研-IT2026，匿名填写。\r\n",
  "benign", "ham_business", ["itsurvey_real_portal"],
  "真调研走门户", "zh", "plain", "deliver", True, "与 gray_0095 对照")
E("gray_0098_einvoice_fake.eml",
  HD("电子发票", "fp@tax-relay36.example", "me@personal.example", "您的发票可开具（领取专票）", "")
  + "专票领取需补开票信息：https://fp-lq36.example.info/e\r\n（税号+开户行+账号）\r\n",
  "malicious", "pii_harvest", ['einvoice_fake_claim'], "假发票领取", "zh", "plain", "block", True, "同形对照")
E("gray_0099_einvoice_real.eml",
  HD("电子发票", "fp@tax.example", "me@personal.example", "发票已开具（App 查看）")
  + "电子发票在税务 App-票夹查看。\r\n本邮件无链接。\r\n",
  "benign", "ham_personal", ["einvoice_real_app"],
  "真数电票只在 App", "zh", "plain", "deliver", True, "与 gray_0098 对照")
E("gray_0100_wifi_code_fake.eml",
  HD("行政", "admin@corp-relay37.example", "guest@corp.internal", "访客 Wi-Fi 密码（新）")
  + "领取新密码：https://guest-wf37.example.info/p\r\n",
  "malicious", "account_phishing", ["guest_password_fake"],
  "假访客密码", "zh", "plain", "block", True, "真密码当面或短信，不发链接")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch25 written: {len(LABELS)} samples")
