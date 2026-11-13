#!/usr/bin/env python3
"""Batch 3: i18n malicious + hard positives + hard-negative ham, authored individually."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(name, raw): open(os.path.join(ROOT, "synth", name), "wb").write(raw)
def H(disp, frm, to, subj, extra=""):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Wed, 26 Aug 2026 11:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b3@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\n")
P = "Content-Type: text/plain; charset=utf-8\r\n\r\n"
def E(name, raw, label, family, lang, tech, note="", enc="utf-8"):
    W(name, raw if isinstance(raw, bytes) else raw.encode(enc, errors="replace"))
    LABELS.append({"file": f"synth/{name}", "case_id": name[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 3, "note": note})

# ---- malicious: i18n ----
E("mal_0042_ja_stop.eml",
  (H("アカウント管理", "id-manage@example-svc.example", "tanaka@corp.internal",
     "=?iso-2022-jp?B?" + base64.b64encode("アカウント停止のご案内".encode("iso2022_jp")).decode() + "?=")
   + "Content-Type: text/plain; charset=iso-2022-jp\r\n\r\n"
   + "お客様のアカウントに対して不正なログイン試行が確認されました。\r\n"
     "24時間以内に下記より本人確認を行わない場合、アカウントを停止します。\r\n"
     "https://id-manage-verify.example.jp/confirm\r\n"),
  "malicious", "account_phishing", "ja", ["iso2022jp_body"], "", "iso2022_jp")

E("mal_0043_ja_extra_fee.eml",
  (H("利用案内", "guide@mail-svc.example", "sato@corp.internal",
     "=?utf-8?B?" + base64.b64encode("ご利用料金の確認のお願い".encode()).decode() + "?=")
   + P +
   "今月のご利用料金の確認が取れておりません。\r\n"
   "お手数ですが、下記よりご登録情報のご確認をお願いいたします。\r\n"
   "https://fee-confirm.example.jp/step\r\n"),
  "malicious", "account_phishing", "ja", ["ja_fee_confirm"], "")

E("mal_0044_ru_undeclared.eml",
  (H("Служба безопасности", "sec@bank-notice.example", "ivanov@corp.internal", "Notification")
   + "Content-Type: text/plain\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
   + "Обнаружена попытка входа с нового устройства. Подтвердите личность\r\n"
     "в течение 24 часов, иначе доступ будет приостановлен:\r\n"
     "https://sec-confirm.example.ru/login\r\n"),
  "malicious", "account_phishing", "ru", ["undeclared_charset_cp1251"], "", "cp1251")

E("mal_0045_ru_card.eml",
  (H("Банк", "info@bank-card.example", "petrov@corp.internal", "=?utf-8?B?0JrQsNC6INC90LUg0L/Rg9GC?=")
   + "Content-Type: text/plain; charset=windows-1251\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
   + "Уважаемый клиент, ваша карта будет заблокирована. Подтвердите данные:\r\n"
     "http://203.0.113.60/card/confirm\r\n"),
  "malicious", "account_phishing", "ru", ["declared_cp1251_card"], "", "cp1251")

E("mal_0046_vi_lock.eml",
  (H("Bao mat", "sec@vn-notice.example", "nguyen@corp.internal", "Canh bao tai khoan")
   + P +
   "Tài khoản của bạn có hoạt động đăng nhập bất thường và sẽ bị tạm khóa.\r\n"
   "Vui lòng xác minh ngay trong vòng 24 giờ:\r\n"
   "https://vn-verify.example.info/xac-minh\r\n"),
  "malicious", "account_phishing", "vi", ["vi_lock"], "")

E("mal_0047_th_suspend.eml",
  (H("ฝ่ายความปลอดภัย", "sec@th-notice.example", "somchai@corp.internal",
     "=?utf-8?B?" + base64.b64encode("แจ้งเตือนการระงับบัญชี".encode()).decode() + "?=")
   + P +
   "บัญชีของคุณถูกระงับชั่วคราวเนื่องจากกิจกรรมที่น่าสงสัย\r\n"
   "กรุณายืนยันตัวตนภายใน 24 ชั่วโมง: https://th-verify.example.co/confirm\r\n"),
  "malicious", "account_phishing", "th", ["th_suspend"], "")

E("mal_0048_id_disable.eml",
  (H("Tim Keamanan", "sec@id-notice.example", "budi@corp.internal", "Pemberitahuan akun")
   + P +
   "Akun Anda akan dinonaktifkan karena aktivitas login yang mencurigakan.\r\n"
   "Verifikasi sekarang dalam 24 jam: https://id-verify.example.org/cek\r\n"),
  "malicious", "account_phishing", "id", ["id_disable"], "")

E("mal_0049_hant_rare.eml",
  (H("系統管理中心", "admin@sys-hant.example", "chen@corp.internal", "帳戶維護通知")
   + P +
   "您的帳戶已完成年度稽核，尚有兩項資料未補齊，\r\n"
   "請於本週內完成補錄，逾期將暫停匯款與轉賬功能：\r\n"
   "https://sys-hant.example.tw/supplement\r\n"),
  "malicious", "account_phishing", "zh-hant", ["rare_traditional_supplement"], "")

E("mal_0050_yue_bank.eml",
  (H("網上銀行", "cs@hk-bank.example", "ho@corp.internal", "帳戶凍結提示")
   + P +
   "你嘅帳戶因為安全理由已經被凍結，請立即登入做身份確認，\r\n"
   "唔係三個工作日內會被永久停用：https://hk-secure.example.hk/verify\r\n"),
  "malicious", "account_phishing", "zh-yue", ["cantonese_bank"], "")

E("mal_0051_en_paraphrase.eml",
  (H("IT Service", "desk@it-help.example", "murphy@corp.internal", "Quick housekeeping") + P +
   "Hi Murphy,\n\n"
   "During last night's routine check a couple of your workspace entries\n"
   "didn't match our records. Nothing alarming — just re-confirm them at your\n"
   "convenience today so your access doesn't get throttled:\n"
   "https://it-housekeeping.example.net/recheck\n\n"
   "Cheers, the service desk\n"),
  "malicious", "account_phishing", "en", ["paraphrase_low_pressure"], "硬正样本：低压措辞")

# ---- malicious: hard positives (open vectors) ----
E("mal_0052_parcels_claim.eml",
  (H("理赔中心", "claim@express-ops.example", "fei@corp.internal", "包裹破损理赔需本人确认") + P +
   "您的包裹在分拨时外包装破损，理赔需本人确认身份。\r\n"
   "请回复本邮件：姓名+电话+银行卡号（接收赔款），并拍摄手持身份证视频。\r\n"
   "三个工作日内有效。\r\n"),
  "malicious", "pii_harvest", "zh", ["reply_pii_parcel_claim"], "")

E("mal_0053_parcel_hotline.eml",
  (H("派送站", "station@express-notice.example", "fei@corp.internal", "派送异常，请速联系站点") + P +
   "您的地址不详无法派送，今天 18:00 前致电派送员处理，\r\n"
   "逾期包裹退回：幺三九幺七六五幺零三四（微信同号）。\r\n"),
  "malicious", "toad", "zh", ["parcel_yao_phone"], "")

E("mal_0054_subsidy_new.eml",
  (H("政策解读", "policy@note.example", "all@corp.internal", "最新一轮稳岗返还开始申报") + P +
   "符合条件的企业可申领新一轮稳岗返还，线上核对可返金额后提交，\r\n"
   "入口：refund-apply.example.info\r\n"),
  "malicious", "subsidy_fraud", "zh", ["subsidy_paraphrase"], "")

E("mal_0055_wire_tail.eml",
  (H("财务总监", "cfo-office@partner.example", "treasury@corp.internal", "尾款今天必须出去") + P +
   "HS 那笔尾款今天必须出去，账户用对方今早发来的新资料（在各自邮箱），\r\n"
   "走完截图回我。流程单据下周统一补。\r\n"),
  "malicious", "bec", "zh", ["tail_payment_new_account"], "")

E("mal_0056_redirect_ms.eml",
  (H("IT服务台", "helpdesk@partner.example", "it@corp.internal", "密码自助重置入口") + P +
   "收到多起重置失败反馈，请使用备用入口重置（微软官方跳转）：\r\n"
   "https://microsoft.commail.redir.example/?u=https://reset-pwd.example.co/r\r\n"),
  "malicious", "link_obfuscation", "zh", ["lookalike_redirect_chain"], "")

E("mal_0057_repair_link.eml",
  (H("平台运营", "ops@shop-svc.example", "merchant@corp.internal", "店铺资质待补充") + P +
   "您的一项经营资质信息不完整，为避免下架，请在三个工作日内补录：\r\n"
   "https://shop-qualia.example.net/fix\r\n"),
  "malicious", "account_phishing", "zh", ["paraphrase_qualia"], "硬正样本")

E("mal_0058_meeting_confirm.eml",
  (H("总裁办-日程", "sched@partner.example", "ea@corp.internal", "临时变动：股东会材料") + P +
   "刚接到变动，股东会材料改用外部加密链接发送，\r\n"
   "点此用公司邮箱登录查收：https://sh-materials.example.ru/view\r\n"
   "内容敏感，勿外传。\r\n"),
  "malicious", "account_phishing", "zh", ["confidential_login_lure"], "")

E("mal_0059_ocr_know.eml",
  (H("学籍中心", "registry@edu-notice.example", "parent@mail.example", "学籍信息核对通知") + P +
   "请家长在 48 小时内完成学籍信息核对，逾期未核对将影响学籍注册，\r\n"
   "核对入口：https://xj-check.example.org/parent\r\n"),
  "malicious", "account_phishing", "zh", ["school_registry_lure"], "家长定向")

E("mal_0060_vip_expire.eml",
  (H("会员运营", "vip@club-ops.example", "shen@corp.internal", "年卡权益即将失效") + P +
   "您的年卡权益 3 日后失效，含积分与权益余额，\r\n"
   "延期需本人操作：https://vip-renew.example.club/keep\r\n"),
  "malicious", "account_phishing", "zh", ["vip_expiry"], "")

# ---- ham: hard negatives ----
E("ham_0042_sms_code_bank.eml",
  (H("手机银行", "sms@bank.example", "me@personal.example", "动态验证码") + P +
   "您正在办理转账，验证码 820914，切勿泄露给任何人包括银行工作人员。\r\n"
   "本邮件由系统发出。\r\n"),
  "benign", "ham_business", "zh", ["own_verification_code"], "硬负样本")

E("ham_0043_invoice_reminder.eml",
  (H("应收提醒", "ar@vendor.example", "ap@corp.internal", "8月发票未收到回执") + P +
   "您好：8 月发票 9/2 已寄出，系统显示尚未签收。\r\n"
   "如已收到请忽略；未收到我们安排补寄并顺延账期。\r\n"),
  "benign", "ham_business", "zh", ["invoice_followup"], "")

E("ham_0044_maint_ip.eml",
  (H("运维平台", "ops@corp.internal", "sre@corp.internal", "今晚灰度发布窗口") + P +
   "今晚 23:00-01:00 网关灰度，控制台 http://10.20.31.7:8080/gray 可看实时比例。\r\n"
   "出问题直接停，预案在 runbook 第 4 节。\r\n"),
  "benign", "ham_business", "zh", ["internal_ip_console"], "硬负样本：内网IP链接")

E("ham_0045_salary_confirm.eml",
  (H("薪酬平台", "pay@corp.internal", "staff@corp.internal", "9月工资条已可查询") + P +
   "9 月工资条已生成，门户-薪酬-我的工资条 查看。\r\n"
   "异议 3 个工作日内提，平台不采集银行卡信息。\r\n"),
  "benign", "ham_business", "zh", ["salary_internal"], "")

E("ham_0046_vendor_statement.eml",
  (H("对账", "statement@vendor.example", "finance@corp.internal", "8月对账单与差异说明") + P +
   "您好：8 月对账单见附件区 Excel，其中第 14 笔为冲抵项已标注。\r\n"
   "差异 217.4 元系运费口径，下月统一调整。\r\n"),
  "benign", "ham_business", "zh", ["statement_diff"], "")

E("ham_0047_insurance_renew.eml",
  (H("承保中心", "policy@insure.example", "me@personal.example", "保单周年提醒") + P +
   "您的医疗险将于 10/12 到期，续保通道已开放（柜台或官网登录后操作）。\r\n"
   "本邮件无链接；详情以官网展示为准。\r\n"),
  "benign", "ham_personal", "zh", ["insurance_renew"], "")

E("ham_0048_school_fee.eml",
  (H("财务处", "cwc@school.example", "parent@mail.example", "本学期代办费缴纳说明") + P +
   "各位家长：代办费通过校园平台缴纳（班主任发的纸质单上有二维码，\r\n"
   "请核对金额 680 元），截止周五。\r\n"),
  "benign", "ham_personal", "zh", ["school_fee_qr_paper"], "纸质二维码口径，无电子链接")

E("ham_0049_talk_accepted.eml",
  (H("Program Chair", "chairs@conf.example", "research@corp.internal", "Your talk is accepted") + P +
   "Congratulations — your submission was accepted as a full talk.\r\n"
   "Please confirm attendance by Sep 20 via the speaker portal you used to submit.\r\n"),
  "benign", "ham_business", "en", ["talk_accepted"], "")

E("ham_0050_dunning.eml",
  (H("应收", "billing@vendor.example", "ap@corp.internal", "账款逾期提醒（第2次）") + P +
   "您好：INV-2026-0812 已逾期 15 天，金额 48,300 元。\r\n"
   "请安排或回复预计付款日，否则暂停供货。\r\n"),
  "benign", "ham_business", "zh", ["dunning"], "")

E("ham_0051_ham_portal_survey.eml",
  (H("员工体验", "survey@corp.internal", "all-staff@corp.internal", "食堂满意度调查（匿名）") + P +
   "本月食堂满意度调查开始，匿名填写约 2 分钟，\r\n"
   "入口：https://portal.corp.internal/survey/canteen\r\n"
   "结果用于档口调整。\r\n"),
  "benign", "ham_business", "zh", ["internal_survey"], "")

E("ham_0052_team_dinner.eml",
  (H("组长-老许", "xu@corp.internal", "team-a@corp.internal", "周五项目饭，老地方") + P +
   "这次迭代收尾，周五晚 7 点老地方川菜，AA，\r\n"
   "来的扣 1。带家属提前说，加位。\r\n"),
  "benign", "ham_personal", "zh", ["team_dinner"], "")

E("ham_0053_carpool.eml",
  (H("同城拼车群", "carpool@list.example", "me@personal.example", "周四晚杭州->上海 2 位") + P +
   "周四 19:00 出发，沪昆高速直达，还差 2 人分摊油费。\r\n"
   "行李多的提前说后备箱。\r\n"),
  "benign", "ham_personal", "zh", ["carpool"], "")

E("ham_0054_property_notice.eml",
  (H("物业服务中心", "pmu@community.example", "owner@list.example", "本周停水检修通知") + P +
   "周四 9:00-15:00 全楼停水检修水泵。提前储水。\r\n"
   "电梯不受影响。报修电话 0571-88xx。\r\n"),
  "benign", "ham_personal", "zh", ["property_notice"], "")

E("ham_0055_library_recall.eml",
  (H("图书馆", "lib@city.example", "me@personal.example", "图书到期催还") + P +
   "您借阅的《系统性能分析》今日到期，续借可在小程序操作或到馆办理。\r\n"
   "逾期将产生积分影响。\r\n"),
  "benign", "ham_personal", "zh", ["library_recall"], "")

E("ham_0056_volunteer.eml",
  (H("志愿者协会", "volunteer@community.example", "me@personal.example", "周六社区活动报名") + P +
   "本周六上午社区旧物改造活动需 5 名志愿者，含午餐。\r\n"
   "回复报名，集合地点会所门口。\r\n"),
  "benign", "ham_personal", "zh", ["volunteer"], "")

E("ham_0057_onboarding_it.eml",
  (H("IT入职支持", "newhire-it@corp.internal", "newhire@corp.internal", "入职首日 IT 准备") + P +
   "报道当天带身份证原件，工位与设备已备好。\r\n"
   "账号开通后首次登录需在办公网内完成（门户-新员工入口）。\r\n"),
  "benign", "ham_business", "zh", ["onboarding_internal"], "")

E("ham_0058_release_note.eml",
  (H("发布组", "release@corp.internal", "all-staff@corp.internal", "网关 1.9.4 发布说明") + P +
   "要点：超时分级回退、熔断阈值可配、修复 3 处内存泄漏。\r\n"
   "变更清单见 CHANGELOG，灰度比例 20% 起。\r\n"),
  "benign", "ham_business", "zh", ["release_note"], "")

E("ham_0059_esop_notice.eml",
  (H("股权管理", "esop@corp.internal", "staff@corp.internal", "行权窗口开放（10月）") + P +
   "本期行权窗口 10/9-10/20，操作在薪酬平台股权页。\r\n"
   "规则与去年一致，咨询走 HR 工单。\r\n"),
  "benign", "ham_business", "zh", ["esop_window"], "")

E("ham_0060_import_customs.eml",
  (H("货代", "ops@forwarder.example", "supply@corp.internal", "进口清关文件补交") + P +
   "海关要求补充原产地证扫描件，请今天发我邮箱，\r\n"
   "放行时效只剩 24 小时。费用不变。\r\n"),
  "benign", "ham_business", "zh", ["customs_docs"], "")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch3 written: {len(LABELS)} samples")
