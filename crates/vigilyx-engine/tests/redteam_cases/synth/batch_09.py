#!/usr/bin/env python3
"""Batch 9: individually authored (finance/edu/lifestyle lures + daily ham)."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def H(disp, frm, to, subj, extra=""):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Tue, 01 Sep 2026 10:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b9@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\n")
P = "Content-Type: text/plain; charset=utf-8\r\n\r\n"
def ATT(t, fn, ct, b64):
    return ("Content-Type: multipart/mixed; boundary=\"BS\"\r\n\r\n"
            f"--BS\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{t}\r\n"
            f"--BS\r\nContent-Type: {ct}\r\nContent-Disposition: attachment; filename=\"{fn}\"\r\n"
            f"Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--BS--\r\n")
def E(n, raw, label, family, tech, note=""):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": "zh", "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 9, "note": note})

E("mal_0141_credit_expire.eml",
  (H("授信管理", "sx@loan-svc.example", "finance@corp.internal", "授信额度到期前需完成复审") + P +
   "贵司在途授信 9/12 到期，复审资料请在线提交：\r\n"
   "https://credit-review.example.org/sx\r\n"
   "（需法人身份证与经办人手机验证码）\r\n").encode(),
  "malicious", "pii_harvest", ["credit_review_collect"], "")

E("mal_0142_school_msg.eml",
  (H("校讯通", "xxt@edu-notice.example", "parent@mail.example", "【校讯通】孩子课堂表现已更新") + P +
   "班主任发布了本周课堂表现与作业，家长查看请登录：\r\n"
   "https://xxt-view.example.info/login（学号+家长手机号）\r\n").encode(),
  "malicious", "account_phishing", ["school_msg_login"], "家长定向")

E("mal_0143_vaccine_book.eml",
  (H("接种通知", "ym@health-svc.example", "parent@mail.example", "流感疫苗预约（校园专场）") + P +
   "校园专场接种需提前登记儿童信息：\r\n"
   "https://vac-book.example.org/c\r\n"
   "（姓名+出生证号+家长身份证）\r\n").encode(),
  "malicious", "pii_harvest", ["vaccine_collect"], "")

E("mal_0144_hotel_member.eml",
  (H("会员礼遇", "club@hotel-res.example", "me@personal.example", "会员积分即将过期（本月）") + P +
   "您有 18,600 积分本月过期，可兑房券：\r\n"
   "https://hotel-duihuan.example.club/e\r\n"
   "需卡号后四位+手机验证码。\r\n").encode(),
  "malicious", "credential_harvest", ["points_sms_code"], "")

E("mal_0145_ticket_rebook.eml",
  (H("行程变更", "cs@trip-rebook.example", "me@personal.example", "您的航班取消，可获 300 元补偿") + P +
   "因运力原因您的航班取消，除退款外可领 300 元补偿：\r\n"
   "https://rebook-comp.example.vip/c\r\n"
   "（需银行卡+预留手机号）\r\n").encode(),
  "malicious", "pii_harvest", ["flight_comp_collect"], "")

E("mal_0146_game_code.eml",
  (H("游戏运营", "gift@game-svc.example", "me@personal.example", "赛季皮肤兑换码已生成") + P +
   "兑换码已生成，领取需账号验证：\r\n"
   "https://game-duihuan.example.info/g\r\n"
   "（游戏账号+密码二次确认）\r\n").encode(),
  "malicious", "credential_harvest", ["game_account_collect"], "收游戏账号")

E("mal_0147_bargain.eml",
  (H("好友助力", "notice@shop-kan.example", "me@personal.example", "好友请您助力砍价") + P +
   "点击助力并登录即可帮好友砍一刀：\r\n"
   "https://kan-help.example.vip/a\r\n"
   "（微信一键登录）\r\n").encode(),
  "malicious", "account_phishing", ["bargain_login"], "仿一键登录")

E("mal_0148_refer_bonus.eml",
  (H("人才推荐", "ref@hr-bonus.example", "staff@corp.internal", "内推奖金登记（第3季度）") + P +
   "您有一笔内推奖金待登记领取：\r\n"
   "https://ref-bonus.example.net/q3\r\n"
   "需身份证号与银行卡完成税务代扣登记。\r\n").encode(),
  "malicious", "pii_harvest", ["refer_bonus_collect"], "")

E("mal_0149_minutes_macro.eml",
  (H("会议秘书", "sec@partner-meet.example", "pm@corp.internal", "纪要及行动项（含跟踪表）")
   + ATT("纪要正文见邮件，行动项跟踪表在附件（请启用宏自动刷新）。",
         "行动项跟踪表.xls", "application/vnd.ms-excel",
         base64.b64encode(b"\xd0\xcf\x11\xe0" + b"\x00"*64).decode())),
  "malicious", "malware_attachment", ["legacy_xls_macro"], "旧格式宏诱导")

E("mal_0150_vendor_xls.eml",
  (H("华信-对账", "dzhz@hongxin-trade.example", "ap@corp.internal", "9月对账单（差异两笔）")
   + ATT("对账单见附件，两笔差异黄色标注，请核对回签。",
         "对账单202609.xls", "application/vnd.ms-excel",
         base64.b64encode(b"\xd0\xcf\x11\xe0" + b"\x00"*64).decode())),
  "malicious", "malware_attachment", ["vendor_xls_macro"], "对账单载体宏")

E("mal_0151_resume_link.eml",
  (H("猎头-猎聘通", "lt@zhipin-mail.example", "me@personal.example", "您的简历被 3 家企业查看") + P +
   "查看企业名单与联系方式：\r\n"
   "https://resume-view.example.co/v\r\n"
   "（需手机号+验证码登录）\r\n").encode(),
  "malicious", "account_phishing", ["resume_view_login"], "")

E("mal_0152_offer_link.eml",
  (H("录用通知", "offer@hire-svc.example", "candidate@mail.example", "Offer 已发放，请在线确认") + P +
   "点击查收并确认入职（需上传身份证正反面）：\r\n"
   "https://offer-view.example.info/c\r\n"
   "48 小时内未确认视为放弃。\r\n").encode(),
  "malicious", "pii_harvest", ["offer_upload_id"], "")

E("mal_0153_album_link.eml",
  (H("行政台", "photo@corp-photos.example", "staff@corp.internal", "团建照片已生成（在线相册）") + P +
   "相册链接（企业邮箱账号登录）：\r\n"
   "https://corp-photo-view.example.net/a\r\n").encode(),
  "malicious", "credential_harvest", ["album_login_collect"], "收企业邮箱账密")

E("mal_0154_payslip_link.eml",
  (H("薪酬平台", "pay-view@salary-saas.example", "staff@corp.internal", "9月工资条已生成") + P +
   "查收工资条（首次需验证）：\r\n"
   "https://pay-slip.example.org/v\r\n"
   "（工号+身份证后六位+银行卡后四位）\r\n").encode(),
  "malicious", "pii_harvest", ["payslip_multi_factor_collect"], "多要素收集")

E("mal_0155_attend_appeal.eml",
  (H("考勤系统", "appeal@hr-att.example", "staff@corp.internal", "您有一条考勤异常待申诉") + P +
   "8/27 漏打卡 1 次，请今日内申诉否则计入缺勤：\r\n"
   "https://att-appeal.example.net/s\r\n"
   "（域账号登录）\r\n").encode(),
  "malicious", "credential_harvest", ["appeal_domain_login"], "")

E("mal_0156_annual_draw.eml",
  (H("年会组委会", "nh@corp-party.example", "staff@corp.internal", "年会抽奖登记开启") + P +
   "登记后自动参与抽奖（需工号+手机号+部门）：\r\n"
   "https://party-reg.example.club/d\r\n"
   "登记截止周五。\r\n").encode(),
  "malicious", "pii_harvest", ["annual_party_collect"], "")

E("mal_0157_holiday_gift.eml",
  (H("员工关怀", "gift@corp-care.example", "staff@corp.internal", "中秋礼盒自选（数量有限）") + P +
   "自选通道（需登录）：\r\n"
   "https://care-choice.example.info/g\r\n"
   "先到先得。\r\n").encode(),
  "malicious", "account_phishing", ["gift_choice_login"], "")

E("mal_0158_supplies_apply.eml",
  (H("行政-采购", "sup@office-need.example", "admin@corp.internal", "办公用品月度申购（新系统）") + P +
   "申购迁移到新系统，首次需验证身份：\r\n"
   "https://sup-new.example.org/i\r\n"
   "（域账号+动态码）\r\n").encode(),
  "malicious", "credential_harvest", ["supplies_domain_otp"], "")

E("mal_0159_ticket_overdue.eml",
  (H("IT服务台", "itsm@corp-help.example", "dev@corp.internal", "工单 ITSM-8842 超时预警") + P +
   "工单即将超时升级，请处理：\r\n"
   "https://itsm-handle.example.net/8842\r\n"
   "（需域账号登录）\r\n").encode(),
  "malicious", "credential_harvest", ["itsm_domain_login"], "")

E("mal_0160_ssl_expire.eml",
  (H("证书服务", "ssl@cert-notify.example", "webmaster@corp.internal", "SSL 证书 48 小时后过期") + P +
   "证书即将过期，续期需验证域名所有者：\r\n"
   "https://ssl-renew-check.example.info/r\r\n"
   "（邮箱账号+密码验证所有权）\r\n").encode(),
  "malicious", "credential_harvest", ["ssl_renew_collect"], "")

E("ham_0141_typhoon_stop.eml",
  (H("应急小组", "emg@corp.internal", "all-staff@corp.internal", "台风红色预警：明日居家办公") + P +
   "气象台升级红色预警，明日全员居家，班车停运。\r\n"
   "生产值班不变，食堂关闭一天。\r\n").encode(),
  "benign", "ham_business", ["typhoon_remote"], "")

E("ham_0142_fire_check.eml",
  (H("安全环保部", "safety@corp.internal", "campus@corp.internal", "明日消防检查（勿占用消防通道）") + P +
   "明上午消防大队检查，请各部门清理通道与灭火器前杂物，\r\n"
   "电动车别推进楼。\r\n").encode(),
  "benign", "ham_business", ["fire_inspection"], "")

E("ham_0143_canteen_result.eml",
  (H("员工体验", "survey@corp.internal", "all-staff@corp.internal", "食堂满意度结果公示") + P +
   "回收 1,204 份：面食窗口呼声最高，二期将增设。\r\n"
   "完整数据见员工体验频道。\r\n").encode(),
  "benign", "ham_business", ["survey_result"], "")

E("ham_0144_shuttle_late.eml",
  (H("行政-车队", "fleet@corp.internal", "campus@corp.internal", "早班车延误通知") + P +
   "1 号线早班车因道路施工延误约 20 分钟，\r\n"
   "实时位置见车队小程序。\r\n").encode(),
  "benign", "ham_business", ["shuttle_delay"], "")

E("ham_0145_parcel_proxy.eml",
  (H("行政台", "admin-desk@corp.internal", "campus@corp.internal", "快递统一代收点变更") + P +
   "代收点移至 1F 大厅东侧货架，大件仍走南门收发室。\r\n"
   "下班前自取，隔天清架。\r\n").encode(),
  "benign", "ham_business", ["parcel_proxy"], "")

E("ham_0146_badge_photo.eml",
  (H("行政", "admin@corp.internal", "all-staff@corp.internal", "工牌照片更新（本周）") + P +
   "新门禁系统需重拍工牌照，摄影棚在 2F，随到随拍，\r\n"
   "白底深色上衣。\r\n").encode(),
  "benign", "ham_business", ["badge_photo"], "")

E("ham_0147_contacts.eml",
  (H("行政台", "admin-desk@corp.internal", "leads@corp.internal", "内部通讯录季度更新") + P +
   "通讯录以门户为准，本周五冻结同步到话机，\r\n"
   "有离职未销号/新号未录的部门自查。\r\n").encode(),
  "benign", "ham_business", ["contacts_update"], "")

E("ham_0148_leaver_doc.eml",
  (H("人资系统", "ehr@corp.internal", "leaver@corp.internal", "离职证明开具指引") + P +
   "离职证明在门户-人资-证明自助开具，电子章有效，\r\n"
   "纸质版可到前台打印。\r\n").encode(),
  "benign", "ham_business", ["leaver_cert"], "")

E("ham_0149_reimburse_delay.eml",
  (H("财务共享", "fssc@corp.internal", "all-staff@corp.internal", "本月报销打款延迟说明") + P +
   "因银企通道升级，本月 25-28 日报销将延至次月 2 日统一打款，\r\n"
   "急用可走绿色通道（审批权限不变）。\r\n").encode(),
  "benign", "ham_business", ["reimburse_delay"], "")

E("ham_0150_fx_window.eml",
  (H("资金部", "treasury@corp.internal", "finance@corp.internal", "9月结汇窗口安排") + P +
   "本月结汇窗口 9/8、9/22，单笔 50 万美元以上需提前两天报备。\r\n"
   "牌价以中行 9:15 为准。\r\n").encode(),
  "benign", "ham_business", ["fx_window"], "")

E("ham_0151_bookcrossing.eml",
  (H("读书会", "books@corp.internal", "all-staff@corp.internal", "图书漂流角新到一批") + P +
   "3F 茶水间漂流角新到 30 本，随意取阅，看完放回或换一本。\r\n"
   "扉页可留一句话。\r\n").encode(),
  "benign", "ham_business", ["bookcrossing"], "")

E("ham_0152_readathon.eml",
  (H("读书会", "books@corp.internal", "club@corp.internal", "21天共读打卡组队") + P +
   "下期共读《纳瓦尔宝典》，打卡小程序自由组队，\r\n"
   "全勤送一本书。\r\n").encode(),
  "benign", "ham_business", ["readathon"], "")

E("ham_0153_badminton_time.eml",
  (H("羽毛球社", "bdm@corp.internal", "club@corp.internal", "本周改周五（场地原因）") + P +
   "本周改周五 20:00，馆方维护，人数照旧接龙。\r\n"
   "新买的球到了。\r\n").encode(),
  "benign", "ham_business", ["club_time_change"], "")

E("ham_0154_coffee_fix.eml",
  (H("行政台", "admin-desk@corp.internal", "floor3@corp.internal", "咖啡机维修中（本周）") + P +
   "3F 咖啡机奶管故障返修中，先用 5F 的。\r\n"
   "胶囊还有存货在柜子下层。\r\n").encode(),
  "benign", "ham_business", ["coffee_fix"], "")

E("ham_0155_microwave.eml",
  (H("行政台", "admin-desk@corp.internal", "campus@corp.internal", "微波炉使用提醒") + P +
   "近期两次焦糊报警，带壳鸡蛋与密封盒请勿加热，\r\n"
   "用完随手擦内壁。\r\n").encode(),
  "benign", "ham_business", ["microwave"], "")

E("ham_0156_motherroom.eml",
  (H("行政-关怀", "care@corp.internal", "all-staff@corp.internal", "母婴室位置与预约说明") + P +
   "母婴室在 2F 东侧，门禁申请走行政台，\r\n"
   "冰箱内物品请贴姓名贴。\r\n").encode(),
  "benign", "ham_business", ["mother_room"], "")

E("ham_0157_overtime_meal.eml",
  (H("行政", "admin@corp.internal", "oncall@corp.internal", "加班餐供应时间调整") + P +
   "加班餐供应延至 21:30，22:00 后值班室有泡面与自热锅。\r\n"
   "加班餐补自动判定，无需申请。\r\n").encode(),
  "benign", "ham_business", ["overtime_meal"], "")

E("ham_0158_carpool_colleague.eml",
  (H("小蔺", "lin@corp.internal", "me@corp.internal", "周三通勤捎你") + P +
   "周三我开车走文一西，捎你一段，8:10 楼下。\r\n"
   "顺路帮我带杯冰美式。\r\n").encode(),
  "benign", "ham_business", ["carpool_colleague"], "")

E("ham_0159_swap_meet.eml",
  (H("工会", "union@corp.internal", "all-staff@corp.internal", "闲置交换角（月底）") + P +
   "月底大堂闲置交换：书、手办、小家电都行，\r\n"
   "自行贴标签自取，无人看管靠自觉。\r\n").encode(),
  "benign", "ham_business", ["swap_meet"], "")

E("ham_0160_pet_day.eml",
  (H("工会", "union@corp.internal", "all-staff@corp.internal", "带宠日报名（10/12）") + P +
   "草坪带宠日回归，需疫苗齐全（拍照登记），\r\n"
   "限 20 组，接龙报名。\r\n").encode(),
  "benign", "ham_business", ["pet_day"], "")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch9 written: {len(LABELS)} samples")
