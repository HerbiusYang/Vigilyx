#!/usr/bin/env python3
"""Batch 12: individually authored (crypto/travel/campus lures + campus ham)."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def H(disp, frm, to, subj, extra=""):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Fri, 04 Sep 2026 10:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b12@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\n")
P = "Content-Type: text/plain; charset=utf-8\r\n\r\n"
def E(n, raw, label, family, tech, note="", lang="zh"):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 12, "note": note})

E("mal_0191_cold_wallet.eml",
  (H("安全公告", "sec@wallet-notice.example", "me@personal.example", "检测到异常提币请求") + P +
   "您的钱包有一笔待确认提币。非本人操作请立即冻结并验证助记词备份状态：\r\n"
   "https://wallet-safe-check.example.vip/f\r\n").encode(),
  "malicious", "account_phishing", ["crypto_withdraw_lure"], "币圈定向（不直接索助记词，更隐蔽）")

E("mal_0192_exchange_kyc.eml",
  (H("合规中心", "kyc@coin-ex.example", "me@personal.example", "KYC 信息即将过期") + P +
   "您的 KYC 认证 7 日后过期，影响提币。更新需重新提交：\r\n"
   "https://kyc-up.example.info/k\r\n"
   "（身份证正反面+手持照+银行卡）\r\n").encode(),
  "malicious", "pii_harvest", ["exchange_kyc_collect"], "")

E("mal_0193_airdrop.eml",
  (H("活动", "drop@token-air.example", "me@personal.example", "空投领取（连钱包）") + P +
   "持有者可领空投，连接钱包签名确认：\r\n"
   "https://air-claim.example.club/c\r\n"
   "（小狐狸/MetaMask 一键连接）\r\n").encode(),
  "malicious", "account_phishing", ["airdrop_wallet_connect"], "钓钱包签名")

E("mal_0194_visa_material.eml",
  (H("签证中心", "visa@consul-svc.example", "me@personal.example", "签证材料补件（5日内）") + P +
   "您的申请缺存款证明与在职材料，补件通道：\r\n"
   "https://visa-bu.example.org/s\r\n"
   "（护照号+银行卡流水上传）\r\n").encode(),
  "malicious", "pii_harvest", ["visa_collect"], "")

E("mal_0195_hotel_book.eml",
  (H("订单服务", "book@stay-svc.example", "me@personal.example", "预订未完成（房费未付）") + P +
   "您的房费支付未完成，订单将取消。续付：\r\n"
   "https://stay-pay.example.info/c\r\n"
   "（卡号+有效期+CVV）\r\n").encode(),
  "malicious", "credential_harvest", ["hotel_cvv_collect"], "")

E("mal_0196_dorm_net.eml",
  (H("校园网", "net@campus-net.example", "student@mail.example", "校园网实名复核（本月）") + P +
   "按网信要求复核上网实名信息：\r\n"
   "https://campus-net-fu.example.org/r\r\n"
   "（学号+身份证号+校园网密码）\r\n").encode(),
  "malicious", "credential_harvest", ["campus_net_collect"], "")

E("mal_0197_scholar_visum.eml",
  (H("导师合作", "prof@univ-coop.example", "student@univ.example", "联合培养 CSC 申请协助") + P +
   "可协助准备材料，需先登记：\r\n"
   "https://csc-help.example.info/r\r\n"
   "（身份证号+家庭收入+导师推荐信扫描）\r\n").encode(),
  "malicious", "pii_harvest", ["csc_collect"], "学术定向")

E("mal_0198_lab_fee.eml",
  (H("实验中心", "lab@univ-lab.example", "student@univ.example", "超时机时费结算") + P +
   "您的 GPU 机时超额 42 元，未结清停用账号：\r\n"
   "https://lab-fee.example.org/j\r\n"
   "（学号+校园卡密码）\r\n").encode(),
  "malicious", "credential_harvest", ["lab_fee_collect"], "收校园卡密码")

E("mal_0199_exam_seat.eml",
  (H("考务", "kw@exam-seat.example", "student@mail.example", "准考证打印入口变更") + P +
   "打印入口临时变更，请使用新入口（需重新登录）：\r\n"
   "https://kw-new.example.info/p\r\n"
   "（身份证号+报名号）\r\n").encode(),
  "malicious", "pii_harvest", ["exam_seat_collect"], "")

E("mal_0200_grad_rent.eml",
  (H("毕业办理", "by@univ-exit.example", "student@univ.example", "离校手续欠费清零提醒") + P +
   "图书滞纳+水电欠费共 38.6 元，结清后放行档案：\r\n"
   "https://exit-pay.example.org/q\r\n"
   "（学号+统一身份认证密码）\r\n").encode(),
  "malicious", "credential_harvest", ["exit_fee_collect"], "")

E("mal_0201_club_card.eml",
  (H("会员通", "vip@fit-chain.example", "me@personal.example", "您的会籍被标记为待转门店") + P +
   "因三个月未到店，会籍将被转为门店共享卡。保留原会籍：\r\n"
   "https://fit-keep.example.vip/k\r\n"
   "（手机号+支付密码）\r\n").encode(),
  "malicious", "credential_harvest", ["gym_pay_password"], "收支付密码")

E("mal_0202_inspect_report.eml",
  (H("年检中心", "nj@car-inspect.example", "driver@personal.example", "年检报告有 1 项不合格待确认") + P +
   "灯光不合格，确认复检安排：\r\n"
   "https://nj-rebook.example.org/b\r\n"
   "（行驶证号+车架号后六位）\r\n").encode(),
  "malicious", "pii_harvest", ["inspect_collect"], "")

E("mal_0203_battery_swap.eml",
  (H("换电服务", "hd@swap-svc.example", "rider@personal.example", "电池押金调整需确认") + P +
   "押金政策调整，原路退回需确认收款账户：\r\n"
   "https://swap-yt.example.info/t\r\n"
   "（身份证+银行卡+手机验证码）\r\n").encode(),
  "malicious", "pii_harvest", ["deposit_refund_collect"], "骑手定向")

E("mal_0204_waimai_fee.eml",
  (H("商家服务", "sj@takeout-svc.example", "merchant@corp.internal", "门店服务费率调整确认") + P +
   "新费率 9/10 生效，确认后继续接单：\r\n"
   "https://takeout-fee.example.net/c\r\n"
   "（商家账号+结算密码）\r\n").encode(),
  "malicious", "credential_harvest", ["merchant_settle_password"], "收结算密码")

E("mal_0205_guild_sign.eml",
  (H("直播公会", "gh@live-guild.example", "talent@personal.example", "签约通道今日关闭") + P +
   "保底 8,000/月，签约需实名+人脸：\r\n"
   "https://guild-sign.example.vip/s\r\n"
   "今日 24:00 截止。\r\n").encode(),
  "malicious", "pii_harvest", ["guild_sign_face"], "")

E("mal_0206_pet_adopt.eml",
  (H("领养之家", "ly@pet-home.example", "me@personal.example", "待领养：英短（运费自理）") + P +
   "免费领养，仅需付空运笼+检疫费 380：\r\n"
   "https://pet-adopt-pay.example.info/f\r\n"
   "（微信/支付宝均可）\r\n").encode(),
  "malicious", "social_trust", ["pet_adopt_fee"], "宠物领养骗局")

E("mal_0207_house_bid.eml",
  (H("置业顾问", "kf@loupan-svc.example", "me@personal.example", "认筹享 98 折（今日登记截止）") + P +
   "认筹金 5 万（可退），线上登记通道：\r\n"
   "https://loupan-rc.example.info/d\r\n"
   "（姓名+身份证+银行卡）\r\n").encode(),
  "malicious", "pii_harvest", ["house_deposit_collect"], "")

E("mal_0208_dec_subsidy.eml",
  (H("旧改办", "jg@old-renew.example", "owner@personal.example", "旧房改造补贴申领（按面积）") + P +
   "按证载面积每平 300 元，登记申领：\r\n"
   "https://renew-bt.example.org/a\r\n"
   "（产权证号+身份证+银行卡）\r\n").encode(),
  "malicious", "subsidy_fraud", ["renovation_subsidy"], "")

E("mal_0209_deed_tax.eml",
  (H("契税补贴", "qs@tax-house.example", "buyer@personal.example", "契税补贴返还（2024-2026 批次）") + P +
   "符合 1% 补贴政策，返还登记：\r\n"
   "https://qs-fan.example.info/h\r\n"
   "（合同编号+身份证+收款卡）\r\n").encode(),
  "malicious", "subsidy_fraud", ["deed_tax_rebate"], "")

E("mal_0210_used_car.eml",
  (H("过户服务", "gh@car-transfer.example", "seller@personal.example", "买方已付定金，过户资料待传") + P +
   "买方已付定金，请上传行驶证+身份证+银行卡照片完成过户保证金托管：\r\n"
   "https://car-escrow.example.vip/u\r\n").encode(),
  "malicious", "pii_harvest", ["used_car_escrow_collect"], "")

E("ham_0191_csc_office.eml",
  (H("研究生院-国际处", "intl@univ.example", "student@univ.example", "CSC 联培校内提名开始") + P +
   "校内提名 9/20 截止，材料清单在外网系统填报（校内统一身份登录），\r\n"
   "纸质成绩单到教务窗口。\r\n").encode(),
  "benign", "ham_business", ["csc_real_nomination"], "与假 CSC 协助同形（校内系统+不收证件）")

E("ham_0192_lab_ok.eml",
  (H("实验中心", "lab@univ.example", "student@univ.example", "GPU 配额已恢复") + P +
   "你的机时配额本月已重置（200 卡时），超额可在门户申请临时加额。\r\n"
   "欠费历史清零。\r\n").encode(),
  "benign", "ham_business", ["lab_real_quota"], "")

E("ham_0193_dorm_real.eml",
  (H("网络中心", "nic@univ.example", "student@univ.example", "宿舍网免费提速已完成") + P +
   "统一升级 500M 完成，无需操作；账号即学号，\r\n"
   "密码重置请携带证件到网络中心柜台。\r\n").encode(),
  "benign", "ham_business", ["dorm_net_real"], "真校园网通知（重置密码需线下柜台）")

E("ham_0194_exam_real.eml",
  (H("考务办", "kw@univ.example", "student@univ.example", "四六级报名确认（校内系统）") + P +
   "报名信息请在教务系统核对（统一身份认证登录），\r\n"
   "缴费走校内支付平台，谨防山寨查分网站。\r\n").encode(),
  "benign", "ham_business", ["exam_real_notice"], "与假准考证入口同形+反诈提示")

E("ham_0195_gym_pause.eml",
  (H("健身房", "no-reply@gym.example", "me@personal.example", "会员卡暂停申请已生效") + P +
   "您申请的 30 天暂停已生效，顺延不扣费。\r\n"
   "恢复在小程序自助操作。\r\n").encode(),
  "benign", "ham_personal", ["gym_pause_real"], "")

E("ham_0196_inspect_done.eml",
  (H("车管所", "dmv@gov-veh.example", "driver@personal.example", "年检合格标志已生成") + P +
   "电子合格标志已推送至交管 APP，纸质贴纸已取消。\r\n"
   "本邮件无需回复。\r\n").encode(),
  "benign", "ham_personal", ["inspect_real_pass"], "")

E("ham_0197_swap_real.eml",
  (H("换电服务", "sv@swap-svc.example", "rider@personal.example", "本月换电套餐账单") + P +
   "套餐 299 元已自动扣费（支付宝代扣），明细见 App。\r\n"
   "退订请在 App 内操作，我们不会电话索要信息。\r\n").encode(),
  "benign", "ham_personal", ["swap_real_bill"], "")

E("ham_0198_takeout_real.eml",
  (H("商家服务", "sj@takeout-svc.example", "merchant@corp.internal", "费率说明更新（10月）") + P +
   "新费率结构说明已发到商家后台公告，结算不变、提现不变，\r\n"
   "有疑问联系您的城市经理。\r\n").encode(),
  "benign", "ham_business", ["takeout_real_notice"], "")

E("ham_0199_guild_real.eml",
  (H("直播平台", "mcn@live-svc.example", "talent@personal.example", "结算单（8月）已生成") + P +
   "8 月礼物流水结算单见后台，提现走平台内通道，\r\n"
   "平台不会通过邮件索要密码或验证码。\r\n").encode(),
  "benign", "ham_business", ["guild_real_settlement"], "")

E("ham_0200_realtor.eml",
  (H("置业顾问-小徐", "xu@realty.example", "me@personal.example", "您看的楼盘加推了") + P +
   "上周您看的 89 户型加推 12 套，还是老折扣。\r\n"
   "带身份证来售楼处就行，认筹可退。\r\n").encode(),
  "benign", "ham_personal", ["realtor_real_push"], "房产销售真实跟进（线下渠道）")

E("ham_0201_property_tax.eml",
  (H("税务", "dsj@tax-gov.example", "owner@personal.example", "房产税申报提醒（10月）") + P +
   "请在电子税务局 APP 完成，首次申报可见操作指引。\r\n"
   "税务局不会以短信链接办理业务。\r\n").encode(),
  "benign", "ham_personal", ["property_tax_real"], "")

E("ham_0202_renov_team.eml",
  (H("装修队长-阿坤", "kun@renov.example", "me@personal.example", "周三进场，提前备好门槛石") + P +
   "水电定位图发你了，确认后周三进场。\r\n"
   "进度款按节点来，验收后付。\r\n").encode(),
  "benign", "ham_personal", ["renovation_real"], "")

E("ham_0203_car_deal.eml",
  (H("二手车行", "wang@usedcar.example", "seller@personal.example", "买家约周六看车") + P +
   "买家周六上午来，你把行驶证带上，\r\n"
   "过户我们陪同，车款当面结。\r\n").encode(),
  "benign", "ham_personal", ["usedcar_real"], "")

E("ham_0204_visa_real.eml",
  (H("签证中心", "info@visa-center.example", "me@personal.example", "您的护照已可领取") + P +
   "签证已完成，工作日 9:00-16:00 凭回执单领取。\r\n"
   "代领需委托书+双方身份证复印件。\r\n").encode(),
  "benign", "ham_personal", ["visa_real_pickup"], "")

E("ham_0205_hotel_confirm.eml",
  (H("预订平台", "book@stay-svc.example", "me@personal.example", "预订确认：9/12-9/13") + P +
   "大床房已确认，到店付。取消免费期限 9/11 18:00。\r\n"
   "订单详情在 App 内查看。\r\n").encode(),
  "benign", "ham_personal", ["hotel_real_confirm"], "")

E("ham_0206_alumni.eml",
  (H("校友会", "xyh@univ.example", "alumni@mail.example", "毕业十年返校日（10/2）") + P +
   "返校日安排：系楼参观、恩师茶叙、合影。报名回执即可，\r\n"
   "费用 AA，家属欢迎。\r\n").encode(),
  "benign", "ham_personal", ["alumni_day"], "")

E("ham_0207_cps_lab.eml",
  (H("实验室", "lab@univ.example", "student@univ.example", "组会改周三（导师出差）") + P +
   "导师周三出差，组会提前到周三 10:00，\r\n"
   "轮到小陈讲论文，PPT 提前一晚发组里。\r\n").encode(),
  "benign", "ham_business", ["lab_meeting_shift"], "")

E("ham_0208_library_room.eml",
  (H("图书馆", "lib@univ.example", "student@univ.example", "研修间预约规则更新") + P +
   "新学期起研修间需扫码签到（入座码在预约系统），\r\n"
   "15 分钟未签到自动释放。\r\n").encode(),
  "benign", "ham_business", ["library_room_rule"], "")

E("ham_0209_print_shop.eml",
  (H("打印店", "shop@print-campus.example", "student@univ.example", "论文装订好了") + P +
   "三本都胶装好了，明早来自取，\r\n"
   "发票开好了夹在第一本里。\r\n").encode(),
  "benign", "ham_personal", ["print_shop"], "")

E("ham_0210_campus_bus.eml",
  (H("后勤", "houqin@univ.example", "all@univ.example", "校车时刻调整（教学周）") + P +
   "教学周恢复双班车，末班 21:40。\r\n"
   "实时位置看后勤小程序。\r\n").encode(),
  "benign", "ham_business", ["campus_bus"], "")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch12 written: {len(LABELS)} samples")
