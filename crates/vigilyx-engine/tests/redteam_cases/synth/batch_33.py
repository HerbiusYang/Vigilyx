#!/usr/bin/env python3
"""Batch 33: vehicle/property/energy/agri/cross-border/gaming/media lures + real notices."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def HD(disp, frm, to, subj, extra="", ct="text/plain; charset=utf-8"):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Sun, 27 Sep 2026 09:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b33@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\nContent-Type: {ct}\r\n\r\n")
def E(n, raw, label, family, tech, note="", lang="zh", fmt="plain", expected=None, ambiguous=False, borderline=""):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": expected or ("block" if label == "malicious" else "deliver"),
        "engine_status": "not_evaluated", "synthetic": True, "batch": 33,
        "format": fmt, "note": note, "ambiguous": ambiguous, "borderline": borderline})

E("mal_0571_license_renew.eml",
  HD("车管服务", "jz@dl-renew25.example", "driver@personal.example", "驾驶证期满换证（体检直传）")
  + "体检报告直传：https://jz-tj25.example.info/u\r\n（身份证+体检表+照片）\r\n",
  "malicious", "pii_harvest", ["license_renew_upload"], "换证收体检件")
E("mal_0572_scrappage.eml",
  HD("以旧换新", "bf@car-scrap25.example", "driver@personal.example", "报废补贴资格复核（先缴解押费）")
  + "解押费 800：https://bf-jy25.example.vip/p\r\n",
  "malicious", "social_trust", ["scrappage_fee"], "报废补贴解押费")
E("mal_0573_nysh_plate.eml",
  HD("网约车监管", "wl@ride-reg25.example", "driver@personal.example", "运输证年审（司机端人脸）")
  + "年审：https://wl-ns25.example.org/y\r\n（人脸+驾驶证+行驶证）\r\n",
  "malicious", "pii_harvest", ["ny_plate_face"], "运输证年审收人脸")
E("mal_0574_hoa_vote.eml",
  HD("业委会", "yw@hoa-svc25.example", "owner@personal.example", "业委会换届投票（线上授权）")
  + "线上授权投票：https://yw-tp25.example.info/v\r\n（房产证号+身份证）\r\n",
  "malicious", "pii_harvest", ["auto"], "b33fix")
E("mal_0575_repair_fund.eml",
  HD("维修资金", "wx@fund-repair25.example", "owner@personal.example", "电梯大修资金征询（微信代收）")
  + "本次按户 3,200，扫码缴至筹备组：\r\n见附件收款码\r\n",
  "malicious", "social_trust", ["repair_fund_personal_qr"], "维修资金个人码")
E("mal_0576_parking_deed.eml",
  HD("车位产权", "cw@parking-deed25.example", "owner@personal.example", "车位不动产登记补件")
  + "补件：https://cw-bj25.example.info/u\r\n（购房合同+身份证+车位平面图）\r\n",
  "malicious", "pii_harvest", ["auto"], "b33fix")
E("mal_0577_group_rent.eml",
  HD("群租举报", "qz@rent-report25.example", "owner@personal.example", "您的房源被举报群租（陈述申辩）")
  + "申辩材料：https://qz-sb25.example.info/s\r\n（房产证+租客名单+身份证）\r\n",
  "malicious", "pii_harvest", ["group_rent_defense"], "群租举报收件")
E("mal_0578_carbon_comply.eml",
  HD("碳市场", "th@carbon-svc25.example", "esg@corp.internal", "碳配额履约缺口（OTC 购买）")
  + "OTC 购买意向金：6225 0091 5566 2210\r\n（备注配额代码）\r\n",
  "malicious", "bec", ["carbon_otc_deposit"], "碳配额 OTC 定金")
E("mal_0579_green_cert.eml",
  HD("绿证", "lz@green-cert25.example", "esg@corp.internal", "绿证批量划转（账户核验）")
  + "核验：https://lz-hy25.example.info/v\r\n（交易账号+密码）\r\n",
  "malicious", "credential_harvest", ["green_cert_verify"], "绿证核验")
E("mal_0580_energy_audit.eml",
  HD("能耗双控", "nh@energy-audit25.example", "facility@corp.internal", "能耗数据补报（导出模板宏）")
  + "模板模板见附件，启用宏后自动汇总上报。\r\n",
  "malicious", "malware_attachment", ["auto"], "b33fix")
E("mal_0581_agri_machine.eml",
  HD("农机补贴", "nj@agri-subsidy25.example", "farmer@personal.example", "购机补贴申领（指标今日）")
  + "申领：https://nj-sl25.example.info/a\r\n（身份证+购机发票+银行卡）\r\n",
  "malicious", "pii_harvest", ["agri_subsidy_collect"], "农机补贴收件")
E("mal_0582_land_flow.eml",
  HD("土地流转", "td@land-flow25.example", "farmer@personal.example", "流转合同鉴证（鉴证费）")
  + "鉴证费 200/亩：https://td-jz25.example.vip/p\r\n",
  "malicious", "bec", ["land_flow_fee"], "流转鉴证费")
E("mal_0583_rural_loan.eml",
  HD("惠农贷", "hn@rural-loan25.example", "farmer@personal.example", "贴息贷款贴息返还")
  + "返还登记：https://hn-fh25.example.vip/r\r\n（身份证+惠农卡号）\r\n",
  "malicious", "subsidy_fraud", ["auto"], "b33fix")
E("mal_0584_shop_audit2.eml",
  HD("跨境电商", "kj@shop-audit25.example", "merchant@corp.internal", "店铺二审（视频验证预约）")
  + "预约费 99：https://kj-yy25.example.info/b\r\n（法人身份证+营业执照）\r\n",
  "malicious", "pii_harvest", ["crossborder_second_audit"], "店铺二审预约费")
E("mal_0585_vat_agent.eml",
  HD("税务代理", "vs@vat-agent25.example", "merchant@corp.internal", "VAT 税号注册（低税率）")
  + "注册费 EUR 299：https://vs-zc25.example.vip/r\r\n（公司文件+法人证件）\r\n",
  "malicious", "pii_harvest", ["vat_registration_scam"], "VAT 税号")
E("mal_0586_follow_seller.eml",
  HD("品牌保护", "pp@brand-guard25.example", "merchant@corp.internal", "跟卖警告（授权撤除费）")
  + "撤除费 $199：https://pp-cc25.example.info/pay\r\n",
  "malicious", "bec", ["fake_follow_seller"], "假跟卖投诉")
E("mal_0587_tm_squat2.eml",
  HD("商标注册", "sb@tm-squat25.example", "merchant@corp.internal", "您的店招被抢注（防御注册）")
  + "防御注册费 1,800：https://sb-fy25.example.vip/p\r\n",
  "malicious", "bec", ["auto"], "b33fix")
E("mal_0588_game_license.eml",
  HD("出版服务", "cb@game-license25.example", "pm@corp.internal", "版号加急（内部通道）")
  + "加急费 60,000：6225 0091 9920 3311\r\n",
  "malicious", "bec", ["auto"], "b33fix")
E("mal_0589_channel_settle.eml",
  HD("渠道联运", "qd@game-channel25.example", "pm@corp.internal", "联运分成结算账户变更")
  + "分成改付：6225 0091 8820 1145（XX 工作室）\r\n",
  "malicious", "bec", ["channel_settle_swap"], "联运分成换账户")
E("mal_0590_cheat_appeal.eml",
  HD("游戏处罚", "cf@game-penalty25.example", "player@personal.example", "封号申诉（保证金）")
  + "解封保证金 300：https://cf-jb25.example.vip/p\r\n",
  "malicious", "social_trust", ["unban_deposit"], "解封保证金")
E("mal_0591_pr_delete.eml",
  HD("舆情优化", "yq@pr-delete25.example", "pr@corp.internal", "负面词条处理（报价）")
  + "搜索词处理 3,000/条，先付后删，联系方式见链接。\r\nhttps://yq-sc25.example.vip/q\r\n",
  "malicious", "bec", ["auto"], "b33fix")
E("mal_0592_kol_pay.eml",
  HD("KOL商务", "kol@influencer25.example", "marketing@corp.internal", "达人档期锁定（预付）")
  + "预付 50%：6225 0091 3310 7742\r\n",
  "malicious", "bec", ["kol_prepay_swap"], "达人预付")
E("mal_0593_press_invite.eml",
  HD("媒体邀请", "mt@press-invite25.example", "pr@corp.internal", "专访机会（媒体注册费）")
  + "注册费 1,200：https://mt-zc25.example.info/p\r\n",
  "malicious", "bec", ["press_invite_fee"], "媒体注册费")

E("ham_0506_license_real2.eml",
  HD("交管12123", "jz@12123.example", "driver@personal.example", "驾驶证期满换证提醒")
  + "12123 App 内申请，体检医院联网免纸质。\r\n",
  "benign", "ham_personal", ["license_real_app"], "与换证钓鱼同形")
E("ham_0507_scrap_real.eml",
  HD("商务局", "swj@biz-gov.example", "driver@personal.example", "报废更新补贴公示")
  + "名单公示 7 日，补贴直达个人账户。\r\n",
  "benign", "ham_personal", ["auto"], "b33fix")
E("ham_0508_hoa_real2.eml",
  HD("业委会", "yw@community.example", "owner@personal.example", "换届投票（线下+公证）")
  + "周六现场投票，委托需公证委托书。\r\n",
  "benign", "ham_personal", ["hoa_real_offline"], "与线上授权钓鱼对照")
E("ham_0509_repair_real2.eml",
  HD("物业", "wy@property.example", "owner@personal.example", "维修资金使用征询（专户）")
  + "资金走房管局专户，凭单到银行柜台或官方线上专户缴纳，\r\n物业不代收。\r\n",
  "benign", "ham_personal", ["repair_real_special_account"], "真维修资金：专户+不代收")
E("ham_0510_carbon_real.eml",
  HD("碳市场", "th@exchange.example", "esg@corp.internal", "履约截止与持仓提示")
  + "12/15 前完成清缴，交易在注册登记系统。\r\n",
  "benign", "ham_business", ["auto"], "b33fix")
E("ham_0511_green_real.eml",
  HD("绿证", "lz@exchange.example", "esg@corp.internal", "绿证成交回报")
  + "成交明细见交易平台。\r\n",
  "benign", "ham_business", ["green_real_trade"], "")
E("ham_0512_agri_real.eml",
  HD("农业农村局", "nj@agri.example", "farmer@personal.example", "补贴申领指南（政务App）")
  + "皖事通-农机补贴申报，材料拍照上传。\r\n",
  "benign", "ham_personal", ["agri_real_app"], "与农机钓鱼同形")
E("ham_0513_land_real.eml",
  HD("农村产权", "cq@land.example", "farmer@personal.example", "流转合同鉴证完成")
  + "回执见附件。\r\n",
  "benign", "ham_personal", ["auto"], "b33fix")
E("ham_0514_vat_real.eml",
  HD("税务代理", "vs@vat-firm.example", "merchant@corp.internal", "VAT 注册回执（税局官网可验）")
  + "税号见附件，官网自助核验。\r\n",
  "benign", "ham_business", ["vat_real_verifiable"], "真 VAT：官网可验")
E("ham_0515_follow_real2.eml",
  HD("亚马逊", "pz@marketplace.example", "merchant@corp.internal", "跟卖投诉已受理（站内）")
  + "处理进度在卖家平台-品牌注册。\r\n邮件仅为通知。\r\n",
  "benign", "ham_business", ["follow_real_platform"], "真跟卖处理在站内")
E("ham_0516_license_gov.eml",
  HD("出版署", "cb@nppa.example", "pm@corp.internal", "版号审批进度")
  + "进度以署官网公示为准。\r\n",
  "benign", "ham_business", ["auto"], "b33fix")
E("ham_0517_channel_real.eml",
  HD("渠道联运", "qd@game.example", "pm@corp.internal", "月度分成结算单")
  + "结算单见附件，账户按合同。\r\n",
  "benign", "ham_business", ["channel_real_statement"], "与换账户对照")
E("ham_0518_penalty_real.eml",
  HD("游戏客服", "kf@game.example", "player@personal.example", "申诉复核结果")
  + "维持处罚；证据不足。客服渠道见官网。\r\n",
  "benign", "ham_personal", ["auto"], "b33fix")
E("ham_0519_pr_real.eml",
  HD("公关顾问", "gw@pr-firm.example", "pr@corp.internal", "监测周报与应对建议")
  + "见附件。涉及不实信息建议走平台申诉与法律函件。\r\n",
  "benign", "ham_business", ["pr_real_weekly"], "真公关：平台申诉+法律函（与删帖灰产对照）")
E("ham_0520_kol_real.eml",
  HD("KOL商务", "kol@agency.example", "marketing@corp.internal", "达人合作确认函")
  + "档期与报价确认，合同走对公。\r\n",
  "benign", "ham_business", ["auto"], "b33fix")
E("ham_0521_press_real2.eml",
  HD("媒体", "mt@press.example", "pr@corp.internal", "专访安排确认")
  + "周四 15:00 线下，记者名单附后。\r\n",
  "benign", "ham_business", ["press_real_schedule"], "真专访：线下+名单")
E("ham_0522_energy_real.eml",
  HD("能耗监测", "nh@corp.internal", "facility@corp.internal", "上月能耗报表")
  + "报表见附件 Excel（无宏）。\r\n",
  "benign", "ham_business", ["auto"], "b33fix")
with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch33 written: {len(LABELS)} samples")
