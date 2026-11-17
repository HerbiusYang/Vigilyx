#!/usr/bin/env python3
"""Batch 21: e-commerce/logistics/lifestyle lures + matching real notices."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def HD(disp, frm, to, subj, ct="text/plain; charset=utf-8"):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Mon, 14 Sep 2026 09:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b21@synth.example>\r\n"
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\nContent-Type: {ct}\r\n\r\n")
def E(n, raw, label, family, tech, note="", lang="zh", fmt="plain"):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 21,
        "format": fmt, "note": note})

E("mal_0336_aftersale_code.eml",
  HD("售后中心", "sh@shop-after.example", "me@personal.example", "售后单 AS8842 需短信核验")
  + "您的换货申请需短信核验，验证通道：\r\nhttps://after-check.example.info/v\r\n"
  "（收货手机号+短信验证码）\r\n",
  "malicious", "pii_harvest", ["aftersale_sms_collect"], "售后收验证码")
E("mal_0337_points_zero2.eml",
  HD("积分商城", "jf@points-2026.example", "me@personal.example", "您的积分本月底清零")
  + "可兑视频月卡/加油券，兑换需核验支付密码：\r\nhttps://pts-dh2.example.vip/e\r\n",
  "malicious", "credential_harvest", ["points_pay_password"], "积分收支付密码")
E("mal_0338_fast_refund.eml",
  HD("极速退款", "tk@refund-fast.example", "me@personal.example", "退款卡在银行通道，需人工加急")
  + "您的退款卡在通道，加急需人工核实收款卡：\r\nhttps://rf-jj.example.info/a\r\n"
  "（卡号+预留手机+身份证后六位）\r\n",
  "malicious", "pii_harvest", ["refund_stuck_card_collect"], "退款卡单话术")
E("mal_0339_daifu.eml",
  HD("好友代付", "pay@friend-pay.example", "me@personal.example", "好友请您代付（拼单尾款 158 元）")
  + "点击查看代付详情并付款：\r\nhttps://friend-df.example.vip/p\r\n"
  "（微信支付/支付宝均可）\r\n",
  "malicious", "social_trust", ["friend_daifu"], "代付链接")
E("mal_0340_groupbuy_fail.eml",
  HD("拼团助手", "pt@tuan-notice.example", "me@personal.example", "拼团未成团，退款需激活")
  + "本期未成团，退款需先激活收款账户：\r\nhttps://tuan-tk.example.info/r\r\n",
  "malicious", "account_phishing", ["groupbuy_refund_activate"], "")
E("mal_0341_reject_parcel.eml",
  HD("派送通知", "ps@express-reject.example", "me@personal.example", "您的快件被标记'拒收'，退回前可撤回")
  + "撤回需支付保价费 3 元并登记手机号：\r\nhttps://reject-ch2.example.info/x\r\n",
  "malicious", "pii_harvest", ["reject_fee_collect"], "")
E("mal_0342_overseas_tax.eml",
  HD("海外购", "hg@oversea-buy.example", "me@personal.example", "包裹被海关暂扣，补缴行邮税 128 元")
  + "补缴通道：https://hg-bs2.example.info/t\r\n（申报单号+身份证号）\r\n",
  "malicious", "account_phishing", ["overseas_tax_lure"], "海外购补税")
E("mal_0343_secondhand_margin.eml",
  HD("闲鱼服务", "xy@idle-market.example", "me@personal.example", "买家已拍下，冻结保证金可退")
  + "保证金 500 元在冻结中，解冻需验证收款信息：\r\nhttps://xy-jd2.example.vip/u\r\n",
  "malicious", "pii_harvest", ["secondhand_deposit_unlock"], "二手保证金话术")
E("mal_0344_live_prize2.eml",
  HD("直播间", "lb@live-draw2.example", "me@personal.example", "恭喜抽中空气炸锅（主播自掏）")
  + "登记收货信息（姓名+电话+详细地址+身份证号核对年龄）：\r\nhttps://lb-lq2.example.club/g\r\n",
  "malicious", "pii_harvest", ["live_prize_address_id"], "中奖收身份证'核对年龄'")
E("mal_0345_waimati_tx.eml",
  HD("外卖红包", "hb@takeout-red.example", "me@personal.example", "可提现红包 26.8 元（今日到期）")
  + "提现需绑定银行卡并验证手机服务密码：\r\nhttps://hb-tx2.example.info/d\r\n",
  "malicious", "credential_harvest", ["redpacket_service_password"], "")
E("mal_0346_hotel_points.eml",
  HD("酒店集团", "hy@stay-points.example", "me@personal.example", "会籍降级预警（差 2 晚保级）")
  + "补差价保级通道：https://hy-bj2.example.info/k\r\n（需卡号后四位+CVN）\r\n",
  "malicious", "credential_harvest", ["hotel_cvn_collect"], "收 CVN")
E("mal_0347_flight_miles.eml",
  HD("航空里程", "lc@air-miles.example", "me@personal.example", "里程 12 月过期，可折现")
  + "折现登记收款卡：https://lc-zx2.example.vip/m\r\n",
  "malicious", "pii_harvest", ["miles_cashout_card"], "")
E("mal_0348_tel_balance.eml",
  HD("话费服务", "hf@mobile-bal.example", "me@personal.example", "话费余额 1.2 元，今日停机")
  + "低额充值绿色通道（需服务密码）：https://hf-cz2.example.info/g\r\n",
  "malicious", "credential_harvest", ["balance_service_password"], "")
E("mal_0349_broadband_up.eml",
  HD("宽带提速", "kd@speed-up.example", "me@personal.example", "免费提速 500M 需确认设备")
  + "设备确认（宽带账号+服务密码）：https://kd-ts2.example.info/s\r\n",
  "malicious", "credential_harvest", ["broadband_password"], "")
E("mal_0350_car_insurance2.eml",
  HD("车险中心", "cx@auto-ins2.example", "driver@personal.example", "脱保预警：交强险 3 日后到期")
  + "在线续保直减 200（车牌+身份证+行驶证上传）：https://cx-xb2.example.vip/i\r\n",
  "malicious", "pii_harvest", ["insurance_upload_docs"], "续保收三证")
E("mal_0351_rent_platform.eml",
  HD("租房平台", "zf@rent-svc2.example", "me@personal.example", "房东设置了'看房保证金'")
  + "看房前需冻结 200 元保证金（退）：https://zf-bz2.example.info/f\r\n",
  "malicious", "social_trust", ["viewing_deposit"], "看房保证金骗局")
E("mal_0352_delivery_vip.eml",
  HD("快递会员", "kd-vip@express-club.example", "me@personal.example", "您符合快递年卡免费开通条件")
  + "开通需实名核验：https://kd-vip2.example.vip/o\r\n（身份证+人脸）\r\n",
  "malicious", "pii_harvest", ["delivery_vip_face"], "")

E("ham_0291_ship_arrive.eml",
  HD("顺丰速运", "sf@notice.sf.example", "me@personal.example", "快件派送中（预计今日达）")
  + "运单 SF1398xxxx8841 派送中，小哥电话见短信。\r\n", 
  "benign", "ham_personal", ["ship_real_simple"], "")
E("ham_0292_refund_done.eml",
  HD("商城", "service@shop.example", "me@personal.example", "退款已原路退回")
  + "39 元已退回原支付账户，1-3 日到账。\r\n本邮件无需任何操作。\r\n",
  "benign", "ham_personal", ["refund_real_original"], "原路退回+无需操作")
E("ham_0293_review_invite.eml",
  HD("商城", "review@shop.example", "me@personal.example", "邀请评价：保温杯")
  + "购买 7 天了，方便评价一下吗？\r\nApp 内直接评价，无任何奖励。\r\n",
  "benign", "ham_personal", ["review_real_no_reward"], "真评价邀请（无奖励诱导）")
E("ham_0294_member_monthly.eml",
  HD("会员中心", "vip@shop.example", "me@personal.example", "9月会员月报")
  + "本月共省 42 元，含运费券 4 张。\r\n明细在 App-会员-月报。\r\n",
  "benign", "ham_personal", ["member_report_real"], "")
E("ham_0295_logistics_except.eml",
  HD("中通快递", "zto@notice.example", "me@personal.example", "快件派送异常（天气原因）")
  + "受台风影响预计延迟 1-2 天，无需联系。\r\n恢复后自动派送。\r\n",
  "benign", "ham_personal", ["logistics_real_delay"], "")
E("ham_0296_aftersale_done.eml",
  HD("售后中心", "sh@shop.example", "me@personal.example", "换货已发出：新的水杯")
  + "换货已发出，旧件到仓后自动关闭售后单。\r\n",
  "benign", "ham_personal", ["aftersale_real_done"], "")
E("ham_0297_oa_notice.eml",
  HD("OA 系统", "oa@corp.internal", "all@corp.internal", "国庆值班表已发布")
  + "值班表在门户-行政-值班，请相关同事知悉。\r\n补贴按新标准。\r\n",
  "benign", "ham_business", ["oa_real_notice"], "")
E("ham_0298_expense_reject.eml",
  HD("财务共享", "fssc@corp.internal", "ma.chao@corp.internal", "报销单 BX-8842 被驳回")
  + "驳回原因：发票抬头错误。修改后在门户重新提交。\r\n平台内操作，无需邮件回复。\r\n",
  "benign", "ham_business", ["expense_reject_real_portal"], "驳回走内网")
E("ham_0299_vpn_maint.eml",
  HD("网络服务", "vpn@corp.internal", "remote@corp.internal", "VPN 周三晚例行维护")
  + "周三 22:00-24:00 例行维护，期间间歇可用。\r\n无升级，无需操作。\r\n",
  "benign", "ham_business", ["vpn_maint_real"], "")
E("ham_0300_payslip_pub.eml",
  HD("薪酬平台", "pay@corp.internal", "staff@corp.internal", "9月工资条已发布")
  + "门户-薪酬查看，问题三个工作日内提。\r\n平台不索要任何信息。\r\n",
  "benign", "ham_business", ["payslip_real_simple"], "")
E("ham_0301_card_ok.eml",
  HD("考勤系统", "att@corp.internal", "lu.meng@corp.internal", "补卡申请已通过")
  + "9/2 漏打卡已补，出勤正常。\r\n",
  "benign", "ham_business", ["card_real_ok"], "")
E("ham_0302_room_change2.eml",
  HD("会议室系统", "room@corp.internal", "staff@corp.internal", "您抢到的会议室被调换")
  + "5F-502 设备故障，自动调换为 5F-508，日历已同步。\r\n",
  "benign", "ham_business", ["room_real_auto_swap"], "")
E("ham_0303_forum_notify.eml",
  HD("内部论坛", "bbs@corp.internal", "dev@corp.internal", "您的帖子被加精")
  + "《网关排障一页纸》被加精并收录知识库。\r\n",
  "benign", "ham_business", ["forum_real_digest"], "")
E("ham_0304_sso_window.eml",
  HD("身份平台", "sso@corp.internal", "all@corp.internal", "SSO 周六升级（免登保留）")
  + "周六 02:00-04:00 升级，已登录会话保留。\r\n无需重新绑定。\r\n",
  "benign", "ham_business", ["sso_real_no_rebind"], "真 SSO 升级明确无需重绑")
E("ham_0305_grad_public.eml",
  HD("研究生院", "yjs@univ.example", "student@univ.example", "推免名单公示")
  + "推免名单今日起公示 10 日，异议发研招办邮箱。\r\n系统内可查。\r\n",
  "benign", "ham_business", ["grad_real_public"], "")
E("ham_0306_dorm_change.eml",
  HD("学生公寓", "gy@univ.example", "student@univ.example", "宿舍调换申请结果")
  + "调至紫荆 3-412，本周五前搬完。\r\n钥匙到楼长处换。\r\n",
  "benign", "ham_business", ["dorm_real_result"], "")
E("ham_0307_grade_out.eml",
  HD("教务处", "jwc@univ.example", "student@univ.example", "期中成绩已发布")
  + "成绩在教务系统查询，复查申请截止周五。\r\n系统内提交。\r\n",
  "benign", "ham_business", ["grade_real_system"], "")
E("ham_0308_checkup_done.eml",
  HD("体检中心", "report@checkup.example", "me@personal.example", "体检报告已出（两项随访）")
  + "纸质版已寄出；线上在小程序查看。\r\n医生解读另行预约。\r\n",
  "benign", "ham_personal", ["checkup_real_report"], "体检报告通知")
E("ham_0309_vaccine_book_ok.eml",
  HD("社区卫生", "sq@health.example", "me@personal.example", "流感疫苗预约成功")
  + "周四 15:00 带身份证接种，迟到需重约。\r\n小程序内可改期。\r\n",
  "benign", "ham_personal", ["vaccine_real_booked"], "")
E("ham_0310_insurance_year.eml",
  HD("车险中心", "cx@insurance.example", "driver@personal.example", "保单年度回顾")
  + "本年度出险 0 次，明年续保享无赔款优待。\r\n续保临近时官方渠道通知。\r\n",
  "benign", "ham_personal", ["insurance_real_review"], "")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch21 written: {len(LABELS)} samples")
