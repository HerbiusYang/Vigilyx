#!/usr/bin/env python3
"""Batch 26: consumer-finance/credit lures + real notices."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def HD(disp, frm, to, subj):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Sat, 19 Sep 2026 09:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b26@synth.example>\r\n"
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
def E(n, raw, label, family, tech, note=""):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": "zh", "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 26, "note": note})

E("mal_0421_grace_period.eml", HD("信用卡中心", "xk@card-grace7.example", "me@personal.example", "宽限期最后一天（免息分期可申请）")
  + "分期申请：https://xk-fq7.example.info/a\r\n（卡号+CVV+有效期）\r\n",
  "malicious", "credential_harvest", ["credit_grace_cvv"], "宽限期收 CVV")
E("mal_0422_reserve_fund.eml", HD("消费金融", "xf@reserve-fund7.example", "me@personal.example", "备用金 5 万已批（当日提现）")
  + "提现：https://xf-tx7.example.vip/c\r\n（银行卡+手机服务密码）\r\n",
  "malicious", "credential_harvest", ["reserve_fund_password"], "备用金收服务密码")
E("mal_0423_guarantee_off.eml", HD("担保服务", "db@guarantee-off7.example", "me@personal.example", "担保解除需结清单")
  + "结清单上传：https://db-jc7.example.info/u\r\n（身份证+还款流水）\r\n",
  "malicious", "pii_harvest", ["guarantee_release_docs"], "担保解除收件")
E("mal_0424_credit_fix.eml", HD("征信服务", "zx@credit-fix7.example", "me@personal.example", "征信修复（内部通道）")
  + "评估登记：https://zx-pg7.example.vip/r\r\n（身份证+手机服务密码）\r\n",
  "malicious", "credential_harvest", ["credit_repair_scam"], "征信修复灰产")
E("mal_0425_bad_debt.eml", HD("资产处置", "zc@debt-svc7.example", "me@personal.example", "呆账核销确认（影响购房）")
  + "核销确认：https://zc-hx7.example.info/c\r\n",
  "malicious", "account_phishing", ["bad_debt_pressure"], "呆账恐吓")
E("mal_0426_refi.eml", HD("贷款置换", "zh@refi-svc7.example", "me@personal.example", "高息置换低息（限期）")
  + "置换登记：https://zh-dj7.example.vip/s\r\n（身份证+原贷款合同号）\r\n",
  "malicious", "pii_harvest", ["refinance_lure"], "置换话术")
E("mal_0427_car_prepay.eml", HD("车贷服务", "cd@carloan7.example", "driver@personal.example", "提前结清违约金减免")
  + "减免申请：https://cd-jm7.example.info/a\r\n（车架号+身份证）\r\n",
  "malicious", "pii_harvest", ["carloan_fee_remit"], "违约金减免")
E("mal_0428_rate_swap.eml",
  HD("房贷服务", "fd@mortgage7.example", "me@personal.example", "利率转换 LPR 最后一批")
  + "转换登记：https://fd-lpr7.example.info/s\r\n（贷款合同号+身份证）\r\n",
  "malicious", "account_phishing", ["auto"], "b26fix")
E("mal_0429_coupon.eml", HD("消费券", "xfq@city-coupon7.example", "me@personal.example", "餐饮消费券待领取（48h）")
  + "领取：https://xfq-lq7.example.vip/g\r\n（微信登录授权）\r\n",
  "malicious", "account_phishing", ["coupon_wechat_auth"], "消费券收授权")
E("mal_0430_installment.eml", HD("分期服务", "fq@install7.example", "me@personal.example", "账单分期最后提醒（今日）")
  + "分期：https://fq-b7.example.info/d\r\n（卡号后四位+手机验证码）\r\n",
  "malicious", "pii_harvest", ["installment_sms"], "分期收验证码")
E("mal_0431_limit_up2.eml", HD("提额", "te@limit-up7.example", "me@personal.example", "固定额度评估通过")
  + "确认提额：https://te-tg7.example.vip/k\r\n（卡号+有效期+CVV+手机）\r\n",
  "malicious", "credential_harvest", ["limit_cvv_full"], "提额收全卡信息")
E("mal_0432_auto_deduct2.eml", HD("自动扣款", "zd@auto-deduct7.example", "me@personal.example", "免密扣款已开启（可关闭）")
  + "关闭需验证：https://zd-gb7.example.info/o\r\n（卡号+预留手机）\r\n",
  "malicious", "pii_harvest", ["auto_deduct_cancel"], "扣款关闭话术")
E("mal_0433_loan_rebate.eml", HD("贷款返佣", "fl@loan-rebate7.example", "me@personal.example", "推荐返现 888（可提）")
  + "提现：https://fl-tx7.example.vip/t\r\n（银行卡+验证码）\r\n",
  "malicious", "pii_harvest", ["rebate_withdraw"], "返佣提现")
E("mal_0434_credit_report2.eml", HD("征信中心", "zx@report-svc7.example", "me@personal.example", "年度报告未领取（影响贷款）")
  + "领取：https://zx-lq7.example.info/r\r\n（身份证+查询密码）\r\n",
  "malicious", "credential_harvest", ["credit_report_password"], "征信报告收查询密码")
E("mal_0435_paylater.eml",
  HD("先用后付", "xy@paylater7.example", "me@personal.example", "开通成功，首单立减 30")
  + "首单使用需确认收货地址与支付验证：https://xy-sd7.example.vip/f\r\n",
  "malicious", "account_phishing", ["auto"], "b26fix")
E("mal_0436_oyster_card.eml", HD("交通卡", "jt@transit7.example", "commuter@personal.example", "通勤卡年审（不审停用）")
  + "年审：https://jt-ns7.example.info/y\r\n（身份证+手机）\r\n",
  "malicious", "pii_harvest", ["transit_annual"], "通勤卡年审")
E("mal_0437_insurance_payback.eml", HD("保费返还", "bf@premium-back7.example", "me@personal.example", "多缴保费退还（税务要求）")
  + "退税登记：https://bf-tui7.example.vip/r\r\n（银行卡+身份证）\r\n",
  "malicious", "pii_harvest", ["premium_tax_refund"], "保费退还话术")
E("mal_0438_fund_frozen2.eml", HD("资金安全", "aq@fund-safe7.example", "me@personal.example", "理财账户临时冻结（异常赎回）")
  + "解冻核验：https://aq-jd7.example.info/u\r\n（交易密码+身份证）\r\n",
  "malicious", "credential_harvest", ["wealth_frozen_password"], "理财解冻收交易密码")
E("mal_0439_lottery_tax2.eml",
  HD("兑奖中心", "dj@prize-tax7.example", "me@personal.example", "奖金需先缴 20% 个人所得税")
  + "缴税后放款：https://dj-js7.example.vip/p\r\n",
  "malicious", "account_phishing", ["auto"], "b26fix")
E("mal_0440_hybrid_loan.eml", HD("组合贷", "zh@hybrid-loan7.example", "me@personal.example", "商转公名额释放（今日）")
  + "登记：https://zh-mg7.example.vip/s\r\n（公积金账号+密码）\r\n",
  "malicious", "credential_harvest", ["hybrid_loan_password"], "商转公收公积金密码")

E("ham_0381_card_bill.eml", HD("信用卡中心", "cc@bank.example", "me@personal.example", "10月账单已出")
  + "明细在手机银行查看；本邮件无链接。\r\n",
  "benign", "ham_personal", ["card_real_bill"], "真账单无链接")
E("ham_0382_repay_ok2.eml", HD("信用卡中心", "cc@bank.example", "me@personal.example", "还款成功 3,200 元")
  + "额度已恢复。\r\n",
  "benign", "ham_personal", ["repay_real_ok"], "")
E("ham_0383_credit_query.eml", HD("征信中心", "zx@pboc.example", "me@personal.example", "您的查询申请已受理")
  + "24 小时后在官网查看，本邮件无链接。\r\n",
  "benign", "ham_personal", ["credit_real_official"], "真征信只在官网")
E("ham_0384_fund_arrival.eml", HD("理财", "lc@bank.example", "me@personal.example", "理财赎回已到账")
  + "本金+收益已入关联账户。\r\n",
  "benign", "ham_personal", ["fund_real_arrival"], "")
E("ham_0385_coupon_real.eml", HD("消费券", "gov@city.example", "me@personal.example", "消费券已发放至您的账户")
  + "在指定 App-卡包查看使用规则。\r\n",
  "benign", "ham_personal", ["coupon_real_app"], "真消费券发 App")
E("ham_0386_limit_real.eml", HD("信用卡中心", "cc@bank.example", "me@personal.example", "额度评估结果")
  + "本次未调整，6 个月后自动再评。\r\n",
  "benign", "ham_personal", ["limit_real_result"], "")
E("ham_0387_insurance_real2.eml", HD("保单服务", "bd@insure.example", "me@personal.example", "保单年度红利通知书")
  + "红利分配见附件。\r\n",
  "benign", "ham_personal", ["insurance_real_dividend"], "")
E("ham_0388_transit_real2.eml", HD("交通卡", "jt@transit.example", "commuter@personal.example", "月度通勤账单")
  + "共 44 次，折扣明细见 App。\r\n",
  "benign", "ham_personal", ["transit_real_bill"], "与年审钓鱼同形")
E("ham_0389_paylater_real.eml", HD("先用后付", "xy@shop.example", "me@personal.example", "已按期结清（本月）")
  + "下月额度自动恢复。\r\n",
  "benign", "ham_personal", ["paylater_real_settled"], "")
E("ham_0390_auto_renew_real.eml", HD("订阅服务", "dy@svc.example", "me@personal.example", "自动续费前 3 日提醒")
  + "如需取消请在 App-订阅管理，本邮件无链接。\r\n",
  "benign", "ham_personal", ["autorenew_real_reminder"], "真续费提醒")
E("ham_0391_loan_bill2.eml", HD("贷款", "dk@bank.example", "me@personal.example", "10月还款计划")
  + "月供 4,321，代扣日 10 日。\r\n",
  "benign", "ham_personal", ["loan_real_plan"], "")
E("ham_0392_tax_receipt.eml", HD("个税", "gs@tax.example", "me@personal.example", "汇算退税已到账")
  + "请核对银行卡入账记录。\r\n",
  "benign", "ham_personal", ["tax_real_arrival"], "真退税到账")
E("ham_0393_fund_confirm.eml", HD("基金", "jj@fund.example", "me@personal.example", "申购确认单")
  + "确认份额见附件。\r\n",
  "benign", "ham_personal", ["fund_real_confirm"], "")
E("ham_0394_bank_msg2.eml", HD("银行", "yh@bank.example", "me@personal.example", "工资入账 12,840.05 元")
  + "余额变动通知，本邮件无链接。\r\n",
  "benign", "ham_personal", ["salary_real_notice"], "")
E("ham_0395_credit_up_real.eml", HD("信用卡中心", "cc@bank.example", "me@personal.example", "临时额度已生效")
  + "有效期见短信。\r\n",
  "benign", "ham_personal", ["temp_limit_real"], "")
E("ham_0396_insurance_due.eml", HD("保单服务", "bd@insure.example", "me@personal.example", "续期保费即将代扣")
  + "代扣账户为预留账户，无需操作。\r\n",
  "benign", "ham_personal", ["premium_real_autodeduct"], "")
E("ham_0397_stock_notice.eml", HD("券商", "qh@broker.example", "me@personal.example", "中签缴款通知")
  + "请保证账户余额，系统自动缴款。\r\n",
  "benign", "ham_personal", ["ipo_real_notice"], "")
E("ham_0398_pension.eml",
  HD("年金", "nj@hr.example", "employee@corp.internal", "企业年金账户季报")
  + "季报见附件，余额与收益明细。\r\n",
  "benign", "ham_business", ["auto"], "b26fix")
E("ham_0399_expense_card.eml", HD("行政", "xz@corp.internal", "staff@corp.internal", "公务卡激活提醒")
  + "本人至银行网点激活。\r\n",
  "benign", "ham_business", ["corp_card_real_offline"], "公务卡线下激活")
E("ham_0400_tax_education.eml", HD("财务", "cw@corp.internal", "all@corp.internal", "专项扣除填报培训（回放）")
  + "回放见内网学习平台。\r\n",
  "benign", "ham_business", ["tax_training_real"], "")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch26 written: {len(LABELS)} samples")
