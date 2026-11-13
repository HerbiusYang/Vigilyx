#!/usr/bin/env python3
"""Batch 23: edu/medical/gov expanded lures + real institution notices."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def HD(disp, frm, to, subj, ct="text/plain; charset=utf-8"):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Wed, 16 Sep 2026 09:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b23@synth.example>\r\n"
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\nContent-Type: {ct}\r\n\r\n")
def E(n, raw, label, family, tech, note="", lang="zh", fmt="plain"):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 23,
        "format": fmt, "note": note})

E("mal_0369_baoyan.eml",
  HD("推免工作组", "tm@univ-svc4.example", "student@univ.example", "保研材料预审未通过（补正）")
  + "补正入口：https://tm-bz4.example.org/f\r\n（学号+身份证+教务密码）\r\n",
  "malicious", "credential_harvest", ["baoyan_supplement"], "保研收教务密码")
E("mal_0370_dorm_swap.eml",
  HD("学生公寓", "gy@apart-svc4.example", "student@univ.example", "调宿申请需人脸核身")
  + "核身链接：https://gy-hs4.example.info/v\r\n",
  "malicious", "pii_harvest", ["dorm_face"], "")
E("mal_0371_sport_exam.eml",
  HD("体育部", "ty@pe-svc4.example", "student@univ.example", "体测补考报名（最后一批）")
  + "报名：https://ty-bk4.example.info/s\r\n（学号+手机+校园卡密码）\r\n",
  "malicious", "credential_harvest", ["sport_card_password"], "")
E("mal_0372_offer_deposit.eml",
  HD("Admissions", "admit@uni-abroad4.example", "student@mail.example", "Your offer requires a seat deposit")
  + "Secure your seat ($500): https://uni-abroad4.example/pay/seat\r\n",
  "malicious", "account_phishing", ["offer_seat_deposit"], "留学占位费", "en")
E("mal_0373_online_credit.eml",
  HD("继续教育", "jj@edu-svc4.example", "student@mail.example", "网课学分互认登记")
  + "登记：https://jj-hr4.example.org/r\r\n（身份证+学历备案号）\r\n",
  "malicious", "pii_harvest", ["credit_transfer_pii"], "")
E("mal_0374_oral_exam.eml",
  HD("考务", "ky@cet-svc4.example", "student@mail.example", "口语考试准考证补打")
  + "补打入口（新）：https://ky-bd4.example.info/p\r\n",
  "malicious", "account_phishing", ["oral_admit_new_link"], "四六级口语")
E("mal_0375_recommend_fee.eml",
  HD("学术服务", "xs@paper-svc4.example", "student@mail.example", "导师推荐信加急（费用代转）")
  + "加急需向导师助理转 800 元诚意金：\r\n6225 0091 7766 5544\r\n",
  "malicious", "bec", ["recommendation_fee_scam"], "推荐信付费灰产")
E("mal_0376_campus_loan.eml",
  HD("资助办", "zz@loan-help4.example", "student@mail.example", "校园贷利息减免（最后一批）")
  + "减免登记：https://zz-jm4.example.vip/a\r\n（学信网账号密码）\r\n",
  "malicious", "credential_harvest", ["campus_loan_chsi_password"], "收学信网密码")
E("mal_0377_registry_queue.eml",
  HD("挂号平台", "gh@clinic-svc4.example", "me@personal.example", "候补成功：专家号 1 个")
  + "确认候补（15分钟内）：https://gh-qr4.example.info/c\r\n（就诊卡号+密码）\r\n",
  "malicious", "credential_harvest", ["hospital_queue_password"], "")
E("mal_0378_medical_remote.eml",
  HD("医保中心", "yb@remote-svc4.example", "me@personal.example", "异地就医备案到期")
  + "续备案：https://yb-xu4.example.org/d\r\n（社保卡号+身份证）\r\n",
  "malicious", "pii_harvest", ["medical_remote_renew"], "")
E("mal_0379_prenatal.eml",
  HD("妇幼专项", "fy@health-svc4.example", "me@personal.example", "产检补助申领（未领）")
  + "申领：https://fy-sl4.example.info/g\r\n（孕周+身份证+银行卡）\r\n",
  "malicious", "pii_harvest", ["prenatal_subsidy"], "")
E("mal_0380_rx_delivery.eml",
  HD("药房配送", "yf@rx-delivery4.example", "me@personal.example", "处方药配送需补卡信息")
  + "补卡链接：https://yf-bk4.example.info/c\r\n（卡号+身份证）\r\n",
  "malicious", "pii_harvest", ["rx_delivery_card"], "处方药收卡")
E("mal_0381_gov_subsidy2.eml",
  HD("稳岗返还", "wg@hrss-svc4.example", "hr@corp.internal", "稳岗返还比例上调（需重报）")
  + "重报入口：https://wg-bb4.example.info/r\r\n（统一社会信用代码+经办人身份证）\r\n",
  "malicious", "subsidy_fraud", ["stable_post_rereport"], "稳岗返还话术")
E("mal_0382_ocr_years.eml",
  HD("年报服务", "nb@report-svc4.example", "legal@corp.internal", "年报填报代录（最后一天）")
  + "代录登记：https://nb-dl4.example.vip/e\r\n（执照+法人身份证）\r\n",
  "malicious", "pii_harvest", ["annual_report_agent"], "年报代录灰产")
E("mal_0383_car_plate.eml",
  HD("小客车调控", "kg@plate-svc4.example", "me@personal.example", "摇号资格待激活（编码过期）")
  + "激活：https://kg-jh4.example.info/a\r\n（身份证+手机服务密码）\r\n",
  "malicious", "credential_harvest", ["plate_service_password"], "")
E("mal_0384_violation.eml",
  HD("交管服务", "jg@traffic-notice4.example", "driver@personal.example", "新增违章 3 分 200 元（图片可查）")
  + "图片与处理：https://jg-wz4.example.info/v\r\n",
  "malicious", "account_phishing", ["traffic_violation_lure"], "违章话术")
E("mal_0385_housing_fund2.eml",
  HD("公积金", "gjj@fund-svc4.example", "employee@corp.internal", "按年冲还贷签约提醒")
  + "在线签约：https://gjj-qy4.example.org/s\r\n（公积金密码+银行卡）\r\n",
  "malicious", "credential_harvest", ["fund_sign_password"], "")

E("ham_0331_baoyan_real.eml",
  HD("推免工作组", "tm@univ.example", "student@univ.example", "预审意见已录入系统")
  + "意见在推免系统内查看，补正系统内上传。\r\n",
  "benign", "ham_business", ["baoyan_real_system"], "与保研钓鱼同形")
E("ham_0332_dorm_real2.eml",
  HD("学生公寓", "gy@univ.example", "student@univ.example", "调宿结果公示")
  + "结果在公寓服务号查询。\r\n",
  "benign", "ham_business", ["dorm_real_public"], "")
E("ham_0333_sport_real.eml",
  HD("体育部", "ty@univ.example", "student@univ.example", "体测缓测安排")
  + "缓测下周三，教务系统报名。\r\n",
  "benign", "ham_business", ["sport_real_reschedule"], "")
E("ham_0334_admit_real.eml",
  HD("Admissions", "admit@univ.example", "student@mail.example", "Offer package sent (portal)")
  + "Your offer is in the applicant portal (existing login):\r\nhttps://apply.univ.example/status\r\n",
  "benign", "ham_business", ["offer_real_portal"], "", "en")
E("ham_0335_cet_real2.eml",
  HD("考务办", "kw@univ.example", "student@mail.example", "口语考试时间公布")
  + "时间在准考证（报名系统内打印），谨防山寨补打网站。\r\n",
  "benign", "ham_business", ["cet_real_warn"], "")
E("ham_0336_hospital_real2.eml",
  HD("挂号平台", "gh@hospital.example", "me@personal.example", "候补提醒（未成功）")
  + "本周候补未成功，下周自动顺延。\r\n小程序内可取消。\r\n",
  "benign", "ham_personal", ["queue_real_pending"], "与候补钓鱼同形")
E("ham_0337_yibao_real.eml",
  HD("医保中心", "yb@gov.example", "me@personal.example", "异地就医备案成功")
  + "备案已生效，凭证在医保 App。\r\n",
  "benign", "ham_personal", ["yibao_real_done"], "备案成功通知")
E("ham_0338_vaccine_real2.eml",
  HD("社区卫生", "sq@health.example", "me@personal.example", "儿童疫苗第2剂次提醒")
  + "周五 14:00，带接种本。\r\n",
  "benign", "ham_personal", ["vaccine_real_reminder"], "")
E("ham_0339_plate_real.eml",
  HD("小客车调控", "kg@gov.example", "me@personal.example", "本期摇号未中（编码保留）")
  + "编码自动保留，下期继续。\r\n官网可查。\r\n",
  "benign", "ham_personal", ["plate_real_result"], "与摇号钓鱼同形")
E("ham_0340_violation_real.eml",
  HD("交管12123", "jg@gov.example", "driver@personal.example", "新增一条违法记录（官方App处理）")
  + "请登录交管 12123 App 查看与处理。\r\n本邮件无链接。\r\n",
  "benign", "ham_personal", ["violation_real_app_only"], "真违章只在官方 App")
E("ham_0341_fund_real2.eml",
  HD("公积金中心", "gjj@gov.example", "employee@corp.internal", "年度结息完成")
  + "结息已入账，明细在公积金 App。\r\n",
  "benign", "ham_personal", ["fund_real_interest"], "")
E("ham_0342_socsec_real.eml",
  HD("社保", "sb@gov.example", "employee@corp.internal", "社保年度基数申报完成")
  + "已按新基数申报，个人部分明细见 App。\r\n",
  "benign", "ham_business", ["social_real_done"], "")
E("ham_0343_library_real2.eml",
  HD("图书馆", "lib@city.example", "me@personal.example", "借阅到期（可在线续借）")
  + "小程序-我的-续借。\r\n",
  "benign", "ham_personal", ["library_real_renew"], "")
E("ham_0344_museum_real.eml",
  HD("省博物馆", "bwg@culture.example", "me@personal.example", "特展预约成功")
  + "周六 10:00 场，凭二维码入馆。\r\n",
  "benign", "ham_personal", ["museum_real_ticket"], "")
E("ham_0345_game_real.eml",
  HD("游戏平台", "svc@game.example", "me@personal.example", "赛季结算与奖励")
  + "段位与奖励已发放，客户端内查看。\r\n",
  "benign", "ham_personal", ["game_real_season"], "赛季结算通知")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch23 written: {len(LABELS)} samples")
