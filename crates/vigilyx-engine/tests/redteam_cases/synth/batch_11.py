#!/usr/bin/env python3
"""Batch 11: individually authored (subsidy/supply-chain/B2B lures + org ham)."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def H(disp, frm, to, subj, extra=""):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Thu, 03 Sep 2026 09:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b11@synth.example>\r\n" + extra +
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\n")
P = "Content-Type: text/plain; charset=utf-8\r\n\r\n"
def E(n, raw, label, family, tech, note="", lang="zh"):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": lang, "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 11, "note": note})

E("mal_0171_tradein_subsidy.eml",
  (H("以旧换新", "bt@gov-subsidy.example", "me@personal.example", "家电以旧换新补贴资格待确认") + P +
   "您申请的国家补贴（一级能效 20%）资格待确认，今日失效：\r\n"
   "https://bt-confirm.example.info/v\r\n"
   "（身份证号+银行卡号领取）\r\n").encode(),
  "malicious", "subsidy_fraud", ["tradein_subsidy_collect"], "国家补贴话术（2025-26 高发）")

E("mal_0172_dcep_red.eml",
  (H("数字人民币", "hd@dcep-pilot.example", "me@personal.example", "试点红包待领取（48小时）") + P +
   "您被纳入数字人民币试点红包名单，领取需开通钱包：\r\n"
   "https://dcep-hongbao.example.vip/l\r\n"
   "（手机号+银行卡+验证码）\r\n").encode(),
  "malicious", "pii_harvest", ["dcep_red_collect"], "")

E("mal_0173_birth_allow.eml",
  (H("生育津贴", "sy@rsj-svc.example", "employee@corp.internal", "生育津贴申领（材料补交）") + P +
   "津贴申领缺一项材料，请补交：\r\n"
   "https://sy-bu.example.org/j\r\n"
   "（夫妻双方身份证号+出生证明编号+银行卡）\r\n").encode(),
  "malicious", "pii_harvest", ["birth_allow_collect"], "")

E("mal_0174_heat_allow.eml",
  (H("人社服务", "rs@hot-subsidy.example", "outdoor@corp.internal", "高温补贴集中申领（本周）") + P +
   "户外岗位高温补贴可线上申领：\r\n"
   "https://hot-apply.example.info/g\r\n"
   "（身份证号+社保卡号）\r\n").encode(),
  "malicious", "subsidy_fraud", ["heat_allow_collect"], "")

E("mal_0175_tax_refund2.eml",
  (H("个税服务", "hs@tax-refund2.example", "staff@corp.internal", "2025年度汇算有可退税款") + P +
   "经初步核算您有 3,180 元可退，确认退税信息：\r\n"
   "https://hs-tui.example.co/r\r\n"
   "（身份证号+I卡号+个税APP密码）\r\n").encode(),
  "malicious", "credential_harvest", ["tax_refund_collect"], "退税季高发")

E("mal_0176_invoice_prize.eml",
  (H("有奖发票", "jx@invoice-prize.example", "me@personal.example", "您的发票中了二等奖") + P +
   "发票兑奖需登记收款信息：\r\n"
   "https://fp-jiang.example.info/d\r\n"
   "（发票代码+号码+银行卡）\r\n").encode(),
  "malicious", "pii_harvest", ["invoice_prize_collect"], "")

E("mal_0177_parking_bid.eml",
  (H("招投标平台", "zb@parking-proj.example", "bd@corp.internal", "智慧停车项目保证金缴纳通知") + P +
   "贵司已通过资格预审，需在明日 17:00 前缴纳投标保证金 80,000 元：\r\n"
   "https://zb-bond.example.org/pay（对公+经办人U盾）\r\n"
   "逾期视为弃标。\r\n").encode(),
  "malicious", "bec", ["bid_bond_urgency"], "B2B 采购定向")

E("mal_0178_supplier_audit2.eml",
  (H("采购中心", "sc@supplier-au.example", "vendor@corp.internal", "供应商资质年审（电子签章）") + P +
   "年度资质审需重新电子签章：\r\n"
   "https://sc-au.example.info/sign\r\n"
   "（营业执照号+法人身份证+对公账户）\r\n").encode(),
  "malicious", "pii_harvest", ["supplier_audit_collect"], "供应商定向")

E("mal_0179_export_rebate.eml",
  (H("退税代理", "dl@export-dl.example", "trade@corp.internal", "出口退税加急代办（最快3日）") + P +
   "专业代办出口退税，需提供报关单+增值税发票+对公账户预留信息：\r\n"
   "对接加微信 tuidl-886（备注公司名）。\r\n").encode(),
  "malicious", "bec", ["export_rebate_agent"], "灰产代办")

E("mal_0180_npm_supply.eml",
  (H("npm security", "advisory@npm-sec.example", "dev@corp.internal", "[CRITICAL] dependency update required") + P +
   "Your lockfile references a compromised package. Apply the fix immediately:\r\n"
   "https://npm-sec-fix.example.info/patch\r\n"
   "(One-click patch requires registry login.)\r\n").encode(),
  "malicious", "account_phishing", ["fake_supply_chain_advisory"], "供应链安全仿冒", "en")

E("mal_0181_docker_notify.eml",
  (H("Docker Hub", "notice@docker-sec.example", "dev@corp.internal", "Image flagged: policy violation") + P +
   "Your image gateway:1.9.4 was flagged. Review and re-push after remediation:\r\n"
   "https://docker-remediate.example.co/img\r\n").encode(),
  "malicious", "account_phishing", ["fake_docker_notice"], "英文研发定向", "en")

E("mal_0182_github_sec.eml",
  (H("GitHub Security", "sec@github-alert.example", "dev@corp.internal", "Security advisory affects your repo") + P +
   "CVE-2026-3391 affects vigilyx/gateway. Patch branch auto-generated:\r\n"
   "https://github-alert.example.net/patch/vigilyx\r\n"
   "(Sign in with your credentials to merge.)\r\n").encode(),
  "malicious", "credential_harvest", ["fake_github_advisory"], "收源站凭据", "en")

E("mal_0183_edr_quarantine.eml",
  (H("终端安全", "edr@sec-endpoint.example", "it@corp.internal", "您的终端已被隔离（检测到木马）") + P +
   "终端检测到远控木马，已网络隔离。\r\n"
   "自助解除（需管理员账号）：https://edr-unlock.example.info/r\r\n"
   "10 分钟内未处理将上报安全部。\r\n").encode(),
  "malicious", "credential_harvest", ["fake_edr_unlock"], "假杀软恐吓")

E("mal_0184_cncvd.eml",
  (H("CNCVD", "report@vuln-report.example", "sec@corp.internal", "贵司系统存在高危漏洞（已测绘）") + P +
   "测绘发现贵司对外系统存在未授权访问漏洞，详情与修复指引：\r\n"
   "https://vuln-detail.example.org/d\r\n"
   "（需负责人手机号+验证码查看）\r\n").encode(),
  "malicious", "credential_harvest", ["fake_vuln_report"], "漏洞通报仿冒")

E("mal_0185_toner_scam.eml",
  (H("耗材服务", "hc@printer-supply.example", "admin@corp.internal", "打印耗材续订确认（老客户价）") + P +
   "按合同为您预留本季度耗材，回签确认后发货：\r\n"
   "确认单：https://hc-confirm.example.info/s\r\n"
   "（采购负责人签字+对公信息核对）\r\n").encode(),
  "malicious", "bec", ["toner_b2b_scam"], "经典 B2B 耗材骗局")

E("mal_0186_nanyan_fee.eml",
  (H("资质年费", "sv@nanyan-svc.example", "webmaster@corp.internal", "ICP备案年检费 360 元待缴") + P +
   "系统显示您的备案年检费未缴（360 元），今日未缴将注销：\r\n"
   "https://nianjian-pay.example.vip/f\r\n").encode(),
  "malicious", "account_phishing", ["fake_icp_fee"], "备案本身免费——伪造成本")

E("mal_0187_meitu_face.eml",
  (H("美术宝", "kf@art-edu.example", "parent@mail.example", "课程赠品画板待领取（人脸核销）") + P +
   "赠品需家长人脸核销领取：\r\n"
   "https://art-hexiao.example.club/v\r\n"
   "（家长人脸+手机号）\r\n").encode(),
  "malicious", "pii_harvest", ["face_verify_collect"], "")

E("mal_0188_poster_fee.eml",
  (H("会议出版", "pub@ieee-like.example", "research@corp.internal", "Poster accepted - publication fee") + P +
   "Your poster is accepted for the proceedings. Publication fee 260 USD:\r\n"
   "https://ieee-like-pay.example.org/fee\r\n").encode(),
  "malicious", "account_phishing", ["poster_publication_fee"], "学术海报收费", "en")

E("mal_0189_coauthor.eml",
  (H("Prof. Gao", "gao@intl-acad.example", "research@corp.internal", "Co-authorship invitation") + P +
   "I read your recent work and would like to invite you as co-author.\r\n"
   "Registration through our portal is required first: https://acad-reg.example.info/j\r\n").encode(),
  "malicious", "account_phishing", ["predatory_coauthor"], "掠夺性期刊邀署名", "en")

E("mal_0190_driver_margin.eml",
  (H("网约车服务", "sj@ride-svc.example", "driver@personal.example", "司机账号激活（保证金 299）") + P +
   "注册成功，缴激活保证金后接单：\r\n"
   "https://ride-act.example.vip/m\r\n"
   "满 300 单全退。\r\n").encode(),
  "malicious", "pii_harvest", ["driver_deposit"], "")

E("ham_0171_dependabot.eml",
  (H("GitHub", "noreply@github.example", "dev@corp.internal", "[SECURITY] Dependabot alert on vigilyx") + P +
   "Dependabot found 2 alerts (moderate) in vigilyx/gateway.\r\n"
   "Review: https://github.example/vigilyx/gateway/security/dependabot\r\n"
   "Automated patch PRs already opened against default branch.\r\n").encode(),
  "benign", "ham_business", ["real_dependabot"], "真供应链告警（官方域+只读通知）", "en")

E("ham_0172_soc_weekly.eml",
  (H("安全运营中心", "soc@corp.internal", "it-all@corp.internal", "SOC 周报（第35周）") + P +
   "本周：拦截钓鱼 37 封、恶意附件 6 个；一处弱口令已整改。\r\n"
   "钓鱼演练点击率 4.2%，环比降 1pt。\r\n").encode(),
  "benign", "ham_business", ["soc_weekly"], "")

E("ham_0173_edr_handled.eml",
  (H("终端安全", "edr@corp.internal", "it@corp.internal", "已处置：财务部一台终端误报解除") + P +
   "EDR 对一台终端的告警经分析为误报（加密备份进程），已恢复网络。\r\n"
   "样本已入白名单，无需用户操作。\r\n").encode(),
  "benign", "ham_business", ["edr_real_handled"], "与假 EDR 恐吓同形（真件不索账号）")

E("ham_0174_toner_real.eml",
  (H("行政-采购", "purchasing@corp.internal", "admin@corp.internal", "耗材季度订单已下单") + P +
   "按库存预警自动补货完成（硒鼓 x4、A4 纸 x20 箱），\r\n"
   "供应商对公结算，物流周五到。\r\n").encode(),
  "benign", "ham_business", ["toner_real_internal"], "与耗材骗局同形（走内部采购）")

E("ham_0175_bid_platform.eml",
  (H("政采平台", "notify@ccgp-like.example", "bd@corp.internal", "项目开标提醒：智慧停车（9/10）") + P +
   "您响应的项目将于 9/10 09:30 开标，请按时解密投标文件。\r\n"
   "平台内操作，勿信任何加急缴费通知。\r\n").encode(),
  "benign", "ham_business", ["real_bid_platform"], "与假保证金同形（真平台自带反诈提示）")

E("ham_0176_export_progress.eml",
  (H("财务-税务", "tax@corp.internal", "trade@corp.internal", "7月出口退税进度") + P +
   "7 月批次退税已进入国库审核，预计本周到账。\r\n"
   "单证在税务系统可查，有疑义找小蔡。\r\n").encode(),
  "benign", "ham_business", ["export_real_progress"], "与代办灰产同形")

E("ham_0177_camping_list.eml",
  (H("工会", "union@corp.internal", "outing@corp.internal", "露营装备共享清单") + P +
   "帐篷/天幕/炉头公司有几套可借，先到先登记。\r\n"
   "睡袋自备，山里夜里 12 度。\r\n").encode(),
  "benign", "ham_business", ["camping"], "")

E("ham_0178_basketball.eml",
  (H("篮球社", "nba@corp.internal", "club@corp.internal", "周四训练改室内馆") + P +
   "下雨改室内，7:30 老地方，分队打半场。\r\n"
   "新买的训练背心到了。\r\n").encode(),
  "benign", "ham_business", ["basketball"], "")

E("ham_0179_ac_clean.eml",
  (H("物业服务中心", "pmu@community.example", "owner@list.example", "本周空调滤网集中清洗") + P +
   "公共区域与入户（预约制）滤网清洗开始，入户请到群里接龙。\r\n"
   "免费，自住优先。\r\n").encode(),
  "benign", "ham_personal", ["ac_clean"], "")

E("ham_0180_elevator.eml",
  (H("物业服务中心", "pmu@community.example", "owner@list.example", "电梯年度维保（周六停梯一部）") + P +
   "周六 9:00-17:00 维保 2 号梯，1 号梯正常运行。\r\n"
   "搬运大件请避开。\r\n").encode(),
  "benign", "ham_personal", ["elevator_maintenance"], "")

E("ham_0181_lanyard.eml",
  (H("行政", "admin@corp.internal", "all-staff@corp.internal", "新挂绳到货（自取）") + P +
   "新春款挂绳在前台，旧换新自愿，工牌本体不动。\r\n"
   "剩最后两箱。\r\n").encode(),
  "benign", "ham_business", ["lanyard"], "")

E("ham_0182_holiday_bus.eml",
  (H("行政-车队", "fleet@corp.internal", "campus@corp.internal", "节前班车末班提前") + P +
   "中秋前最后一个工作日末班车提前至 16:30 发车，\r\n"
   "加班请自行安排。\r\n").encode(),
  "benign", "ham_business", ["holiday_shuttle"], "")

E("ham_0183_mid_autumn.eml",
  (H("人资", "hr@corp.internal", "all-staff@corp.internal", "中秋节放假安排") + P +
   "9/25-9/27 放假三天，9/28（周日）上班。\r\n"
   "值班表走老流程，节前安全自查另行通知。\r\n").encode(),
  "benign", "ham_business", ["mid_autumn"], "")

E("ham_0184_national_duty.eml",
  (H("行政台", "admin-desk@corp.internal", "leaders@corp.internal", "国庆值班表（草案）") + P +
   "草案见附件，有问题今天内回，明早报备。\r\n"
   "值班补贴按新标准执行。\r\n").encode(),
  "benign", "ham_business", ["national_duty_roster"], "")

E("ham_0185_gala_show.eml",
  (H("年会组委会", "nh@corp.internal", "all-staff@corp.internal", "年会节目征集（10/15 截止）") + P +
   "节目不限形式，往年天花板是运维的太极。\r\n"
   "报名找组委会小江。\r\n").encode(),
  "benign", "ham_business", ["gala_show"], "")

E("ham_0186_book_donate.eml",
  (H("读书会", "books@corp.internal", "all-staff@corp.internal", "部门书角募书") + P +
   "3F 书角开放捐书，技术人文皆可，写名字贴纸在行政台。\r\n"
   "满 200 本解锁新书架。\r\n").encode(),
  "benign", "ham_business", ["book_donate"], "")

E("ham_0187_wiki_digest.eml",
  (H("知识库", "wiki-bot@corp.internal", "all-staff@corp.internal", "本周知识库精选") + P +
   "《灰度发布手册》v2、《新员工第一周》重写、\r\n"
   "网关超时排查一页纸。投稿通道常开。\r\n").encode(),
  "benign", "ham_business", ["wiki_digest"], "")

E("ham_0188_tech_video.eml",
  (H("技术委员会", "tc@corp.internal", "dev@corp.internal", "Rust 专题分享回放已上传") + P +
   "上周三场 Rust 专题回放在知识库-视频区，含 slido 提问整理。\r\n"
   "下期主题征集里 Docker 票数领先。\r\n").encode(),
  "benign", "ham_business", ["tech_video"], "")

E("ham_0189_conf_group.eml",
  (H("技术委员会", "tc@corp.internal", "dev@corp.internal", "QCon 团票报名（统一报销）") + P +
   "今年 QCon 组团，门票统一采购后按参加场次报销 70%，\r\n"
   "报名走技术委员会频道，周五截止。\r\n").encode(),
  "benign", "ham_business", ["conf_group_ticket"], "")

E("ham_0190_cert_reimburse.eml",
  (H("培训平台", "learn@corp.internal", "staff@corp.internal", "认证考试费用报销规则") + P +
   "CKA/CKS 首考通过全额报销，补考不报；\r\n"
   "发票抬头开公司，走培训专项。\r\n").encode(),
  "benign", "ham_business", ["cert_reimburse"], "")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch11 written: {len(LABELS)} samples")
