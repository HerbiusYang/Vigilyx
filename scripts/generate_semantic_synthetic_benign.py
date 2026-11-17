#!/usr/bin/env python3
"""Generate synthetic benign mail for the semantic text classifier.

The two research corpora have almost no institutional notices among their
benign rows (E-PhishLLM benign mail is colleague correspondence, Fraud-R1 has
no benign rows), so a classifier trained on them learns "talks about accounts,
payments or verification" as a phishing signal. This generator composes
benign notices and ordinary correspondence in Chinese and English from
sentence pools: bank and card notices, account security alerts that point to
official channels, tax and social insurance reminders, platform orders,
enterprise IT/HR/finance mail, anti-fraud awareness bulletins, business
payment schedules and personal mail.

Only benign mail is generated. Every record is labelled benign and carries a
`notice_type`; the classifier split assigns whole notice types to one side,
so dev and test measure unseen notice types. Organisation names, domains and
phone numbers are fictional. Output follows the semantic_external_harness
case schema. Deterministic for a given seed. Python 3.9 compatible.
"""

import argparse
import hashlib
import json
from pathlib import Path
import random

DATASET = "vigilyx-synthetic-benign"

# ---------------------------------------------------------------------------
# Shared Chinese pools
# ---------------------------------------------------------------------------

ZH_CITIES = ["临江", "东湖", "云川", "青禾", "南屿", "北岭", "西泽", "安平", "长汀", "白沙", "宁远", "清河"]
ZH_SURNAMES = list("王李张刘陈杨黄赵吴周徐孙马朱胡郭何林罗高郑梁谢宋唐韩冯")
ZH_GIVEN = ["伟", "芳", "敏", "静", "磊", "洋", "艳", "杰", "娟", "涛", "明", "超", "霞", "平", "刚", "婷", "鹏", "丽", "强", "晨", "宇", "欣", "浩", "倩"]
ZH_DEPTS = ["财务部", "人力资源部", "信息技术部", "行政部", "采购部", "市场部", "销售部", "法务部", "研发中心", "客户服务中心", "运营部", "审计部"]
ZH_COMPANIES = ["{city}远航科技有限公司", "{city}启明信息技术有限公司", "{city}恒泰贸易有限公司", "{city}联创制造有限公司",
                "{city}嘉禾物流有限公司", "{city}瑞丰食品有限公司", "{city}博远咨询有限公司", "{city}明德教育科技有限公司",
                "{city}海川建设工程有限公司", "{city}安和医疗器械有限公司"]
ZH_SALUTATIONS = ["尊敬的客户：", "尊敬的{name}先生/女士：", "{name}，您好：", "您好！", "尊敬的用户，您好：", "各位同事：",
                  "亲爱的{name}：", "{name}您好，", "尊敬的会员：", ""]
ZH_CLOSINGS = ["感谢您的支持与配合！", "特此通知。", "祝您生活愉快！", "如有疑问，欢迎随时咨询。", "谢谢！", "此致\n敬礼",
               "祝工作顺利！", "感谢您的理解。", ""]
ZH_OFFICIAL_CHANNELS = ["官方App", "官方网站（请手动输入网址访问）", "官方微信公众号", "营业网点", "官方客服热线"]
ZH_NEVER_ASK = [
    "我们的工作人员不会以任何理由向您索要密码、短信验证码或银行卡完整信息。",
    "请注意：本通知不包含任何需要您输入密码的链接，请勿向任何人透露验证码。",
    "我们不会通过电话、短信或邮件要求您转账、提供验证码或下载远程控制软件。",
    "如收到自称本机构工作人员要求转账或提供验证码的信息，请勿理会，并通过官方渠道核实。",
    "本邮件为系统自动发送，请勿直接回复。",
    "温馨提示：请妥善保管个人信息，谨防诈骗。",
]

# ---------------------------------------------------------------------------
# Chinese notice types: subjects, intro, detail and action pools.
# Placeholders: {org} {name} {date} {date2} {time} {amount} {last4} {order}
# {days} {company} {dept} {person} {city} {project} {pct} {count}
# ---------------------------------------------------------------------------

ZH_TYPES = {
    "bank_transaction": {
        "orgs": ["{city}农商银行", "{city}商业银行", "华岳银行", "安泰银行", "兴和银行"],
        "subjects": ["账户动账提醒", "交易提醒", "您的账户有一笔交易", "{org}动账通知", "尾号{last4}账户资金变动提醒"],
        "intro": ["您尾号{last4}的账户于{date} {time}发生一笔交易，交易金额人民币{amount}元。",
                  "您尾号{last4}的借记卡于{date}{time}完成一笔转入，金额{amount}元，当前状态为已入账。",
                  "您尾号{last4}的信用卡于{date}在商户“{city}百货”消费{amount}元。"],
        "details": ["交易类型：{txn}。", "交易渠道：{channel}。", "可用余额请以{org}官方App查询结果为准。", "本笔交易已于{date}完成清算。"],
        "actions": ["如为本人操作，请忽略本提醒。", "如非本人操作，请立即拨打卡片背面的客服电话或登录{org}官方App冻结卡片。",
                    "您可登录{org}官方App在“账户明细”中查看交易详情。", "无需进行任何操作。"],
        "slots": {"txn": ["消费", "代发工资", "转账转入", "快捷支付", "自动还款", "水电缴费"],
                  "channel": ["手机银行", "POS消费", "网上银行", "柜面", "第三方支付"]},
    },
    "card_statement": {
        "orgs": ["华岳银行信用卡中心", "安泰银行信用卡中心", "{city}商业银行信用卡部"],
        "subjects": ["{month}月信用卡电子账单", "信用卡还款提醒", "您的信用卡账单已出", "本期账单通知"],
        "intro": ["您尾号{last4}的信用卡本期账单已出，本期应还金额{amount}元，最后还款日为{date}。",
                  "温馨提醒：您尾号{last4}的信用卡本期最低还款额为{amount2}元，到期还款日{date}。",
                  "您{month}月的信用卡电子账单已生成，账单周期为{date2}至{date}。"],
        "details": ["本期新增消费{count}笔，分期待还{amount2}元。", "您已开通自动还款，系统将于到期还款日从您绑定的本人借记卡扣款。",
                    "本期积分新增{count}分，可在官方App积分商城查看。", "账单明细见附件PDF，打开密码为您身份证号后六位。"],
        "actions": ["您可通过{org}官方App、网上银行或柜面办理还款。", "如已还款，请忽略本提醒。",
                    "如对账单有疑问，请拨打信用卡背面的客服电话。", "请确保绑定还款账户余额充足。"],
        "slots": {},
    },
    "account_security": {
        "orgs": ["华岳银行", "安泰银行", "云川网络", "星河云盘", "{city}政务服务平台", "青禾支付"],
        "subjects": ["账户登录提醒", "新设备登录通知", "密码修改成功", "安全设置变更提醒", "您的账户在新设备登录"],
        "intro": ["您的账户于{date} {time}在一台新设备上登录，登录地点：{city}。",
                  "您于{date}成功修改了登录密码。", "您的账户绑定手机号已于{date}变更成功。",
                  "我们检测到您的账户于{date}在{city}登录，与您常用地点不同。"],
        "details": ["设备类型：{device}。", "如为您本人操作，无需处理。", "登录方式：{method}。"],
        "actions": ["如非本人操作，请打开{org}官方App，在“设置-账号安全”中修改密码并下线其他设备。",
                    "如非本人操作，请通过官方客服热线联系我们，我们会协助您冻结账户。",
                    "建议您定期在官方App内检查已登录设备。", "如为本人操作，请忽略本邮件。"],
        "slots": {"device": ["iPhone", "Android手机", "Windows电脑", "Mac电脑", "平板电脑"],
                  "method": ["密码登录", "短信验证码登录", "扫码登录", "指纹登录"]},
        "never_ask": True,
    },
    "kyc_update": {
        "orgs": ["华岳银行", "安泰银行", "{city}农商银行", "兴和证券", "安和保险"],
        "subjects": ["客户身份信息更新提示", "您的证件即将到期", "请及时更新预留身份证件", "客户信息核验提醒"],
        "intro": ["根据反洗钱相关规定，您在我行预留的身份证件将于{date}到期。",
                  "系统显示您登记的有效身份证件已过期，为不影响您正常办理业务，请及时更新。",
                  "按照监管要求，我们需要定期核验客户身份信息。"],
        "details": ["证件到期后，部分非柜面业务可能受到限制，已有存款和资金安全不受影响。",
                    "更新完成后，相关限制将自动解除。", "本次更新不收取任何费用。"],
        "actions": ["您可携带本人有效身份证件原件到任一营业网点办理，或在{org}官方App“我的-个人信息”中自助更新。",
                    "请通过{org}官方App上传新证件，切勿通过任何陌生链接或第三方提交身份证照片。",
                    "如需协助，请拨打官方客服热线或前往附近网点。"],
        "slots": {},
        "never_ask": True,
    },
    "investment_notice": {
        "orgs": ["兴和证券", "华岳基金", "星河证券", "安泰银行理财子公司"],
        "subjects": ["投资者适当性评估到期提醒", "产品到期兑付公告", "基金分红公告", "交易规则调整通知", "理财产品净值披露"],
        "intro": ["您持有的“{product}”已于{date}到期，本金及收益将于{days}个工作日内划转至您的本人资金账户。",
                  "您的风险承受能力评估结果将于{date}到期。", "{org}旗下“{product}”将于{date}实施分红，每份派发现金红利{small}元。",
                  "根据交易所业务规则调整，自{date}起部分交易时间安排有所变化。"],
        "details": ["分红款将直接计入您的资金账户，无需额外操作。", "历史业绩不代表未来表现，投资需谨慎。",
                    "详细信息请以公司官网公告为准。", "评估到期后将无法购买高于当前风险等级的产品。"],
        "actions": ["请登录{org}官方App完成风险测评。", "如有疑问，可咨询您的客户经理或拨打官方客服热线。", "本通知仅作告知，无需回复。"],
        "slots": {"product": ["稳健增利一号", "季季盈", "安享365天", "均衡成长混合", "中短债精选"],
                  "small": ["0.012", "0.035", "0.008", "0.020"]},
        "never_ask": True,
    },
    "insurance": {
        "orgs": ["安和保险", "华岳人寿", "泰康安心财险", "{city}平安车险服务中心"],
        "subjects": ["保单续期缴费提醒", "理赔进度通知", "保单生效通知", "车险到期提醒"],
        "intro": ["您的保单（尾号{last4}）将于{date}到期，续期保费为{amount}元。",
                  "您提交的理赔申请（案件号{order}）已审核通过，理赔金额{amount}元。",
                  "您投保的保单已于{date}生效，保单号尾号{last4}。"],
        "details": ["理赔款将转入您申请时登记的本人银行账户，预计{days}个工作日到账。",
                    "理赔过程不收取任何手续费、保证金或解冻费。", "续期保费将按约定从您授权的账户扣缴。"],
        "actions": ["您可在{org}官方App查看理赔进度。", "如需变更扣款账户，请本人通过官方App或柜面办理。",
                    "如有疑问请拨打官方客服热线。"],
        "slots": {},
        "never_ask": True,
    },
    "tax": {
        "orgs": ["{city}市税务局", "国家税务总局{city}市税务局", "{city}市电子税务局"],
        "subjects": ["个人所得税年度汇算提醒", "纳税申报期提醒", "发票开具通知", "税费缴纳提醒"],
        "intro": ["{year}年度个人所得税综合所得汇算清缴将于{date}截止。",
                  "本月纳税申报期截止日为{date}，请按时完成申报。", "您申请开具的电子发票已开具完成，发票金额{amount}元。"],
        "details": ["需要退税的纳税人，退税款将退至您本人在系统中登记的银行账户。",
                    "税务机关不会通过短信链接或电话要求您缴纳“手续费”或“保证金”。", "逾期未申报可能影响纳税信用。"],
        "actions": ["请通过官方个人所得税App或电子税务局网站办理。", "请登录电子税务局下载发票。",
                    "如需帮助，可拨打纳税服务热线或前往办税服务厅咨询。"],
        "slots": {},
    },
    "social_insurance": {
        "orgs": ["{city}市人力资源和社会保障局", "{city}市医疗保障局", "{city}住房公积金管理中心"],
        "subjects": ["社保缴费基数调整通知", "城乡居民医保缴费提醒", "公积金年度结息通知", "社保卡年审提醒"],
        "intro": ["{year}年度社会保险缴费基数将于{date}起调整。", "{year}年度城乡居民医疗保险集中缴费期为{date2}至{date}。",
                  "您的住房公积金账户已完成年度结息，结息金额{amount}元。"],
        "details": ["本次调整由单位统一申报，个人无需操作。", "缴费标准以官方公布为准。", "结息金额已计入您的公积金账户余额。"],
        "actions": ["可通过本地官方政务服务平台或社保经办窗口办理。", "请通过官方政务App查询个人账户信息。",
                    "如有疑问，请拨打当地社保咨询热线。"],
        "slots": {},
    },
    "traffic": {
        "orgs": ["{city}市公安局交通管理局", "{city}车管所"],
        "subjects": ["机动车年检提醒", "交通违法处理提醒", "驾驶证换证提醒"],
        "intro": ["您名下车牌号为{plate}的机动车检验有效期将于{date}届满。", "您的驾驶证有效期将于{date}届满，请在期满前办理换证。",
                  "您名下车辆有一条未处理的交通违法记录。"],
        "details": ["交管部门不会通过短信链接要求缴纳罚款。", "处理违法记录请以官方平台查询结果为准。"],
        "actions": ["请通过官方交管服务App或到车管所办理。", "可登录官方交管服务平台查询详情（请手动输入官方网址）。"],
        "slots": {"plate": ["云A·3K29X", "临B·7M531", "青C·Q8820", "安D·52F17"]},
    },
    "court_arbitration": {
        "orgs": ["{city}仲裁委员会", "{city}市中级人民法院诉讼服务中心", "{city}商事调解中心"],
        "subjects": ["开庭通知", "案件受理通知", "调解会议安排"],
        "intro": ["贵方作为当事人的案件（案号{case}）定于{date} {time}开庭审理。", "您提交的申请已受理，案号{case}。",
                  "关于{company}与贵司的合同纠纷，调解会议安排在{date}。"],
        "details": ["请携带相关证据材料原件准时到庭。", "电子送达文书可通过官方诉讼服务平台查阅。", "本程序不收取任何“保证金”或“加急费”。"],
        "actions": ["如需申请延期，请通过官方诉讼服务平台提交书面申请。", "如有疑问请致电诉讼服务中心。"],
        "slots": {"case": ["（{year}）民初{num}号", "仲字〔{year}〕第{num}号", "（{year}）商调{num}号"]},
    },
    "school": {
        "orgs": ["{city}实验小学", "{city}第一中学", "{city}外国语学校", "{city}职业技术学院"],
        "subjects": ["家长会通知", "寒假放假安排", "校服征订说明", "学期学杂费缴纳通知", "期末考试安排"],
        "intro": ["本学期家长会定于{date} {time}在各班教室举行。", "根据校历安排，寒假放假时间为{date2}至{date}。",
                  "本学期学杂费缴费通道已开通，缴费截止日期为{date}。"],
        "details": ["缴费仅通过学校官方缴费平台进行，学校不会要求向个人账户转账。", "请家长督促孩子做好假期安全。", "如有特殊情况请提前向班主任请假。"],
        "actions": ["请通过学校官方缴费平台缴纳，或联系班主任了解详情。", "具体安排请以班主任通知为准。"],
        "slots": {},
    },
    "university": {
        "orgs": ["{city}大学教务处", "{city}理工大学研究生院", "{city}师范大学学生处"],
        "subjects": ["选课通知", "奖学金评审结果公示", "毕业论文提交安排", "学籍信息核对通知"],
        "intro": ["{year}年秋季学期选课将于{date}开始。", "{year}年度奖学金评审结果现予以公示，公示期至{date}。",
                  "请各位同学于{date}前在教务系统中核对个人学籍信息。"],
        "details": ["如对公示结果有异议，请在公示期内向学院书面反映。", "选课结果以教务系统为准。"],
        "actions": ["请登录学校教务系统办理。", "有疑问请联系学院教学秘书。"],
        "slots": {},
    },
    "hospital": {
        "orgs": ["{city}市人民医院", "{city}妇幼保健院", "{city}体检中心", "{city}口腔医院"],
        "subjects": ["预约挂号成功通知", "体检报告已出", "复诊提醒", "疫苗接种预约提醒"],
        "intro": ["您已成功预约{date} {time}{dept_med}门诊。", "您于{date2}进行的健康体检报告已生成。", "根据医生建议，您需于{date}前后复诊。"],
        "details": ["请携带本人身份证及医保卡就诊。", "就诊前请完成院内预检分诊。", "如需取消预约，请提前一天操作。"],
        "actions": ["可在医院官方公众号“报告查询”中查看。", "如需改约，请通过医院官方App办理。"],
        "slots": {"dept_med": ["内科", "眼科", "口腔科", "皮肤科", "骨科", "儿科"]},
    },
    "telecom": {
        "orgs": ["{city}移动", "{city}联通", "{city}电信", "云川宽带"],
        "subjects": ["{month}月话费账单", "套餐变更成功通知", "宽带到期提醒", "积分到期提醒"],
        "intro": ["您{month}月话费账单已出，本月消费{amount}元。", "您申请的套餐变更已于{date}生效。", "您的宽带服务将于{date}到期。"],
        "details": ["账单详情可在官方App查询。", "积分兑换请通过官方渠道，谨防虚假积分兑换短信。"],
        "actions": ["可通过官方App或营业厅续费。", "如有疑问请拨打官方客服热线。"],
        "slots": {},
    },
    "utility": {
        "orgs": ["{city}供电公司", "{city}自来水公司", "{city}燃气公司"],
        "subjects": ["计划停电通知", "水费账单提醒", "燃气安全检查通知", "停水通知"],
        "intro": ["因线路检修，{city}{street}将于{date} {time}起计划停电约{hours}小时。", "您户号尾号{last4}的本期水费为{amount}元。",
                  "我公司将于{date}起对辖区用户开展入户燃气安全检查。"],
        "details": ["入户检查人员均佩戴工作证，检查不收取任何费用。", "如遇恶劣天气，作业时间可能顺延。"],
        "actions": ["可通过官方公众号或营业厅缴费。", "如需核实检查人员身份，请拨打官方服务热线。"],
        "slots": {"street": ["滨江路", "人民路", "建设街道", "光明社区", "新华路"], "hours": ["4", "6", "8"]},
    },
    "property": {
        "orgs": ["{city}锦华物业服务中心", "{city}绿城物业管理处", "{city}华府小区物业"],
        "subjects": ["电梯维保通知", "停车费缴纳通知", "消防设施检查通知", "小区公共区域保洁安排"],
        "intro": ["{date}将对{building}号楼电梯进行年度维保，届时电梯暂停使用。", "{year}年度停车费缴纳工作已开始，截止日期为{date}。",
                  "物业将于{date}对各楼栋消防设施进行例行检查。"],
        "details": ["缴费请至物业服务中心前台或通过物业官方小程序办理。", "给您带来的不便敬请谅解。"],
        "actions": ["如有疑问请联系物业服务中心。", "请业主相互转告。"],
        "slots": {"building": ["3", "5", "7", "12", "18"]},
    },
    "ecommerce": {
        "orgs": ["云川商城", "青禾优选", "南屿电器官方旗舰店", "北岭书店"],
        "subjects": ["您的订单已发货", "退款已到账", "订单确认通知", "售后服务进度通知"],
        "intro": ["您购买的“{goods}”已于{date}发货，订单号{order}。", "您申请的退款{amount}元已原路退回至您的付款账户。",
                  "您的订单{order}已支付成功，我们将尽快为您安排发货。"],
        "details": ["退款到账时间以支付渠道为准，一般为1-3个工作日。", "物流信息可在订单详情中查看。", "收货时请当面验货。"],
        "actions": ["您可在App“我的订单”中查看物流进度。", "如需售后服务，请在订单页面申请，平台客服不会要求您添加私人联系方式或另行转账。"],
        "slots": {"goods": ["无线耳机", "空气净化器", "儿童绘本套装", "办公椅", "电饭煲", "运动鞋"]},
    },
    "logistics": {
        "orgs": ["嘉禾快递", "云川速运", "青禾物流"],
        "subjects": ["包裹派送通知", "包裹已签收", "派送延误说明", "快递柜取件提醒"],
        "intro": ["您的包裹（运单尾号{last4}）预计{date}送达。", "您的包裹已于{date} {time}由本人签收。", "受天气影响，您的包裹派送将延迟{days}天。"],
        "details": ["取件码已发送至您的手机，请勿泄露给他人。", "快递员不会以理赔为由要求您提供银行卡信息。"],
        "actions": ["可在官方App中查询物流轨迹。", "如有问题请联系官方客服。"],
        "slots": {},
    },
    "travel": {
        "orgs": ["云川航空", "南屿航空", "青禾酒店", "{city}国际大酒店"],
        "subjects": ["航班变动通知", "值机提醒", "预订确认", "入住提醒"],
        "intro": ["您预订的{date}航班因航路调整，起飞时间调整为{time}。", "您预订的{date}入住的大床房已确认。", "您的航班将于明日起飞，可提前办理网上值机。"],
        "details": ["如需改签或退票，请通过官方App或购票渠道办理，航空公司不会要求您向个人账户转账办理退改。", "酒店入住时请出示本人有效证件。"],
        "actions": ["请通过官方App办理值机。", "如需取消预订，请在入住前一天18点前操作。"],
        "slots": {},
    },
    "cloud_service": {
        "orgs": ["星河云", "云川计算", "青禾云服务"],
        "subjects": ["云服务器即将到期", "账单已出账", "安全告警通知", "资源使用量提醒"],
        "intro": ["您账号下的云服务器实例将于{date}到期。", "您{month}月的云服务账单已出，金额{amount}元。",
                  "我们检测到您的实例存在弱口令风险。", "您的对象存储使用量已达到配额的{pct}%。"],
        "details": ["到期后实例将停止服务，数据保留{days}天。", "账单明细可在控制台费用中心查看。"],
        "actions": ["请登录控制台办理续费。", "建议您登录控制台修改实例密码并开启安全组限制。", "如需扩容，请在控制台中自助操作。"],
        "slots": {},
        "never_ask": True,
    },
    "mailbox_admin": {
        "orgs": ["信息技术部", "IT服务台", "集团信息中心"],
        "subjects": ["邮箱容量提醒", "邮件系统维护通知", "邮箱密码到期提醒", "多因素认证启用通知"],
        "intro": ["您的邮箱已使用容量的{pct}%。", "邮件系统将于{date} {time}进行升级维护，预计持续{hours}小时。",
                  "根据公司信息安全制度，您的域账号密码将于{days}天后到期。", "公司将于{date}起全面启用多因素认证。"],
        "details": ["维护期间网页版邮箱暂停访问，客户端收发可能延迟。", "IT部门不会通过邮件索要您的密码。", "请勿点击自称“邮箱升级”的陌生链接。"],
        "actions": ["请清理不需要的邮件或归档至本地，如需扩容请在内部服务台提交申请。", "请通过公司内网自助服务门户修改密码。",
                    "请于工作时间到IT服务台现场完成认证设备绑定。", "如有疑问请拨打内线{ext}。"],
        "slots": {"ext": ["8001", "6110", "2333", "5100"]},
    },
    "hr": {
        "orgs": ["人力资源部", "人事行政中心", "HR共享服务中心"],
        "subjects": ["{month}月工资条", "年假余额提醒", "新员工入职材料清单", "社保公积金基数调整说明", "年度绩效考核安排"],
        "intro": ["您{month}月的工资条已发布。", "截至{date}，您的剩余年假为{days}天。", "欢迎加入{company}！请于入职当天携带以下材料。",
                  "{year}年度绩效考核将于{date}启动。"],
        "details": ["工资条可登录公司HR系统查看。", "入职材料包括：身份证复印件、学历证书复印件、离职证明。", "考核结果将用于年度调薪参考。"],
        "actions": ["请登录公司HR系统查看或提交申请。", "如有疑问请联系人力资源部{person}，内线{ext}。"],
        "slots": {"ext": ["8012", "6120", "2310"]},
    },
    "finance_dept": {
        "orgs": ["财务部", "财务共享中心"],
        "subjects": ["月末结账安排", "报销单据提交提醒", "发票开具规范说明", "差旅费报销标准更新"],
        "intro": ["本月财务结账日为{date}，请各部门于此前提交报销单据。", "根据公司财务制度，差旅费报销标准自{date}起调整。",
                  "近期部分报销发票抬头不规范，现将要求说明如下。"],
        "details": ["报销款将统一发放至员工本人工资卡。", "发票抬头须为公司全称，税号需完整准确。", "逾期提交的单据将顺延至下月处理。"],
        "actions": ["请通过公司费控系统提交。", "如有疑问请联系财务部{person}。"],
        "slots": {},
    },
    "vendor_payment": {
        "orgs": ["{company}财务部", "{company}采购部"],
        "subjects": ["{month}月对账单确认", "付款计划通知", "关于合同款支付安排", "发票已寄出"],
        "intro": ["附件为{month}月对账单，请贵司核对确认。", "根据合同约定，第二期货款{amount}元计划于{date}支付。",
                  "我司已开具增值税专用发票，金额{amount}元，快递单号{order}。"],
        "details": ["款项将支付至合同中约定的贵司对公账户。", "如贵司收款账户发生变更，请出具加盖公章的书面函件，我司将电话回拨原联系人核实后再行变更。",
                    "对账无误请回签盖章扫描件。"],
        "actions": ["如有差异请于{date}前反馈。", "如有疑问请联系{person}。"],
        "slots": {},
    },
    "meeting": {
        "orgs": ["{dept}", "总经理办公室", "项目管理办公室"],
        "subjects": ["会议通知：{topic}", "关于召开{topic}的通知", "{topic}会议纪要", "会议时间调整"],
        "intro": ["定于{date} {time}在{room}召开{topic}。", "原定{date2}的{topic}调整至{date} {time}。", "现将{date2}{topic}纪要发送各位，请查收。"],
        "details": ["请各部门负责人准时参加。", "会议材料见附件。", "如不能参会，请提前向{person}请假。", "会议议程：一、工作汇报；二、问题讨论；三、下阶段安排。"],
        "actions": ["请回复确认是否参会。", "如有议题补充请于会前告知。"],
        "slots": {"topic": ["季度经营分析会", "项目评审会", "安全生产例会", "预算编制讨论会", "客户需求沟通会"],
                  "room": ["三楼会议室", "大会议室", "线上会议", "二号会议室"]},
    },
    "project": {
        "orgs": ["{dept}"],
        "subjects": ["{project}进度更新", "{project}周报", "关于{project}测试安排", "需求变更说明"],
        "intro": ["{project}本周完成了需求评审和接口联调。", "附上{project}本周进展，请大家查阅。", "{project}测试环境已部署完成，测试计划于{date}开始。"],
        "details": ["当前整体进度约{pct}%。", "存在风险：第三方接口文档尚未最终确认。", "下周计划完成性能测试并输出报告。"],
        "actions": ["请相关同事于{date}前反馈意见。", "如有问题可以随时找我沟通。"],
        "slots": {},
    },
    "anti_fraud": {
        "orgs": ["{city}市公安局反诈中心", "{org_bank}消费者权益保护部", "公司安全管理部", "{city}市反诈骗联席办公室"],
        "subjects": ["反诈骗风险提示", "警惕冒充客服诈骗", "防范电信网络诈骗温馨提示", "关于近期钓鱼邮件的安全提醒"],
        "intro": ["近期有不法分子冒充电商客服，以“退款理赔”为由诱导受害人转账。",
                  "近期出现冒充公检法人员，以“涉嫌洗钱需配合调查”为名要求转账至“安全账户”的诈骗。",
                  "近期发现以“邮箱即将停用，点击验证”为主题的钓鱼邮件。", "近期有骗子冒充领导添加员工微信，要求紧急转账。"],
        "details": ["公安机关不存在所谓“安全账户”，也不会通过电话办案。", "正规客服不会要求您下载屏幕共享软件或提供验证码。",
                    "遇到要求转账的情况，请务必通过原有电话等可靠方式核实。", "如已转账，请立即拨打110报警。"],
        "actions": ["如收到可疑信息，请勿点击链接，并向安全部门报告。", "请大家提高警惕，相互转告。"],
        "slots": {"org_bank": ["华岳银行", "安泰银行"]},
    },
    "association": {
        "orgs": ["{city}市软件行业协会", "{city}市物流协会", "{city}市注册会计师协会"],
        "subjects": ["年会参会通知", "{year}年度会费缴纳通知", "行业培训报名通知"],
        "intro": ["协会定于{date}召开{year}年度会员大会。", "{year}年度会费缴纳工作现已开始，标准为{amount}元/年。", "协会将于{date}举办行业政策解读培训。"],
        "details": ["会费请汇入协会对公账户，协会将开具正式票据。", "参会名额有限，请尽早报名。"],
        "actions": ["请于{date}前回执报名。", "如有疑问请联系秘书处{person}。"],
        "slots": {},
    },
    "recruitment": {
        "orgs": ["{company}人力资源部", "{company}招聘组"],
        "subjects": ["面试邀请", "录用通知", "笔试安排"],
        "intro": ["感谢您应聘我司{position}岗位，诚邀您于{date} {time}参加面试。", "恭喜您通过面试，我司拟录用您担任{position}。",
                  "您应聘的{position}岗位笔试安排在{date}。"],
        "details": ["面试地点：{city}市{street}{num}号{company}。", "我司招聘全程不收取任何费用。", "入职时间可与HR协商。"],
        "actions": ["请回复确认是否参加。", "如需调整时间，请提前联系{person}。"],
        "slots": {"position": ["前端工程师", "会计", "销售经理", "行政专员", "数据分析师"], "street": ["科技路", "人民路", "高新大道"]},
    },
    "community": {
        "orgs": ["{city}市{street}街道办事处", "{city}{street}社区居委会"],
        "subjects": ["垃圾分类宣传活动通知", "社区义诊活动", "居民信息登记通知", "防汛安全提示"],
        "intro": ["社区将于{date}在文化广场开展{activity}。", "近期将迎来强降雨天气，请居民做好防范。", "为做好社区服务，现开展居民基础信息登记。"],
        "details": ["登记工作由社区网格员上门开展，网格员佩戴工作证。", "活动免费参加，欢迎居民踊跃参与。"],
        "actions": ["如有疑问请到社区服务站咨询。", "请大家相互转告。"],
        "slots": {"activity": ["垃圾分类宣传", "义诊", "消防演练", "敬老活动"], "street": ["光明", "新华", "滨江", "和平"]},
    },
    "subscription": {
        "orgs": ["云川视频", "青禾音乐", "北岭阅读", "星河网盘"],
        "subjects": ["会员即将自动续费", "会员续费成功", "会员到期提醒"],
        "intro": ["您的连续包月会员将于{date}自动续费，续费金额{amount2}元。", "您的年度会员已续费成功，有效期至{date}。", "您的会员将于{date}到期。"],
        "details": ["如不需要续费，可在App“设置-自动续费管理”中关闭。", "到期后已保存的内容不会丢失。"],
        "actions": ["可在官方App中管理会员服务。", "如有疑问请联系官方客服。"],
        "slots": {},
    },
    "platform_account": {
        "orgs": ["云川网络", "青禾社区", "南屿出行", "星河支付"],
        "subjects": ["隐私政策更新通知", "账号注销申请已受理", "实名认证提醒", "服务协议变更说明"],
        "intro": ["我们更新了隐私政策，更新内容将于{date}生效。", "您提交的账号注销申请已受理，注销冷静期为{days}天。",
                  "根据相关法律法规，部分功能需完成实名认证后使用。"],
        "details": ["如在冷静期内重新登录，注销申请将自动撤销。", "主要更新内容包括个人信息的收集范围和存储期限。"],
        "actions": ["您可在App“我的-设置-账号与安全”中完成实名认证。", "完整内容请在App中查看。"],
        "slots": {},
        "never_ask": True,
    },
    "personal": {
        "orgs": [""],
        "subjects": ["周末聚餐", "照片发你了", "最近怎么样", "借的书", "下周出差", "生日快乐"],
        "intro": ["好久不见，最近工作忙吗？", "上次旅行的照片整理好了，放在附件里。", "周六晚上一起吃个饭吧，地点在{city}老街那家。",
                  "你上次借我的那本书看完了吗？不急。", "下周我要去{city}出差，有空可以见一面。"],
        "details": ["孩子最近上学挺适应的。", "我爸妈身体都挺好，谢谢关心。", "天气转凉了，注意添衣。", "我最近在学做饭，手艺还行。"],
        "actions": ["有空回个消息。", "到时候电话联系。", "改天再约。"],
        "slots": {},
        "salutations": ["{name}：", "嗨，", "{name}，", ""],
        "closings": ["", "回聊。", "先这样。"],
    },
    "sales": {
        "orgs": ["{company}销售部", "{company}商务部"],
        "subjects": ["报价单", "关于合同续签事宜", "新品介绍", "样品寄送通知"],
        "intro": ["附件为贵司询价的{goods_b}报价单，报价有效期至{date}。", "双方合作协议将于{date}到期，现就续签事宜与您沟通。",
                  "我司新推出的{goods_b}已上市，现将产品资料发送给您。"],
        "details": ["以上报价含税含运费。", "付款方式按原合同约定执行。", "样品已通过{logi}寄出，单号{order}。"],
        "actions": ["如有疑问欢迎来电沟通。", "期待与贵司继续合作。"],
        "slots": {"goods_b": ["工业传感器", "办公耗材", "包装材料", "网络设备", "实验试剂"], "logi": ["嘉禾快递", "云川速运"]},
    },
}

# ---------------------------------------------------------------------------
# Shared English pools
# ---------------------------------------------------------------------------

EN_CITIES = ["Riverton", "Maplewood", "Eastport", "Cedar Falls", "Northvale", "Lakeside", "Brookfield", "Fairhaven", "Oakridge", "Westbury"]
EN_FIRST = ["James", "Mary", "Daniel", "Linda", "Kevin", "Sarah", "Michael", "Emma", "David", "Olivia", "Chris", "Sophia", "Ryan", "Grace", "Alex", "Nina"]
EN_LAST = ["Carter", "Hughes", "Patel", "Nguyen", "Brooks", "Foster", "Reed", "Coleman", "Price", "Ward", "Barnes", "Ellis"]
EN_DEPTS = ["Finance", "Human Resources", "IT Services", "Facilities", "Procurement", "Marketing", "Legal", "Customer Success", "Operations"]
EN_COMPANIES = ["Northwind Components", "Bluefield Analytics", "Harborline Logistics", "Granite Peak Consulting", "Silverleaf Foods",
                "Crescent Media Group", "Ironwood Manufacturing", "Summit Ridge Software", "Clearwater Health Partners", "Redwood Supply Co."]
EN_SALUTATIONS = ["Dear customer,", "Dear {name},", "Hi {first},", "Hello {first},", "Dear member,", "Hello,", "Hi team,", "Dear colleagues,", "Hi all,", ""]
EN_CLOSINGS = ["Thank you.", "Best regards,", "Kind regards,", "Thanks,", "Sincerely,", "Thank you for your patience.", "Have a great day.", "Cheers,", ""]
EN_NEVER_ASK = [
    "We will never ask for your password, PIN or one-time code by email, text or phone.",
    "This message contains no links that ask you to sign in. If in doubt, open our app or type our web address yourself.",
    "Our staff will never ask you to move money to a 'safe account' or install remote-access software.",
    "This is an automated message; replies to this address are not monitored.",
    "If you receive a message claiming to be from us that asks for your code, do not respond and report it through our app.",
]

EN_TYPES = {
    "bank_transaction": {
        "orgs": ["Northbridge Bank", "Harbor Mutual Bank", "{city} Community Credit Union", "Keystone Federal"],
        "subjects": ["Transaction alert", "A payment was made from your account", "Deposit received", "Your account activity alert"],
        "intro": ["A {txn} of ${amount} was made from your account ending in {last4} on {date_en}.",
                  "A deposit of ${amount} was credited to your checking account ending in {last4} on {date_en}.",
                  "Your debit card ending in {last4} was used at {merchant} for ${amount2} on {date_en}."],
        "details": ["Available balance and full details are shown in the {org} mobile app.", "This alert was sent based on your alert preferences.", "Pending transactions may take up to two business days to post."],
        "actions": ["If you recognize this transaction, no action is needed.", "If you don't recognize it, call the number on the back of your card or lock your card in the {org} app.",
                    "You can change your alert settings in the app under Profile > Alerts."],
        "slots": {"txn": ["payment", "transfer", "bill payment", "withdrawal"], "merchant": ["Fresh Market", "City Parking", "Corner Pharmacy", "Brightline Fuel"]},
    },
    "card_statement": {
        "orgs": ["Northbridge Bank Card Services", "Keystone Card", "Harbor Mutual Credit Card"],
        "subjects": ["Your statement is ready", "Payment due reminder", "Your {month_en} statement", "AutoPay scheduled"],
        "intro": ["Your statement for the card ending in {last4} is now available. Statement balance: ${amount}.",
                  "Your minimum payment of ${amount2} is due on {date_en}.", "Your AutoPay of ${amount} is scheduled for {date_en} from your linked checking account."],
        "details": ["Payments made after 5 p.m. ET may post the next business day.", "You earned {count} reward points this period.", "Your statement is available in the Documents section of the app."],
        "actions": ["To view your statement, sign in through the app or by typing our address into your browser.", "If you've already paid, please disregard this reminder.", "Questions? Call the number on the back of your card."],
        "slots": {},
    },
    "account_security": {
        "orgs": ["Northbridge Bank", "Cobalt Cloud", "Streamly", "Parcelhub", "Brightline Airways", "Keystone Federal"],
        "subjects": ["New sign-in to your account", "Your password was changed", "Security settings updated", "New device added to your account"],
        "intro": ["We noticed a new sign-in to your account on {date_en} from a {device} near {city}.",
                  "The password for your account was changed on {date_en}.", "Two-step verification was turned on for your account on {date_en}.",
                  "A new device was added to your account on {date_en}."],
        "details": ["Device: {device}.", "If this was you, there's nothing else to do.", "Sign-in method: {method}."],
        "actions": ["If this wasn't you, open the {org} app and go to Settings > Security to change your password and sign out other devices.",
                    "If you don't recognize this activity, contact us using the phone number on our official website.", "You can review recent activity at any time in your account settings."],
        "slots": {"device": ["Windows PC", "Mac", "iPhone", "Android phone", "tablet"], "method": ["password", "passkey", "security key", "authenticator app"]},
        "never_ask": True,
    },
    "kyc_update": {
        "orgs": ["Northbridge Bank", "Harbor Mutual Bank", "Keystone Brokerage"],
        "subjects": ["Please update your identification", "Your ID on file is expiring", "Annual customer information review"],
        "intro": ["Our records show that the identification document on file for you expires on {date_en}.",
                  "As part of our regular review required by banking regulations, we ask customers to confirm their contact details once a year.",
                  "We need an updated copy of your identification to keep your account information current."],
        "details": ["Your funds remain safe and accessible during this review.", "There is no fee for updating your information."],
        "actions": ["You can update your details in the {org} app under Profile, or visit any branch with a valid photo ID.",
                    "Please do not send ID documents by email; use the secure upload in our app or bring them to a branch."],
        "slots": {},
        "never_ask": True,
    },
    "investment_notice": {
        "orgs": ["Keystone Brokerage", "Summit Asset Management", "Harbor Retirement Services"],
        "subjects": ["Dividend payment notice", "Your quarterly statement is available", "Trade confirmation", "Required minimum distribution reminder"],
        "intro": ["A dividend of ${amount2} from {fund} was credited to your account on {date_en}.", "Your quarterly investment statement for the period ending {date_en} is available.",
                  "Your order to buy {count} shares of {fund} was executed on {date_en}."],
        "details": ["Past performance does not guarantee future results.", "Statements are available in the Documents center."],
        "actions": ["Sign in to your account to review your holdings.", "Contact your advisor if you have questions."],
        "slots": {"fund": ["Summit Balanced Fund", "Harbor Index 500", "Keystone Bond Fund", "Global Growth Fund"]},
    },
    "insurance": {
        "orgs": ["Evergreen Insurance", "Shield Mutual", "Harbor Auto Insurance"],
        "subjects": ["Your policy renewal", "Claim update", "Your claim payment has been issued", "Policy documents available"],
        "intro": ["Your policy ending in {last4} renews on {date_en}. Your renewal premium is ${amount}.",
                  "Your claim {order} has been approved, and a payment of ${amount} has been issued.", "Your new policy documents are now available."],
        "details": ["The payment will be deposited to the bank account you provided when filing the claim.", "We never charge a fee to release a claim payment.", "Your premium will be drafted from your account on file."],
        "actions": ["You can track your claim in the {org} app.", "To change your payment method, sign in to your account or call your agent."],
        "slots": {},
        "never_ask": True,
    },
    "tax": {
        "orgs": ["{city} Department of Revenue", "State Tax Office", "{city} County Treasurer"],
        "subjects": ["Tax filing deadline reminder", "Your refund has been processed", "Property tax bill available", "Estimated tax payment reminder"],
        "intro": ["The deadline to file your {year} return is {date_en}.", "Your {year} refund of ${amount} was issued by direct deposit on {date_en}.",
                  "Your {year} property tax bill of ${amount} is now available."],
        "details": ["Refunds are only sent to the bank account listed on your return.", "We do not ask for payment by gift card, wire transfer or cryptocurrency.", "Payment options are listed on the official county website."],
        "actions": ["You can check your status on the official website by typing the address into your browser.", "For help, call the taxpayer assistance line listed on our website."],
        "slots": {},
    },
    "school": {
        "orgs": ["{city} Elementary School", "{city} High School", "Lincoln Middle School"],
        "subjects": ["Parent-teacher conferences", "Winter break schedule", "Field trip permission form", "School lunch account balance"],
        "intro": ["Parent-teacher conferences will be held on {date_en} from 3 to 7 p.m.", "Winter break runs from {date2_en} through {date_en}; classes resume the following Monday.",
                  "Your student's lunch account balance is ${amount2}."],
        "details": ["Sign-up sheets are available in the school office.", "Payments can be made through the district's parent portal or at the front office."],
        "actions": ["Please contact your child's teacher with any questions.", "Return the signed form to the classroom teacher by Friday."],
        "slots": {},
    },
    "university": {
        "orgs": ["Office of the Registrar", "{city} University Financial Aid", "Graduate School Office"],
        "subjects": ["Course registration opens soon", "Financial aid disbursement", "Graduation application deadline", "Transcript request completed"],
        "intro": ["Registration for the fall term opens on {date_en}.", "Your financial aid of ${amount} was applied to your student account on {date_en}.",
                  "The deadline to apply for graduation is {date_en}."],
        "details": ["Any remaining credit will be refunded to the account you set up in the student portal.", "Holds on your account may prevent registration."],
        "actions": ["Log in to the student portal to review your schedule.", "Contact the registrar's office with questions."],
        "slots": {},
    },
    "healthcare": {
        "orgs": ["{city} Medical Center", "Lakeside Family Clinic", "CarePoint Pharmacy", "Brightsmile Dental"],
        "subjects": ["Appointment reminder", "Your test results are available", "Prescription ready for pickup", "Time to schedule your checkup"],
        "intro": ["This is a reminder of your appointment on {date_en} at {time_en}.", "New test results are available in your patient portal.",
                  "Your prescription is ready for pickup at our {city} location."],
        "details": ["Please arrive 15 minutes early and bring your insurance card.", "Results are reviewed by your provider before release."],
        "actions": ["To reschedule, call our office or use the patient portal.", "Reply C to confirm or call us to cancel."],
        "slots": {},
    },
    "telecom_utility": {
        "orgs": ["{city} Power & Light", "{city} Water Utility", "Clearline Wireless", "FiberNet Internet"],
        "subjects": ["Your bill is ready", "Planned service outage", "AutoPay confirmation", "Your plan change is complete"],
        "intro": ["Your {month_en} bill of ${amount} is ready and will be paid by AutoPay on {date_en}.",
                  "Crews will perform maintenance in your area on {date_en}; service may be interrupted for up to {hours} hours.",
                  "Your plan change took effect on {date_en}."],
        "details": ["Our crews carry company ID and will never ask for payment at your door.", "You can view usage details in your online account."],
        "actions": ["Manage your account in our app or by calling customer service.", "No action is required."],
        "slots": {"hours": ["2", "4", "6"]},
    },
    "ecommerce": {
        "orgs": ["Parcelhub", "Brightcart", "Northshore Outfitters", "Cornerstone Books"],
        "subjects": ["Your order has shipped", "Refund issued", "Order confirmation #{order}", "Your return was received"],
        "intro": ["Your order {order} has shipped and should arrive by {date_en}.", "We've issued a refund of ${amount2} to your original payment method.",
                  "Thanks for your order! We're getting {goods_en} ready to ship."],
        "details": ["Refunds can take 3-5 business days to appear on your statement.", "Tracking updates may take up to 24 hours to appear."],
        "actions": ["You can track your package in Your Orders.", "Need help? Visit the Help Center in our app; we will never ask you to pay outside our checkout."],
        "slots": {"goods_en": ["your headphones", "the desk lamp", "your running shoes", "the coffee maker", "your books"]},
    },
    "shipping": {
        "orgs": ["SwiftShip", "Parcel Express", "Coastal Freight"],
        "subjects": ["Your package was delivered", "Delivery scheduled", "Delivery delayed", "Package ready for pickup"],
        "intro": ["Your package (tracking ending {last4}) was delivered on {date_en} at {time_en}.", "Your package is scheduled for delivery on {date_en}.",
                  "Due to weather, your delivery is delayed by {days} days."],
        "details": ["No signature was required.", "We do not charge redelivery fees by text message."],
        "actions": ["Track your shipment in our app.", "Contact customer support through our official website."],
        "slots": {},
    },
    "travel": {
        "orgs": ["Brightline Airways", "Coastal Air", "Harborview Hotel", "Summit Car Rental"],
        "subjects": ["Your flight time has changed", "Check-in is open", "Reservation confirmed", "Your rental is confirmed"],
        "intro": ["Your flight on {date_en} now departs at {time_en}.", "Check-in is now open for your flight to {city}.",
                  "Your reservation for {date_en} is confirmed. Confirmation number: {order}."],
        "details": ["Changes and refunds can be made in Manage Trips.", "Please bring a valid photo ID at check-in."],
        "actions": ["Check in through our app or website.", "Contact us if you need to change your reservation."],
        "slots": {},
    },
    "cloud_service": {
        "orgs": ["Cobalt Cloud", "Stratus Hosting", "Nimbus Workspace"],
        "subjects": ["Your invoice is available", "Subscription renewal notice", "Storage usage alert", "Security recommendation for your project"],
        "intro": ["Your invoice for {month_en} (${amount}) is available in the billing console.", "Your subscription renews on {date_en}.",
                  "Your workspace has used {pct}% of its storage quota.", "We found a storage bucket in your project that allows public access."],
        "details": ["Your payment method on file will be charged automatically.", "Usage details are available in the console."],
        "actions": ["Review billing in the console.", "We recommend reviewing access settings in the console.", "To add storage, an administrator can upgrade the plan in the admin console."],
        "slots": {},
        "never_ask": True,
    },
    "it_department": {
        "orgs": ["IT Service Desk", "Information Security Team", "Corporate IT"],
        "subjects": ["Scheduled email maintenance", "Your network password expires soon", "Mailbox size notice", "MFA enrollment required", "Security awareness training due"],
        "intro": ["Email services will be under maintenance on {date_en} from {time_en} for about {hours} hours.",
                  "Your network password will expire in {days} days, per company policy.", "Your mailbox is {pct}% full.",
                  "All employees must enroll in multi-factor authentication by {date_en}.", "Your annual security awareness training is due by {date_en}."],
        "details": ["IT will never ask for your password by email.", "Messages claiming your mailbox will be deleted unless you sign in are not from IT.", "Outlook may run in offline mode during maintenance."],
        "actions": ["Change your password from a company laptop using Ctrl+Alt+Del, or through the self-service portal on the intranet.",
                    "Please archive or delete old messages; contact the service desk at ext. {ext} if you need more space.",
                    "Complete enrollment in person at the IT help bar or through the intranet portal.", "Find the training in the learning portal on the intranet."],
        "slots": {"ext": ["4100", "2255", "7000"], "hours": ["2", "3", "4"]},
    },
    "hr": {
        "orgs": ["Human Resources", "People Operations", "Payroll Team"],
        "subjects": ["Your pay stub is available", "Open enrollment begins {date_en}", "Welcome to {company}!", "Performance review timeline", "Holiday schedule"],
        "intro": ["Your pay stub for the period ending {date_en} is available.", "Benefits open enrollment runs from {date2_en} to {date_en}.",
                  "We're excited to have you join {company} on {date_en}.", "The annual performance review cycle starts on {date_en}."],
        "details": ["Changes to direct deposit can only be made in the HR system after signing in with your company account.", "Bring two forms of ID on your first day for I-9 verification.", "Your manager will schedule a review meeting."],
        "actions": ["Log in to the HR portal to review.", "Reach out to {person} in People Ops with any questions."],
        "slots": {},
    },
    "finance_dept": {
        "orgs": ["Finance", "Accounts Payable", "Corporate Finance"],
        "subjects": ["Month-end close schedule", "Expense report reminder", "Updated travel policy", "Purchase order approval needed"],
        "intro": ["Month-end close is {date_en}; please submit expense reports before then.", "The travel and expense policy has been updated effective {date_en}.",
                  "A purchase order for ${amount} is waiting for your approval in the procurement system."],
        "details": ["Reimbursements are paid to your payroll account.", "Receipts are required for expenses over $25."],
        "actions": ["Submit reports through the expense system.", "Questions can go to {person} in Finance."],
        "slots": {},
    },
    "vendor_payment": {
        "orgs": ["{company} Accounts Payable", "{company} Procurement"],
        "subjects": ["Remittance advice", "Payment schedule for PO {order}", "Statement reconciliation for {month_en}", "Invoice {order} received"],
        "intro": ["We've scheduled payment of ${amount} for invoice {order} on {date_en}.", "Attached is our statement for {month_en}; please confirm the balance.",
                  "We received your invoice {order} for ${amount} and it is in our approval queue."],
        "details": ["Payment will be made to the bank account on file in your vendor profile.",
                    "Any change to remittance details must be submitted on company letterhead and will be confirmed by calling your contact at the number we already have on file.",
                    "Our standard terms are net 30."],
        "actions": ["Please let us know of any discrepancies by {date_en}.", "Contact {person} with questions."],
        "slots": {},
    },
    "meeting": {
        "orgs": ["{dept}", "Office of the CEO", "Project Management Office"],
        "subjects": ["Meeting: {topic_en}", "Rescheduled: {topic_en}", "Notes from {topic_en}", "Agenda for {topic_en}"],
        "intro": ["The {topic_en} is scheduled for {date_en} at {time_en} in {room_en}.", "We've moved the {topic_en} to {date_en} at {time_en}.",
                  "Here are the notes from today's {topic_en}."],
        "details": ["The deck is attached.", "Action items are listed at the end of the notes.", "Please add agenda items to the shared doc before the meeting."],
        "actions": ["Please accept the calendar invite.", "Let me know if you can't attend."],
        "slots": {"topic_en": ["quarterly business review", "sprint planning", "budget review", "client kickoff", "safety committee meeting"],
                  "room_en": ["Conference Room B", "the main boardroom", "the video call", "Room 4.12"]},
    },
    "project": {
        "orgs": ["{dept}"],
        "subjects": ["{project_en} status update", "Weekly update: {project_en}", "{project_en} test plan", "Change request for {project_en}"],
        "intro": ["Quick update on {project_en}: we finished integration testing this week.", "Attached is the weekly status report for {project_en}.",
                  "The test environment for {project_en} is ready and testing starts {date_en}."],
        "details": ["We're about {pct}% complete.", "Risk: the vendor API documentation is still in draft.", "Next week we'll focus on performance testing."],
        "actions": ["Please send feedback by {date_en}.", "Happy to walk through it if useful."],
        "slots": {},
    },
    "security_awareness": {
        "orgs": ["Information Security Team", "{org_bank} Fraud Prevention", "{city} Police Department Community Outreach"],
        "subjects": ["Security tip: gift card scams", "Beware of impersonation scams", "Phishing awareness reminder", "How to spot fake invoices"],
        "intro": ["Scammers are posing as executives and asking employees to buy gift cards urgently.",
                  "We've seen messages pretending to be from our help desk claiming your mailbox will be closed unless you sign in.",
                  "Criminals sometimes pose as police or bank staff and ask people to move money to a 'safe account'.",
                  "Fraudsters may send invoices with changed bank details that look like they come from a real supplier."],
        "details": ["Real agencies never ask for payment in gift cards or cryptocurrency.", "Always verify payment changes by calling a known number.", "Report suspicious messages with the Report button in Outlook."],
        "actions": ["If you receive a suspicious message, don't click links; report it to the security team.", "Share this tip with your family."],
        "slots": {"org_bank": ["Northbridge Bank", "Harbor Mutual"]},
    },
    "nonprofit": {
        "orgs": ["{city} Food Bank", "Riverside Animal Shelter", "Hope Literacy Project"],
        "subjects": ["Thank you for your donation", "Volunteer schedule", "Your annual giving summary", "Event reminder"],
        "intro": ["Thank you for your gift of ${amount2} on {date_en}.", "Your volunteer shift is on {date_en} at {time_en}.",
                  "Your {year} giving summary is attached for your tax records.", "Our community dinner is on {date_en}."],
        "details": ["No goods or services were provided in exchange for this gift.", "Parking is available behind the building."],
        "actions": ["Reply to this email if you need to change your shift.", "We look forward to seeing you."],
        "slots": {},
    },
    "personal": {
        "orgs": [""],
        "subjects": ["Dinner Saturday?", "Photos from the trip", "Catching up", "Your book", "Happy birthday!", "Visiting next week"],
        "intro": ["It's been a while! How's the new job going?", "I finally sorted the photos from the lake trip; a few are attached.",
                  "Want to grab dinner Saturday at that place near {city} station?", "Did you finish the book I lent you? No rush at all.",
                  "I'll be in {city} for work next week if you're free for coffee."],
        "details": ["The kids are doing well at school.", "Mom says hi.", "We finally painted the kitchen.", "I've been running in the mornings again."],
        "actions": ["Let me know when you're free.", "Call me sometime.", "Talk soon!"],
        "slots": {},
        "salutations": ["Hi {first},", "Hey {first},", ""],
        "closings": ["", "Talk soon,", "Love,", "Cheers,"],
    },
    "subscription": {
        "orgs": ["Streamly", "Tunebox", "Pagewise", "Nimbus Drive"],
        "subjects": ["Your subscription renews soon", "Payment received", "Your membership is expiring", "Receipt for your subscription"],
        "intro": ["Your monthly plan will renew on {date_en} for ${amount2}.", "Thanks! We received your payment of ${amount2}.", "Your membership expires on {date_en}."],
        "details": ["You can turn off auto-renew at any time in Account settings.", "Your saved content won't be deleted."],
        "actions": ["Manage your plan in the app.", "Questions? Visit our Help Center."],
        "slots": {},
    },
    "platform_account": {
        "orgs": ["Streamly", "Parcelhub", "Cobalt Cloud", "Brightcart"],
        "subjects": ["We're updating our privacy policy", "Your account deletion request", "Changes to our terms of service", "Your data export is ready"],
        "intro": ["We're updating our privacy policy effective {date_en}.", "We received your request to delete your account. Deletion will complete in {days} days.",
                  "We've made changes to our terms of service.", "The data export you requested is ready to download from your account settings."],
        "details": ["If you sign in before then, the request will be canceled.", "The main changes clarify how long we keep data."],
        "actions": ["You can read the full policy in the app.", "No action is needed if you agree with the changes."],
        "slots": {},
        "never_ask": True,
    },
    "sales": {
        "orgs": ["{company} Sales", "{company} Account Management"],
        "subjects": ["Quote for {goods_b_en}", "Contract renewal", "Product update", "Samples shipped"],
        "intro": ["Attached is the quote for {goods_b_en} you requested; it's valid until {date_en}.", "Our agreement expires on {date_en}, and I'd like to discuss renewal.",
                  "Sharing an overview of our new {goods_b_en} line."],
        "details": ["Pricing includes shipping.", "Payment terms remain as in our current contract.", "Samples shipped via SwiftShip, tracking {order}."],
        "actions": ["Happy to set up a call.", "Let me know if you have questions."],
        "slots": {"goods_b_en": ["industrial sensors", "office supplies", "packaging materials", "network switches", "lab reagents"]},
    },
}

# ---------------------------------------------------------------------------
# Version 2: procedural notices that ask the recipient to complete a matter by
# a deadline through an official channel (the hardest benign notices), and
# ordinary business correspondence about quotes, invoices and payments.
# One notice type per institution kind or correspondence topic.
# ---------------------------------------------------------------------------

ZH_PROCEDURAL_KINDS = {
    "market_regulation": ("gov", ["{city}市市场监督管理局"], ["{year}年度企业年度报告公示", "食品经营许可证延续申请", "企业登记联络员信息备案"]),
    "statistics": ("gov", ["{city}市统计局"], ["{month}月统计报表报送", "经济普查单位清查表填报"]),
    "customs": ("gov", ["{city}海关"], ["进出口货物收发货人备案信息年度确认", "报关单修改申请材料补充"]),
    "immigration": ("gov", ["{city}市公安局出入境管理支队"], ["出入境证件换领预约", "签证延期申请材料补正"]),
    "housing": ("gov", ["{city}市住房和城乡建设局"], ["物业服务企业信用信息填报", "建筑施工企业安全生产许可证延期"]),
    "fire": ("gov", ["{city}市消防救援支队"], ["单位消防安全自查报告提交", "年度消防设施检测报告备案"]),
    "environment": ("gov", ["{city}市生态环境局"], ["排污许可执行报告提交", "企业环境信息依法披露"]),
    "hr_bureau": ("gov", ["{city}市人力资源和社会保障局"], ["工伤保险缴费基数申报", "职业技能等级证书信息核对", "劳动用工备案"]),
    "medical_insurance": ("gov", ["{city}市医疗保障局"], ["定点医药机构年度考核材料提交", "异地就医备案"]),
    "real_estate": ("gov", ["{city}市不动产登记中心"], ["不动产权证书领取", "抵押登记材料补正"]),
    "notary": ("gov", ["{city}市公证处"], ["公证材料补充提交", "公证书领取"]),
    "court": ("gov", ["{city}市人民法院"], ["电子送达文书签收确认", "庭前证据交换"]),
    "tax_bureau": ("gov", ["国家税务总局{city}市税务局"], ["企业所得税年度汇算清缴申报", "发票票种核定信息确认", "跨区域涉税事项报验"]),
    "science_bureau": ("gov", ["{city}市科学技术局"], ["高新技术企业认定材料报送", "科技项目中期检查材料提交"]),
    "commerce_bureau": ("gov", ["{city}市商务局"], ["外贸企业经营情况调查表填报", "境外展会补贴申报"]),
    "education_bureau": ("gov", ["{city}市教育局"], ["义务教育入学信息登记", "教师资格定期注册"]),
    "bank_corporate": ("finance", ["华岳银行{city}分行", "安泰银行{city}分行", "{city}农商银行"], ["对公账户年度对账", "企业预留印鉴信息核实", "网银数字证书更新", "企业账户受益所有人信息登记"]),
    "bank_personal": ("finance", ["华岳银行", "安泰银行", "兴和银行"], ["个人客户身份证件到期更新", "长期不动户激活", "预留手机号码核实"]),
    "broker": ("finance", ["兴和证券{city}营业部", "星河证券"], ["投资者风险承受能力重新评估", "科创板交易权限知识测评", "休眠账户激活"]),
    "futures": ("finance", ["华岳期货"], ["期货账户年度回访", "保证金监控中心查询账户激活"]),
    "insurer": ("finance", ["安和保险", "华岳人寿"], ["保单年度信息核对", "团体保险参保人员名单确认", "续保信息确认"]),
    "fund": ("finance", ["华岳基金"], ["基金账户身份信息完善", "定投协议到期确认"]),
    "trust": ("finance", ["{city}国际信托"], ["受益人信息确认", "年度信托报告查阅确认"]),
    "audit_firm": ("enterprise", ["{city}立信会计师事务所", "{city}中审会计师事务所"], ["银行询证函回函", "往来款项函证确认", "年报审计资料提交"]),
    "law_firm": ("enterprise", ["{city}明理律师事务所"], ["委托代理合同签署", "案件证据材料补充提交"]),
    "group_hr": ("internal", ["集团人力资源部", "人力资源共享中心"], ["个人信息年度核对", "劳动合同续签确认", "社保公积金缴费基数确认", "年度体检预约"]),
    "group_it": ("internal", ["集团信息中心", "IT运维部"], ["终端安全软件升级", "VPN账号年度复核", "办公电脑资产盘点", "邮箱账号权限复核"]),
    "group_finance": ("internal", ["集团财务部"], ["年度预算填报", "供应商付款信息确认", "固定资产盘点", "个税专项附加扣除信息确认"]),
    "group_admin": ("internal", ["行政部", "综合管理部"], ["工位调整确认", "年会节目报名", "员工证件照采集"]),
    "university": ("edu", ["{city}大学研究生院", "{city}理工大学教务处"], ["学位论文查重提交", "学籍电子注册", "奖学金申请材料提交", "毕业生就业信息填报"]),
    "school": ("edu", ["{city}实验小学", "{city}第二中学"], ["学生体检信息确认", "课后服务报名", "学生医保参保登记"]),
    "training_center": ("edu", ["{city}职业技能培训中心"], ["继续教育学时登记", "考试报名信息确认"]),
    "hospital": ("health", ["{city}市人民医院", "{city}中医院"], ["体检预约确认", "医保备案信息核对"]),
    "telecom": ("platform", ["{city}移动", "{city}电信"], ["实名信息年度核验", "集团客户账单确认"]),
    "utility": ("utility", ["{city}供电公司", "{city}燃气公司", "{city}自来水公司"], ["用电户名过户材料补充", "燃气表更换预约", "阶梯水价家庭人口登记"]),
    "property": ("utility", ["{city}锦华物业", "{city}绿城物业"], ["业主大会表决", "装修备案登记", "车位租赁续签"]),
    "merchant_platform": ("platform", ["云川商城商家服务中心", "青禾优选招商部"], ["店铺年度资质复审", "保证金账户对账", "商家主体信息复核"]),
    "logistics": ("platform", ["嘉禾物流", "云川速运"], ["月结账单确认", "运单签收异常处理"]),
    "cloud": ("platform", ["星河云", "云川计算"], ["账号实名认证复核", "网站备案信息核验", "资源到期续费"]),
    "association": ("association", ["{city}市软件行业协会", "{city}市注册会计师协会"], ["会员信息年度更新", "年度会费缴纳", "继续教育学时申报"]),
    "exchange": ("association", ["{city}产权交易所", "{city}公共资源交易中心"], ["投标保证金退还确认", "交易主体信息登记", "CA数字证书续期"]),
    "airline_program": ("platform", ["云川航空常旅客服务中心"], ["会员资料完善", "里程有效期确认"]),
    "rental": ("utility", ["{city}安居公寓", "{city}人才公寓管理中心"], ["租约续签", "年度租金调整确认"]),
}

ZH_PROCEDURAL_CHANNELS = {
    "gov": ["通过{city}市政务服务网（请手动输入官方网址）", "前往{city}市政务服务中心窗口", "通过本地官方政务App", "登录本机关官方网站相应栏目", "携带相关材料到现场"],
    "finance": ["通过{org}官方App", "通过企业网银", "前往开户网点", "联系您的客户经理", "通过官方网站（请自行输入网址）"],
    "enterprise": ["按函证上的地址直接回函", "通过事务所公开的联系方式与我们确认", "与项目经理{person}联系"],
    "internal": ["通过公司内网门户", "在OA系统中", "到{dept}现场"],
    "edu": ["登录学校信息门户", "通过教务系统", "联系班主任或辅导员"],
    "health": ["通过医院官方公众号", "到门诊服务台"],
    "platform": ["登录官方App", "在控制台中", "登录商家后台"],
    "utility": ["到营业厅", "通过官方公众号", "联系服务中心"],
    "association": ["登录协会官方网站", "联系秘书处"],
}

ZH_PROCEDURAL_CONSEQUENCES = {
    "gov": ["逾期未办理的，将依照有关规定处理。", "逾期未报送的，可能被列入经营异常名录。", "逾期需重新预约。", "未按时办理将影响后续相关业务。"],
    "finance": ["逾期未更新的，部分非柜面业务将暂停办理，账户资金安全不受影响。", "逾期未完成的，相关交易权限将暂停，完成后即可恢复。", "逾期未回复的，视为对账无误。"],
    "enterprise": ["如有不符，请在回函中注明。", "请于截止日前寄回，以免影响审计进度。"],
    "internal": ["逾期未提交将无法纳入本期发放。", "未完成的同事将收到部门提醒。", "逾期系统将自动关闭填报。"],
    "edu": ["逾期视为放弃。", "未按时提交将影响学位申请。"],
    "health": ["逾期将顺延至下一批次。"],
    "platform": ["逾期未处理的，相关服务将暂停，数据保留{days}天。", "逾期视为确认无误。"],
    "utility": ["逾期将顺延至下一批次办理。", "逾期视为弃权。"],
    "association": ["逾期将影响会员权益。"],
}

ZH_PROCEDURAL_SUBJECTS = ["关于{matter}的通知", "{matter}提醒", "请及时办理{matter}", "【温馨提示】{matter}", "{matter}的说明", "关于开展{matter}工作的通知"]
ZH_PROCEDURAL_INTROS = [
    "请于{date}前完成{matter}。", "{matter}工作已经开始，截止时间为{date}。", "根据有关规定，现开展{matter}，请务必在{date}前办理。",
    "您（贵单位）需在{date}前完成{matter}。", "现将{matter}有关事项通知如下：截止日期为{date}。", "按照年度工作安排，{matter}须于{date}前完成。",
    "为保障您的合法权益，请在{date}前办理{matter}。",
]
ZH_PROCEDURAL_DETAILS = [
    "办理时请携带营业执照副本及经办人身份证件。", "本次办理不收取任何费用。", "办理时间为工作日9:00-17:00。", "已办理的请忽略本通知。",
    "具体要求详见附件。", "咨询电话：{phone}。", "联系人：{person}，电话{phone}。", "材料清单及填写说明见附件。", "如材料齐全，可当场办结。",
]

EN_PROCEDURAL_KINDS = {
    "county_clerk": ("gov", ["{city} County Clerk's Office"], ["your business name renewal", "the annual report for your registered business"]),
    "dmv": ("gov", ["State Department of Motor Vehicles"], ["your vehicle registration renewal", "your driver license renewal"]),
    "licensing_board": ("gov", ["State Board of Accountancy", "State Nursing Board", "State Contractors Licensing Board"], ["your license renewal", "your continuing education reporting"]),
    "tax_office": ("gov", ["{city} Department of Revenue", "State Tax Office"], ["your quarterly sales tax return", "your annual withholding reconciliation"]),
    "jury": ("gov", ["{city} County Superior Court"], ["your juror qualification questionnaire"]),
    "elections": ("gov", ["{city} County Elections Office"], ["your voter registration address confirmation"]),
    "passport": ("gov", ["Passport Agency"], ["your passport application follow-up documents"]),
    "school_district": ("edu", ["{city} Unified School District"], ["annual enrollment verification", "your student's immunization records update"]),
    "university": ("edu", ["Office of the Registrar", "{city} University Financial Aid Office"], ["your FAFSA verification documents", "your graduation application", "your housing contract renewal"]),
    "bank_business": ("finance", ["Northbridge Bank Business Services", "Harbor Mutual Commercial Banking"], ["the annual beneficial ownership certification", "your treasury token replacement", "the annual account review"]),
    "bank_personal": ("finance", ["Northbridge Bank", "Keystone Federal"], ["your updated identification", "your dormant account reactivation", "your contact information review"]),
    "brokerage": ("finance", ["Keystone Brokerage", "Summit Investments"], ["your investor profile update", "your options trading agreement review", "your W-8BEN recertification"]),
    "retirement": ("finance", ["Harbor Retirement Services", "Summit 401(k) Plan"], ["your beneficiary designation review", "your required minimum distribution election"]),
    "insurer": ("finance", ["Evergreen Insurance", "Shield Mutual"], ["your policy renewal questionnaire", "the group enrollment census", "your vehicle mileage update"]),
    "audit_firm": ("enterprise", ["Granite & Lowe CPAs", "Ridgeway Audit Partners"], ["the bank confirmation request", "the receivables confirmation", "the year-end audit request list"]),
    "law_firm": ("enterprise", ["Hale & Morgan LLP"], ["the engagement letter", "the document production for your case"]),
    "employer_hr": ("internal", ["Human Resources", "People Operations"], ["your annual benefits enrollment", "your I-9 reverification", "your emergency contact update", "the annual code of conduct acknowledgment"]),
    "employer_it": ("internal", ["IT Service Desk", "Corporate IT"], ["your laptop refresh appointment", "the annual access review for your team", "the endpoint security update"]),
    "employer_finance": ("internal", ["Finance", "Accounts Payable"], ["your corporate card statement reconciliation", "the budget submission for next year", "your expense report approvals"]),
    "vendor_onboarding": ("enterprise", ["{company} Procurement", "{company} Supplier Management"], ["your W-9 form for vendor setup", "the supplier code of conduct acknowledgment", "your insurance certificate renewal"]),
    "healthcare": ("health", ["{city} Medical Center", "Lakeside Family Clinic"], ["your annual wellness visit scheduling", "your patient registration update"]),
    "utility": ("utility", ["{city} Power & Light", "{city} Water Utility"], ["the meter access appointment", "your service transfer paperwork"]),
    "hoa": ("utility", ["Maple Ridge HOA", "{city} Commons Association"], ["the annual board election ballot", "your architectural review request"]),
    "landlord": ("utility", ["Parkview Apartments", "{city} Property Management"], ["your lease renewal", "the annual smoke detector inspection"]),
    "cloud": ("platform", ["Cobalt Cloud", "Stratus Hosting"], ["your billing contact verification in the console", "your domain registration renewal", "your organization's annual security attestation"]),
    "marketplace": ("platform", ["Brightcart Seller Services", "Parcelhub Partner Center"], ["your seller tax information interview", "your annual business verification"]),
    "association": ("association", ["{city} Bar Association", "National Society of Engineers"], ["your membership renewal", "your continuing education credits report"]),
    "loyalty": ("platform", ["Brightline Airways Miles", "Harborview Rewards"], ["your profile completion", "your points expiration review"]),
}

EN_PROCEDURAL_CHANNELS = {
    "gov": ["through the official state website (type the address yourself)", "in person at the {city} service center", "by mail using the enclosed form"],
    "finance": ["in the {org} app", "through online banking", "at any branch", "with your relationship manager", "by typing our web address into your browser"],
    "enterprise": ["by replying directly to the address on the confirmation", "by contacting {person} at the number you already have for us"],
    "internal": ["through the HR portal on the intranet", "in Workday", "with your manager", "at the IT help bar"],
    "edu": ["through the student portal", "with the school office", "through the parent portal"],
    "health": ["through the patient portal", "by calling our front desk"],
    "platform": ["in the console", "in your account settings", "in the seller dashboard"],
    "utility": ["by calling our customer service line", "through your online account", "with the management office"],
    "association": ["through the member portal", "by contacting the membership office"],
}

EN_PROCEDURAL_CONSEQUENCES = {
    "gov": ["Late filings may be subject to penalties set by law.", "If we do not receive it by the deadline, your application will be closed and you may reapply.", "Missing the deadline may delay processing."],
    "finance": ["Until it is completed, some online services may be limited; your funds remain safe and accessible at a branch.", "If you do not respond, the account will remain open with its current settings.", "If we don't hear from you, we will treat the statement as confirmed."],
    "enterprise": ["Please note any differences directly on the form.", "A timely reply helps us complete the audit on schedule."],
    "internal": ["If you miss the window, your current elections will roll over.", "Your manager will receive a reminder if it is not completed.", "Late items will be processed next cycle."],
    "edu": ["Late submissions may delay your aid.", "Missing records may affect enrollment."],
    "health": ["If you can't make it, please let us know so we can offer the slot to another patient."],
    "platform": ["If it isn't completed, some features will be paused until you do; your data will not be deleted.", "If no changes are made, your current settings stay in place."],
    "utility": ["If we can't access the meter, we'll estimate your usage.", "If we don't hear from you, we'll contact you to reschedule."],
    "association": ["Lapsed memberships can be reinstated at any time."],
}

EN_PROCEDURAL_SUBJECTS = ["Action needed: {matter}", "Reminder: {matter}", "Please complete {matter}", "Deadline approaching for {matter}", "Information about {matter}"]
EN_PROCEDURAL_INTROS = [
    "Please complete {matter} by {date_en}.", "This is a reminder that {matter} is due on {date_en}.", "We're writing to ask you to complete {matter} before {date_en}.",
    "Our records show that {matter} is still outstanding; the deadline is {date_en}.", "As required each year, please complete {matter} no later than {date_en}.",
]
EN_PROCEDURAL_DETAILS = [
    "There is no fee for this.", "If you've already completed this, please disregard this notice.", "Instructions are attached.",
    "Questions can be directed to {person}.", "Office hours are Monday through Friday, 9 a.m. to 5 p.m.", "Please have your account number or reference number ready.",
]

ZH_BUSINESS_TOPICS = {
    "quote": ["附件是{goods_b}的报价单，单价比上次下调了{pct2}%。", "关于贵司询价的{goods_b}，报价已更新，请查收附件。", "报价有效期到{date}，含税含运费。"],
    "contract": ["合同终稿已发，请法务确认第{num2}条的违约责任条款。", "盖章版合同已通过快递寄出，单号{order}。", "合同里交付时间的表述需要再确认一下。"],
    "invoice": ["本月的发票已开具，金额{amount}元，电子版见附件。", "请提供贵司开票信息（名称、税号、地址电话、开户行及账号），财务开票要用。", "发票已寄出，请注意查收。"],
    "payment": ["第二笔款项已提交审批，预计{date}支付至合同约定账户。", "上月货款已于{date}支付，请查收并回复确认。", "我方需收到发票后七个工作日内付款，请尽快开票。"],
    "delivery": ["货物预计{date}到达贵司仓库，请安排人员签收。", "这批货有{count}箱外包装破损，已拍照留存，麻烦跟进一下。", "发货清单见附件，请核对数量。"],
    "meeting_coord": ["下周三下午两点在我们公司开项目协调会，请{person}参加。", "评审会改到{date}，地点不变。", "会议纪要已整理好，请大家补充。"],
    "documents": ["供应商入库需要贵司营业执照副本和开户许可证扫描件，麻烦发一下。", "麻烦把上次培训的签到表和照片发我一份，做总结用。", "请把项目验收资料整理后发到我邮箱。"],
    "hiring_coord": ["候选人{name}的面试安排在{date}上午十点，请您准时参加。", "新同事{name}下周一入职，麻烦IT准备电脑和账号。", "面试评价表请在今天下班前填好。"],
    "customer_service": ["客户反馈上周的订单少发了{count}件，麻烦核实后补发。", "关于客户的投诉，我们已经电话沟通过，对方同意更换。", "售后单已经登记，维修人员明天上门。"],
    "travel_coord": ["机票和酒店已经订好，行程单见附件。", "出差报销请在回来后一周内提交。", "这次去{city}拜访客户，行程安排见附件。"],
    "reimbursement": ["你上个月的报销单少了两张发票，补齐后再提交。", "报销款已经打到工资卡里了，请查收。", "差旅费超标的部分需要领导签字说明。"],
}
ZH_BUSINESS_OPENERS = ["{name}经理，您好：", "{person}：", "各位好，", "{name}总，您好！", "大家好，", "{name}，你好，", ""]
ZH_BUSINESS_CLOSERS = ["辛苦了，谢谢！", "有问题随时沟通。", "盼复。", "谢谢配合。", "麻烦了。", "请知悉。"]

EN_BUSINESS_TOPICS = {
    "quote": ["Attached is the updated quote for {goods_b_en}; unit pricing is down {pct2}% from last time.", "The quote is valid through {date_en} and includes shipping.", "Let me know if you need a different quantity break."],
    "contract": ["The final draft of the agreement is attached; could legal take a look at section {num2}?", "We sent the signed contract by courier, tracking {order}.", "We need to confirm the delivery date language before signing."],
    "invoice": ["Invoice {order} for ${amount} is attached.", "Could you send your billing details so we can set you up in our system?", "We mailed the paper invoice today as requested."],
    "payment": ["The second installment is in approval and should go out on {date_en} to the account in our contract.", "Last month's payment went out on {date_en}; please confirm receipt.", "We pay within 30 days of receiving a valid invoice."],
    "delivery": ["The shipment should arrive at your warehouse on {date_en}.", "{count} cartons arrived damaged; photos are attached.", "The packing list is attached; please check the quantities."],
    "meeting_coord": ["Can we meet Wednesday at 2 to go over the project plan?", "The review has moved to {date_en}; same room.", "Notes from today are attached; feel free to add anything I missed."],
    "documents": ["For vendor setup we need a completed W-9 and your certificate of insurance.", "Could you send the sign-in sheet from the training session?", "Please send the acceptance documents when they're ready."],
    "hiring_coord": ["{name}'s interview is on {date_en} at 10; please plan to join.", "Our new hire starts Monday; can IT have a laptop ready?", "Please submit your interview feedback by end of day."],
    "customer_service": ["The customer says last week's order was short {count} units; can you check and reship?", "I spoke with the customer and they agreed to a replacement.", "The repair ticket is logged and a technician will visit tomorrow."],
    "travel_coord": ["Flights and hotel are booked; itinerary attached.", "Please submit travel expenses within a week of returning.", "Here's the plan for the client visit in {city}."],
}
EN_BUSINESS_OPENERS = ["Hi {first},", "Hello {first},", "Hi all,", "Dear {name},", "Team,", ""]
EN_BUSINESS_CLOSERS = ["Thanks!", "Let me know if you have questions.", "Thanks for your help.", "Appreciate it.", "Best,", "Regards,"]


def procedural_types(chinese):
    kinds = ZH_PROCEDURAL_KINDS if chinese else EN_PROCEDURAL_KINDS
    channels = ZH_PROCEDURAL_CHANNELS if chinese else EN_PROCEDURAL_CHANNELS
    consequences = ZH_PROCEDURAL_CONSEQUENCES if chinese else EN_PROCEDURAL_CONSEQUENCES
    types = {}
    for kind, (group, orgs, matters) in kinds.items():
        if chinese:
            actions = ["您可%s办理。" % channel for channel in channels[group]] + ["请%s办理。" % channel for channel in channels[group]]
        else:
            actions = ["You can complete this %s." % channel for channel in channels[group]]
        types["procedural_" + kind] = {
            "orgs": orgs,
            "subjects": ZH_PROCEDURAL_SUBJECTS if chinese else EN_PROCEDURAL_SUBJECTS,
            "intro": ZH_PROCEDURAL_INTROS if chinese else EN_PROCEDURAL_INTROS,
            "details": (ZH_PROCEDURAL_DETAILS if chinese else EN_PROCEDURAL_DETAILS) + consequences[group],
            "actions": actions,
            "slots": {"matter": matters},
            "fixed_slots": True,
            "disclaimer_rate": 0.2,
        }
    return types


def business_types(chinese):
    topics = ZH_BUSINESS_TOPICS if chinese else EN_BUSINESS_TOPICS
    types = {}
    for topic, sentences in topics.items():
        others = [sentence for name, items in sorted(topics.items()) if name != topic for sentence in items]
        if chinese:
            subjects = ["关于%s" % label for label in ("报价", "合同", "发票", "付款", "发货", "会议", "资料", "面试", "售后", "出差", "报销")] + ["回复：%s" % topic_label for topic_label in ("上次沟通的事", "资料", "安排")]
        else:
            subjects = ["Re: %s" % label for label in ("quote", "contract", "invoice", "payment", "shipment", "meeting", "documents", "interview", "order issue", "trip")] + ["Quick question", "Follow-up"]
        types["business_" + topic] = {
            "orgs": [""],
            "subjects": subjects,
            "intro": sentences,
            "details": others,
            "actions": ZH_BUSINESS_CLOSERS if chinese else EN_BUSINESS_CLOSERS,
            "salutations": ZH_BUSINESS_OPENERS if chinese else EN_BUSINESS_OPENERS,
            "closings": ["", ""] + (["谢谢", "祝好"] if chinese else ["Thanks,", "Best,"]),
            "slots": {"goods_b": ["工业传感器", "办公耗材", "包装材料", "网络设备", "实验试剂"],
                      "goods_b_en": ["industrial sensors", "office supplies", "packaging materials", "network switches", "lab reagents"],
                      "pct2": ["3", "5", "8"], "num2": ["5", "7", "9", "12"]},
            "fixed_slots": True,
            "disclaimer_rate": 0.0,
            "business_signature": True,
        }
    return types


def types_for(version, chinese):
    base = dict(ZH_TYPES if chinese else EN_TYPES)
    if version >= 2:
        base.update(procedural_types(chinese))
        base.update(business_types(chinese))
    return base


ZH_MONTHS = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"]
EN_MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
ZH_PROJECTS = ["数据中台项目", "ERP升级项目", "新门店信息化项目", "客户服务系统改造", "仓储管理系统项目"]
EN_PROJECTS = ["Data Platform", "ERP Upgrade", "Mobile App Redesign", "Warehouse System", "Customer Portal"]


def zh_name(rng):
    return rng.choice(ZH_SURNAMES) + rng.choice(ZH_GIVEN) + (rng.choice(ZH_GIVEN) if rng.random() < 0.5 else "")


def en_name(rng):
    return rng.choice(EN_FIRST), rng.choice(EN_LAST)


def common_slots(rng, chinese):
    year = rng.choice(["2025", "2026"])
    month = rng.randrange(1, 13)
    day = rng.randrange(1, 29)
    month2 = rng.randrange(1, 13)
    day2 = rng.randrange(1, 29)
    slots = {
        "year": year,
        "last4": "%04d" % rng.randrange(0, 10000),
        "order": "%d%07d" % (rng.randrange(1, 10), rng.randrange(0, 10 ** 7)),
        "amount": "{:,.2f}".format(rng.choice([rng.randrange(10, 1000), rng.randrange(1000, 60000)]) + rng.randrange(0, 100) / 100),
        "amount2": "{:,.2f}".format(rng.randrange(5, 800) + rng.randrange(0, 100) / 100),
        "days": str(rng.choice([2, 3, 5, 7, 10, 14, 15, 30])),
        "pct": str(rng.choice([60, 75, 80, 85, 90, 95])),
        "count": str(rng.randrange(2, 60)),
        "num": str(rng.randrange(100, 9999)),
        "hours": str(rng.choice([2, 3, 4, 6, 8])),
    }
    if chinese:
        city = rng.choice(ZH_CITIES)
        slots.update({
            "city": city,
            "date": "%s年%d月%d日" % (year, month, day) if rng.random() < 0.6 else "%d月%d日" % (month, day),
            "date2": "%d月%d日" % (month2, day2),
            "time": "%02d:%02d" % (rng.randrange(7, 22), rng.choice([0, 15, 30, 45])),
            "month": rng.choice(ZH_MONTHS),
            "name": zh_name(rng),
            "person": zh_name(rng) + rng.choice(["", "经理", "老师", "主管"]),
            "dept": rng.choice(ZH_DEPTS),
            "company": rng.choice(ZH_COMPANIES).format(city=rng.choice(ZH_CITIES)),
            "project": rng.choice(ZH_PROJECTS),
        })
    else:
        first, last = en_name(rng)
        city = rng.choice(EN_CITIES)
        slots.update({
            "city": city,
            "date_en": "%s %d" % (EN_MONTHS[month - 1], day) + (", %s" % year if rng.random() < 0.5 else ""),
            "date2_en": "%s %d" % (EN_MONTHS[month2 - 1], day2),
            "time_en": "%d:%02d %s" % (rng.randrange(1, 13), rng.choice([0, 15, 30, 45]), rng.choice(["a.m.", "p.m.", "AM", "PM"])),
            "month_en": rng.choice(EN_MONTHS),
            "name": "%s %s" % (first, last) if rng.random() < 0.5 else rng.choice(["Mr. ", "Ms. "]) + last,
            "first": first,
            "person": "%s %s" % en_name(rng),
            "dept": rng.choice(EN_DEPTS),
            "company": rng.choice(EN_COMPANIES),
            "project_en": rng.choice(EN_PROJECTS),
        })
    return slots


def fill(template, slots, rng, extra):
    values = dict(slots)
    for key, options in extra.items():
        values[key] = rng.choice(options)
    # Slot values may themselves contain slots (organisation names, case numbers).
    for _ in range(3):
        try:
            text = template.format(**values)
        except KeyError as error:
            raise KeyError("missing slot %s in %r" % (error, template))
        if "{" not in text:
            return text
        template = text
    return text


def pick(rng, items, low, high):
    count = min(len(items), rng.randint(low, high))
    return rng.sample(items, count)


def compose(rng, spec, chinese):
    slots = common_slots(rng, chinese)
    extra = dict(spec.get("slots", {}))
    # Version-2 types draw extra randomness only for themselves, so version-1
    # output is unchanged for a given seed.
    if spec.get("fixed_slots"):
        extra = {key: [rng.choice(options)] for key, options in extra.items()}
        slots["phone"] = ("0%d-%08d" % (rng.randrange(10, 999), rng.randrange(0, 10 ** 8))) if chinese \
            else "(%03d) 555-%04d" % (rng.randrange(200, 999), rng.randrange(0, 10000))
    org = fill(rng.choice(spec["orgs"]), slots, rng, extra) if spec["orgs"] != [""] else ""
    slots["org"] = org
    subject = fill(rng.choice(spec["subjects"]), slots, rng, extra)
    if org and rng.random() < 0.35:
        subject = ("【%s】%s" % (org, subject)) if chinese else ("%s: %s" % (org, subject))
    salutations = spec.get("salutations") or (ZH_SALUTATIONS if chinese else EN_SALUTATIONS)
    closings = spec.get("closings") or (ZH_CLOSINGS if chinese else EN_CLOSINGS)
    lines = []
    salutation = fill(rng.choice(salutations), slots, rng, extra)
    if salutation:
        lines.append(salutation)
    paragraph = pick(rng, spec["intro"], 1, 2) + pick(rng, spec["details"], 0, 3)
    sentences = [fill(item, slots, rng, extra) for item in paragraph]
    actions = [fill(item, slots, rng, extra) for item in pick(rng, spec["actions"], 1, 2)]
    joiner = "" if chinese else " "
    if rng.random() < 0.5:
        lines.append(joiner.join(sentences + actions))
    else:
        lines.append(joiner.join(sentences))
        lines.extend(actions)
    if "disclaimer_rate" in spec:
        if rng.random() < spec["disclaimer_rate"]:
            lines.append(rng.choice(ZH_NEVER_ASK if chinese else EN_NEVER_ASK))
    elif spec.get("never_ask") or rng.random() < 0.15:
        if rng.random() < 0.7:
            lines.append(rng.choice(ZH_NEVER_ASK if chinese else EN_NEVER_ASK))
    closing = rng.choice(closings)
    if closing:
        lines.append(closing)
    signature = org or (slots["name"] if chinese else slots["first"])
    if spec.get("business_signature"):
        signature = ("%s\n%s %s" % (slots["person"], slots["company"], slots["dept"])) if chinese \
            else "%s\n%s, %s" % (slots["person"], slots["dept"], slots["company"])
    if org and rng.random() < 0.5:
        signature += ("\n" + slots["date"]) if chinese else ""
    lines.append(signature)
    separator = rng.choice(["\n", "\n\n"])
    body = separator.join(line for line in lines if line)
    if not chinese and rng.random() < 0.2:
        body += "\n\nTo stop receiving these alerts, update your preferences in the app."
    if chinese and rng.random() < 0.2:
        body += "\n\n（本邮件由系统自动发送，请勿回复）"
    return subject, body


def digest(value):
    return hashlib.sha256(value).hexdigest()


def generate(output, seed, per_language, version):
    rng = random.Random(seed)
    output.mkdir(parents=True)
    records = []
    seen = set()
    for language, types in (("zh", types_for(version, True)), ("en", types_for(version, False))):
        names = sorted(types)
        produced = 0
        attempts = 0
        while produced < per_language:
            attempts += 1
            if attempts > per_language * 20:
                raise RuntimeError("not enough distinct %s samples" % language)
            notice_type = names[produced % len(names)]
            subject, body = compose(rng, types[notice_type], language == "zh")
            canonical = json.dumps({"subject": subject, "body": body}, ensure_ascii=False, sort_keys=True).encode()
            content_id = digest(canonical)
            if content_id in seen:
                continue
            seen.add(content_id)
            produced += 1
            records.append({
                "schema_version": 1,
                "content_id": content_id,
                "subject": subject,
                "body": body,
                "content_type": "text/plain",
                "sources": [{
                    "dataset": DATASET,
                    "language": language,
                    "label": "benign",
                    "category": notice_type,
                    "subcategory": "",
                    "data_type": "email",
                    "variant": "original",
                    "sample_id": "synthetic/%s/%s/%d" % (language, notice_type, produced),
                    "notice_type": "%s/%s" % (language, notice_type),
                }],
            })
    path = output / "cases.jsonl"
    with path.open("xb") as stream:
        for record in records:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    manifest = {
        "schema_version": 1,
        "dataset": DATASET,
        "seed": seed,
        "per_language": per_language,
        "generator_version": version,
        "notice_types": {"zh": sorted(types_for(version, True)), "en": sorted(types_for(version, False))},
        "cases_sha256": digest(path.read_bytes()),
        "records": len(records),
    }
    with (output / "manifest.json").open("x") as stream:
        json.dump(manifest, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({key: manifest[key] for key in ("records", "cases_sha256")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--seed", default="vigilyx-synthetic-benign-v1")
    parser.add_argument("--per-language", type=int, default=3000)
    parser.add_argument("--version", type=int, choices=(1, 2), default=1)
    args = parser.parse_args()
    generate(args.output, args.seed, args.per_language, args.version)
