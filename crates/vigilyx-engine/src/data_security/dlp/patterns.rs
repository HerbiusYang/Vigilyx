//! DLP 正则模式

//! `LazyLock<Regex>` 静态编译, `RegexSet` 预筛, 常量表。

use regex::{Regex, RegexSet};
use std::sync::LazyLock;

// 基础模式 (16 个)

/// 信用卡号 (16 位, 允许空格/连字符/点分隔)
/// 使用 ASCII \b 避免匹配中文字符边界 (Unicode \b 会把中文当 \w)
/// 分隔符限 `[\s\-\.]{0,4}`: 真实卡号写法最多 4 组分隔, 无上限分隔会让卡号
/// 跨越 512KiB 扫描窗口边界且超出重叠区 (DLP_SCAN_OVERLAP) 而漏检;
/// 误报由 Luhn + BIN 校验兜底
pub(super) static RE_CREDIT_CARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u:\b)\d{4}[\s\-\.]{0,4}\d{4}[\s\-\.]{0,4}\d{4}[\s\-\.]{0,4}\d{4}(?-u:\b)").unwrap()
});

/// 中国身份证号 (18 位, 最后 1 位可为 X, 容忍空格/连字符/点/间隔号分隔, 每组最多 2 个分隔符)
/// 使用 ASCII \b 避免中文边界问题；finder 中去分隔符后做校验位验证
pub(super) static RE_CHINESE_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u:\b)\d(?:[\s\-.·]{0,2}\d){16}[\s\-.·]{0,2}[\dXx](?-u:\b)").unwrap()
});

/// 中国手机号 (1[3-9] 开头 11 位, ASCII 边界防止匹配身份证/银行卡内部)
/// 容忍空格/连字符/点/间隔号分隔写法 (每组最多 2 个分隔符)；finder 中去分隔符后校验长度

/// 使用 `(?-u:\b)` 强制 ASCII 单词边界:
/// - ASCII `\b` 只认 `[a-zA-Z0-9_]` 为单词字符
/// - 防止从 18 位身份证内部截出 11 位手机号
/// - 中文字符在 ASCII 模式下不是单词字符 -> `电话13812345678` 中的边界成立
pub(super) static RE_CHINESE_PHONE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b)1[3-9](?:[\s\-.·]{0,2}\d){9}(?-u:\b)").unwrap());

/// 银行卡号 (16-19 位, ASCII 边界, 容忍空格/连字符分隔)
pub(super) static RE_BANK_CARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b)\d(?:[\s\-]?\d){15,18}(?-u:\b)").unwrap());

/// 中国结构化地址模式
/// 匹配: "XX省XX市XX区/县XX路/街XX号" 等
/// 至少包含两级地址层级 (省+市, 市+区, 区+路, 路+号 等)
pub(super) static RE_CHINESE_ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"[\p{Han}]{2,10}(?:省|自治区)[\p{Han}]{2,10}(?:市|州|盟)|[\p{Han}]{2,10}(?:市|州)[\p{Han}]{2,10}(?:区|县|旗)|[\p{Han}]{2,10}(?:区|县)[\p{Han}]{2,20}(?:路|街|道|巷|弄|里)|[\p{Han}]{2,20}(?:路|街|道|巷)[\p{Han}\d]{1,10}号"
    ).unwrap()
});

/// 电子邮箱地址
pub(super) static RE_EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap());

/// 系统邮箱前缀 (排除误报)
pub(super) const SYSTEM_EMAIL_PREFIXES: &[&str] = &[
    "noreply",
    "no-reply",
    "system",
    "mailer-daemon",
    "postmaster",
    "admin",
    "root",
    "daemon",
    "nobody",
    "bounce",
    "donotreply",
    "do-not-reply",
];

/// 中国护照号 (E/G/D/S/P/H/L + 8 位数字)
pub(super) static RE_PASSPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[EGDSPHLegdsph]\d{8}\b").unwrap());

/// 统一社会信用代码 (18 位, 排除 I/O/Z/S/V 字符, 大小写容忍)
pub(super) static RE_SOCIAL_CREDIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[1-9A-HJ-NP-RTUW][0-9A-HJ-NP-RTUW][0-9A-HJ-NP-RTUW]{6}[0-9A-HJ-NP-RTUW]{9}[0-9A-HJ-NP-RTUW]\b").unwrap()
});

/// 密码/口令模式
/// 匹配: "密码:xxx", "password: xxx", "口令:xxx", "PIN: xxxx", "PIN码:xxxx"
/// 简体/繁体成对: 密码/密碼, 账号/帳號, 帐户/帳戶 (帐号/账户 为常见简写变体)
pub(super) static RE_CREDENTIAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:Password|password|pass|pwd|密码|密碼|口令|pin码|pin|passcode|secret|credential|账号|帳號|帐户|帳戶|帐号|账户)\s*[：:=]\s*\S+")
        .unwrap()
});

/// SWIFT/BIC 代码 (8 或 11 位: 4 位银行 + 2 位国家 + 2 位地区 + 3 位分行, 大小写容忍)
pub(super) static RE_SWIFT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b").unwrap());

/// CVV/CVC/安全码 (3-4 位, 需要上下文关键词避免误报)
pub(super) static RE_CVV_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:cvv|cvc|cvv2|cvc2|安全码|验证码|card\s*verification)\s*[：:=]?\s*(\d{3,4})\b")
        .unwrap()
});

// 银行新增模式 (P1.2)

/// 税号 - 15 位 (新 18 位已由统一社会信用代码覆盖, 大小写容忍)
/// 结构: 6 位行政区划代码 + 9 位组织机构代码
pub(super) static RE_TAX_ID_15: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b\d{6}[A-HJ-NP-Y0-9]{9}\b").unwrap());

/// IBAN 银行账号 (2 位国家 + 2 位校验 + 11-30 位账号, 大小写容忍)
pub(super) static RE_IBAN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").unwrap());

/// 大金额检测 (数字 + 货币/量级关键词)
/// 排除单独的 "元" 避免 "100元" 误报, 保留 "万元/亿元" 等量级词和外币
pub(super) static RE_LARGE_AMOUNT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?\s*(?:万元|亿元|USD|CNY|RMB|美元|欧元|EUR|GBP|JPY|英镑|日元)",
    )
    .unwrap()
});

/// 银行账号 (上下文关键词 + 10-14 位, 避免误报, 容忍空格/连字符分隔)
/// 使用 \b 确保不从超长数字串中截取出 10-14 位 (超长串尾部无词边界, 整体不匹配)
/// 账号关键词简体/繁体成对: 账号/帐号/帐户/账户 + 帳號/帳戶
pub(super) static RE_BANK_ACCOUNT_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:账号|帐号|帐户|账户|帳號|帳戶|account\s*number|account|acct|转入|转账|汇入|汇款|收款|付款|打款)\s*[：:=]?\s*(\d(?:[\s\-]?\d){9,13})(?-u:\b)",
    )
    .unwrap()
});

/// 保单号/合同编号 (关键词 + 编号/号)
pub(super) static RE_CONTRACT_NUMBER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:保单|贷款|合同|contract|loan|policy)\s*(?:编号|号|no|number)?\s*[：:=]?\s*([A-Z]{0,4}\d{8,20})",
    )
    .unwrap()
});

// 编码视图候选 (D1-2 二级解码重扫, 不属于 DLP_REGEX_SET 预筛体系)

/// Base64 候选段: >=40 个 base64 字符 + 可选 <=2 个填充等号
/// 40 字符下限 (~30 字节明文) 排除短哈希/短 token, 降低误扫
pub(super) static RE_BASE64_CANDIDATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{40,}={0,2}").unwrap());

/// Hex 候选段: 可选 0x 前缀 + >=32 个 hex 字符 (大小写容忍)
pub(super) static RE_HEX_CANDIDATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:0x)?[0-9a-f]{32,}").unwrap());

// JR/T 0197-2020 模式 (idx 16-29)

/// 生物特征关键词 (C4) - 至少 2 个不同关键词才命中
pub(super) static RE_BIOMETRIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:指纹|虹膜|人脸识别|声纹|面部特征|生物特征|faceID|fingerprint|iris|facial\s*recognition|voiceprint|步态|耳纹|眼纹)").unwrap()
});

/// 医疗健康关键词 (C4) - 至少 2 个不同关键词才命中
pub(super) static RE_MEDICAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:病历|诊断|处方|病症|住院|手术记录|过敏史|病史|医嘱|检验报告|用药记录|血型|基因检测|体检报告|传染病|麻醉记录|护理记录|生育信息|既往病史|家族病史)").unwrap()
});

/// 车辆信息 (C3) - 车牌, 大小写容忍
pub(super) static RE_VEHICLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁][A-HJ-NP-Z][A-HJ-NP-Z0-9]{4,5}[A-HJ-NP-Z0-9挂学警港澳]").unwrap()
});

/// VIN 车架号 (C3) - 17 位字母数字, 排除 I/O/Q, 大小写容忍
pub(super) static RE_VIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[A-HJ-NPR-Z0-9]{17}\b").unwrap());

/// 房产/不动产关键词 (C3) - 关键词 + 编号/号上下文
pub(super) static RE_PROPERTY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:不动产权证|房产证|土地证|房屋所有权证|产权证|房产登记)\s*(?:编号|号)?[：:=]?\s*[\w\-]{5,}|(?:不动产|房产|土地使用权|房屋产权)").unwrap()
});

/// 工资/收入信息 (C3) - 关键词 + 金额上下文
pub(super) static RE_INCOME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:工资|薪资|年薪|月薪|收入|税后|税前|公积金缴存|社保缴费|个人所得税|纳税额)\s*[：:=]?\s*[\d,.]+\s*(?:元|万|万元)?").unwrap()
});

/// 地理位置 (C3)
pub(super) static RE_GEO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\d{2,3}\.\d{4,8}\s*[,，]\s*\d{2,3}\.\d{4,8}\b|(?:经度|纬度|longitude|latitude|GPS坐标|定位)\s*[：:=]?\s*\d{2,3}\.\d{3,}").unwrap()
});

/// 验证码/OTP (C3)
/// 注意: `验证码` 在 CVV 上下文检测中也有使用, 引擎层面做了去重避免重复计数
pub(super) static RE_OTP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:验证码|动态口令|OTP|短信验证|动态密码|auth.?code|confirmation.?code)\s*[：:=]?\s*\d{4,8}").unwrap()
});

/// 贷款/信用信息 (C3) - 关键词 + 金额上下文
pub(super) static RE_LOAN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:贷款余额|欠款金额|逾期金额|还款金额|借款金额|授信额度|信用额度|贷款总额|欠息|罚息)\s*[：:=]?\s*[\d,.]+\s*(?:元|万|万元)?").unwrap()
});

/// 保险信息 (C3) - 关键词上下文
pub(super) static RE_INSURANCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:投保人|被保险人|受益人|保险人|保单号|保费|保额|理赔金额|出险|核保|保全|退保)\s*[：:=]?\s*[\w\d,.]+").unwrap()
});

/// 家庭关系信息 (C3) - 关键词 + 姓名/关系上下文
pub(super) static RE_FAMILY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:父亲|母亲|配偶|子女|兄弟|姐妹|家属|紧急联系人|监护人|夫妻|亲属)\s*[：:=]?\s*(?:[\p{Han}]{2,4}|[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)|(?:家庭关系|亲属关系|社交关系)").unwrap()
});

/// 员工/职务信息 (C2) - 关键词上下文
/// 特定关键词(员工编号/工号/入职日期/离职日期)分隔符可选;
/// 通用关键词(部门/岗位/职位/在职)必须有分隔符, 避免"岗位职责"等通用表述误报
pub(super) static RE_EMPLOYEE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        "(?:",
          r"(?:员工编号|工号|入职日期|离职日期)\s*[：:=]?\s*[\w\p{Han}\d\-/]+",
        "|",
          r"(?:部门|岗位|职位|在职)\s*[：:=]\s*[\w\p{Han}\d\-/]+",
        ")",
    )).unwrap()
});

/// 司法记录关键词 (C2) - 至少 2 个不同关键词才命中
pub(super) static RE_JUDICIAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:失信被执行人|被执行人|开庭公告|犯罪记录|行政处罚|违法违规|立案信息|判决书|裁定书|强制执行|限制消费|限制出境)").unwrap()
});

/// 学历/教育信息 (C2)
pub(super) static RE_EDUCATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:学历|学位|毕业院校|毕业学校|毕业日期|入学日期|就读学校)\s*[：:=]?\s*[\w\p{Han}\d\-/]+").unwrap()
});

/// 营业执照注册号 (C2) - 15 位数字
pub(super) static RE_BIZ_LICENSE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:营业执照|工商登记|注册号)\s*(?:编号|号)?[：:=]?\s*\d{15}",
    )
    .unwrap()
});

// RegexSet 预筛 (P3.1)

/// DLP 模式的 RegexSet - 一次扫描判断哪些模式可能命中

/// 索引与 scan_text 中的处理一一对应, 修改时必须同步.
/// 共 30 个模式 (0-15 基础, 16-29 JR/T 0197-2020).
pub(super) static DLP_REGEX_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?-u:\b)\d{4}[\s\-\.]{0,4}\d{4}[\s\-\.]{0,4}\d{4}[\s\-\.]{0,4}\d{4}(?-u:\b)", // 0: credit_card (ASCII boundary for CJK compat)
        r"(?-u:\b)\d(?:[\s\-.·]{0,2}\d){16}[\s\-.·]{0,2}[\dXx](?-u:\b)", // 1: chinese_id (ASCII boundary, separator tolerant)
        r"(?-u:\b)1[3-9](?:[\s\-.·]{0,2}\d){9}(?-u:\b)", // 2: phone (ASCII boundary prevents ID internal match)
        r"(?-u:\b)\d(?:[\s\-]?\d){15,18}(?-u:\b)", // 3: bank_card (ASCII boundary)
        r"[\p{Han}]{2,10}(?:省|自治区|市|州|区|县)[\p{Han}]{1,20}(?:市|州|盟|区|县|旗|路|街|道|巷|弄|里)|[\p{Han}]{2,20}(?:路|街|道|巷)[\p{Han}\d]{1,10}号", // 4: address
        r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", // 5: email
        r"\b[EGDSPHLegdsph]\d{8}\b",                         // 6: passport
        r"(?i)\b[1-9A-HJ-NP-RTUW][0-9A-HJ-NP-RTUW]{17}\b",   // 7: social_credit
        r"(?i)(?:Password|password|pass|pwd|密码|密碼|口令|pin码|pin|passcode|secret|credential|账号|帳號|帐户|帳戶|帐号|账户)\s*[：:=]", // 8: credential
        r"(?i)\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b", // 9: swift (matches detailed regex exactly)
        r"(?i)(?:cvv|cvc|cvv2|cvc2|安全码|验证码|card\s*verification)", // 10: cvv
        r"(?i)\b\d{6}[A-HJ-NP-Y0-9]{9}\b",       // 11: tax_id
        r"(?i)\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", // 12: iban
        r"(?i)\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?\s*(?:万元|亿元|USD|CNY|RMB|美元|欧元|EUR|GBP|JPY|英镑|日元)", // 13: large_amount
        r"(?i)(?:账号|帐号|帐户|账户|帳號|帳戶|account|acct|转入|转账|汇入|汇款|收款|付款|打款)\s*[：:=]?\s*\d(?:[\s\-]?\d){9,13}", // 14: bank_account (pre-filter; boundary check in detailed regex)
        r"(?i)(?:保单|贷款|合同|contract|loan|policy)\s*(?:编号|号|no|number)?\s*[：:=]?\s*[A-Z]{0,4}\d{8,20}", // 15: contract_number
        // JR/T 0197-2020
        r"(?i)(?:指纹|虹膜|人脸识别|声纹|面部特征|生物特征|faceID|fingerprint|iris|facial\s*recognition|voiceprint|步态|耳纹|眼纹)", // 16: biometric
        r"(?i)(?:病历|诊断|处方|病症|住院|手术|过敏史|病史|医嘱|检验报告|用药记录|血型|基因|体检报告|传染病|麻醉|护理记录|生育信息)", // 17: medical
        r"(?i)[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁][A-HJ-NP-Z]|\bVIN\b|\b[A-HJ-NPR-Z0-9]{17}\b", // 18: vehicle (+ VIN, 允许数字开头与详查一致)
        r"(?:不动产|房产|房产证|土地证|房屋所有权|土地使用权|房屋产权|产权证|房产登记)", // 19: property
        r"(?:工资|薪资|年薪|月薪|收入|税后|税前|公积金缴存|社保缴费|个人所得税|纳税额)", // 20: income
        r"\b\d{2,3}\.\d{4,}\s*[,，]\s*\d{2,3}\.\d{4,}|(?:经度|纬度|longitude|latitude|GPS坐标|定位)", // 21: geo
        r"(?i)(?:验证码|动态口令|OTP|短信验证|动态密码|auth.?code|confirmation.?code)", // 22: otp
        r"(?:贷款余额|贷款总额|欠款|逾期金额|还款金额|借款|授信额度|信用额度|欠息|罚息)", // 23: loan
        r"(?:投保人|被保险人|受益人|保险人|保单号|保费|保额|理赔|出险|核保|保全|退保)", // 24: insurance
        r"(?:父亲|母亲|配偶|子女|兄弟|姐妹|家属|紧急联系人|监护人|夫妻|亲属|亲属关系|家庭关系|社交关系)", // 25: family
        r"(?:员工编号|工号|职位|入职日期|离职|在职|部门|岗位)", // 26: employee
        r"(?:失信被执行人|被执行人|开庭公告|犯罪记录|行政处罚|违法违规|立案|判决书|裁定书|强制执行|限制消费|限制出境)", // 27: judicial
        r"(?:学历|学位|毕业院校|毕业学校|毕业日期|入学日期|就读学校)", // 28: education
        r"(?:营业执照|工商登记|注册号)\s*(?:编号|号)?", // 29: biz_license
    ])
    .unwrap()
});

/// IBAN 国家代码 -> 长度映射 (ISO 13616)

/// 仅包含长度唯一的国家, 用于精确匹配, 减少误报.
pub(super) const IBAN_COUNTRY_LENGTHS: &[(&str, usize)] = &[
    ("DE", 22),
    ("GB", 22),
    ("FR", 27),
    ("CH", 21),
    ("AT", 20),
    ("NL", 18),
    ("BE", 16),
    ("IT", 27),
    ("ES", 24),
    ("LU", 20),
    ("IE", 22),
    ("PT", 25),
    ("SE", 24),
    ("DK", 18),
    ("NO", 15),
    ("FI", 18),
    ("PL", 28),
    ("CZ", 24),
    ("HU", 28),
    ("RO", 24),
    ("BG", 22),
    ("HR", 21),
    ("SK", 24),
    ("SI", 19),
    ("LT", 20),
    ("LV", 21),
    ("EE", 20),
    ("MT", 31),
    ("CY", 28),
    ("GR", 27),
    ("AE", 23),
    ("SA", 24),
    ("QA", 29),
    ("BH", 22),
    ("KW", 30),
    ("JO", 30),
    ("LB", 28),
    ("TR", 26),
    ("IL", 23),
];
