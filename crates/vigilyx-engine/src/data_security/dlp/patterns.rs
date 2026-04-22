//! DLP mode

//! `LazyLock<Regex>` Static, `RegexSet`, Constanttable.

use regex::{Regex, RegexSet};
use std::sync::LazyLock;

// mode (16)

/// Card number (16 bit, Contains charactersdelimited)
/// Use ASCII \b EnsureChinesecharacters (Unicode \b Chinese \w,)
pub(super) static RE_CREDIT_CARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u:\b)\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}(?-u:\b)").unwrap()
});

/// Medium large ID cardNumber (18 bit, last1bit X)
/// Use ASCII \b EnsureChinesecharacters
pub(super) static RE_CHINESE_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b)\d{17}[\dXx](?-u:\b)").unwrap());

/// Medium large Mobile phoneNumber (1[3-9] Header 11 bit, ASCII preventmatchID card/Bank Internal)

/// Use `(?-u:\b)` Force ASCII mode word boundary:
/// - ASCII `\b` only `[a-zA-Z0-9_]` word char(word char)
/// - -> From 18 bitID cardMedium Get 11 bit
/// - Chinesecharacters ASCII mode word char -> ` 13812345678` Medium ` -> 1`
pub(super) static RE_CHINESE_PHONE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b)1[3-9]\d{9}(?-u:\b)").unwrap());

/// BankCard number (16-19 bit, ASCII)
pub(super) static RE_BANK_CARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b)\d{16,19}(?-u:\b)").unwrap());

/// Medium - structure Addressmode
/// match: "XX XXCityXXDistrict/CountyXXRoad/StreetXXNumber" wait
/// At leastpacketContains Address level (City+District, District+Road, Road+Number wait)
pub(super) static RE_CHINESE_ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"[\p{Han}]{2,10}(?:省|自治District)[\p{Han}]{2,10}(?:City|州|盟)|[\p{Han}]{2,10}(?:City|州)[\p{Han}]{2,10}(?:District|County|旗)|[\p{Han}]{2,10}(?:District|County)[\p{Han}]{2,20}(?:Road|Street|道|巷|弄|里)|[\p{Han}]{2,20}(?:Road|Street|道|巷)[\p{Han}\d]{1,10}Number"
    ).unwrap()
});

/// emailAddress
pub(super) static RE_EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap());

/// Systememailfirst Name (Exclude)
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

/// Medium Number (E/G/D/S/P/H/L + 8 bit)
pub(super) static RE_PASSPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[EGDSPHLegdsph]\d{8}\b").unwrap());

/// 1 Code/Digit (18 bit, Exclude I/O/Z/S/V characters)
pub(super) static RE_SOCIAL_CREDIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[1-9A-HJ-NP-RTUW][0-9A-HJ-NP-RTUW][0-9A-HJ-NP-RTUW]{6}[0-9A-HJ-NP-RTUW]{9}[0-9A-HJ-NP-RTUW]\b").unwrap()
});

/// Password/ mode
/// match: "Password:xxx", "password: xxx", ":xxx", "PIN: xxxx", "PINCode/Digit:xxxx"
pub(super) static RE_CREDENTIAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:Password|password|pass|pwd|密码|口令|pinCode/Digit|pin|passcode|secret|credential)\s*[：:=]\s*\S+")
        .unwrap()
});

/// SWIFT/BIC Code/Digit (8 11 bit: 4 Bank + 2 + 2 + 3 bit line)
pub(super) static RE_SWIFT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b").unwrap());

/// CVV/CVC/SecurityCode/Digit (3-4 bit, Need/RequireContextKeywordsAvoid)
pub(super) static RE_CVV_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:cvv|cvc|cvv2|cvc2|SecurityCode/Digit|VerifyCode/Digit|card\s*verification)\s*[：:=]?\s*(\d{3,4})\b")
        .unwrap()
});

// line Add mode (P1.2)

/// Number - 15 bit (New 18 bitalreadyBy Code/Digitoverride)
/// : 6 bitline District Code/Digit + 9 bit Code/Digit ()
pub(super) static RE_TAX_ID_15: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{6}[A-HJ-NP-Y0-9]{9}\b").unwrap());

/// IBAN BankAccount number (2 + 2 bitVerify + 11-30 bitAccount number)
pub(super) static RE_IBAN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").unwrap());

/// large Amountdetect (+ / bitKeywords)
/// Exclude "Yuan" Avoid "100Yuan" Sunday, keep "10k yuan/ Yuan" And Number
pub(super) static RE_LARGE_AMOUNT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?\s*(?:10k yuan|亿Yuan|USD|CNY|RMB|美Yuan|欧Yuan|EUR|GBP|JPY|英镑|SundayYuan)",
    )
    .unwrap()
});

/// BankAccount number (ContextKeywords + 10-14 bit, Avoid)
/// Use \b Ensure From longof Medium Get
pub(super) static RE_BANK_ACCOUNT_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:Account number|帐Number|account|acct|转入|转账|汇入|汇款|收款|付款|打款)\s*[：:=]?\s*(\d{10,14})\b",
    )
    .unwrap()
});

/// Policy number/ SameNumber (Keywords + Serial number)
pub(super) static RE_CONTRACT_NUMBER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:保单|贷款|合Same|contract|loan|policy)\s*(?:Number|Serial number|no|number)?\s*[：:=]?\s*([A-Z]{0,4}\d{8,20})",
    )
    .unwrap()
});

// JR/T 0197-2020 mode (idx 16-29)

/// Keywords (C4) - At least 2 Keywords Medium
pub(super) static RE_BIOMETRIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:指纹|虹膜|人脸识别|声纹|面部特征|生物特征|faceID|fingerprint|iris|facial\s*recognition|voiceprint|步态|耳纹|眼纹)").unwrap()
});

/// Keywords (C4) - At least 2 Keywords Medium
pub(super) static RE_MEDICAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:病历|诊Break/Judge|处方|病症|住院|手术Recording|敏史|病史|医嘱|检验报告|用药Recording|血型|基due todetect|体检报告|传染病|麻醉Recording|护理Recording|生育Info|found病史|家族病史)").unwrap()
});

/// (C3) -, VIN
pub(super) static RE_VEHICLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁][A-HJ-NP-Z][A-HJ-NP-Z0-9]{4,5}[A-HJ-NP-Z0-9挂学警港澳]").unwrap()
});

/// VIN chassis number (C3) - 17 alphanumeric characters, excluding I/O/Q
pub(super) static RE_VIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-HJ-NPR-Z0-9]{17}\b").unwrap());

/// / Keywords (C3) - Keywords + Serial numberContext
pub(super) static RE_PROPERTY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:不动产权证|房产证|土地证|房屋Ownership证|产权证|房产登记)\s*(?:Number|Serial number)?[：:=]?\s*[\w\-]{5,}|(?:不动产|房产|土地Use权|房屋产权)").unwrap()
});

/// / Info (C3) - Keywords + AmountContext
pub(super) static RE_INCOME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:工资|薪资|年薪|Monthly salary|收入|税后|税first|公积金缴stored|社保缴费|人所得税|纳税额)\s*[：:=]?\s*[\d,.]+\s*(?:Yuan|万|10k yuan)?").unwrap()
});

/// (C3)
pub(super) static RE_GEO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\d{2,3}\.\d{4,8}\s*[,，]\s*\d{2,3}\.\d{4,8}\b|(?:经度|纬度|longitude|latitude|GPS坐标|定bit)\s*[：:=]?\s*\d{2,3}\.\d{3,}").unwrap()
});

/// VerifyCode/Digit/OTP (C3)
/// : `VerifyCode/Digit` From - Keywordsalready CVV detectMediumUse,Avoid
pub(super) static RE_OTP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:VerifyCode/Digit|Dynamic口令|OTP|short信Verify|DynamicPassword|auth.?code|confirmation.?code)\s*[：:=]?\s*\d{4,8}").unwrap()
});

/// / Info (C3) - Keywords + AmountContext
pub(super) static RE_LOAN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:贷款余额|欠款Amount|逾PeriodAmount| 款Amount|借款Amount|授信额度|信用额度|贷款总额|欠息|罚息)\s*[：:=]?\s*[\d,.]+\s*(?:Yuan|万|10k yuan)?").unwrap()
});

/// Info (C3) - KeywordsContext
pub(super) static RE_INSURANCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:Policyholder|被保险人|受益人|保险人|Policy number|保费|保额|理赔Amount|出险|核保|保全|退保)\s*[：:=]?\s*[\w\d,.]+").unwrap()
});

/// Info (C3) - Keywords + Name/ Context
pub(super) static RE_FAMILY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:父亲|母亲|Spouse|子女|兄弟|姐妹|家属|紧急联系人|监护人|夫妻|亲属)\s*[：:=]?\s*(?:[\p{Han}]{2,4}|[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)|(?:家庭关系|亲属关系|社交关系)").unwrap()
});

/// / Info (C2) - KeywordsContext
/// Keywords(Serial number/Employee ID/ SundayPeriod/ SundayPeriod)delimited;
/// GeneralKeywords(/ bit/ bit/)delimited stored,Avoid" "" bit "waitGeneral
pub(super) static RE_EMPLOYEE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        "(?:",
          r"(?:员工Serial number|Employee ID|入职SundayPeriod|离职SundayPeriod)\s*[：:=]?\s*[\w\p{Han}\d\-/]+",
        "|",
          r"(?:部门|岗bit|职bit|在职)\s*[：:=]\s*[\w\p{Han}\d\-/]+",
        ")",
    )).unwrap()
});

/// RecordingKeywords (C2) - At least 2 Keywords Medium
pub(super) static RE_JUDICIAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:失信被Executeline人|被Executeline人|开庭公告|犯罪Recording|line政处罚|违法违规|立案Info|判决书|裁定书|ForceExecuteline|limit消费|limit出境)").unwrap()
});

/// / Info (C2)
pub(super) static RE_EDUCATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:学历|学bit|毕业院校|毕业学校|毕业SundayPeriod|入学SundayPeriod|就read学校)\s*[：:=]?\s*[\w\p{Han}\d\-/]+").unwrap()
});

/// Execute Number (C2) - 15 bit
pub(super) static RE_BIZ_LICENSE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:营业Execute照|工商登记|RegisterNumber)\s*(?:Number|Serial number)?[：:=]?\s*\d{15}",
    )
    .unwrap()
});

// RegexSet (P3.1)

/// DLP modeof RegexSet - 1Time/Count verdict modepossibly Medium

/// Index scan_text MediumofProcess,Modify Synchronous.
/// 30 mode (0-15, 16-29 JR/T 0197-2020).
pub(super) static DLP_REGEX_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?-u:\b)\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}(?-u:\b)", // 0: credit_card (ASCII boundary for CJK compat)
        r"(?-u:\b)\d{17}[\dXx](?-u:\b)", // 1: chinese_id (ASCII boundary)
        r"(?-u:\b)1[3-9]\d{9}(?-u:\b)",  // 2: phone (ASCII boundary prevents ID internal match)
        r"(?-u:\b)\d{16,19}(?-u:\b)",    // 3: bank_card (ASCII boundary)
        r"[\p{Han}]{2,10}(?:省|自治District|City|州|District|County)[\p{Han}]{1,20}(?:City|州|盟|District|County|旗|Road|Street|道|巷|弄|里)|[\p{Han}]{2,20}(?:Road|Street|道|巷)[\p{Han}\d]{1,10}Number", // 4: address
        r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", // 5: email
        r"\b[EGDSPHLegdsph]\d{8}\b",                         // 6: passport
        r"\b[1-9A-HJ-NP-RTUW][0-9A-HJ-NP-RTUW]{17}\b",       // 7: social_credit
        r"(?i)(?:Password|password|pass|pwd|密码|口令|pinCode/Digit|pin|passcode|secret|credential)\s*[：:=]", // 8: credential
        r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b", // 9: swift (matches detailed regex exactly)
        r"(?i)(?:cvv|cvc|cvv2|cvc2|SecurityCode/Digit|VerifyCode/Digit|card\s*verification)", // 10: cvv
        r"\b\d{6}[A-HJ-NP-Y0-9]{9}\b",       // 11: tax_id
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", // 12: iban
        r"(?i)\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?\s*(?:10k yuan|亿Yuan|USD|CNY|RMB|美Yuan|欧Yuan|EUR|GBP|JPY|英镑|SundayYuan)", // 13: large_amount
        r"(?i)(?:Account number|帐Number|account|acct|转入|转账|汇入|汇款|收款|付款|打款)\s*[：:=]?\s*\d{10,14}", // 14: bank_account (pre-filter; boundary check in detailed regex)
        r"(?i)(?:保单|贷款|合Same|contract|loan|policy)\s*(?:Number|Serial number|no|number)?\s*[：:=]?\s*[A-Z]{0,4}\d{8,20}", // 15: contract_number
        // JR/T 0197-2020
        r"(?i)(?:指纹|虹膜|人脸识别|声纹|面部特征|生物特征|faceID|fingerprint|iris|voiceprint|步态|耳纹)", // 16: biometric
        r"(?i)(?:病历|诊Break/Judge|处方|病症|住院|手术|敏史|病史|医嘱|检验报告|用药Recording|血型|基due to|体检报告|传染病|麻醉)", // 17: medical
        r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁][A-HJ-NP-Z]|(?i)\bVIN\b|\b[A-HJ-NPR-Z][A-HJ-NPR-Z0-9]{16}\b", // 18: vehicle (+ VIN)
        r"(?:不动产|房产证|土地证|房屋Ownership|产权证|房产登记)", // 19: property
        r"(?:工资|薪资|年薪|Monthly salary|收入|税后|税first|公积金缴stored|社保缴费|人所得税)", // 20: income
        r"\b\d{2,3}\.\d{4,}\s*[,，]\s*\d{2,3}\.\d{4,}|(?:经度|纬度|longitude|latitude|GPS坐标|定bit)", // 21: geo
        r"(?i)(?:VerifyCode/Digit|Dynamic口令|OTP|short信Verify|DynamicPassword|auth.?code|confirmation.?code)", // 22: otp
        r"(?:贷款余额|贷款总额|欠款|逾PeriodAmount| 款Amount|借款|授信额度|信用额度|欠息|罚息)", // 23: loan
        r"(?:Policyholder|被保险人|受益人|保险人|Policy number|保费|保额|理赔|出险|核保|退保)", // 24: insurance
        r"(?:父亲|母亲|Spouse|子女|兄弟|姐妹|家属|紧急联系人|监护人|亲属关系|家庭关系)", // 25: family
        r"(?:员工Serial number|Employee ID|职bit|入职SundayPeriod|离职|在职|部门|岗bit)", // 26: employee
        r"(?:失信被Executeline人|被Executeline人|开庭公告|犯罪Recording|line政处罚|违法违规|立案|判决书|裁定书|ForceExecuteline|limit消费|limit出境)", // 27: judicial
        r"(?:学历|学bit|毕业院校|毕业学校|毕业SundayPeriod|入学SundayPeriod|就read学校)", // 28: education
        r"(?:营业Execute照|工商登记|RegisterNumber)\s*(?:Number|Serial number)?", // 29: biz_license
    ])
    .unwrap()
});

/// IBAN Code/Digit -> Length (ISO 13616)

/// 1 of IBAN Length, match,large.
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
