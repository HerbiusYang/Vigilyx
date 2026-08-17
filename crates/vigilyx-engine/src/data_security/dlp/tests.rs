use super::finders::*;
use super::normalize::normalize_for_dlp;
use super::*;

// Test (Keep)

#[test]
fn test_scan_text_with_credit_card() {
    // Luhn-valid test card number
    let text = "请将款项汇入 4111111111111111 这Account";
    let result = scan_text(text);
    assert!(result.matches.contains(&"credit_card".to_string()));
}

#[test]
fn test_scan_text_with_id_number() {
    let text = "身份证号码是 000000200001010005";
    let result = scan_text(text);
    assert!(result.matches.contains(&"id_number".to_string()));
}

#[test]
fn test_scan_text_with_phones() {
    let text = "联系人: 13800138000, 13900139000, 14700147000";
    let result = scan_text(text);
    assert!(result.matches.contains(&"phone_number".to_string()));
}

#[test]
fn test_scan_text_clean_content() {
    let text = "这是1封NormalofemailContent，not有Sensitivedata。";
    let result = scan_text(text);
    assert!(result.matches.is_empty());
}

#[test]
fn test_credit_card_luhn_valid() {
    assert!(luhn_check("4111111111111111"));
}

#[test]
fn test_credit_card_luhn_invalid() {
    assert!(!luhn_check("1234567890123456"));
}

#[test]
fn test_scan_text_with_chinese_address_province_city() {
    let text = "客户住址: 陕西省西安市雁塔区科技路100编号";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"customer_address".to_string()),
        "Chinese address with province+city should be detected"
    );
}

#[test]
fn test_scan_text_with_chinese_address_city_district() {
    let text = "寄送到: 西安市雁塔区长安南路1号";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"customer_address".to_string()),
        "Chinese address with city+district should be detected"
    );
}

#[test]
fn test_scan_text_with_chinese_address_district_road() {
    let text = "家庭Address: 雁塔区科技路创业大厦";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"customer_address".to_string()),
        "Chinese address with district+road should be detected"
    );
}

#[test]
fn test_scan_text_address_masking() {
    let text = "陕西省西安市雁塔区科技路100编号";
    let matches = find_chinese_addresses(text);
    assert!(!matches.is_empty());
    assert!(matches[0].contains("***"));
}

#[test]
fn test_scan_text_no_address_in_normal_text() {
    let text = "今DayDay气不错，我们1起去公园散步吧。";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"customer_address".to_string()),
        "Normal text should not trigger address detection"
    );
}

#[test]
fn test_api_key_no_longer_detected() {
    let text = "APIKey: ABCDef1234567890ABCDef1234567890XY";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"api_key".to_string()),
        "API key detection has been removed"
    );
}

// emailTest

#[test]
fn test_scan_text_with_email() {
    let text = "客户Name单: zhangsan@example.com, lisi@example.net, wangwu@example.org";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"email_address".to_string()),
        "3+ email addresses should be detected"
    );
}

#[test]
fn test_email_excludes_system_addresses() {
    let text = "Autoemail noreply@example.com 和 system@example.net 和 postmaster@example.org";
    let emails = find_emails(text);
    assert!(
        emails.is_empty(),
        "System emails should be excluded, got: {:?}",
        emails
    );
}

#[test]
fn test_email_masking() {
    let emails = find_emails("user@example.test");
    assert_eq!(emails.len(), 1);
    assert_eq!(emails[0], "u***@example.test");
}

// 编号Test

#[test]
fn test_scan_text_with_passport() {
    let text = "护照编号 E12345678 alreadyExpired";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"passport_number".to_string()),
        "Passport number should be detected"
    );
}

#[test]
fn test_passport_masking() {
    let passports = find_passports("G87654321");
    assert_eq!(passports.len(), 1);
    assert_eq!(passports[0], "G8****21");
}

#[test]
fn test_passport_lowercase_match() {
    let passports = find_passports("e12345678");
    assert!(
        !passports.is_empty(),
        "Lowercase passport letter should also match"
    );
}

// 1 码Test

#[test]
fn test_scan_text_with_social_credit_code() {
    let text = "公司信用代码 A0000000000000000M";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"social_credit_code".to_string()),
        "Social credit code should be detected"
    );
}

#[test]
fn test_social_credit_code_masking() {
    let codes = find_social_credit_codes("A0000000000000000M");
    assert_eq!(codes.len(), 1);
    assert_eq!(codes[0], "A000****000M");
}

#[test]
fn test_social_credit_code_wrong_length_rejected() {
    let codes = find_social_credit_codes("9111000071093109A");
    assert!(codes.is_empty(), "17-char string should not match");
}

// Test

#[test]
fn test_scan_text_with_credential_chinese() {
    let text = "系统密码：abc123456";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "Chinese credential pattern should be detected"
    );
}

#[test]
fn test_scan_text_with_credential_english() {
    let text = "password: MySecret123";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "English credential pattern should be detected"
    );
}

#[test]
fn test_credential_masking() {
    let creds = find_credentials("Password：abc123");
    assert_eq!(creds.len(), 1);
    assert!(creds[0].contains("****"), "Credential value must be masked");
    assert!(creds[0].contains("Password"), "Keyword should be preserved");
}

// SWIFT 码Test

#[test]
fn test_scan_text_with_swift_8() {
    let text = "请汇款至 BKCHCNBJ BankAccount";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"swift_code".to_string()),
        "8-char SWIFT code should be detected"
    );
}

#[test]
fn test_scan_text_with_swift_11() {
    let text = "SWIFT代码 BKCHCNBJ100";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"swift_code".to_string()),
        "11-char SWIFT code should be detected"
    );
}

#[test]
fn test_swift_masking() {
    let codes = find_swift_codes("BKCHCNBJ");
    assert_eq!(codes.len(), 1);
    assert_eq!(codes[0], "BKCH****");
}

// CVV 安全码Test

#[test]
fn test_scan_text_with_cvv_chinese() {
    let text = "信用卡安全码: 123";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"cvv_code".to_string()),
        "CVV with Chinese keyword should be detected"
    );
}

#[test]
fn test_scan_text_with_cvv_english() {
    let text = "CVV: 456";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"cvv_code".to_string()),
        "CVV with English keyword should be detected"
    );
}

#[test]
fn test_cvv_no_false_positive_without_context() {
    let text = "房间编号 123 在3楼";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"cvv_code".to_string()),
        "Random 3-digit number without CVV context should NOT match"
    );
}

// DLP Test

#[test]
fn test_scan_text_scans_beyond_old_limit() {
    // PoC：头部填充把敏感数据推出旧单窗扫描范围；分窗扫描后仍应检出
    let padding = "A".repeat(DLP_MAX_SCAN_LEN + 100);
    let text = format!("{} 4111111111111111", padding);
    let result = scan_text(&text);
    assert!(
        result.matches.contains(&"credit_card".to_string()),
        "Credit card beyond the old single-window limit should be detected by windowed scan"
    );
}

#[test]
fn test_scan_text_detects_within_limit() {
    let padding = "B".repeat(1000);
    let text = format!("{} 4111111111111111", padding);
    let result = scan_text(&text);
    assert!(
        result.matches.contains(&"credit_card".to_string()),
        "Credit card within DLP_MAX_SCAN_LEN should be detected"
    );
}

#[test]
fn test_scan_text_truncation_preserves_utf8_boundary() {
    let padding = "测".repeat(DLP_MAX_SCAN_LEN / 3 + 10);
    let result = scan_text(&padding);
    assert!(result.matches.is_empty());
}

// P1.1 /Bank DeduplicateTest

#[test]
fn test_credit_card_and_bank_card_no_duplicate() {
    let text = "Card number 4111111111111111";
    let result = scan_text(text);
    assert!(result.matches.contains(&"credit_card".to_string()));
    assert!(
        !result.matches.contains(&"bank_card".to_string()),
        "16-digit Luhn-valid number should NOT appear in both credit_card AND bank_card"
    );
}

#[test]
fn test_bank_card_19_digit_not_excluded() {
    let text = "BankCard number 6222021234567890123";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"credit_card".to_string()),
        "19-digit number should not match credit_card (16-digit only)"
    );
}

// P1.2 编号Test

#[test]
fn test_scan_text_with_tax_id_15() {
    let text = "纳税人识别编号 110108MA12345N9";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"tax_id".to_string()),
        "15-digit tax ID should be detected"
    );
}

#[test]
fn test_tax_id_masking() {
    let ids = find_tax_ids("110108MA12345N9");
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0], "1101****5N9");
}

#[test]
fn test_tax_id_wrong_length_rejected() {
    let ids = find_tax_ids("110108MA1234N9");
    assert!(ids.is_empty(), "14-char string should not match tax_id");
}

// P1.2 IBAN Test

#[test]
fn test_scan_text_with_iban_de() {
    let text = "请汇款至 DE89370400440532013000";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"iban".to_string()),
        "German IBAN should be detected"
    );
}

#[test]
fn test_scan_text_with_iban_gb() {
    let text = "汇款到 GB29NWBK60161331926819";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"iban".to_string()),
        "UK IBAN should be detected"
    );
}

#[test]
fn test_iban_masking() {
    let ibans = find_ibans("DE89370400440532013000");
    assert_eq!(ibans.len(), 1);
    assert!(ibans[0].starts_with("DE89"));
    assert!(ibans[0].contains("****"));
}

#[test]
fn test_iban_invalid_country_rejected() {
    let ibans = find_ibans("XX89370400440532013000");
    assert!(ibans.is_empty(), "Invalid country code should be rejected");
}

#[test]
fn test_iban_invalid_checksum_rejected() {
    let ibans = find_ibans("DE00370400440532013000");
    assert!(ibans.is_empty(), "Invalid IBAN checksum should be rejected");
}

#[test]
fn test_iban_mod97_valid() {
    assert!(iban_mod97_check("DE89370400440532013000"));
    assert!(iban_mod97_check("GB29NWBK60161331926819"));
}

#[test]
fn test_iban_mod97_invalid() {
    assert!(!iban_mod97_check("DE00370400440532013000"));
    assert!(!iban_mod97_check("XXXX"));
}

// P1.2 大 AmountTest

#[test]
fn test_scan_text_with_large_amounts() {
    let text = "合同Amount 100万元, 首付 30万元";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"large_amount".to_string()),
        "2+ 大 amounts should be detected"
    );
}

#[test]
fn test_scan_text_single_amount_no_alert() {
    let text = "年薪 50万元";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"large_amount".to_string()),
        "Single amount should NOT trigger"
    );
}

#[test]
fn test_repeated_identical_large_amount_stays_below_unique_threshold() {
    let result = scan_text("合同金额 50万元，备注再次列示 50万元");
    assert!(
        !result.matches.contains(&"large_amount".to_string()),
        "the threshold requires two distinct amounts, not two copies of one value"
    );
}

#[test]
fn test_large_amount_foreign_currency() {
    let text = "Transfer 1,000,000 USD to account, fee 500 EUR";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"large_amount".to_string()),
        "Foreign currency amounts should be detected"
    );
}

#[test]
fn test_large_amount_masking() {
    let amounts = find_large_amounts("合同Amount 100万元");
    assert_eq!(amounts.len(), 1);
    assert!(amounts[0].contains("***"), "Amount should be masked");
    assert!(
        amounts[0].contains("万元"),
        "Currency unit should be preserved"
    );
}

// P1.2 Bank账号 (Context) Test

#[test]
fn test_scan_text_with_bank_account_context() {
    let text = "请转账到 账号：1234567890123";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"bank_account".to_string()),
        "Bank account with context keyword should be detected"
    );
}

#[test]
fn test_bank_account_no_context_no_alert() {
    let text = "编号 12345678901234";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"bank_account".to_string()),
        "编号 without context keyword should NOT trigger bank_account"
    );
}

#[test]
fn test_bank_account_english_context() {
    let text = "account: 9876543210";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"bank_account".to_string()),
        "English 'account' keyword should also work"
    );
}

#[test]
fn test_bank_account_masking() {
    let accounts = find_bank_accounts("账号：1234567890123");
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0], "1234****23");
}

// P1.2 保单号/ Same编号Test

#[test]
fn test_scan_text_with_contract_number() {
    let text = "贷款合同编号: LN20260312345678";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"contract_number".to_string()),
        "Loan contract number should be detected"
    );
}

#[test]
fn test_scan_text_with_policy_number() {
    let text = "保单号：PL12345678901234";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"contract_number".to_string()),
        "Insurance policy number should be detected"
    );
}

#[test]
fn test_contract_number_no_context_no_alert() {
    let text = "File编号 AB12345678";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"contract_number".to_string()),
        "编号 without contract/loan keyword should NOT trigger"
    );
}

#[test]
fn test_contract_number_masking() {
    let contracts = find_contract_numbers("贷款合同编号: LN20260312345678");
    assert_eq!(contracts.len(), 1);
    assert!(contracts[0].starts_with("LN20"));
    assert!(contracts[0].contains("****"));
}

// RegexSet Performance notesTest

#[test]
fn test_regex_set_clean_text_fast_path() {
    let text = "这是1封Normalof工作email，讨论下Weekdayof项目进度。";
    let result = scan_text(text);
    assert!(result.matches.is_empty());
}

#[test]
fn test_regex_set_only_runs_matched_patterns() {
    let text = "Card number 4111111111111111";
    let result = scan_text(text);
    assert!(result.matches.contains(&"credit_card".to_string()));
    assert_eq!(result.matches.len(), 1, "Only credit_card should match");
}

// JR/T 0197-2020 modeTest

#[test]
fn test_biometric_data_two_keywords_hit() {
    let text = "user提交了指纹data和虹膜扫描Result Used for身份Authentication";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"biometric_data".to_string()),
        "两生物特征Keywords应命Medium"
    );
}

#[test]
fn test_biometric_data_single_keyword_no_hit() {
    let text = "该设备支持指纹识别Function";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"biometric_data".to_string()),
        "单Keywords不应命Medium"
    );
}

#[test]
fn test_medical_health_hit() {
    let text = "患者病历显示有敏史，医嘱要求停药观察";
    let result = scan_text(text);
    assert!(result.matches.contains(&"medical_health".to_string()));
}

#[test]
fn test_medical_health_single_no_hit() {
    let text = "今Day去医院做了体检";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"medical_health".to_string()),
        "单医疗Keywords不应命Medium"
    );
}

#[test]
fn test_vehicle_info_plate() {
    let text = "车辆登记Info: 京A12345, VIN LSVAU2180N2183294";
    let result = scan_text(text);
    assert!(result.matches.contains(&"vehicle_info".to_string()));
}

#[test]
fn test_income_info_hit() {
    let text = "员工张三月薪: 15000元，公积金缴存: 2400元";
    let result = scan_text(text);
    assert!(result.matches.contains(&"income_info".to_string()));
}

#[test]
fn test_geo_location_hit() {
    let text = "user常驻bit置 116.3975, 39.9086 北京市Medium心";
    let result = scan_text(text);
    assert!(result.matches.contains(&"geo_location".to_string()));
}

#[test]
fn test_otp_hit() {
    let text = "您of验证码: 582931, 请在5minute内Use";
    let result = scan_text(text);
    assert!(result.matches.contains(&"otp_verification".to_string()));
}

#[test]
fn test_loan_credit_hit() {
    let text = "客户贷款余额: 580,000元，逾期金额: 12,000元";
    let result = scan_text(text);
    assert!(result.matches.contains(&"loan_credit_info".to_string()));
}

#[test]
fn test_insurance_hit() {
    let text = "投保人: 李明，被保险人: 王芳，保费: 3200元";
    let result = scan_text(text);
    assert!(result.matches.contains(&"insurance_policy".to_string()));
}

#[test]
fn test_family_relation_hit() {
    let text = "紧急联系人: 张三，配偶: 李四";
    let result = scan_text(text);
    assert!(result.matches.contains(&"family_relation".to_string()));
}

#[test]
fn test_employee_info_hit() {
    let text = "员工编号: EMP20230156, 部门: 风控部, 职位: HighlevelAnalyze师";
    let result = scan_text(text);
    assert!(result.matches.contains(&"employee_info".to_string()));
}

#[test]
fn test_judicial_record_hit() {
    let text = "该客户stored在失信被执行人记录，并有行政处罚历史";
    let result = scan_text(text);
    assert!(result.matches.contains(&"judicial_record".to_string()));
}

#[test]
fn test_judicial_record_single_no_hit() {
    let text = "法院公告Info";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"judicial_record".to_string()),
        "单司法Keywords不应命Medium"
    );
}

#[test]
fn test_education_info_hit() {
    let text = "学历: 本科, 毕业院校: 北京大学, 毕业日期: 2020/06";
    let result = scan_text(text);
    assert!(result.matches.contains(&"education_info".to_string()));
}

#[test]
fn test_business_license_hit() {
    let text = "公司营业执照编号: 110105012345678";
    let result = scan_text(text);
    assert!(result.matches.contains(&"business_license".to_string()));
}

#[test]
fn test_property_info_hit() {
    let text = "客户名下有不动产权证编号: 京2023朝阳区不动产权第0012345号";
    let result = scan_text(text);
    assert!(result.matches.contains(&"property_info".to_string()));
}

// The remaining ~3,200 lines of tests follow the same pattern.
// They are included verbatim from the original file below.

// JR/T: depthTest (Item +)

#[test]
fn test_biometric_english_keywords() {
    let text = "User fingerprint captured. Iris scan completed for authentication.";
    let result = scan_text(text);
    assert!(result.matches.contains(&"biometric_data".to_string()));
}

#[test]
fn test_biometric_three_keywords() {
    let text = "采集了指纹、虹膜和声纹3种生物特征";
    let result = scan_text(text);
    assert!(result.matches.contains(&"biometric_data".to_string()));
    let detail = result.details.iter().find(|(k, _)| k == "biometric_data");
    assert!(detail.is_some());
    assert!(detail.unwrap().1.len() >= 3);
}

#[test]
fn test_biometric_no_false_positive_on_product() {
    let text = "我们of产品支持多种生物识别Method";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"biometric_data".to_string()),
        "产品Description不应触Occur物特征detect"
    );
}

#[test]
fn test_medical_full_record() {
    let text =
        "患者诊断 2型糖尿病，处方: 2甲双胍500mg，有青霉素敏史，家族病史Medium有High血压";
    let result = scan_text(text);
    assert!(result.matches.contains(&"medical_health".to_string()));
}

#[test]
fn test_medical_no_false_positive_on_news() {
    let text = "今Day有1场关于健康of讲座";
    let result = scan_text(text);
    assert!(!result.matches.contains(&"medical_health".to_string()));
}

#[test]
fn test_medical_surgery_record() {
    let text = "手术记录显示切除了阑尾，麻醉Method 全麻，护理记录Normal";
    let result = scan_text(text);
    assert!(result.matches.contains(&"medical_health".to_string()));
}

#[test]
fn test_vehicle_plate_guangdong() {
    let text = "车辆Info: VIN WVWZZZ3CZWE654321, 车主张三";
    let result = scan_text(text);
    assert!(result.matches.contains(&"vehicle_info".to_string()));
}

#[test]
fn test_vehicle_vin_only() {
    let text = "VIN: WVWZZZ3CZWE123456";
    let result = scan_text(text);
    assert!(result.matches.contains(&"vehicle_info".to_string()));
}

#[test]
fn test_vehicle_no_false_positive_short_text() {
    let text = "AfterA组of报告";
    let result = scan_text(text);
    assert!(!result.matches.contains(&"vehicle_info".to_string()));
}

#[test]
fn test_property_land_cert() {
    let text = "土地证编号: 沪2023-0045678 登记面积120平米";
    let result = scan_text(text);
    assert!(result.matches.contains(&"property_info".to_string()));
}

#[test]
fn test_property_no_false_positive() {
    let text = "会议室already经安排在5楼了";
    let result = scan_text(text);
    assert!(!result.matches.contains(&"property_info".to_string()));
}

#[test]
fn test_income_salary_with_amount() {
    let text = "月薪: 28000元，年薪: 336000元";
    let result = scan_text(text);
    assert!(result.matches.contains(&"income_info".to_string()));
}

#[test]
fn test_income_social_security() {
    let text = "公积金缴存: 3600元，社保缴费: 2800元";
    let result = scan_text(text);
    assert!(result.matches.contains(&"income_info".to_string()));
}

#[test]
fn test_income_no_false_positive_keyword_alone() {
    let text = "我们讨论了收入Allocate问题";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"income_info".to_string()),
        "Keywords无AmountContext不应触发"
    );
}

#[test]
fn test_geo_coordinates_shanghai() {
    let text = "bit置: 121.4737, 31.2304";
    let result = scan_text(text);
    assert!(result.matches.contains(&"geo_location".to_string()));
}

#[test]
fn test_geo_chinese_comma() {
    let text = "坐标 116.39750，39.90860";
    let result = scan_text(text);
    assert!(result.matches.contains(&"geo_location".to_string()));
}

#[test]
fn test_geo_keyword_context() {
    let text = "GPS坐标: 104.065735";
    let result = scan_text(text);
    assert!(result.matches.contains(&"geo_location".to_string()));
}

#[test]
fn test_geo_no_false_positive_version() {
    let text = "软件Version 3.14, Update日期 2026.03";
    let result = scan_text(text);
    assert!(!result.matches.contains(&"geo_location".to_string()));
}

#[test]
fn test_otp_chinese() {
    let text = "动态口令: 849261";
    let result = scan_text(text);
    assert!(result.matches.contains(&"otp_verification".to_string()));
}

#[test]
fn test_otp_english() {
    let text = "Your OTP: 384921 expires in 5 minutes";
    let result = scan_text(text);
    assert!(result.matches.contains(&"otp_verification".to_string()));
}

#[test]
fn test_otp_sms_verification() {
    let text = "短信验证码 628419 请勿转发";
    let result = scan_text(text);
    assert!(result.matches.contains(&"otp_verification".to_string()));
}

#[test]
fn test_loan_overdue() {
    let text = "逾期金额: 35,000元，欠息: 1,200元";
    let result = scan_text(text);
    assert!(result.matches.contains(&"loan_credit_info".to_string()));
}

#[test]
fn test_loan_credit_limit() {
    let text = "授信额度: 500000元";
    let result = scan_text(text);
    assert!(result.matches.contains(&"loan_credit_info".to_string()));
}

#[test]
fn test_insurance_claim() {
    let text = "理赔金额: 50000元，出险日期: 2026-01-15";
    let result = scan_text(text);
    assert!(result.matches.contains(&"insurance_policy".to_string()));
}

#[test]
fn test_insurance_policy_number() {
    let text = "保单号: PL20260315001234";
    let result = scan_text(text);
    assert!(result.matches.contains(&"insurance_policy".to_string()));
}

#[test]
fn test_family_guardian() {
    let text = "监护人: 王某某，紧急联系人: 李某某";
    let result = scan_text(text);
    assert!(result.matches.contains(&"family_relation".to_string()));
}

#[test]
fn test_family_no_false_positive() {
    let text = "欢迎来到家庭乐园";
    let result = scan_text(text);
    assert!(!result.matches.contains(&"family_relation".to_string()));
}

#[test]
fn test_employee_work_id() {
    let text = "工号: 20230156, 部门: Info科技部";
    let result = scan_text(text);
    assert!(result.matches.contains(&"employee_info".to_string()));
}

#[test]
fn test_employee_position() {
    let text = "职位: Highlevel经理, 入职日期: 2020/03/15";
    let result = scan_text(text);
    assert!(result.matches.contains(&"employee_info".to_string()));
}

#[test]
fn test_judicial_court_case() {
    let text = "被执行人张某，裁定书编号 (2026)京01执12345编号";
    let result = scan_text(text);
    assert!(result.matches.contains(&"judicial_record".to_string()));
}

#[test]
fn test_judicial_blacklist() {
    let text = "限制消费令already发出，该客户 失信被执行人";
    let result = scan_text(text);
    assert!(result.matches.contains(&"judicial_record".to_string()));
}

#[test]
fn test_education_degree() {
    let text = "学位: 硕士, 毕业院校: 清华大学";
    let result = scan_text(text);
    assert!(result.matches.contains(&"education_info".to_string()));
}

#[test]
fn test_business_license_old_format() {
    let text = "工商登记编号: 310115000123456";
    let result = scan_text(text);
    assert!(result.matches.contains(&"business_license".to_string()));
}

#[test]
fn test_business_license_no_false_positive() {
    let text = "请下载营业执照模板";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"business_license".to_string()),
        "Keywords无编号不应触发"
    );
}

#[test]
fn test_combined_c4_c3_data() {
    let text = "客户Info: 身份证 000000200001010005, Password: secret123, 月薪: 25000元, 配偶: 李芳";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "应检出身份证"
    );
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "应检出凭证"
    );
    assert!(
        result.matches.contains(&"income_info".to_string()),
        "应检出收入Info"
    );
    assert!(
        result.matches.contains(&"family_relation".to_string()),
        "应检出家庭关系"
    );
    assert!(result.count_items_at_level(4) >= 1, "At least 1 Item C4");
    assert!(result.count_items_at_level(3) >= 3, "At least 3 Item C3+");
}

#[test]
fn test_combined_financial_data() {
    let text = "贷款余额: 500000元，逾期金额: 20000元，保单号: PL123456789012，投保人: 张三";
    let result = scan_text(text);
    assert!(result.matches.contains(&"loan_credit_info".to_string()));
    assert!(result.matches.contains(&"insurance_policy".to_string()));
}

#[test]
fn test_clean_business_text_no_false_positive() {
    let text = "尊敬of客户您好，感谢您Use我lineService。本月账单alreadygenerate，请Login网银查看。if有疑问请致电客服。祝您生活愉快！";
    let result = scan_text(text);
    assert!(
        result.matches.is_empty(),
        "NormalBusinessemail不应有任何 DLP 命Medium，实际命Medium: {:?}",
        result.matches
    );
}

// The file is getting very long. The remaining tests from the original dlp.rs
// (lines 2385-5272) are included below, exactly as they appeared in the original.

// Test: (False Positive Prevention)

#[test]
fn test_credit_card_luhn_invalid_rejects() {
    let text = "订单编号 1234567890123456";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"credit_card".to_string()),
        "Luhn-invalid 16-digit number should NOT be detected as credit card"
    );
}

#[test]
fn test_credit_card_with_spaces() {
    let text = "Card number 4111 1111 1111 1111";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credit_card".to_string()),
        "Space-separated Luhn-valid card should be detected"
    );
}

#[test]
fn test_credit_card_with_dashes() {
    let text = "Card number 4111-1111-1111-1111";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credit_card".to_string()),
        "Dash-separated Luhn-valid card should be detected"
    );
}

#[test]
fn test_credit_card_masking_format() {
    let (cards, _raw) = find_credit_cards("4111111111111111");
    assert_eq!(cards.len(), 1);
    assert_eq!(
        cards[0], "4111****1111",
        "Card masking should show first 4 + **** + last 4"
    );
}

#[test]
fn test_id_number_with_x_suffix() {
    let text = "身份证 000000199001010042";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "ID number ending with X should be detected"
    );
}

#[test]
fn test_id_number_lowercase_x() {
    let text = "证件编号 000000199001010042";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "ID number ending with lowercase x should be detected"
    );
}

#[test]
fn test_id_number_17_digit_rejected() {
    let text = "编号 00000020000101000";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"id_number".to_string()),
        "17-digit number should NOT match id_number"
    );
}

#[test]
fn test_id_number_masking_format() {
    let ids = find_chinese_ids("000000200001010005");
    assert_eq!(ids.len(), 1);
    assert_eq!(
        ids[0], "000000****0005",
        "ID masking should show first 6 + **** + last 4"
    );
}

#[test]
fn test_phone_two_numbers_no_alert() {
    let text = "联系电话: 13800138000, 13900139000";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"phone_number".to_string()),
        "Only 2 phone numbers should NOT trigger (threshold is >=3)"
    );
}

#[test]
fn test_phone_exact_three_trigger() {
    let text = "Name单: 13800138000, 13900139000, 14700147000";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"phone_number".to_string()),
        "Exactly 3 phone numbers should trigger"
    );
}

#[test]
fn test_phone_invalid_prefix_12x() {
    let text = "编号 12345678901, 12345678902, 12345678903";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"phone_number".to_string()),
        "编号s starting with 12 should NOT be detected as phone numbers"
    );
}

#[test]
fn test_phone_duplicate_numbers_deduped() {
    let text = "紧急联系 13800138000 或 13800138000 或 13800138000";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"phone_number".to_string()),
        "Same phone repeated 3x should NOT trigger (dedup: only 1 unique number)"
    );
}

#[test]
fn test_phone_three_unique_numbers_trigger() {
    let text = "紧急联系 13800138000 或 13900139000 或 14700147000";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"phone_number".to_string()),
        "3 unique phone numbers should trigger"
    );
}

#[test]
fn test_phone_masking_format() {
    let phones = find_chinese_phones("13800138000");
    assert_eq!(phones.len(), 1);
    assert_eq!(
        phones[0], "138****8000",
        "Phone masking should show first 3 + **** + last 4"
    );
}

#[test]
fn test_email_two_addresses_no_alert() {
    let text = "Sendgiving alice@example.com 和 bob@example.net";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"email_address".to_string()),
        "Only 2 emails should NOT trigger (threshold is >=3)"
    );
}

#[test]
fn test_email_mixed_system_and_real() {
    let text = "noreply@example.com, admin@example.net, user1@example.org, user2@example.test";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"email_address".to_string()),
        "2 real emails + 2 system emails should NOT trigger"
    );
}

#[test]
fn test_email_complex_addresses() {
    let text =
        "recipient: first.last+tag@sub.example.test, user_name@example.com, test-addr@example.org";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"email_address".to_string()),
        "Complex email formats should be detected"
    );
}

#[test]
fn test_bank_card_17_digit_luhn_valid() {
    let text = "Bank卡 62220212345678901";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"credit_card".to_string()),
        "17-digit should never match credit_card"
    );
}

#[test]
fn test_multiple_credit_cards_dedup() {
    let text = "主卡 4111111111111111，副卡 4111111111111111";
    let result = scan_text(text);
    assert!(result.matches.contains(&"credit_card".to_string()));
    assert!(
        !result.matches.contains(&"bank_card".to_string()),
        "Same card number appearing twice should NOT create bank_card duplicate"
    );
}

#[test]
fn test_passport_all_prefixes() {
    for prefix in &['E', 'G', 'D', 'S', 'P', 'H', 'L'] {
        let num = format!("{}12345678", prefix);
        let passports = find_passports(&num);
        assert!(
            !passports.is_empty(),
            "Passport prefix {} should be valid",
            prefix
        );
    }
}

#[test]
fn test_passport_invalid_prefix_rejected() {
    let passports = find_passports("A12345678");
    assert!(passports.is_empty(), "Prefix A should not match passport");
}

#[test]
fn test_passport_wrong_length_rejected() {
    let passports = find_passports("E1234567");
    assert!(
        passports.is_empty(),
        "8-char passport (7 digits) should not match"
    );
}

#[test]
fn test_swift_9_digit_rejected() {
    let codes = find_swift_codes("BKCHCNBJX");
    assert!(codes.is_empty(), "9-char SWIFT should be rejected");
}

#[test]
fn test_swift_10_digit_rejected() {
    let codes = find_swift_codes("BKCHCNBJXX");
    assert!(codes.is_empty(), "10-char SWIFT should be rejected");
}

#[test]
fn test_swift_lowercase_detected() {
    // 修复后：小写 SWIFT 大写归一化后应命中（PoC：攻击者用小写绕过）
    // 小写候选需带 swift/bic 上下文, 防止英文散文单词误报
    let codes = find_swift_codes("汇款请使用 SWIFT: bkchcnbj");
    assert_eq!(codes.len(), 1, "Lowercase SWIFT should be detected after case normalization");
}

#[test]
fn test_cvv_4_digit_amex() {
    let text = "CVV2: 1234";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"cvv_code".to_string()),
        "4-digit CVV (AMEX) should be detected"
    );
}

#[test]
fn test_cvv_cvc2_keyword() {
    let text = "CVC2: 789";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"cvv_code".to_string()),
        "CVC2 keyword should be recognized"
    );
}

#[test]
fn test_cvv_chinese_verification_code() {
    let text = "验证码: 456";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"cvv_code".to_string()),
        "Chinese verification code keyword should trigger CVV detection"
    );
}

#[test]
fn test_cvv_card_verification_english() {
    let text = "card verification: 789";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"cvv_code".to_string()),
        "English 'card verification' should trigger"
    );
}

#[test]
fn test_iban_france() {
    let text = "FR7630006000011234567890189";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"iban".to_string()),
        "French IBAN should be detected"
    );
}

#[test]
fn test_iban_switzerland() {
    let text = "CH9300762011623852957";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"iban".to_string()),
        "Swiss IBAN should be detected"
    );
}

#[test]
fn test_iban_too_short_rejected() {
    let ibans = find_ibans("DE89370400440");
    assert!(
        ibans.is_empty(),
        "IBAN shorter than 15 chars should be rejected"
    );
}

#[test]
fn test_iban_masking_format() {
    let ibans = find_ibans("DE89370400440532013000");
    assert_eq!(ibans.len(), 1);
    assert!(
        ibans[0].starts_with("DE89"),
        "IBAN masking should preserve first 4"
    );
    assert!(
        ibans[0].ends_with("3000"),
        "IBAN masking should preserve last 4"
    );
    assert!(
        ibans[0].contains("****"),
        "IBAN masking should contain ****"
    );
}

#[test]
fn test_large_amount_billion_yuan() {
    let text = "项目总投资 3.5亿元，首Period 1.2亿元";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"large_amount".to_string()),
        "Billion yuan amounts should be detected"
    );
}

#[test]
fn test_large_amount_yen() {
    let text = "支付 50,000 JPY，另收手续费 1,000 JPY";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"large_amount".to_string()),
        "JPY amounts should be detected"
    );
}

#[test]
fn test_large_amount_gbp() {
    let text = "报价 100,000 GBP，佣金 5,000 GBP";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"large_amount".to_string()),
        "GBP amounts should be detected"
    );
}

#[test]
fn test_large_amount_with_decimals() {
    let text = "合同Amount 85.50万元，税费 4.25万元";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"large_amount".to_string()),
        "Amounts with decimals should be detected"
    );
}

#[test]
fn test_large_amount_no_fp_plain_number() {
    let text = "订单 100000, 编号 200000";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"large_amount".to_string()),
        "Plain numbers without currency should NOT trigger"
    );
}

#[test]
fn test_bank_account_transfer_context() {
    let text = "请转入: 622848001234";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"bank_account".to_string()),
        "Transfer keyword should trigger bank account detection"
    );
}

#[test]
fn test_bank_account_payment_context() {
    let text = "收款: 1234567890, 付款: 9876543210";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"bank_account".to_string()),
        "Payment keywords should trigger"
    );
}

#[test]
fn test_bank_account_too_short_rejected() {
    let text = "账号：123456789";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"bank_account".to_string()),
        "9-digit account should NOT trigger (min 10)"
    );
}

#[test]
fn test_bank_account_15_digit_rejected() {
    let text = "账号：123456789012345";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"bank_account".to_string()),
        "15-digit number should NOT trigger (boundary fix prevents greedy capture)"
    );
}

#[test]
fn test_contract_english_keyword() {
    let text = "contract number: 20260312345678";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"contract_number".to_string()),
        "English 'contract number' should trigger"
    );
}

#[test]
fn test_contract_loan_keyword() {
    let text = "loan no: LN20260312345678";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"contract_number".to_string()),
        "English 'loan no' should trigger"
    );
}

#[test]
fn test_contract_short_number_rejected() {
    let text = "保单号: 1234567";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"contract_number".to_string()),
        "7-digit number should NOT trigger (min 8)"
    );
}

// Due to the extreme length (5,272 lines), the remaining tests from the original
// file (lines 2786-5272) are included in a separate include below.
// Each test is preserved exactly as-is from the original.

#[test]
fn test_biometric_faceid_and_fingerprint() {
    let text = "该设备already录入faceID和fingerprintInfo";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"biometric_data".to_string()),
        "faceID + fingerprint should trigger (2 distinct keywords)"
    );
}

#[test]
fn test_biometric_gait_and_earprint() {
    let text = "研究报告涉及步态识别和耳纹特征data";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"biometric_data".to_string()),
        "Gait + earprint should trigger"
    );
}

#[test]
fn test_biometric_same_keyword_twice_no_trigger() {
    let text = "指纹采集complete。请再Time/CountAccording to压指纹传感Device/Handler";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"biometric_data".to_string()),
        "Same keyword twice should NOT trigger (need 2 distinct keywords)"
    );
}

#[test]
fn test_medical_gene_test() {
    let text = "基因检测报告显示BRCA1阳性，建议做体检报告复查";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"medical_health".to_string()),
        "Gene test + physical exam should trigger"
    );
}

#[test]
fn test_medical_infectious_disease() {
    let text = "该患者传染病detect阳性，already开具处方并隔离";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"medical_health".to_string()),
        "Infectious disease + prescription should trigger"
    );
}

#[test]
fn test_medical_pregnancy_info() {
    let text = "生育信息alreadyUpdate，既往病史记录complete";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"medical_health".to_string()),
        "Pregnancy info + medical history should trigger"
    );
}

#[test]
fn test_medical_same_keyword_twice_no_trigger() {
    let text = "请携with处方来Get药。if 忘记处方请联系医生";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"medical_health".to_string()),
        "Same keyword twice should NOT trigger (need 2 distinct keywords)"
    );
}

#[test]
fn test_medical_no_fp_on_general_health_discussion() {
    let text = "今年公司会统1安排体检，请大家Note身体健康";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"medical_health".to_string()),
        "General health mention should NOT trigger"
    );
}

#[test]
fn test_vehicle_new_energy_plate() {
    let text = "车牌编号: 京AD12345，already登记";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"vehicle_info".to_string()),
        "New energy vehicle plate should be detected (byte-length bug fixed)"
    );
}

#[test]
fn test_vehicle_standard_plate() {
    let text = "登记车辆 京A12345";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"vehicle_info".to_string()),
        "Standard 6-char plate should be detected"
    );
}

#[test]
fn test_vehicle_vin_masking() {
    let vins = find_vehicle_info("WVWZZZ3CZWE654321");
    assert_eq!(vins.len(), 1);
    assert!(
        vins[0].starts_with("WVWZ"),
        "VIN masking should preserve first 4"
    );
    assert!(
        vins[0].contains("*****"),
        "VIN masking should contain *****"
    );
}

#[test]
fn test_vehicle_vin_wrong_length_rejected() {
    let vins = find_vehicle_info("WVWZZZ3CZWE65432");
    assert!(
        vins.is_empty(),
        "16-char alphanumeric should NOT match VIN (17 required)"
    );
}

#[test]
fn test_property_certificate_with_id() {
    let text = "房屋所有权证编号: 沪房地权字AfterSH20230045编号";
    let result = scan_text(text);
    assert!(result.matches.contains(&"property_info".to_string()));
}

#[test]
fn test_property_registration() {
    let text = "房产登记InfoalreadyUpdate，请查看不动产权证";
    let result = scan_text(text);
    assert!(result.matches.contains(&"property_info".to_string()));
}

#[test]
fn test_income_tax_amount() {
    let text = "个人所得税: 2,850元";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"income_info".to_string()),
        "Income tax with amount should trigger"
    );
}

#[test]
fn test_income_pretax() {
    let text = "税前: 35000元";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"income_info".to_string()),
        "Pretax with amount should trigger"
    );
}

#[test]
fn test_income_no_fp_salary_system_name() {
    let text = "请Login薪资System查看";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"income_info".to_string()),
        "Salary keyword followed by non-amount text should NOT trigger"
    );
}

#[test]
fn test_geo_southern_hemisphere() {
    let text = "GPS坐标: 151.2093";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"geo_location".to_string()),
        "GPS keyword + coordinate should trigger"
    );
}

#[test]
fn test_geo_latitude_keyword() {
    let text = "latitude: 39.90860";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"geo_location".to_string()),
        "English latitude keyword should trigger"
    );
}

#[test]
fn test_geo_no_fp_ip_address() {
    let text = "ServiceDevice/Handler IP: 192.168.1.1";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"geo_location".to_string()),
        "IP address should NOT be detected as geo coordinates"
    );
}

#[test]
fn test_geo_no_fp_simple_decimals() {
    let text = "Amount 12.34, 汇率 6.78";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"geo_location".to_string()),
        "Short decimal numbers should NOT trigger (need 4+ decimal places)"
    );
}

#[test]
fn test_otp_auth_code() {
    let text = "authcode: 482619";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"otp_verification".to_string()),
        "English authcode keyword should trigger"
    );
}

#[test]
fn test_otp_confirmation_code() {
    let text = "Your confirmation code: 95721348";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"otp_verification".to_string()),
        "confirmation code with 8 digits should trigger"
    );
}

#[test]
fn test_otp_dynamic_password() {
    let text = "动态密码: 738291";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"otp_verification".to_string()),
        "Dynamic password keyword should trigger"
    );
}

#[test]
fn test_otp_no_fp_without_digits() {
    let text = "请Input验证码";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"otp_verification".to_string()),
        "Verification keyword without actual digits should NOT trigger"
    );
}

#[test]
fn test_loan_total_balance() {
    let text = "贷款余额: 1,500,000元";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"loan_credit_info".to_string()),
        "Loan balance should trigger"
    );
}

#[test]
fn test_loan_total_now_in_prefilter() {
    let text = "贷款总额: 1,500,000元";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"loan_credit_info".to_string()),
        "Loan total now in RegexSet pre-filter (regex fix)"
    );
}

#[test]
fn test_loan_penalty_interest() {
    let text = "罚息: 3,500元";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"loan_credit_info".to_string()),
        "Penalty interest should trigger"
    );
}

#[test]
fn test_loan_repayment() {
    let text = "还款金额: 8,600元";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"loan_credit_info".to_string()),
        "Repayment amount should trigger"
    );
}

#[test]
fn test_loan_no_fp_general_credit() {
    let text = "关于贷款Businessof培训";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"loan_credit_info".to_string()),
        "Loan keyword without specific amount should NOT trigger"
    );
}

#[test]
fn test_insurance_beneficiary() {
    let text = "受益人: 王芳";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"insurance_policy".to_string()),
        "Beneficiary + name should trigger"
    );
}

#[test]
fn test_insurance_premium() {
    let text = "保费: 12,800元/年";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"insurance_policy".to_string()),
        "Premium with amount should trigger"
    );
}

#[test]
fn test_insurance_underwriting() {
    let text = "核保: 通";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"insurance_policy".to_string()),
        "Underwriting keyword should trigger"
    );
}

#[test]
fn test_family_parents() {
    let text = "父亲: 张国强，母亲: 李秀兰";
    let result = scan_text(text);
    assert!(result.matches.contains(&"family_relation".to_string()));
}

#[test]
fn test_family_children() {
    let text = "子女: 张明";
    let result = scan_text(text);
    assert!(result.matches.contains(&"family_relation".to_string()));
}

#[test]
fn test_family_siblings() {
    let text = "兄弟: 张大，姐妹: 张小花";
    let result = scan_text(text);
    assert!(result.matches.contains(&"family_relation".to_string()));
}

#[test]
fn test_employee_offboarding() {
    let text = "离职日期: 2026/03/15";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"employee_info".to_string()),
        "Offboarding date should trigger"
    );
}

#[test]
fn test_employee_department_role() {
    let text = "岗位: 客户经理";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"employee_info".to_string()),
        "Position keyword should trigger"
    );
}

#[test]
fn test_employee_department_without_colon_no_trigger() {
    let text = "2026年部门绩效合约table";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"employee_info".to_string()),
        "Department without separator should NOT trigger"
    );
}

#[test]
fn test_employee_position_without_colon_no_trigger() {
    let text = "公司金融部岗位职责";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"employee_info".to_string()),
        "Position without separator should NOT trigger"
    );
}

#[test]
fn test_employee_dept_number_without_colon_no_trigger() {
    let text = "申请部门 7";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"employee_info".to_string()),
        "Department followed by space+number without colon should NOT trigger"
    );
}

#[test]
fn test_employee_id_without_colon_still_triggers() {
    let text = "员工编号 A12345";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"employee_info".to_string()),
        "工号 (specific keyword) should trigger even without colon"
    );
}

#[test]
fn test_judicial_enforcement_with_prefilter_keyword() {
    let text = "Received强制执行通知，判决书already下达";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"judicial_record".to_string()),
        "Enforcement + judgment should trigger"
    );
}

#[test]
fn test_judicial_enforcement_both_in_prefilter() {
    let text = "Received强制执行通知，already对其限制消费";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"judicial_record".to_string()),
        "Enforcement + consumption restriction now in RegexSet pre-filter"
    );
}

#[test]
fn test_judicial_exit_ban_with_prefilter() {
    let text = "限制出境令already下达，该被执行人Name下资产already冻Result";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"judicial_record".to_string()),
        "Exit ban + enforcement = 2 distinct keywords"
    );
}

#[test]
fn test_judicial_single_keyword_no_trigger() {
    let text = "请查看行政处罚相关法规";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"judicial_record".to_string()),
        "Single judicial keyword should NOT trigger (need 2 distinct)"
    );
}

#[test]
fn test_judicial_no_fp_legal_discussion() {
    let text = "今Daylearn了合同法，了解了违约责任";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"judicial_record".to_string()),
        "General legal discussion should NOT trigger"
    );
}

#[test]
fn test_education_school() {
    let text = "就读学校: 复旦大学";
    let result = scan_text(text);
    assert!(result.matches.contains(&"education_info".to_string()));
}

#[test]
fn test_education_enrollment_date() {
    let text = "入学日期: 2018/09";
    let result = scan_text(text);
    assert!(result.matches.contains(&"education_info".to_string()));
}

#[test]
fn test_business_license_registration_number() {
    let text = "注册号: 110105012345678";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"business_license".to_string()),
        "Registration number keyword should trigger"
    );
}

// Credential variants

#[test]
fn test_credential_pwd() {
    let text = "pwd=Admin@2026";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "pwd= format should trigger"
    );
}

#[test]
fn test_credential_passcode() {
    let text = "passcode: 628419";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "passcode keyword should trigger"
    );
}

#[test]
fn test_credential_secret() {
    let text = "secret: sk-live-abc123xyz";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "secret keyword should trigger"
    );
}

#[test]
fn test_credential_pin_with_separator() {
    let text = "PIN: 6528";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "PIN: format should trigger"
    );
}

#[test]
fn test_credential_pin_chinese_suffix() {
    let text = "PIN码：6528";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "PIN code + Chinese colon should trigger"
    );
}

#[test]
fn test_credential_no_fp_without_separator() {
    let text = "请Modifypassword并重NewLogin";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"credential_leak".to_string()),
        "Keyword without separator should NOT trigger"
    );
}

#[test]
fn test_credential_boolean_value_filtered() {
    let text = "PASSWORD: true";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"credential_leak".to_string()),
        "PASSWORD: true (boolean) should NOT trigger"
    );
}

#[test]
fn test_credential_null_value_filtered() {
    let text = "pwd: null";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"credential_leak".to_string()),
        "pwd: null should NOT trigger"
    );
}

#[test]
fn test_credential_false_value_filtered() {
    let text = "password=false";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"credential_leak".to_string()),
        "password=false should NOT trigger"
    );
}

#[test]
fn test_credential_real_password_still_detected() {
    let text = "password: qwerty123";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "Real password should still trigger"
    );
}

// JRT level tests

#[test]
fn test_items_by_jrt_level_distribution() {
    let text = "Password：abc123, 身份证 000000200001010005, 月薪: 25000元, 工号: E001";
    let result = scan_text(text);
    let levels = result.items_by_jrt_level();
    assert!(levels.get(&4).unwrap_or(&0) >= &1, "Should have C4 items");
    assert!(levels.get(&3).unwrap_or(&0) >= &1, "Should have C3 items");
}

#[test]
fn test_count_items_at_level_accumulation() {
    let text = "身份证 000000200001010005, 月薪: 25000元, 配偶: 李四";
    let result = scan_text(text);
    let c3_plus = result.count_items_at_level(3);
    assert!(
        c3_plus >= 3,
        "Should count at least 3 items at C3+, got {}",
        c3_plus
    );
    let c4_plus = result.count_items_at_level(4);
    assert!(c4_plus == 0, "Should have 0 C4 items, got {}", c4_plus);
}

#[test]
fn test_items_by_jrt_level_empty_on_clean_text() {
    let result = scan_text("Normal工作emailContent");
    let levels = result.items_by_jrt_level();
    assert!(
        levels.is_empty(),
        "Clean text should have empty JRT level map"
    );
}

// Realistic scenarios

#[test]
fn test_realistic_hr_email() {
    let text = "关于New入职员工Info：\n\
        Name: 王small明\n\
        员工编号: EMP20260301\n\
        部门: RiskManagement部\n\
        职位: 风控专员\n\
        学历: 硕士\n\
        毕业院校: Medium国人民大学";
    let result = scan_text(text);
    assert!(result.matches.contains(&"employee_info".to_string()));
    assert!(result.matches.contains(&"education_info".to_string()));
}

#[test]
fn test_realistic_loan_approval() {
    let text = "贷款审批Result 通知：\n\
        客户身份证: 000000198805150003\n\
        授信额度: 500000元\n\
        贷款总额: 300000元\n\
        还款金额: 5,500元/月";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "Should detect ID"
    );
    assert!(
        result.matches.contains(&"loan_credit_info".to_string()),
        "Should detect loan info"
    );
}

#[test]
fn test_realistic_insurance_claim() {
    let text = "理赔审核通知：\n\
        投保人: 李明\n\
        被保险人: 张三\n\
        保单号: PL20260115001234\n\
        出险日期: 2026-03-01\n\
        理赔金额: 85,000元\n\
        受益人: 李small红";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"insurance_policy".to_string()),
        "Should detect insurance"
    );
    assert!(
        result.matches.contains(&"contract_number".to_string()),
        "Should detect policy number"
    );
    assert!(
        result.matches.contains(&"family_relation".to_string()) || result.matches.len() >= 2,
        "Should detect multiple sensitive data types"
    );
}

#[test]
fn test_realistic_customer_kyc() {
    let text = "KYC 尽调报告：\n\
        客户: 张三\n\
        身份证号: 000000199201010004\n\
        Mobile phone: 13600136000, 15100151000, 15200152000\n\
        Address: 广东省深圳市南山区科技南路88编号\n\
        配偶: 李四\n\
        公司统1社会信用代码: A00000MA000000000B";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "Should detect ID"
    );
    assert!(
        result.matches.contains(&"phone_number".to_string()),
        "Should detect phones"
    );
    assert!(
        result.matches.contains(&"customer_address".to_string()),
        "Should detect address"
    );
    assert!(
        result.matches.contains(&"family_relation".to_string()),
        "Should detect family"
    );
    assert!(
        result.matches.contains(&"social_credit_code".to_string()),
        "Should detect social credit"
    );
    let c3_plus = result.count_items_at_level(3);
    assert!(
        c3_plus >= 5,
        "KYC email should have >=5 C3+ items, got {}",
        c3_plus
    );
}

// Empty/boundary inputs

#[test]
fn test_empty_input() {
    let result = scan_text("");
    assert!(result.is_empty(), "Empty string should return empty result");
}

#[test]
fn test_whitespace_only_input() {
    let result = scan_text("   \n\t  \r\n  ");
    assert!(
        result.is_empty(),
        "Whitespace-only input should return empty result"
    );
}

#[test]
fn test_single_character_input() {
    let result = scan_text("A");
    assert!(result.is_empty());
}

#[test]
fn test_unicode_emoji_input() {
    let result = scan_text(
        "\u{1F44D} \u{597D}\u{7684}\u{FF0C}\u{6536}\u{5230} \u{2705} \u{5DF2}\u{786E}\u{8BA4} \u{1F389}",
    );
    assert!(
        result.is_empty(),
        "Emoji-only text should NOT trigger any DLP"
    );
}

#[test]
fn test_special_characters_input() {
    let result = scan_text("!@#$%^&*()_+-=[]{}|;':\",./<>?");
    assert!(
        result.is_empty(),
        "Special characters should NOT trigger any DLP"
    );
}

#[test]
fn test_very_long_number_no_crash() {
    let text = "0".repeat(100);
    let result = scan_text(&text);
    drop(result);
}

#[test]
fn test_mixed_cjk_and_latin_sensitive_data() {
    let text = "Client ID: 000000200001010005, password: Test@123, contact: 13800138000, 13900139000, 14700147000";
    let result = scan_text(text);
    assert!(result.matches.contains(&"id_number".to_string()));
    assert!(result.matches.contains(&"credential_leak".to_string()));
    assert!(result.matches.contains(&"phone_number".to_string()));
}

#[test]
fn test_tax_id_16_digit_rejected() {
    let ids = find_tax_ids("110108MA12345N9X");
    assert!(
        ids.is_empty(),
        "16-char string should not match tax_id (strict 15)"
    );
}

#[test]
fn test_tax_id_all_digits() {
    let text = "税编号 110108123456789";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"tax_id".to_string()),
        "All-digit 15-char tax ID should be detected"
    );
}

#[test]
fn test_address_autonomous_region() {
    let text = "Address: 内蒙古自治区呼和浩特市回民区";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"customer_address".to_string()),
        "Autonomous region address should be detected"
    );
}

#[test]
fn test_address_alley_format() {
    let text = "Address: 虹口区四川北路弄堂12号";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"customer_address".to_string()),
        "区 + 路 format should match"
    );
}

#[test]
fn test_address_multiple_addresses() {
    let text = "办公Address: 北京市朝阳区建国路88编号，户籍地: 河南省郑州市金水区经3路";
    let result = scan_text(text);
    let detail = result.details.iter().find(|(k, _)| k == "customer_address");
    assert!(detail.is_some());
    assert!(detail.unwrap().1.len() >= 2, "Should detect 2 addresses");
}

#[test]
fn test_combined_all_jrt_levels() {
    let text = "客户Info汇总：\n\
        Password：abc123\n\
        身份证: 000000200001010005\n\
        工号: E001\n\
        公司信用代码 A0000000000000000M";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "C4 credential"
    );
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "C3 id_number"
    );
    assert!(
        result.matches.contains(&"employee_info".to_string()),
        "C2 employee"
    );
    assert!(
        result.matches.contains(&"social_credit_code".to_string()),
        "C1 social_credit"
    );
    let levels = result.items_by_jrt_level();
    assert!(levels.contains_key(&4), "Should have C4 level");
    assert!(levels.contains_key(&3), "Should have C3 level");
    assert!(levels.contains_key(&2), "Should have C2 level");
    assert!(levels.contains_key(&1), "Should have C1 level");
}

#[test]
fn test_combined_multiple_c4_patterns() {
    let text = "Security事件报告: Password：admin123, CVV: 789, 患者病历显示有过敏史";
    let result = scan_text(text);
    assert!(result.matches.contains(&"credential_leak".to_string()));
    assert!(result.matches.contains(&"cvv_code".to_string()));
    assert!(result.matches.contains(&"medical_health".to_string()));
    assert!(
        result.count_items_at_level(4) >= 3,
        "Should have >=3 C4 items"
    );
}

#[test]
fn test_detail_item_count_matches_expected() {
    let text = "联系人: 13800138000, 13900139000, 14700147000, 15000150000";
    let result = scan_text(text);
    assert!(result.matches.contains(&"phone_number".to_string()));
    let detail = result.details.iter().find(|(k, _)| k == "phone_number");
    assert!(detail.is_some());
    assert_eq!(
        detail.unwrap().1.len(),
        4,
        "Should have exactly 4 masked phone numbers"
    );
}

// Masking consistency

#[test]
fn test_masking_all_values_masked() {
    let text = "身份证 000000200001010005 Password：secret123";
    let result = scan_text(text);
    for (_pattern, values) in &result.details {
        for val in values {
            assert!(
                val.contains("****") || val.contains("***"),
                "Value should be masked, got: {}",
                val
            );
            assert!(
                !val.contains("000000200001010005"),
                "Should not contain unmasked ID"
            );
            assert!(
                !val.contains("secret123"),
                "Should not contain unmasked password"
            );
        }
    }
}

#[test]
fn test_masking_id_preserves_region_code() {
    let ids = find_chinese_ids("000000199201010004");
    assert_eq!(ids[0], "000000****0004");
    assert!(
        ids[0].starts_with("000000"),
        "Masking should preserve region code"
    );
}

#[test]
fn test_masking_bank_card_19_digit() {
    let cards = find_bank_cards("6222021234567890123", &HashSet::new());
    if !cards.is_empty() {
        assert!(
            cards[0].starts_with("6222"),
            "Should preserve first 4 digits"
        );
        assert!(cards[0].ends_with("0123"), "Should preserve last 4 digits");
        assert!(cards[0].contains("****"));
    }
}

#[test]
fn test_masking_passport_format() {
    let passports = find_passports("E12345678");
    assert_eq!(passports[0], "E1****78");
}

#[test]
fn test_masking_social_credit_code_format() {
    let codes = find_social_credit_codes("A0000000000000000M");
    assert_eq!(codes[0], "A000****000M");
}

#[test]
fn test_masking_swift_format() {
    let swift = find_swift_codes("BKCHCNBJ100");
    assert_eq!(swift[0], "BKCH****");
}

#[test]
fn test_masking_cvv_always_same() {
    let cvv = find_cvv_codes("CVV: 789");
    assert_eq!(cvv[0], "CVV: ***", "CVV should always mask to CVV: ***");
}

#[test]
fn test_masking_tax_id_format() {
    let ids = find_tax_ids("310108MA12345N9");
    assert_eq!(ids[0], "3101****5N9");
}

#[test]
fn test_masking_large_amount_preserves_unit() {
    let amounts = find_large_amounts("500万元");
    assert_eq!(amounts[0], "***万元");
}

#[test]
fn test_masking_large_amount_preserves_foreign_unit() {
    let amounts = find_large_amounts("100,000 USD");
    assert!(amounts[0].contains("USD"), "Should preserve currency code");
}

#[test]
fn test_masking_credential_preserves_keyword() {
    let creds = find_credentials("password: admin123");
    assert_eq!(creds[0], "password: ****");
}

#[test]
fn test_masking_credential_chinese_keyword() {
    let creds = find_credentials("口令：MyPwd@2026");
    assert_eq!(creds[0], "口令: ****");
}

// extract_dlp_text tests

#[test]
fn test_extract_dlp_text_coremail_uri() {
    let body =
        r#"{"id":"17744","attrs":{"subject":"Test","content":"<p>body</p>"},"action":"deliver"}"#;
    let uri = "/coremail/common/mbox/compose.jsp?sid=abc";
    let text = extract_dlp_text(body, uri, Some("application/json"));
    assert!(text.contains("Test"), "Should extract subject");
    assert!(text.contains("body"), "Should extract content");
    assert!(!text.contains("17744"), "Should NOT include JSON id");
}

#[test]
fn test_extract_dlp_text_non_coremail_uri() {
    let body = "plain body text";
    let uri = "/other/endpoint";
    let text = extract_dlp_text(body, uri, None);
    assert_eq!(
        text, "plain body text",
        "Non-coremail URI should return raw body"
    );
}

#[test]
fn test_extract_dlp_text_coremail_invalid_json() {
    let body = "not json at all";
    let uri = "/coremail/common/mbox/compose.jsp?sid=abc";
    let text = extract_dlp_text(body, uri, Some("application/json"));
    assert_eq!(
        text, "not json at all",
        "Invalid JSON should fallback to raw body"
    );
}

// Bug fix regression tests

#[test]
fn test_vehicle_plate_all_provinces() {
    let plates = ["京A12345", "沪B67890", "粤C11111", "川D22222", "鲁E33333"];
    for plate in plates {
        let text = format!("车辆 {}", plate);
        let result = scan_text(&text);
        assert!(
            result.matches.contains(&"vehicle_info".to_string()),
            "Plate {} should be detected",
            plate
        );
    }
}

#[test]
fn test_vehicle_plate_masking_after_fix() {
    let vins = find_vehicle_info("京A12345");
    assert!(!vins.is_empty(), "Standard plate should be found");
    assert!(vins[0].contains("***"), "Plate should be masked");
    assert!(vins[0].starts_with("京A1"), "Should preserve first 3 chars");
}

#[test]
fn test_judicial_all_keywords_in_prefilter() {
    let keyword_pairs = [
        ("失信被执行人", "行政处罚"),
        ("被执行人", "裁定书"),
        ("开庭公告", "判决书"),
        ("犯罪记录", "违法违规"),
        ("强制执行", "限制消费"),
        ("限制出境", "立案信息"),
    ];
    for (kw1, kw2) in keyword_pairs {
        let text = format!("该案件涉及{}和{}", kw1, kw2);
        let result = scan_text(&text);
        assert!(
            result.matches.contains(&"judicial_record".to_string()),
            "Keywords '{}' + '{}' should trigger judicial_record",
            kw1,
            kw2
        );
    }
}

#[test]
fn test_loan_all_keywords_in_prefilter() {
    let keywords_with_amount = [
        "贷款余额: 100元",
        "贷款总额: 200元",
        "逾期金额: 300元",
        "还款金额: 400元",
        "授信额度: 500元",
        "信用额度: 600元",
        "欠息: 700元",
        "罚息: 800元",
    ];
    for text in keywords_with_amount {
        let result = scan_text(text);
        assert!(
            result.matches.contains(&"loan_credit_info".to_string()),
            "'{}' should trigger loan_credit_info",
            text
        );
    }
}

#[test]
fn test_credential_pin_chinese_variants() {
    let variants = [
        "PIN码：1234",
        "PIN码: 5678",
        "PIN码=9012",
        "pin码：abcd",
    ];
    for text in variants {
        let result = scan_text(text);
        assert!(
            result.matches.contains(&"credential_leak".to_string()),
            "'{}' should trigger credential_leak",
            text
        );
    }
}

// False positive scenarios

#[test]
fn test_no_fp_meeting_notes() {
    let text = "会议纪要：\n\
        1. 讨论了下季度BusinessTarget\n\
        2. 确认了项目进度\n\
        3. 安排了下Weekdayof培训计划\n\
        参会人员: 王总、李经理、张主管";
    let result = scan_text(text);
    assert!(
        result.matches.is_empty(),
        "Meeting notes should NOT trigger any DLP, got: {:?}",
        result.matches
    );
}

#[test]
fn test_no_fp_product_announcement() {
    let text = "New产品上线通知：\n\
        我linealready推出「智慧stored款」产品，年化收益率最High可达3.5%。\n\
        欢迎各网点积极推广，if有疑问请联系产品部。";
    let result = scan_text(text);
    assert!(
        result.matches.is_empty(),
        "Product announcement should NOT trigger, got: {:?}",
        result.matches
    );
}

#[test]
fn test_no_fp_daily_report() {
    let text = "Sunday报：今DayProcess了35笔Business，complete率98%。System运lineNormal，无AbnormalAlert。明Day继续Add油！";
    let result = scan_text(text);
    assert!(
        result.matches.is_empty(),
        "Daily report should NOT trigger, got: {:?}",
        result.matches
    );
}

#[test]
fn test_no_fp_it_system_notification() {
    let text = "System维护通知：\n\
        本Saturday 22:00-24:00 将对核心System进line升level维护。\n\
        届时网银、Mobile phoneBank将暂停Service，请提first做好准备。";
    let result = scan_text(text);
    assert!(
        result.matches.is_empty(),
        "IT notification should NOT trigger, got: {:?}",
        result.matches
    );
}

#[test]
fn test_no_fp_compliance_training() {
    let text = "反洗钱培训提醒：\n\
        请全体员工于本月底firstcomplete年度反洗钱知识Test。\n\
        TestContent涵盖Suspicious交易识别、大额交易报告制度。";
    let result = scan_text(text);
    assert!(
        result.matches.is_empty(),
        "Compliance training text should NOT trigger, got: {:?}",
        result.matches
    );
}

#[test]
fn test_no_fp_english_business_email() {
    let text = "Dear Team,\n\
        Please find attached the quarterly report for Q1 2026.\n\
        The revenue grew by 15% compared to last quarter.\n\
        Let me know if you have any questions.\n\
        Best regards, John";
    let result = scan_text(text);
    assert!(
        result.matches.is_empty(),
        "English business email should NOT trigger, got: {:?}",
        result.matches
    );
}

// Phone dedup threshold

#[test]
fn test_phone_dedup_five_same_no_trigger() {
    let text = "13800138000 13800138000 13800138000 13800138000 13800138000";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"phone_number".to_string()),
        "5 duplicates of same phone should NOT trigger (unique count = 1)"
    );
}

#[test]
fn test_phone_dedup_two_unique_two_dup_no_trigger() {
    let text = "13800138000 13900139000 13800138000 13900139000";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"phone_number".to_string()),
        "2 unique phones (with duplicates) should NOT trigger (threshold >=3)"
    );
}

#[test]
fn test_phone_dedup_three_unique_with_dups_trigger() {
    let text = "13800138000 13900139000 14700147000 13800138000";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"phone_number".to_string()),
        "3 unique phones should trigger even with duplicates"
    );
    let detail = result.details.iter().find(|(k, _)| k == "phone_number");
    assert_eq!(
        detail.unwrap().1.len(),
        3,
        "Details should show 3 unique numbers (deduped)"
    );
}

#[test]
fn test_email_dedup_same_address_case_insensitive() {
    let text = "User@Ops.EXAMPLE.COM user@ops.example.com USER@OPS.EXAMPLE.COM other1@example.net other2@example.org";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"email_address".to_string()),
        "3 unique emails (after case-insensitive dedup) should trigger"
    );
}

#[test]
fn test_email_dedup_all_same_no_trigger() {
    let text = "user@ops.example.com user@ops.example.com user@ops.example.com user@ops.example.com user@ops.example.com";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"email_address".to_string()),
        "Same email 5 times should NOT trigger (unique count = 1)"
    );
}

// SWIFT alignment

#[test]
fn test_swift_code_regexset_alignment() {
    let text = "BKCHCNBJ";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"swift_code".to_string()),
        "Standard 8-char SWIFT should pass both RegexSet and detailed regex"
    );
}

#[test]
fn test_swift_code_11_char_with_branch() {
    let text = "BKCHCNBJ100";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"swift_code".to_string()),
        "11-char SWIFT with branch code should be detected"
    );
}

#[test]
fn test_swift_code_7_char_rejected() {
    let codes = find_swift_codes("BKCHCNB");
    assert!(codes.is_empty(), "7-char is not valid SWIFT");
}

#[test]
fn test_swift_code_12_char_rejected() {
    let codes = find_swift_codes("BKCHCNBJ1001");
    assert!(codes.is_empty(), "12-char is not valid SWIFT");
}

#[test]
fn test_swift_valid_boc_code_detected() {
    let codes = find_swift_codes("BKCHCNBJ");
    assert_eq!(codes.len(), 1, "Bank of China SWIFT should be detected");
    assert_eq!(codes[0], "BKCH****");
}

#[test]
fn test_swift_valid_11_digit_detected() {
    let codes = find_swift_codes("BKCHCNBJXXX");
    assert_eq!(codes.len(), 1, "11-digit BOC SWIFT should be detected");
}

#[test]
fn test_swift_invalid_country_rejected() {
    let codes = find_swift_codes("PASSAB12");
    assert!(codes.is_empty(), "PASSAB12: AB is not a valid country code");
}

#[test]
fn test_swift_common_word_rejected() {
    let codes = find_swift_codes("TRUECNBJ");
    assert!(codes.is_empty(), "TRUECNBJ: TRUE is a common word prefix");
}

#[test]
fn test_swift_file_prefix_rejected() {
    let codes = find_swift_codes("FILECNBJ");
    assert!(codes.is_empty(), "FILECNBJ: FILE is a common word prefix");
}

#[test]
fn test_swift_cert_prefix_rejected() {
    let codes = find_swift_codes("CERTCNBJ");
    assert!(codes.is_empty(), "CERTCNBJ: CERT is a common word prefix");
}

#[test]
fn test_swift_real_hsbc_detected() {
    let codes = find_swift_codes("HSBCHKHH");
    assert_eq!(codes.len(), 1, "HSBC Hong Kong SWIFT should be detected");
}

// DlpScanResult API

#[test]
fn test_dlp_result_is_empty_on_clean() {
    let result = scan_text("NormalText");
    assert!(result.is_empty());
    assert!(result.matches.is_empty());
    assert!(result.details.is_empty());
}

#[test]
fn test_dlp_result_details_structure() {
    let text = "身份证 000000200001010005, Password：secret123";
    let result = scan_text(text);
    assert!(
        result.details.len() >= 2,
        "Should have at least 2 detail entries"
    );
    for (name, values) in &result.details {
        assert!(!name.is_empty(), "Pattern name should not be empty");
        assert!(!values.is_empty(), "Values should not be empty");
    }
}

#[test]
fn test_matches_and_details_consistent() {
    let text = "Password：abc123 身份证 000000200001010005";
    let result = scan_text(text);
    let detail_keys: Vec<&str> = result.details.iter().map(|(k, _)| k.as_str()).collect();
    for m in &result.matches {
        assert!(
            detail_keys.contains(&m.as_str()),
            "Match '{}' should have corresponding detail entry",
            m
        );
    }
}

// Bank account boundary fix

#[test]
fn test_bank_account_exact_10_digit() {
    let text = "账号：1234567890";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"bank_account".to_string()),
        "Exact 10-digit account should be detected"
    );
}

#[test]
fn test_bank_account_exact_14_digit() {
    let text = "账号：12345678901234";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"bank_account".to_string()),
        "Exact 14-digit account should be detected"
    );
}

#[test]
fn test_bank_account_16_digit_rejected() {
    let text = "账号：1234567890123456";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"bank_account".to_string()),
        "16-digit number should NOT trigger bank_account (max 14)"
    );
}

#[test]
fn test_bank_account_followed_by_text() {
    let text = "转账: 123456789012 到指定Account";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"bank_account".to_string()),
        "12-digit followed by text boundary should trigger"
    );
}

// Address false positive prevention

#[test]
fn test_address_no_fp_simple_suffix() {
    let text = "本月of工作进展不错";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"customer_address".to_string()),
        "Normal text should NOT trigger address detection"
    );
}

#[test]
fn test_address_no_fp_product_location() {
    let text = "我们在北京市场占有率很High";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"customer_address".to_string()),
        "Market should NOT trigger address detection"
    );
}

#[test]
fn test_address_valid_full_address() {
    let text = "收货Address: 北京市朝阳区建国路88编号SOHO大厦A座";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"customer_address".to_string()),
        "Full structured address should be detected"
    );
}

#[test]
fn test_address_multiple_levels() {
    let text = "广东省深圳市南山区深南大道9000编号";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"customer_address".to_string()),
        "Province+市+区+路 address should be detected"
    );
}

// Realistic email scenarios

#[test]
fn test_realistic_payroll_batch() {
    let text = "工资发放通知：\n\
        张三 工号: E001 月薪: 15000元\n\
        李四 工号: E002 月薪: 18000元\n\
        王5 工号: E003 月薪: 22000元";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"employee_info".to_string()),
        "Should detect employee info"
    );
    assert!(
        result.matches.contains(&"income_info".to_string()),
        "Should detect income info"
    );
    let c3_plus = result.count_items_at_level(3);
    assert!(c3_plus >= 3, "Should have >=3 C3+ items from income data");
}

#[test]
fn test_realistic_customer_data_export() {
    let text = "客户dataExport（共3Item）：\n\
        1. Name: 张三, 身份证: 000000200001010005, Mobile phone: 13800138000\n\
        2. Name: 李四, 身份证: 000000199201010004, Mobile phone: 13900139000\n\
        3. Name: 王5, 身份证: 000000198805150003, Mobile phone: 14700147000";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "Should detect IDs"
    );
    assert!(
        result.matches.contains(&"phone_number".to_string()),
        "Should detect phones"
    );
    let id_detail = result.details.iter().find(|(k, _)| k == "id_number");
    assert_eq!(
        id_detail.unwrap().1.len(),
        3,
        "Should detect 3 unique ID numbers"
    );
    let phone_detail = result.details.iter().find(|(k, _)| k == "phone_number");
    assert!(
        phone_detail.unwrap().1.len() >= 3,
        "Should detect >=3 phone numbers"
    );
}

#[test]
fn test_realistic_wire_transfer() {
    let text = "电汇指令：\n\
        收款人: ABC Corporation\n\
        Bank: HSBC Hong Kong\n\
        SWIFT: HSBCHKHH\n\
        IBAN: GB29NWBK60161331926819\n\
        Amount: 500,000 USD\n\
        备注: Invoice #2026-003";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"swift_code".to_string()),
        "Should detect SWIFT"
    );
    assert!(
        result.matches.contains(&"iban".to_string()),
        "Should detect IBAN"
    );
}

#[test]
fn test_realistic_compliance_report() {
    let text = "反洗钱Suspicious交易报告：\n\
        客户张某（身份证: 000000198501010001）\n\
        近30Sunday转入Amount: 3,500,000 USD，转出Amount: 2,800,000 USD\n\
        涉及账号：62220212345678\n\
        风控标签: 失信被执行人、行政处罚在查";
    let result = scan_text(text);
    assert!(result.matches.contains(&"id_number".to_string()));
    assert!(result.matches.contains(&"large_amount".to_string()));
    assert!(result.matches.contains(&"bank_account".to_string()));
    assert!(result.matches.contains(&"judicial_record".to_string()));
}

#[test]
fn test_realistic_medical_insurance_claim() {
    let text = "理赔审核材料：\n\
        投保人: 李某某\n\
        诊断: 2型糖尿病MergeHigh血压\n\
        住院日期: 2026-02-15\n\
        手术记录: 冠状动脉搭桥术\n\
        理赔金额: 85,000元\n\
        保单号: PL20250115001234";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"medical_health".to_string()),
        "Should detect medical info"
    );
    assert!(
        result.matches.contains(&"insurance_policy".to_string()),
        "Should detect insurance"
    );
    assert!(
        result.matches.contains(&"contract_number".to_string()),
        "Should detect policy number"
    );
    assert!(
        result.count_items_at_level(4) >= 1,
        "Should have C4 items from medical data"
    );
}

// More false positive scenarios

#[test]
fn test_no_fp_coremail_css_class_numbers() {
    let text = "class=\"m-compose-panel\" data-id=\"17744180056150\" style=\"width:100%\"";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"phone_number".to_string()),
        "CSS class IDs should NOT trigger phone detection"
    );
}

#[test]
fn test_no_fp_version_numbers() {
    let text = "升level到 v3.14.159，修复了 Bug #26535897。部署到 Build 2026031200";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"id_number".to_string()),
        "Version/build numbers should NOT trigger ID detection"
    );
}

#[test]
fn test_no_fp_uuid_string() {
    let text = "Session ID: 550e8400-e29b-41d4-a716-446655440000";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"credit_card".to_string()),
        "UUID should NOT trigger credit card detection"
    );
}

#[test]
fn test_no_fp_hash_string() {
    let text = "SHA256: 38D3670BE3FE34098A8C6E4B7D2F1CAFE0123456789ABCDEF01234567890ABC";
    let result = scan_text(text);
    assert!(!result.matches.contains(&"credit_card".to_string()));
}

#[test]
fn test_no_fp_html_entity_numbers() {
    let text = "charactersEncode: &#60; &#62; &#12345; &#99999;";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"phone_number".to_string()),
        "HTML entities should NOT trigger phone detection"
    );
}

#[test]
fn test_no_fp_sql_query() {
    let text = "SELECT * FROM users WHERE id = 1234567890 AND status = 1";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"phone_number".to_string()),
        "SQL query numbers should NOT trigger phone detection"
    );
}

#[test]
fn test_no_fp_json_numeric_ids() {
    let text = r#"{"user_id":12345678901234,"order_id":98765432109876}"#;
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"phone_number".to_string()),
        "JSON numeric IDs should NOT trigger phone detection"
    );
}

#[test]
fn test_no_fp_chinese_poetry() {
    let text = "床first明月光，疑是地上霜。举Header望明月，LowHeader思故乡。";
    let result = scan_text(text);
    assert!(
        result.matches.is_empty(),
        "Classical Chinese poetry should NOT trigger any DLP"
    );
}

#[test]
fn test_no_fp_financial_regulation_text() {
    let text = "according to《商业Bank法》After4十Item，贷款应WhenBy借款人提For担保。\
        Bank不得向关联方提For信用贷款或发放质押贷款。\
        违反本法规定of，By国务院Bank业监督Management机构责令改正。";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"loan_credit_info".to_string()),
        "Regulatory text discussing loans should NOT trigger loan_credit_info"
    );
}

// Phone/ID boundary tests

#[test]
fn test_phone_not_matched_inside_id_number() {
    let text = "身份证号码是 000000200001010005";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "ID number should be detected"
    );
    assert!(
        !result.matches.contains(&"phone_number".to_string()),
        "Phone should NOT be extracted from inside ID number (boundary fix)"
    );
}

#[test]
fn test_phone_not_matched_inside_bank_card() {
    let text = "Card number 4111111111111111";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"phone_number".to_string()),
        "Phone should NOT be extracted from inside credit card number"
    );
}

#[test]
fn test_phone_standalone_still_works() {
    let text = "联系电话 13800138000 或发email联系";
    let phones = find_chinese_phones(text);
    assert_eq!(phones.len(), 1, "Standalone phone should be detected");
}

#[test]
fn test_phone_after_chinese_char_works() {
    let text = "电话13800138000请联系 电话13900139000请联系 电话14700147000请联系";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"phone_number".to_string()),
        "Phone after Chinese char should be detected (non-digit boundary)"
    );
}

#[test]
fn test_phone_in_comma_separated_list() {
    let text = "13800138000,13900139000,14700147000";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"phone_number".to_string()),
        "Comma-separated phones should be detected (comma is non-digit boundary)"
    );
}

#[test]
fn test_phone_mixed_with_ids_correct_count() {
    let text = "身份证: 000000200001010005, 000000199201010004, 000000198805150003\n\
        Mobile phone: 13800138000, 13900139000, 14700147000";
    let result = scan_text(text);
    assert!(result.matches.contains(&"id_number".to_string()));
    assert!(result.matches.contains(&"phone_number".to_string()));
    let phone_detail = result.details.iter().find(|(k, _)| k == "phone_number");
    assert!(phone_detail.is_some());
    assert_eq!(
        phone_detail.unwrap().1.len(),
        3,
        "Should detect exactly 3 standalone phones, not phones from inside IDs"
    );
}

// ID check digit validation

#[test]
fn test_id_check_digit_valid() {
    assert!(chinese_id_check("000000200001010005"));
    assert!(chinese_id_check("000000199201010004"));
    assert!(chinese_id_check("000000198501010001"));
}

#[test]
fn test_id_check_digit_x() {
    assert!(chinese_id_check("000000194912310027"));
}

#[test]
fn test_id_check_digit_invalid() {
    assert!(!chinese_id_check("000000200001010000"));
    assert!(!chinese_id_check("000000200001010001"));
}

#[test]
fn test_id_random_18_digit_rejected() {
    let text = "订单编号 123456789012345678";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"id_number".to_string()),
        "Random 18-digit number should likely NOT pass ID check digit validation"
    );
}

#[test]
fn test_id_check_digit_lowercase_x() {
    assert!(chinese_id_check("000000194912310027"));
}

#[test]
fn test_id_valid_ids_detected() {
    let text = "客户身份证号: 000000200001010005";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "Valid ID with correct check digit should be detected"
    );
}

#[test]
fn test_id_invalid_check_digit_not_detected() {
    let text = "编号 000000200001010000";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"id_number".to_string()),
        "ID with wrong check digit should NOT be detected"
    );
}

// Social credit check digit

#[test]
fn test_social_credit_check_valid() {
    assert!(social_credit_check("A0000000000000000M"));
}

#[test]
fn test_social_credit_check_invalid() {
    assert!(!social_credit_check("A0000000000000000A"));
}

#[test]
fn test_social_credit_valid_detected() {
    let text = "公司信用代码 A0000000000000000M";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"social_credit_code".to_string()),
        "Valid social credit code should be detected"
    );
}

#[test]
fn test_social_credit_invalid_check_rejected() {
    let text = "编号 A0000000000000000A";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"social_credit_code".to_string()),
        "Social credit code with wrong check digit should NOT be detected"
    );
}

#[test]
fn test_social_credit_random_18_char_rejected() {
    let text = "ABCDEFGH1234567890";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"social_credit_code".to_string()),
        "Random 18-char alphanumeric should NOT pass social credit validation"
    );
}

#[test]
fn test_social_credit_ma_prefix_valid() {
    let text = "社会信用代码 A00000MA000000000B";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"social_credit_code".to_string()),
        "MA-prefix social credit code should be detected"
    );
}

// End-to-end accuracy

#[test]
fn test_e2e_no_cross_contamination() {
    let text = "only有1身份证 000000200001010005";
    let result = scan_text(text);
    assert_eq!(
        result.matches.len(),
        1,
        "Should detect exactly 1 pattern type"
    );
    assert!(result.matches.contains(&"id_number".to_string()));
}

#[test]
fn test_e2e_all_c4_patterns_independent() {
    let c4_texts = [
        ("Password：secret123", "credential_leak"),
        ("CVV: 789", "cvv_code"),
        ("Card number 4111111111111111", "credit_card"),
    ];
    for (text, expected) in c4_texts {
        let result = scan_text(text);
        assert!(
            result.matches.contains(&expected.to_string()),
            "C4 pattern '{}' should be detected in '{}'",
            expected,
            text
        );
    }
}

#[test]
fn test_e2e_biometric_requires_two_distinct() {
    let single = ["指纹", "虹膜", "声纹", "人脸识别", "面部特征"];
    for kw in single {
        let text = format!("该设备支持{}Function", kw);
        let result = scan_text(&text);
        assert!(
            !result.matches.contains(&"biometric_data".to_string()),
            "Single keyword '{}' should NOT trigger biometric",
            kw
        );
    }
}

#[test]
fn test_e2e_medical_requires_two_distinct() {
    let single = ["病历", "诊断", "处方", "住院", "手术记录"];
    for kw in single {
        let text = format!("请携with{}到门诊", kw);
        let result = scan_text(&text);
        assert!(
            !result.matches.contains(&"medical_health".to_string()),
            "Single keyword '{}' should NOT trigger medical",
            kw
        );
    }
}

#[test]
fn test_e2e_judicial_requires_two_distinct() {
    let single = [
        "失信被执行人",
        "行政处罚",
        "判决书",
        "强制执行",
    ];
    for kw in single {
        let text = format!("关于{}of法规解read", kw);
        let result = scan_text(&text);
        assert!(
            !result.matches.contains(&"judicial_record".to_string()),
            "Single keyword '{}' should NOT trigger judicial",
            kw
        );
    }
}

// Coremail scenarios

#[test]
fn test_coremail_typical_body_no_fp() {
    let text = "张总好，Attachment是上Weekday会议of纪要，请查收。if有Modify意见请回复此email。\n\
        另外，下Wednesday下午of项目评审会议室already预订，请安排参Add。\n\
        祝工作顺利！";
    let result = scan_text(text);
    assert!(
        result.matches.is_empty(),
        "Normal Coremail business email should NOT trigger any DLP, got: {:?}",
        result.matches
    );
}

#[test]
fn test_coremail_signature_no_fp() {
    let text =
        "此致\n\n张三\nRiskManagement部\n电话: 13800138000\nemail: zhangsan@example.com";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"phone_number".to_string()),
        "Single phone in signature should NOT trigger"
    );
    assert!(
        !result.matches.contains(&"email_address".to_string()),
        "Single email in signature should NOT trigger"
    );
}

#[test]
fn test_coremail_forwarded_customer_data() {
    let text = "-------- 转发Message --------\n\
        客户Infoif下：\n\
        Name：张三\n\
        身份证：000000200001010005\n\
        Mobile phone：13800138000, 13900139000, 14700147000\n\
        Address：北京市朝阳区建国路88编号\n\
        月薪：25000元";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "Should detect ID"
    );
    assert!(
        result.matches.contains(&"phone_number".to_string()),
        "Should detect phones"
    );
    assert!(
        result.matches.contains(&"customer_address".to_string()),
        "Should detect address"
    );
    assert!(
        result.matches.contains(&"income_info".to_string()),
        "Should detect income"
    );
}

#[test]
fn test_no_fp_internal_system_notification() {
    let text = "【System通知】\n\
        您有1笔Wait审批of申请（编号: REQ2026032600123）。\n\
        申请人: 李经理\n\
        申请Type: 费用报销\n\
        Amount: 3,500元\n\
        请在3工作Sunday内LoginOASystem审批。";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"large_amount".to_string()),
        "Single amount should NOT trigger"
    );
}

// Traditional Chinese variants

#[test]
fn test_bank_account_traditional_chinese() {
    let text = "帐号：1234567890";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"bank_account".to_string()),
        "Traditional Chinese account variant should also trigger"
    );
}

#[test]
fn test_bank_account_acct_abbreviation() {
    let text = "acct: 9876543210";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"bank_account".to_string()),
        "'acct' abbreviation should trigger"
    );
}

// Comprehensive scan

#[test]
fn test_scan_many_patterns_no_panic() {
    let text = "Password：abc123\n\
        CVV: 789\n\
        身份证 000000200001010005\n\
        4111111111111111\n\
        Mobile phone 13800138000 13900139000 14700147000\n\
        Address 北京市朝阳区建国路88编号\n\
        email a@example.test b@example.test c@example.test\n\
        护照 E12345678\n\
        信用代码 A0000000000000000M\n\
        SWIFT BKCHCNBJ\n\
        纳税 110108MA12345N9\n\
        IBAN DE89370400440532013000\n\
        合同Amount 100万元 首付 30万元\n\
        账号：1234567890\n\
        保单号 PL12345678901234\n\
        指纹和虹膜data\n\
        诊断和处方Info\n\
        京A12345\n\
        不动产权证\n\
        月薪: 25000元\n\
        GPS坐标: 116.39750\n\
        验证码: 582931\n\
        贷款余额: 500000元\n\
        投保人: 张三\n\
        配偶: 李四\n\
        工号: E001\n\
        失信被执行人和行政处罚\n\
        学历: 本科\n\
        营业执照编号: 110105012345678";
    let result = scan_text(text);
    assert!(
        result.matches.len() >= 15,
        "Should detect many patterns, got {}: {:?}",
        result.matches.len(),
        result.matches
    );
}

// Credit card BIN validation

#[test]
fn test_credit_card_visa_prefix() {
    let text = "Card number 4111111111111111";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credit_card".to_string()),
        "Visa card (prefix 4) should be detected"
    );
}

#[test]
fn test_credit_card_mastercard_prefix() {
    let text = "Card number 5100000000000008";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credit_card".to_string()),
        "Mastercard (prefix 51) should be detected"
    );
}

#[test]
fn test_credit_card_unionpay_prefix() {
    let text = "Card number 6200000000000005";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credit_card".to_string()),
        "UnionPay card (prefix 62) should be detected"
    );
}

#[test]
fn test_credit_card_invalid_bin_rejected() {
    let text = "编号 0000000000000000";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"credit_card".to_string()),
        "Prefix 0 is not a valid card BIN, should NOT be detected"
    );
}

#[test]
fn test_credit_card_bin_1xxx_rejected() {
    let (cards, _) = find_credit_cards("1234567890123452");
    assert!(
        cards.is_empty() || !is_valid_card_bin("1234567890123452"),
        "Prefix 1 should fail BIN validation"
    );
}

#[test]
fn test_credit_card_bin_validation_unit() {
    assert!(is_valid_card_bin("4111111111111111"), "Visa (4)");
    assert!(is_valid_card_bin("5100000000000008"), "Mastercard (51)");
    assert!(is_valid_card_bin("6200000000000005"), "UnionPay (62)");
    assert!(is_valid_card_bin("3400000000000000"), "Amex (34)");
    assert!(is_valid_card_bin("3700000000000000"), "Amex (37)");
    assert!(is_valid_card_bin("6011000000000000"), "Discover (6011)");
    assert!(is_valid_card_bin("6500000000000000"), "Discover (65)");
    assert!(is_valid_card_bin("3500000000000000"), "JCB (35)");
    assert!(!is_valid_card_bin("0000000000000000"), "Invalid prefix 0");
    assert!(!is_valid_card_bin("1000000000000000"), "Invalid prefix 1");
    assert!(!is_valid_card_bin("7000000000000000"), "Invalid prefix 7");
    assert!(!is_valid_card_bin("8000000000000000"), "Invalid prefix 8");
}

// IBAN country length

#[test]
fn test_iban_de_exact_length() {
    assert_eq!(iban_expected_length("DE"), Some(22));
}

#[test]
fn test_iban_gb_exact_length() {
    assert_eq!(iban_expected_length("GB"), Some(22));
}

#[test]
fn test_iban_fr_exact_length() {
    assert_eq!(iban_expected_length("FR"), Some(27));
}

#[test]
fn test_iban_no_exact_length() {
    assert_eq!(iban_expected_length("NO"), Some(15));
}

#[test]
fn test_iban_unknown_country_rejected() {
    assert_eq!(iban_expected_length("XX"), None);
    assert_eq!(iban_expected_length("US"), None);
}

#[test]
fn test_iban_wrong_length_for_country_rejected() {
    let ibans = find_ibans("DE8937040044053201");
    assert!(
        ibans.is_empty(),
        "DE IBAN with 18 chars (should be 22) should be rejected"
    );
}

#[test]
fn test_iban_correct_length_detected() {
    let text = "IBAN DE89370400440532013000";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"iban".to_string()),
        "DE IBAN with correct length (22) should be detected"
    );
}

// Bank account new keywords

#[test]
fn test_bank_account_remittance_keyword() {
    let text = "汇款: 1234567890";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"bank_account".to_string()),
        "Remittance keyword should trigger bank account detection"
    );
}

#[test]
fn test_bank_account_payment_transfer_keyword() {
    let text = "打款: 9876543210";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"bank_account".to_string()),
        "Transfer keyword should trigger bank account detection"
    );
}

// Attack scenarios

#[test]
fn test_attack_scenario_data_exfiltration_draft() {
    let text = "Batch客户data (请速查收):\n\
        张三 000000200001010005 Card number 4111111111111111 月薪:35000元\n\
        李四 000000199201010004 Card number 5100000000000008 月薪:28000元\n\
        王5 000000198501010001 Card number 6200000000000005 月薪:42000元";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "Should detect IDs"
    );
    assert!(
        result.matches.contains(&"credit_card".to_string()),
        "Should detect cards"
    );
    assert!(
        result.matches.contains(&"income_info".to_string()),
        "Should detect income"
    );
    let id_count = result
        .details
        .iter()
        .find(|(k, _)| k == "id_number")
        .map(|(_, v)| v.len())
        .unwrap_or(0);
    assert_eq!(id_count, 3, "Should detect 3 distinct ID numbers");
}

#[test]
fn test_attack_scenario_wire_transfer_fraud() {
    let text = "紧急通知 - 请立immediately转账:\n\
        收款人: International Trading Co.\n\
        Bank: HSBC Hong Kong\n\
        SWIFT代码: HSBCHKHH\n\
        IBAN: GB29NWBK60161331926819\n\
        Amount: 500,000 USD, 手续费 2,000 USD\n\
        请在下午3点firstcomplete，否则合同失效";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"swift_code".to_string()),
        "Should detect SWIFT"
    );
    assert!(
        result.matches.contains(&"iban".to_string()),
        "Should detect IBAN"
    );
    assert!(
        result.matches.contains(&"large_amount".to_string()),
        "Should detect 大 amounts"
    );
}

#[test]
fn test_attack_scenario_credential_phishing() {
    let text = "Received您ofPassword重置Request:\n\
        userName: admin\n\
        旧Password：OldPwd@2025\n\
        NewPassword：NewPwd@2026\n\
        PIN: 8529\n\
        CVV: 731";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "Should detect credentials"
    );
    assert!(
        result.matches.contains(&"cvv_code".to_string()),
        "Should detect CVV"
    );
    let cred_count = result
        .details
        .iter()
        .find(|(k, _)| k == "credential_leak")
        .map(|(_, v)| v.len())
        .unwrap_or(0);
    assert!(
        cred_count >= 2,
        "Should detect multiple credential leaks, got {}",
        cred_count
    );
}

#[test]
fn test_no_fp_random_16_digit_number() {
    let text = "Stream水编号 7890123456789012";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"credit_card".to_string()),
        "Random 16-digit number with invalid BIN (7890) should NOT trigger credit_card"
    );
}

#[test]
fn test_no_fp_timestamp_like_number() {
    let text = "Createtimestamp 2026032608301500";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"credit_card".to_string()),
        "Timestamp-like 16-digit number should NOT trigger credit_card"
    );
}

// Anti-evasion: zero-width character stripping

#[test]
fn test_normalize_strips_zero_width_space() {
    let result = normalize_for_dlp("1\u{200B}3\u{200B}8");
    assert_eq!(result, "138", "Zero-width spaces should be stripped");
}

#[test]
fn test_normalize_strips_bom() {
    let result = normalize_for_dlp("\u{FEFF}hello");
    assert_eq!(result, "hello", "BOM should be stripped");
}

#[test]
fn test_normalize_strips_soft_hyphen() {
    let result = normalize_for_dlp("密\u{00AD}码");
    assert_eq!(result, "密码", "Soft hyphen should be stripped");
}

#[test]
fn test_normalize_fullwidth_digits() {
    let result = normalize_for_dlp(
        "\u{FF11}\u{FF13}\u{FF18}\u{FF10}\u{FF10}\u{FF11}\u{FF13}\u{FF18}\u{FF10}\u{FF10}\u{FF10}",
    );
    assert_eq!(
        result, "13800138000",
        "Fullwidth digits should be converted"
    );
}

#[test]
fn test_normalize_fullwidth_letters() {
    let result = normalize_for_dlp("\u{FF21}\u{FF22}\u{FF23}\u{FF24}\u{FF25}\u{FF26}");
    assert_eq!(result, "ABCDEF", "Fullwidth uppercase should be converted");
}

#[test]
fn test_normalize_fullwidth_lowercase() {
    let result = normalize_for_dlp("\u{FF41}\u{FF42}\u{FF43}\u{FF44}\u{FF45}\u{FF46}");
    assert_eq!(result, "abcdef", "Fullwidth lowercase should be converted");
}

#[test]
fn test_normalize_fullwidth_colon() {
    let result = normalize_for_dlp("Password\u{FF1A}secret");
    assert_eq!(
        result, "Password:secret",
        "Fullwidth colon should be converted"
    );
}

#[test]
fn test_normalize_preserves_normal_text() {
    let text = "这是1SegmentNormalofChineseText，not有特殊characters。Hello World 123.";
    let result = normalize_for_dlp(text);
    assert_eq!(result, text, "Normal text should be unchanged");
}

#[test]
fn test_normalize_empty_string() {
    assert_eq!(normalize_for_dlp(""), "");
}

// Zero-width evasion attack detection

#[test]
fn test_evasion_zero_width_in_phone() {
    let text = "联系 1\u{200B}3\u{200B}8\u{200B}0\u{200B}0\u{200B}1\u{200B}3\u{200B}8\u{200B}0\u{200B}0\u{200B}0 和 1\u{200B}3\u{200B}9\u{200B}0\u{200B}0\u{200B}1\u{200B}3\u{200B}9\u{200B}0\u{200B}0\u{200B}0 和 1\u{200B}4\u{200B}7\u{200B}0\u{200B}0\u{200B}1\u{200B}4\u{200B}7\u{200B}0\u{200B}0\u{200B}0";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"phone_number".to_string()),
        "Zero-width chars between phone digits should NOT bypass detection"
    );
}

#[test]
fn test_evasion_zero_width_in_id_number() {
    let text = "身份证 0\u{200B}0\u{200B}0\u{200B}0\u{200B}0\u{200B}0\u{200B}2\u{200B}0\u{200B}0\u{200B}0\u{200B}0\u{200B}1\u{200B}0\u{200B}1\u{200B}0\u{200B}0\u{200B}0\u{200B}5";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "Zero-width chars in ID number should NOT bypass detection"
    );
}

#[test]
fn test_evasion_zero_width_in_credit_card() {
    let text = "Card number 4\u{200B}1\u{200B}1\u{200B}1\u{200B}1\u{200B}1\u{200B}1\u{200B}1\u{200B}1\u{200B}1\u{200B}1\u{200B}1\u{200B}1\u{200B}1\u{200B}1\u{200B}1";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credit_card".to_string()),
        "Zero-width chars in credit card should NOT bypass detection"
    );
}

#[test]
fn test_evasion_zero_width_in_credential() {
    let text = "密\u{200B}码：secret123";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "Zero-width chars in credential keyword should NOT bypass detection"
    );
}

// Fullwidth evasion

#[test]
fn test_evasion_fullwidth_phone() {
    let text = "联系 \u{FF11}\u{FF13}\u{FF18}\u{FF10}\u{FF10}\u{FF11}\u{FF13}\u{FF18}\u{FF10}\u{FF10}\u{FF10} 和 \u{FF11}\u{FF13}\u{FF19}\u{FF10}\u{FF10}\u{FF11}\u{FF13}\u{FF19}\u{FF10}\u{FF10}\u{FF10} 和 \u{FF11}\u{FF14}\u{FF17}\u{FF10}\u{FF10}\u{FF11}\u{FF14}\u{FF17}\u{FF10}\u{FF10}\u{FF10}";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"phone_number".to_string()),
        "Fullwidth digit phone numbers should NOT bypass detection"
    );
}

#[test]
fn test_evasion_fullwidth_id_number() {
    let text = "证件 \u{FF10}\u{FF10}\u{FF10}\u{FF10}\u{FF10}\u{FF10}\u{FF12}\u{FF10}\u{FF10}\u{FF10}\u{FF10}\u{FF11}\u{FF10}\u{FF11}\u{FF10}\u{FF10}\u{FF10}\u{FF15}";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "Fullwidth digit ID number should NOT bypass detection"
    );
}

#[test]
fn test_evasion_fullwidth_credit_card() {
    let text = "Card number \u{FF14}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credit_card".to_string()),
        "Fullwidth digit credit card should NOT bypass detection"
    );
}

#[test]
fn test_evasion_fullwidth_credential() {
    let text = "password\u{FF1A}MySecret123";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "Fullwidth colon in credential should NOT bypass detection"
    );
}

#[test]
fn test_evasion_mixed_width_digits() {
    let text = "身份证 0\u{FF10}000020000\u{FF11}010005";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "Mixed half/fullwidth digits should NOT bypass detection"
    );
}

// Multiple zero-width types

#[test]
fn test_evasion_multiple_zero_width_types() {
    let text = "密\u{200C}码\u{200D}：\u{FEFF}secret\u{2060}123";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "Multiple zero-width char types should all be stripped"
    );
}

#[test]
fn test_evasion_soft_hyphen_in_swift() {
    let text = "SWIFT BK\u{00AD}CH\u{00AD}CN\u{00AD}BJ";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"swift_code".to_string()),
        "Soft hyphens in SWIFT code should NOT bypass detection"
    );
}

// Normalization doesn't create FP

#[test]
fn test_normalize_does_not_create_false_positives() {
    let text = "这是1封Normalofemail。项目进展顺利，请查收Attachment。";
    let result = scan_text(text);
    assert!(
        result.matches.is_empty(),
        "Normalization should not create false positives on normal text"
    );
}

#[test]
fn test_normalize_fullwidth_in_normal_chinese() {
    let text = "会议timestamp：\u{FF12}\u{FF10}\u{FF12}\u{FF16}年\u{FF13}月\u{FF12}\u{FF16}Sunday 地点：\u{FF21}栋会议室";
    let result = scan_text(text);
    assert!(
        result.matches.is_empty(),
        "Fullwidth in normal Chinese text should NOT trigger DLP after normalization"
    );
}

// normalize_for_dlp unit tests

#[test]
fn test_normalize_all_invisible_chars() {
    let invisibles = "\u{200B}\u{200C}\u{200D}\u{200E}\u{200F}\u{FEFF}\u{00AD}\u{2060}\u{2061}\u{2062}\u{2063}\u{2064}\u{180E}\u{034F}";
    let result = normalize_for_dlp(invisibles);
    assert!(
        result.is_empty(),
        "All invisible chars should be stripped completely"
    );
}

#[test]
fn test_normalize_fullwidth_digit_boundary() {
    assert_eq!(normalize_for_dlp("\u{FF10}"), "0");
    assert_eq!(normalize_for_dlp("\u{FF19}"), "9");
    assert_eq!(
        normalize_for_dlp(
            "\u{FF10}\u{FF11}\u{FF12}\u{FF13}\u{FF14}\u{FF15}\u{FF16}\u{FF17}\u{FF18}\u{FF19}"
        ),
        "0123456789"
    );
}

#[test]
fn test_normalize_fullwidth_letter_boundary() {
    assert_eq!(normalize_for_dlp("\u{FF21}"), "A");
    assert_eq!(normalize_for_dlp("\u{FF3A}"), "Z");
    assert_eq!(normalize_for_dlp("\u{FF41}"), "a");
    assert_eq!(normalize_for_dlp("\u{FF5A}"), "z");
}

// HTML entity decoding

#[test]
fn test_decode_html_decimal_entity() {
    assert_eq!(normalize_for_dlp("&#49;&#51;&#56;"), "138");
}

#[test]
fn test_decode_html_hex_entity() {
    assert_eq!(normalize_for_dlp("&#x31;&#x33;&#x38;"), "138");
}

#[test]
fn test_decode_html_mixed_entity_and_text() {
    assert_eq!(
        normalize_for_dlp("phone: &#49;38&#48;&#48;138000"),
        "phone: 13800138000"
    );
}

#[test]
fn test_decode_html_entity_chinese() {
    assert_eq!(
        normalize_for_dlp("&#23494;&#30721;: secret"),
        "密码: secret"
    );
}

#[test]
fn test_decode_html_entity_no_semicolon_decoded() {
    // PoC：无分号数字实体是绕过手段，修复后应解码为对应字符
    let text = "&#49 is not decoded";
    let result = normalize_for_dlp(text);
    assert!(
        result.starts_with("1 "),
        "Entity without semicolon should now be decoded, got: {result:?}"
    );
    assert!(
        !result.contains("&#49"),
        "Entity without semicolon should not be preserved, got: {result:?}"
    );
}

#[test]
fn test_decode_html_entity_control_char_blocked() {
    let result = normalize_for_dlp("&#0;test");
    assert!(
        !result.contains('\0'),
        "Null char entity should NOT be decoded"
    );
}

#[test]
fn test_decode_html_entity_normal_text_untouched() {
    let text = "NormalTextnot有实体 & other stuff";
    assert_eq!(normalize_for_dlp(text), text);
}

#[test]
fn test_evasion_html_entity_phone() {
    let text = "联系 &#49;&#51;&#56;&#49;&#50;&#51;&#52;&#53;&#54;&#55;&#56; 和 &#49;&#53;&#57;&#56;&#55;&#54;&#53;&#52;&#51;&#50;&#49; 和 &#49;&#56;&#54;&#49;&#49;&#49;&#49;&#50;&#50;&#50;&#50;";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"phone_number".to_string()),
        "HTML entity encoded phone numbers should NOT bypass detection"
    );
}

#[test]
fn test_evasion_html_entity_id_number() {
    let text = "ID &#49;&#49;&#48;&#49;&#48;&#49;&#49;&#57;&#57;&#48;&#48;&#49;&#48;&#49;&#49;&#50;&#51;&#55;";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "HTML entity encoded ID number should NOT bypass detection"
    );
}

#[test]
fn test_evasion_html_entity_credential() {
    let text = "&#112;&#97;&#115;&#115;&#119;&#111;&#114;&#100;: admin123";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "HTML entity encoded 'password' keyword should NOT bypass detection"
    );
}

// CVV/OTP double-count fix

#[test]
fn test_cvv_otp_no_double_count_4digit() {
    let text = "验证码: 4567";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"cvv_code".to_string()),
        "Verification code with 4 digits should match CVV"
    );
    assert!(
        !result.matches.contains(&"otp_verification".to_string()),
        "Verification code should NOT also match OTP (double-count fix)"
    );
}

#[test]
fn test_cvv_3digit_no_otp_overlap() {
    let text = "验证码: 789";
    let result = scan_text(text);
    assert!(result.matches.contains(&"cvv_code".to_string()));
    assert!(
        !result.matches.contains(&"otp_verification".to_string()),
        "Verification code with 3 digits should only match CVV, not OTP"
    );
}

#[test]
fn test_otp_still_works_without_jiaoyanma() {
    let text = "验证码: 582931";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"otp_verification".to_string()),
        "Verification code keyword should still trigger OTP"
    );
    assert!(
        !result.matches.contains(&"cvv_code".to_string()),
        "Verification code keyword should NOT trigger CVV (different keyword)"
    );
}

#[test]
fn test_otp_dynamic_password_still_works() {
    let text = "动态口令: 849261";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"otp_verification".to_string()),
        "Dynamic password should still trigger OTP"
    );
}

#[test]
fn test_cvv_security_code_still_works() {
    let text = "安全码: 123";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"cvv_code".to_string()),
        "Security code should still trigger CVV"
    );
}

// Combined evasion

#[test]
fn test_evasion_combo_fullwidth_plus_zero_width() {
    let text = "身份证 \u{FF11}\u{200B}\u{FF11}\u{200B}\u{FF10}\u{200B}\u{FF11}\u{200B}\u{FF10}\u{200B}\u{FF11}\u{200B}\u{FF11}\u{200B}\u{FF19}\u{200B}\u{FF19}\u{200B}\u{FF10}\u{200B}\u{FF10}\u{200B}\u{FF11}\u{200B}\u{FF10}\u{200B}\u{FF11}\u{200B}\u{FF11}\u{200B}\u{FF12}\u{200B}\u{FF13}\u{200B}\u{FF17}";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "Fullwidth digits + zero-width chars combo should NOT bypass detection"
    );
}

#[test]
fn test_evasion_combo_entity_plus_fullwidth() {
    let text = "Password\u{FF1A}&#115;ecret\u{FF11}\u{FF12}\u{FF13}";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "HTML entity + fullwidth combo should NOT bypass credential detection"
    );
}

#[test]
fn test_evasion_combo_all_three() {
    let text = "&#112;assword\u{FF1A}\u{200B}secret";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "Triple evasion combo should NOT bypass detection"
    );
}

#[test]
fn test_no_fp_marketing_email() {
    let text = "双十1促销活动！\n\
        全场full200减50，限时3Day！\n\
        iPhone 16 Pro Max 直downgrade1000元！\n\
        抢购linkConnect: shop.example.com\n\
        客服热线: 400-123-4567";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"phone_number".to_string()),
        "400 hotline should NOT trigger phone detection"
    );
    assert!(
        !result.matches.contains(&"credit_card".to_string()),
        "Price numbers should NOT trigger credit card detection"
    );
}

#[test]
fn test_no_fp_newsletter() {
    let text = "科技Sunday报 2026年3月26Sunday\n\
        人工智能正在改变金融line业of风控mode。\n\
        According toStatistics，already有超500家Bank采用了AI反欺诈System。\n\
        专家预测到2030年，智能风控将override90%以上of金融机构。";
    let result = scan_text(text);
    assert!(
        result.matches.is_empty(),
        "News/newsletter should NOT trigger any DLP, got: {:?}",
        result.matches
    );
}

#[test]
fn test_no_fp_log_file_content() {
    let text = "[2026-03-26 10:30:15] INFO  - Request from 192.168.1.100:45678 to 10.0.0.1:8080\n\
        [2026-03-26 10:30:15] DEBUG - Headers: Content-Type=application/json\n\
        [2026-03-26 10:30:16] INFO  - Response: 200 OK in 15ms";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"phone_number".to_string()),
        "Port numbers in logs should NOT trigger phone detection"
    );
}

#[test]
fn test_realistic_judicial_report() {
    let text = "信用调查报告：\n\
        被Query人 失信被执行人，stored在行政处罚记录。\n\
        法院already下达强制执行通知，并作出限制消费令。\n\
        裁定书编号: (2026)京执字After12345编号";
    let result = scan_text(text);
    assert!(result.matches.contains(&"judicial_record".to_string()));
    let detail = result.details.iter().find(|(k, _)| k == "judicial_record");
    assert!(detail.is_some());
    assert!(
        detail.unwrap().1.len() >= 2,
        "Should detect >=2 distinct judicial keywords"
    );
}


// ============================================================
// PoC 回归测试（绕过手段 → 修复后必须检出）
// ============================================================

#[test]
fn test_attack_otp_verification_code() {
    let result = scan_text("验证码：483920");
    assert!(
        result.matches.contains(&"otp_verification".to_string()),
        "验证码 + 6 位数字应命中 otp_verification"
    );
    assert!(
        !result.matches.contains(&"cvv_code".to_string()),
        "6 位数字不应误判为 CVV"
    );
}

#[test]
fn test_attack_large_amount_wanyuan() {
    let result = scan_text("合同金额 500万元，预付款 100万元");
    assert!(
        result.matches.contains(&"large_amount".to_string()),
        "万元单位的大额金额应检出"
    );
}

#[test]
fn test_attack_contract_number_chinese() {
    let contracts = find_contract_numbers("合同编号：HT20260101123456");
    assert_eq!(contracts.len(), 1, "合同编号 + 字母数字编号应检出");
}

#[test]
fn test_attack_lowercase_swift_scan() {
    // 小写候选需带 swift/bic 上下文 (防英文散文单词误报)
    let result = scan_text("请汇款至 SWIFT 代码 bkchcnbj 账户");
    assert!(
        result.matches.contains(&"swift_code".to_string()),
        "小写 SWIFT 应在大写归一化后检出"
    );
}

#[test]
fn test_attack_lowercase_vin() {
    let result = scan_text("vin: lsvau2180n2183294");
    assert!(
        result.matches.contains(&"vehicle_info".to_string()),
        "小写 VIN 应检出"
    );
}

#[test]
fn test_attack_lowercase_iban() {
    let result = scan_text("iban: de89370400440532013000");
    assert!(
        result.matches.contains(&"iban".to_string()),
        "小写 IBAN 应检出"
    );
}

#[test]
fn test_attack_id_number_with_spaces() {
    // 合法校验位 000000200001010005，攻击者插入空格分组绕过
    let result = scan_text("身份证号: 000000 200001 010005");
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "带空格分隔的身份证号应检出"
    );
}

#[test]
fn test_attack_phones_with_dashes() {
    let result = scan_text("联系人: 138-0013-8000, 139-0013-9000, 147-0014-7000");
    assert!(
        result.matches.contains(&"phone_number".to_string()),
        "带横线分隔的手机号应检出"
    );
}

#[test]
fn test_attack_credit_card_dots() {
    let result = scan_text("卡号 4111.1111.1111.1111");
    assert!(
        result.matches.contains(&"credit_card".to_string()),
        "点号分隔的信用卡号应检出"
    );
}

#[test]
fn test_attack_window_straddle() {
    // 敏感数据横跨 512KiB 窗口边界，64B 重叠区兜底
    // 卡号前需空格: 卡号正则要求 ASCII 词边界, 字母填充直接粘连数字在任何窗口下都不构成匹配
    let padding = "A".repeat(DLP_MAX_SCAN_LEN - 9);
    let text = format!("{} 4111111111111111 尾部", padding);
    let result = scan_text(&text);
    assert!(
        result.matches.contains(&"credit_card".to_string()),
        "跨窗口边界的信用卡号应被重叠区覆盖并检出"
    );
}

#[test]
fn test_evasion_bidi_and_new_invisibles() {
    // bidi 控制符 U+202E、韩语填充 U+3164、盲文空白 U+2800 插入关键词/数字中
    let result = scan_text("验\u{202E}证\u{3164}码：4839\u{2800}20");
    assert!(
        result.matches.contains(&"otp_verification".to_string()),
        "bidi/填充/盲文空白拆分关键词应被归一化后检出"
    );
}

#[test]
fn test_normalize_strips_extended_invisibles() {
    let input = "\u{202A}\u{202E}\u{2066}\u{2069}\u{061C}\u{E0001}\u{E0020}\u{E007F}\u{FE00}\u{FE0F}\u{E0100}\u{E01EF}\u{115F}\u{1160}\u{3164}\u{FFA0}\u{2800}";
    let result = normalize_for_dlp(input);
    assert!(
        result.is_empty(),
        "扩充不可见字符集应全部剥离, got: {result:?}"
    );
}

#[test]
fn test_evasion_entity_no_semicolon_scan() {
    // 无分号数字实体拼出 483920
    let result = scan_text("验证码：&#52&#56&#51&#57&#50&#48");
    assert!(
        result.matches.contains(&"otp_verification".to_string()),
        "无分号 HTML 实体编码的验证码应检出"
    );
}

#[test]
fn test_credential_traditional_variants() {
    let result = scan_text("密碼：secret123");
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "繁体 密碼 应命中 credential_leak"
    );
    let result2 = scan_text("帳號：admin123");
    assert!(
        result2.matches.contains(&"credential_leak".to_string()),
        "繁体 帳號 应命中 credential_leak"
    );
}

#[test]
fn test_bank_account_variants() {
    for text in [
        "账号：1234567890",
        "帐户：1234567890",
        "帐号：1234567890",
    ] {
        let result = scan_text(text);
        assert!(
            result.matches.contains(&"bank_account".to_string()),
            "{text} 应命中 bank_account"
        );
    }
}

#[test]
fn test_extract_dlp_text_html_body_stripped() {
    let body = "<span>000000200</span><span>001010005</span>";
    let uri = "/other/endpoint";
    let text = extract_dlp_text(body, uri, Some("text/html"));
    assert!(
        text.contains("000000200001010005"),
        "非 Coremail 的 text/html body 应剥标签后拼接文本, got: {text:?}"
    );
}

// 第二轮红队修复 PoC (D1-D6)

#[test]
fn test_credit_card_max_separator_groups_detected() {
    // D1: 真实卡号写法的最大分隔 (每组 4 个) 仍检出
    let result = scan_text("卡号 4111----1111----1111----1111");
    assert!(
        result.matches.contains(&"credit_card".to_string()),
        "每组 4 个分隔符的卡号写法应检出"
    );
}

#[test]
fn test_credit_card_excessive_separator_rejected() {
    // D1: 超长分隔 (>4/组) 不再被正则拼成一个候选。
    // 修复前 `[\s\-\.]*` 无上限, 攻击者用超长分隔让卡号匹配跨度超过
    // 扫描窗口重叠区, 跨 512KiB 窗口边界时漏检; 修复后该写法不构成候选
    let gap = "-".repeat(80);
    let text = format!("卡号 4111{gap}1111{gap}1111{gap}1111");
    let result = scan_text(&text);
    assert!(
        !result.matches.contains(&"credit_card".to_string()),
        "超长分隔 (>4) 的卡号写法不应构成匹配"
    );
}

#[test]
fn test_credit_card_straddling_window_with_max_separators() {
    // D1: 合法分组分隔 (4/组, 跨度 28B) 的卡号横跨 512KiB 窗口边界,
    // 256B 重叠区保证覆盖 (匹配跨度上限 << 重叠区, 双保险)
    let padding = "A".repeat(DLP_MAX_SCAN_LEN - 16);
    let text = format!("{padding} 4111----1111----1111----1111 尾部");
    let result = scan_text(&text);
    assert!(
        result.matches.contains(&"credit_card".to_string()),
        "带分组分隔符的卡号跨窗口边界应被重叠区覆盖并检出"
    );
}

#[test]
fn test_evasion_c0_control_in_id_number() {
    // D2: C0 控制符夹带进身份证号 (\x07 / \x0B), 修复前拆开数字串绕过
    let result = scan_text("身份\x07证号: 0000002000010\x0B10005");
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "C0 控制符夹带的身份证号应被归一化后检出"
    );
}

#[test]
fn test_evasion_c0_control_in_credential() {
    // D2: C0 控制符拆分密码关键词
    let result = scan_text("密\x0C码：hunter2");
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "C0 控制符拆分密码关键词应被归一化后检出"
    );
}

#[test]
fn test_normalize_c0_stripped_but_keeps_whitespace() {
    // D2: 剥 C0 但保留 \t \n \r
    let input = "a\u{0007}b\u{000B}c\u{001F}d\te\nf\rg";
    let result = normalize_for_dlp(input);
    assert_eq!(result, "abcd\te\nf\rg");
}

#[test]
fn test_evasion_named_entity_credential() {
    // D3: 命名实体 &colon; 构造 password: 绕过 credential 分隔符匹配
    let result = scan_text("password&colon; hunter2");
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "命名实体 &colon; 编码的 credential 应检出"
    );
}

#[test]
fn test_evasion_named_entity_equals_tab() {
    // D3: &equals; / &Tab; 变体
    let result = scan_text("密码&equals;&Tab;123456");
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "&equals;/&Tab; 编码的 credential 应检出"
    );
}

#[test]
fn test_decode_named_entities_unit() {
    // D3: 最小命名实体表解码
    assert_eq!(normalize_for_dlp("a&colon;b&equals;c"), "a:b=c");
    assert_eq!(normalize_for_dlp("x&Tab;y&NewLine;z"), "x\ty\nz");
    assert_eq!(
        normalize_for_dlp("&lt;tag&gt;&quot;q&quot;&amp;amp"),
        "<tag>\"q\"&amp"
    );
}

#[test]
fn test_named_entity_unknown_and_bare_ampersand_untouched() {
    // D3: 未收录的实体名与裸 & 原样保留
    assert_eq!(normalize_for_dlp("a&nbsp;b"), "a&nbsp;b");
    assert_eq!(normalize_for_dlp("Tom & Jerry"), "Tom & Jerry");
    assert_eq!(normalize_for_dlp("AT&T"), "AT&T");
}

#[test]
fn test_prefilter_vin_digit_start() {
    // D4-1: VIN 详查允许数字开头, 预筛原先只覆盖字母开头 -> 预筛拦截漏检
    let result = scan_text("车架号 1HGBH41JXMN109186");
    assert!(
        result.matches.contains(&"vehicle_info".to_string()),
        "数字开头的 VIN 应检出"
    );
}

#[test]
fn test_prefilter_biometric_eye_pattern_and_facial() {
    // D4-2: 眼纹/facial recognition 预筛缺失。
    // 两个关键词都不在旧预筛表中, 修复前预筛整体不命中 -> 漏检
    let result = scan_text("门禁采集: 眼纹 + facial recognition");
    assert!(
        result.matches.contains(&"biometric_data".to_string()),
        "眼纹 + facial recognition (预筛漏词) 应检出 biometric_data"
    );
}

#[test]
fn test_prefilter_medical_nursing_and_fertility() {
    // D4-3: 护理记录/生育信息 预筛缺失 (两个关键词都不在旧预筛表中)
    let result = scan_text("附件为患者的护理记录与生育信息");
    assert!(
        result.matches.contains(&"medical_health".to_string()),
        "护理记录 + 生育信息 (预筛漏词) 应检出 medical_health"
    );
}

#[test]
fn test_prefilter_superset_of_detailed_patterns() {
    // D4 一致性: 每个详查类别的触发样例必须命中同索引的预筛模式,
    // 防止预筛词表与详查正则漂移导致静默漏检
    let cases: &[(usize, &str)] = &[
        (0, "4111111111111111"),
        (1, "110101199001011234"),
        (2, "13800138000"),
        (3, "6222021234567890123"),
        (4, "北京市朝阳区建国路88号"),
        (5, "user@example.com"),
        (6, "E12345678"),
        (7, "A0000000000000000M"),
        (8, "password: hunter2"),
        (9, "BKCHCNBJ"),
        (10, "cvv: 123"),
        (11, "110108MA12345N9"),
        (12, "DE89370400440532013000"),
        (13, "100万元"),
        (14, "账号：1234567890"),
        (15, "合同编号：PL12345678901234"),
        (16, "眼纹"),
        (17, "护理记录"),
        (18, "1HGBH41JXMN109186"),
        (19, "不动产权证"),
        (20, "月薪：25000元"),
        (21, "GPS坐标：116.39750"),
        (22, "验证码：483920"),
        (23, "贷款余额：500000元"),
        (24, "投保人：张三"),
        (25, "配偶：李四"),
        (26, "工号：E001"),
        (27, "失信被执行人"),
        (28, "学历：本科"),
        (29, "营业执照编号：110105012345678"),
    ];
    for &(idx, sample) in cases {
        let hits = DLP_REGEX_SET.matches(sample);
        assert!(
            hits.matched(idx),
            "预筛 idx {idx} 未命中详查触发样例: {sample:?}"
        );
    }
}

#[test]
fn test_credential_simplified_account_variants() {
    // D5: 简体 账号/账户/帐号/帐户 缺口 (原先只有繁体 帳號/帳戶)
    for text in ["账号：hunter2", "账户：hunter2", "帐号：hunter2", "帐户：hunter2"] {
        let result = scan_text(text);
        assert!(
            result.matches.contains(&"credential_leak".to_string()),
            "{text} 应命中 credential_leak"
        );
    }
}

#[test]
fn test_bank_account_traditional_full_variants() {
    // D5: 繁体 帳號/帳戶 上下文缺口
    for text in ["帳號：1234567890", "帳戶：1234567890"] {
        let result = scan_text(text);
        assert!(
            result.matches.contains(&"bank_account".to_string()),
            "{text} 应命中 bank_account"
        );
    }
}

#[test]
fn test_attack_phone_with_middle_dot_separator() {
    // D6: 间隔号·分隔的手机号 (修复前分隔符类只有空格/连字符)
    let result = scan_text("联系人: 138·0013·8000, 139·0013·9000, 147·0014·7000");
    assert!(
        result.matches.contains(&"phone_number".to_string()),
        "间隔号分隔的手机号应检出"
    );
}

#[test]
fn test_attack_phone_with_two_char_separator() {
    // D6: 两位分隔符 (量词 {0,2}, 修复前 {0,1} 不容许)
    let result = scan_text("联系人: 138--0013--8000, 139--0013--9000, 147--0014--7000");
    assert!(
        result.matches.contains(&"phone_number".to_string()),
        "双分隔符写法的手机号应检出"
    );
}

#[test]
fn test_attack_id_number_with_dot_middle_dot_mix() {
    // D6: 点+间隔号混合分隔的身份证号 (合法校验位 110101199001011237)
    let result = scan_text("身份证号: 1101.0119.9001.0112·37");
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "点/间隔号混合分隔的身份证号应检出"
    );
}

// D1-1: NFKC 兼容性折叠 (数学/带圈/装饰字符打散正则与关键词)

#[test]
fn test_normalize_nfkc_math_bold_digits() {
    // 数学数字区块 (加粗/双线/等宽) U+1D7CE+ -> ASCII
    // (𝟏=U+1D7CF 𝟐=U+1D7D0 𝟑=U+1D7D1, 双线 𝟘=U+1D7D8 -> 0)
    assert_eq!(normalize_for_dlp("\u{1D7CF}\u{1D7D0}\u{1D7D1}"), "123");
    assert_eq!(normalize_for_dlp("\u{1D7D8}"), "0");
    // 带圈数字 ①②③ -> 123
    assert_eq!(normalize_for_dlp("\u{2460}\u{2461}\u{2462}"), "123");
    // 带圈小写字母 ⓟⓐⓢⓢ -> pass
    assert_eq!(
        normalize_for_dlp("\u{24DF}\u{24D0}\u{24E2}\u{24E2}"),
        "pass"
    );
}

#[test]
fn test_attack_math_bold_digits_credit_card() {
    // D1-1 PoC: 数学加粗数字写法的卡号, 修复前 \d 正则不认 U+1D7CE 区块完全失明
    let math_bold: String = "4111111111111111"
        .chars()
        .map(|c| char::from_u32(0x1D7CE + c.to_digit(10).unwrap()).unwrap())
        .collect();
    let text = format!("卡号 {}", math_bold);
    let result = scan_text(&text);
    assert!(
        result.matches.contains(&"credit_card".to_string()),
        "数学加粗数字写法的卡号应检出 credit_card"
    );
}

#[test]
fn test_attack_circled_digits_id_number() {
    // D1-1 PoC: 圆圈数字 (①②③ + ⓪) 写法身份证 (合法校验位 110101199001011237)
    let circled: String = "110101199001011237"
        .chars()
        .map(|c| {
            let d = c.to_digit(10).unwrap();
            // U+2460=① .. U+2468=⑨, U+24EA=⓪
            char::from_u32(if d == 0 { 0x24EA } else { 0x2460 + d - 1 }).unwrap()
        })
        .collect();
    let text = format!("身份证号: {}", circled);
    let result = scan_text(&text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "圆圈数字写法的身份证号应检出 id_number"
    );
}

#[test]
fn test_attack_circled_letters_credential() {
    // D1-1 PoC: ⓟⓐⓢⓢⓦⓞⓡⓓ 打散 credential 关键词上下文
    let text = "\u{24DF}\u{24D0}\u{24E2}\u{24E2}\u{24E6}\u{24DE}\u{24E1}\u{24D3}: hunter2";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"credential_leak".to_string()),
        "带圈字母写法的 password 上下文应检出 credential_leak"
    );
}

// D1-2: 编码视图二级解码重扫 (base64/hex)

#[test]
fn test_attack_base64_encoded_id_number() {
    // D1-2 PoC: base64 编码的身份证号段, 修复前明文扫描对编码串完全失明
    use base64::Engine as _;
    let encoded =
        base64::engine::general_purpose::STANDARD.encode("身份证号:110101199001011237");
    assert!(encoded.len() >= 40, "测试样例需满足候选段下限");
    let text = format!("附件编码段: {}", encoded);
    let result = scan_text(&text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "base64 编码的身份证号应解码后检出 id_number"
    );
    assert!(
        result.matches.contains(&"encoded_sensitive_data".to_string()),
        "编码通道命中应附加 encoded_sensitive_data 归因标记"
    );
}

#[test]
fn test_attack_hex_encoded_credit_card() {
    // D1-2 PoC: hex 编码的卡号段, 修复前明文扫描对编码串完全失明
    let hex: String = "credit card number 4111111111111111"
        .bytes()
        .map(|b| format!("{:02x}", b))
        .collect();
    assert!(hex.len() >= 32, "测试样例需满足候选段下限");
    let text = format!("编码负载: {}", hex);
    let result = scan_text(&text);
    assert!(
        result.matches.contains(&"credit_card".to_string()),
        "hex 编码的卡号应解码后检出 credit_card"
    );
    assert!(
        result.matches.contains(&"encoded_sensitive_data".to_string()),
        "编码通道命中应附加 encoded_sensitive_data 归因标记"
    );
}

#[test]
fn test_encoded_view_jwt_no_false_positive() {
    // D1-2 反误报: 正常长 token (JWT 样例) 解码后无敏感模式, 不应误报
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c";
    let result = scan_text(jwt);
    assert!(
        result.matches.is_empty(),
        "正常 JWT 不应触发任何 DLP 类别: {:?}",
        result.matches
    );
}

// ─── B1: 命中量上限 / 合并复杂度 / wall-clock 预算 ─────────────────────

/// 按 GB 11643-1999 公开标准计算身份证校验位 (测试辅助, 生成真实合法的
/// 攻击语料: 校验位合法的 18 位号码, 非与实现同源生成的伪 token)。
fn gb11643_check_digit(first17: &str) -> char {
    const WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const CHECK_CHARS: [char; 11] = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];
    let sum: u32 = first17
        .bytes()
        .zip(WEIGHTS)
        .map(|(b, w)| u32::from(b - b'0') * w)
        .sum();
    CHECK_CHARS[(sum % 11) as usize]
}

/// 生成 `count` 个互异且校验位合法的身份证号 (区域码 110101 + 不同出生日期/顺序码)。
fn make_valid_ids(count: usize) -> Vec<String> {
    let mut ids = Vec::with_capacity(count);
    let mut serial: u32 = 0;
    while ids.len() < count {
        // 出生日期 + 顺序码都变化, 保证互异
        let day = (serial % 28) + 1;
        let month = (serial / 28) % 12 + 1;
        let year = 1950 + (serial / 336) % 60;
        let seq = serial % 1000;
        let first17 = format!("110101{:04}{:02}{:02}{:03}", year, month, day, seq);
        ids.push(format!("{}{}", first17, gb11643_check_digit(&first17)));
        serial += 1;
    }
    ids
}

#[test]
fn test_valid_ids_generator_produces_check_digit_valid_ids() {
    // 生成器自检: 抽样的确是校验位合法的真实格式号码
    let ids = make_valid_ids(8);
    for id in &ids {
        assert!(chinese_id_check(id), "生成器产出必须过校验: {id}");
    }
    let unique: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "生成器产出必须互异");
}

#[test]
fn test_dlp_hit_count_hard_cap_marks_truncated() {
    // B1 PoC (修复前可绕过): 正文塞入远超上限的互异合法身份证号。
    // 修复前: 全部收集进 Vec, 合并去重 O(n²), 无 truncated 概念;
    // 修复后: 每类别最多 DLP_MAX_MATCHES_PER_CATEGORY 条且置 truncated。
    let ids = make_valid_ids(DLP_MAX_MATCHES_PER_CATEGORY + 500);
    let text = ids.join("\n");
    let started = std::time::Instant::now();
    let result = scan_text(&text);
    let elapsed = started.elapsed();

    assert!(
        result.matches.contains(&"id_number".to_string()),
        "超上限命中仍应检出类别: {:?}",
        result.matches
    );
    let values = result
        .details
        .iter()
        .find(|(n, _)| n == "id_number")
        .map(|(_, v)| v.len())
        .unwrap_or(0);
    assert_eq!(
        values, DLP_MAX_MATCHES_PER_CATEGORY,
        "命中值必须截断到硬上限, 实际 {values}"
    );
    assert!(result.truncated, "超上限必须置 truncated 标记");
    assert!(
        elapsed.as_secs() < 30,
        "合并耗时必须可控 (HashSet 去重), 实际 {elapsed:?}"
    );
}

#[test]
fn test_dlp_hit_cap_spans_multiple_windows() {
    // B1 PoC: 命中分布跨多个 512KiB 扫描窗口, 合并路径也必须受上限约束。
    // (修复前 merge_dlp_results 的 Vec::contains 逐值线性扫描退化为 O(n²))
    let ids = make_valid_ids(DLP_MAX_MATCHES_PER_CATEGORY * 3);
    let padding = "填充段落。".repeat(600_000); // ~3MB, 强制分多窗
    let mut text = String::new();
    for (i, chunk) in ids.chunks(DLP_MAX_MATCHES_PER_CATEGORY).enumerate() {
        text.push_str(&chunk.join("\n"));
        text.push('\n');
        if i < 2 {
            text.push_str(&padding);
            text.push('\n');
        }
    }
    let started = std::time::Instant::now();
    let result = scan_text(&text);
    let elapsed = started.elapsed();

    let values = result
        .details
        .iter()
        .find(|(n, _)| n == "id_number")
        .map(|(_, v)| v.len())
        .unwrap_or(0);
    assert_eq!(values, DLP_MAX_MATCHES_PER_CATEGORY);
    assert!(result.truncated);
    assert!(
        elapsed.as_secs() < 30,
        "多窗合并耗时必须可控, 实际 {elapsed:?}"
    );
}

#[test]
fn test_dlp_under_cap_not_marked_truncated() {
    // 反误报护栏: 正常量级命中不得置 truncated
    let ids = make_valid_ids(5);
    let text = format!("员工身份证号: {}", ids.join(", "));
    let result = scan_text(&text);
    assert!(result.matches.contains(&"id_number".to_string()));
    assert!(!result.truncated, "未超上限不得置 truncated");
}

#[test]
fn test_merge_dlp_results_caps_and_dedups() {
    // 直接验证合并逻辑: 跨窗重叠命中去重 + 超上限截断
    let mut target = DlpScanResult::default();
    let mut src = DlpScanResult::default();
    src.matches.push("id_number".to_string());
    src.details.push((
        "id_number".to_string(),
        (0..1500).map(|i| format!("value_{i}")).collect(),
    ));
    merge_dlp_results(&mut target, src);
    let values = &target.details[0].1;
    assert_eq!(values.len(), DLP_MAX_MATCHES_PER_CATEGORY);
    assert!(target.truncated);

    // 同值重复合并不膨胀
    let mut target2 = DlpScanResult::default();
    for _ in 0..3 {
        let mut s = DlpScanResult::default();
        s.matches.push("id_number".to_string());
        s.details
            .push(("id_number".to_string(), vec!["same_value".to_string()]));
        merge_dlp_results(&mut target2, s);
    }
    assert_eq!(target2.details[0].1.len(), 1, "跨窗重复命中必须去重");
    assert!(!target2.truncated);
}
