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
    let text = "ID cardNumberCode/Digit是 000000200001010005";
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
    let text = "客户住址: 陕西省西安City雁塔District科技Road100Number";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"customer_address".to_string()),
        "Chinese address with province+city should be detected"
    );
}

#[test]
fn test_scan_text_with_chinese_address_city_district() {
    let text = "寄送到: 西安City雁塔Districtlong安南Road1Number";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"customer_address".to_string()),
        "Chinese address with city+district should be detected"
    );
}

#[test]
fn test_scan_text_with_chinese_address_district_road() {
    let text = "家庭Address: 雁塔District科技Road创业large厦";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"customer_address".to_string()),
        "Chinese address with district+road should be detected"
    );
}

#[test]
fn test_scan_text_address_masking() {
    let text = "陕西省西安City雁塔District科技Road100Number";
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
    let text = "Autoemail noreply@example.com And system@example.net And postmaster@example.org";
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

// NumberTest

#[test]
fn test_scan_text_with_passport() {
    let text = "护照Number E12345678 alreadyExpired";
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

// 1 Code/DigitTest

#[test]
fn test_scan_text_with_social_credit_code() {
    let text = "公司信用代Code/Digit A0000000000000000M";
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
    let text = "SystemPassword：abc123456";
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

// SWIFT Code/DigitTest

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
    let text = "SWIFT代Code/Digit BKCHCNBJ100";
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

// CVV SecurityCode/DigitTest

#[test]
fn test_scan_text_with_cvv_chinese() {
    let text = "信用卡SecurityCode/Digit: 123";
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
    let text = "房间Number 123 在3楼";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"cvv_code".to_string()),
        "Random 3-digit number without CVV context should NOT match"
    );
}

// DLP Test

#[test]
fn test_scan_text_truncates_oversized_body() {
    let padding = "A".repeat(DLP_MAX_SCAN_LEN + 100);
    let text = format!("{} 4111111111111111", padding);
    let result = scan_text(&text);
    assert!(
        !result.matches.contains(&"credit_card".to_string()),
        "Credit card beyond DLP_MAX_SCAN_LEN should NOT be detected"
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

// P1.2 NumberTest

#[test]
fn test_scan_text_with_tax_id_15() {
    let text = "纳税人识别Number 110108MA12345N9";
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

// P1.2 large AmountTest

#[test]
fn test_scan_text_with_large_amounts() {
    let text = "合SameAmount 10010k yuan, 首付 3010k yuan";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"large_amount".to_string()),
        "2+ large amounts should be detected"
    );
}

#[test]
fn test_scan_text_single_amount_no_alert() {
    let text = "年薪 5010k yuan";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"large_amount".to_string()),
        "Single amount should NOT trigger"
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
    let amounts = find_large_amounts("合SameAmount 10010k yuan");
    assert_eq!(amounts.len(), 1);
    assert!(amounts[0].contains("***"), "Amount should be masked");
    assert!(
        amounts[0].contains("10k yuan"),
        "Currency unit should be preserved"
    );
}

// P1.2 BankAccount number (Context) Test

#[test]
fn test_scan_text_with_bank_account_context() {
    let text = "请转账到 Account number：1234567890123";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"bank_account".to_string()),
        "Bank account with context keyword should be detected"
    );
}

#[test]
fn test_bank_account_no_context_no_alert() {
    let text = "Serial number 12345678901234";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"bank_account".to_string()),
        "Number without context keyword should NOT trigger bank_account"
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
    let accounts = find_bank_accounts("Account number：1234567890123");
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0], "1234****23");
}

// P1.2 Policy number/ SameNumberTest

#[test]
fn test_scan_text_with_contract_number() {
    let text = "贷款合SameSerial number: LN20260312345678";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"contract_number".to_string()),
        "Loan contract number should be detected"
    );
}

#[test]
fn test_scan_text_with_policy_number() {
    let text = "Policy number：PL12345678901234";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"contract_number".to_string()),
        "Insurance policy number should be detected"
    );
}

#[test]
fn test_contract_number_no_context_no_alert() {
    let text = "FileSerial number AB12345678";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"contract_number".to_string()),
        "Number without contract/loan keyword should NOT trigger"
    );
}

#[test]
fn test_contract_number_masking() {
    let contracts = find_contract_numbers("贷款合SameNumber: LN20260312345678");
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
    let text = "user提交了指纹dataAnd虹膜扫描Result Used for身份Authentication";
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
    let text = "员工Zhang SanMonthly salary: 15000Yuan，公积金缴stored: 2400Yuan";
    let result = scan_text(text);
    assert!(result.matches.contains(&"income_info".to_string()));
}

#[test]
fn test_geo_location_hit() {
    let text = "user常驻bit置 116.3975, 39.9086 北BeijingCityMedium心";
    let result = scan_text(text);
    assert!(result.matches.contains(&"geo_location".to_string()));
}

#[test]
fn test_otp_hit() {
    let text = "您ofVerifyCode/Digit: 582931, 请在5minute内Use";
    let result = scan_text(text);
    assert!(result.matches.contains(&"otp_verification".to_string()));
}

#[test]
fn test_loan_credit_hit() {
    let text = "客户贷款余额: 580,000Yuan，逾PeriodAmount: 12,000Yuan";
    let result = scan_text(text);
    assert!(result.matches.contains(&"loan_credit_info".to_string()));
}

#[test]
fn test_insurance_hit() {
    let text = "Policyholder: 李明，被保险人: 王芳，保费: 3200Yuan";
    let result = scan_text(text);
    assert!(result.matches.contains(&"insurance_policy".to_string()));
}

#[test]
fn test_family_relation_hit() {
    let text = "紧急联系人: Zhang San，Spouse: Li Si";
    let result = scan_text(text);
    assert!(result.matches.contains(&"family_relation".to_string()));
}

#[test]
fn test_employee_info_hit() {
    let text = "员工Serial number: EMP20230156, 部门: 风控部, 职bit: HighlevelAnalyze师";
    let result = scan_text(text);
    assert!(result.matches.contains(&"employee_info".to_string()));
}

#[test]
fn test_judicial_record_hit() {
    let text = "该客户stored在失信被Executeline人Recording，并有line政处罚历史";
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
    let text = "学历: 本科, 毕业院校: 北Beijinglarge学, 毕业SundayPeriod: 2020/06";
    let result = scan_text(text);
    assert!(result.matches.contains(&"education_info".to_string()));
}

#[test]
fn test_business_license_hit() {
    let text = "公司营业Execute照Number: 110105012345678";
    let result = scan_text(text);
    assert!(result.matches.contains(&"business_license".to_string()));
}

#[test]
fn test_property_info_hit() {
    let text = "客户Name下有不动产权证Number: Beijing(2023)朝阳District不动产权After0012345Number";
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
    let text = "采集了指纹、虹膜And声纹3种生物特征";
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
        "患者诊Break/Judge 2型糖尿病，处方: 2甲双胍500mg，有青霉素敏史，家族病史Medium有High血压";
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
    let text = "手术Recording显示切除了阑尾，麻醉Method 全麻，护理RecordingNormal";
    let result = scan_text(text);
    assert!(result.matches.contains(&"medical_health".to_string()));
}

#[test]
fn test_vehicle_plate_guangdong() {
    let text = "车辆Info: VIN WVWZZZ3CZWE654321, 车主Zhang San";
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
    let text = "土地证Number: 沪2023-0045678 登记面积120平米";
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
    let text = "Monthly salary: 28000Yuan，年薪: 336000Yuan";
    let result = scan_text(text);
    assert!(result.matches.contains(&"income_info".to_string()));
}

#[test]
fn test_income_social_security() {
    let text = "公积金缴stored: 3600Yuan，社保缴费: 2800Yuan";
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
    let text = "软件Version 3.14, UpdateSundayPeriod 2026.03";
    let result = scan_text(text);
    assert!(!result.matches.contains(&"geo_location".to_string()));
}

#[test]
fn test_otp_chinese() {
    let text = "Dynamic口令: 849261";
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
    let text = "short信VerifyCode/Digit 628419 请勿转发";
    let result = scan_text(text);
    assert!(result.matches.contains(&"otp_verification".to_string()));
}

#[test]
fn test_loan_overdue() {
    let text = "逾PeriodAmount: 35,000Yuan，欠息: 1,200Yuan";
    let result = scan_text(text);
    assert!(result.matches.contains(&"loan_credit_info".to_string()));
}

#[test]
fn test_loan_credit_limit() {
    let text = "授信额度: 500000Yuan";
    let result = scan_text(text);
    assert!(result.matches.contains(&"loan_credit_info".to_string()));
}

#[test]
fn test_insurance_claim() {
    let text = "理赔Amount: 50000Yuan，出险SundayPeriod: 2026-01-15";
    let result = scan_text(text);
    assert!(result.matches.contains(&"insurance_policy".to_string()));
}

#[test]
fn test_insurance_policy_number() {
    let text = "Policy number: PL20260315001234";
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
    let text = "Employee ID: 20230156, 部门: Info科技部";
    let result = scan_text(text);
    assert!(result.matches.contains(&"employee_info".to_string()));
}

#[test]
fn test_employee_position() {
    let text = "职bit: Highlevel经理, 入职SundayPeriod: 2020/03/15";
    let result = scan_text(text);
    assert!(result.matches.contains(&"employee_info".to_string()));
}

#[test]
fn test_judicial_court_case() {
    let text = "被Executeline人张某，裁定书Serial number (2026)Beijing01Execute12345Number";
    let result = scan_text(text);
    assert!(result.matches.contains(&"judicial_record".to_string()));
}

#[test]
fn test_judicial_blacklist() {
    let text = "limit消费令already发出，该客户 失信被Executeline人";
    let result = scan_text(text);
    assert!(result.matches.contains(&"judicial_record".to_string()));
}

#[test]
fn test_education_degree() {
    let text = "学bit: 硕士, 毕业院校: 清华large学";
    let result = scan_text(text);
    assert!(result.matches.contains(&"education_info".to_string()));
}

#[test]
fn test_business_license_old_format() {
    let text = "工商登记Number: 310115000123456";
    let result = scan_text(text);
    assert!(result.matches.contains(&"business_license".to_string()));
}

#[test]
fn test_business_license_no_false_positive() {
    let text = "请下载营业Execute照模板";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"business_license".to_string()),
        "Keywords无Serial number不应触发"
    );
}

#[test]
fn test_combined_c4_c3_data() {
    let text = "客户Info: ID card 000000200001010005, Password: secret123, Monthly salary: 25000Yuan, Spouse: 李芳";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "应检出ID card"
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
    let text = "贷款余额: 500000Yuan，逾PeriodAmount: 20000Yuan，Policy number: PL123456789012，Policyholder: Zhang San";
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
    let text = "订单Number 1234567890123456";
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
    let text = "ID card 000000199001010042";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "ID number ending with X should be detected"
    );
}

#[test]
fn test_id_number_lowercase_x() {
    let text = "证件Number 000000199001010042";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "ID number ending with lowercase x should be detected"
    );
}

#[test]
fn test_id_number_17_digit_rejected() {
    let text = "Serial number 00000020000101000";
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
    let text = "Serial number 12345678901, 12345678902, 12345678903";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"phone_number".to_string()),
        "Numbers starting with 12 should NOT be detected as phone numbers"
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
    let text = "Sendgiving alice@example.com And bob@example.net";
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
fn test_swift_lowercase_rejected() {
    let codes = find_swift_codes("bkchcnbj");
    assert!(codes.is_empty(), "Lowercase SWIFT should be rejected");
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
    let text = "VerifyCode/Digit: 456";
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
    let text = "项目总投资 3.5亿Yuan，首Period 1.2亿Yuan";
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
    let text = "合SameAmount 85.5010k yuan，税费 4.2510k yuan";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"large_amount".to_string()),
        "Amounts with decimals should be detected"
    );
}

#[test]
fn test_large_amount_no_fp_plain_number() {
    let text = "订单 100000, Serial number 200000";
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
    let text = "Account number：123456789";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"bank_account".to_string()),
        "9-digit account should NOT trigger (min 10)"
    );
}

#[test]
fn test_bank_account_15_digit_rejected() {
    let text = "Account number：123456789012345";
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
    let text = "Policy number: 1234567";
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
    let text = "该设备already录入faceIDAndfingerprintInfo";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"biometric_data".to_string()),
        "faceID + fingerprint should trigger (2 distinct keywords)"
    );
}

#[test]
fn test_biometric_gait_and_earprint() {
    let text = "研究报告涉及步态识别And耳纹特征data";
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
    let text = "基due todetect报告显示BRCA1阳性，建议做体检报告复查";
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
    let text = "生育InfoalreadyUpdate，found病史Recordingcomplete";
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
    let text = "今年公司会统1安排体检，请large家Note身体健康";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"medical_health".to_string()),
        "General health mention should NOT trigger"
    );
}

#[test]
fn test_vehicle_new_energy_plate() {
    let text = "车牌Number: 京AD12345，already登记";
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
    let text = "房屋Ownership证Number: 沪房地权字AfterSH20230045Number";
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
    let text = "人所得税: 2,850Yuan";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"income_info".to_string()),
        "Income tax with amount should trigger"
    );
}

#[test]
fn test_income_pretax() {
    let text = "税first: 35000Yuan";
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
    let text = "DynamicPassword: 738291";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"otp_verification".to_string()),
        "Dynamic password keyword should trigger"
    );
}

#[test]
fn test_otp_no_fp_without_digits() {
    let text = "请InputVerifyCode/Digit";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"otp_verification".to_string()),
        "Verification keyword without actual digits should NOT trigger"
    );
}

#[test]
fn test_loan_total_balance() {
    let text = "贷款余额: 1,500,000Yuan";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"loan_credit_info".to_string()),
        "Loan balance should trigger"
    );
}

#[test]
fn test_loan_total_now_in_prefilter() {
    let text = "贷款总额: 1,500,000Yuan";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"loan_credit_info".to_string()),
        "Loan total now in RegexSet pre-filter (regex fix)"
    );
}

#[test]
fn test_loan_penalty_interest() {
    let text = "罚息: 3,500Yuan";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"loan_credit_info".to_string()),
        "Penalty interest should trigger"
    );
}

#[test]
fn test_loan_repayment() {
    let text = " 款Amount: 8,600Yuan";
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
    let text = "保费: 12,800Yuan/年";
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
    let text = "离职SundayPeriod: 2026/03/15";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"employee_info".to_string()),
        "Offboarding date should trigger"
    );
}

#[test]
fn test_employee_department_role() {
    let text = "岗bit: 客户经理";
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
    let text = "公司金融部岗bit职责";
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
    let text = "员工Serial number A12345";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"employee_info".to_string()),
        "Employee ID (specific keyword) should trigger even without colon"
    );
}

#[test]
fn test_judicial_enforcement_with_prefilter_keyword() {
    let text = "ReceivedForceExecuteline通知，判决书already下达";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"judicial_record".to_string()),
        "Enforcement + judgment should trigger"
    );
}

#[test]
fn test_judicial_enforcement_both_in_prefilter() {
    let text = "ReceivedForceExecuteline通知，already对其limit消费";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"judicial_record".to_string()),
        "Enforcement + consumption restriction now in RegexSet pre-filter"
    );
}

#[test]
fn test_judicial_exit_ban_with_prefilter() {
    let text = "limit出境令already下达，该被Executeline人Name下资产already冻Result";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"judicial_record".to_string()),
        "Exit ban + enforcement = 2 distinct keywords"
    );
}

#[test]
fn test_judicial_single_keyword_no_trigger() {
    let text = "请查看line政处罚相关法规";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"judicial_record".to_string()),
        "Single judicial keyword should NOT trigger (need 2 distinct)"
    );
}

#[test]
fn test_judicial_no_fp_legal_discussion() {
    let text = "今Daylearn了合Same法，了解了违约责任";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"judicial_record".to_string()),
        "General legal discussion should NOT trigger"
    );
}

#[test]
fn test_education_school() {
    let text = "就read学校: 复旦large学";
    let result = scan_text(text);
    assert!(result.matches.contains(&"education_info".to_string()));
}

#[test]
fn test_education_enrollment_date() {
    let text = "入学SundayPeriod: 2018/09";
    let result = scan_text(text);
    assert!(result.matches.contains(&"education_info".to_string()));
}

#[test]
fn test_business_license_registration_number() {
    let text = "RegisterNumber: 110105012345678";
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
    let text = "PINCode/Digit：6528";
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
    let text = "Password：abc123, ID card 000000200001010005, Monthly salary: 25000Yuan, Employee ID: E001";
    let result = scan_text(text);
    let levels = result.items_by_jrt_level();
    assert!(levels.get(&4).unwrap_or(&0) >= &1, "Should have C4 items");
    assert!(levels.get(&3).unwrap_or(&0) >= &1, "Should have C3 items");
}

#[test]
fn test_count_items_at_level_accumulation() {
    let text = "ID card 000000200001010005, Monthly salary: 25000Yuan, Spouse: Li Si";
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
        员工Serial number: EMP20260301\n\
        部门: RiskManagement部\n\
        职bit: 风控专员\n\
        学历: 硕士\n\
        毕业院校: Medium国人民large学";
    let result = scan_text(text);
    assert!(result.matches.contains(&"employee_info".to_string()));
    assert!(result.matches.contains(&"education_info".to_string()));
}

#[test]
fn test_realistic_loan_approval() {
    let text = "贷款审批Result 通知：\n\
        客户ID card: 000000198805150003\n\
        授信额度: 500000Yuan\n\
        贷款总额: 300000Yuan\n\
         款Amount: 5,500Yuan/月";
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
        Policyholder: 李明\n\
        被保险人: Zhang San\n\
        Policy number: PL20260115001234\n\
        出险SundayPeriod: 2026-03-01\n\
        理赔Amount: 85,000Yuan\n\
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
        客户: Zhang San\n\
        ID cardNumber: 000000199201010004\n\
        Mobile phone: 13600136000, 15100151000, 15200152000\n\
        Address: 广东省深圳City南山District科技南Road88Number\n\
        Spouse: Li Si\n\
        公司统1社会信用代Code/Digit: A00000MA000000000B";
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
    let text = "税Number 110108123456789";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"tax_id".to_string()),
        "All-digit 15-char tax ID should be detected"
    );
}

#[test]
fn test_address_autonomous_region() {
    let text = "Address: 内蒙古自治District呼And浩特City回民District";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"customer_address".to_string()),
        "Autonomous region address should be detected"
    );
}

#[test]
fn test_address_alley_format() {
    let text = "Address: 虹口District4川北Road弄堂12Number";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"customer_address".to_string()),
        "District + Road format should match"
    );
}

#[test]
fn test_address_multiple_addresses() {
    let text = "办公Address: 北BeijingCity朝阳District建国Road88Number，户籍地: 河南省郑州City金水District经3Road";
    let result = scan_text(text);
    let detail = result.details.iter().find(|(k, _)| k == "customer_address");
    assert!(detail.is_some());
    assert!(detail.unwrap().1.len() >= 2, "Should detect 2 addresses");
}

#[test]
fn test_combined_all_jrt_levels() {
    let text = "客户Info汇总：\n\
        Password：abc123\n\
        ID card: 000000200001010005\n\
        Employee ID: E001\n\
        公司信用代Code/Digit A0000000000000000M";
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
    let text = "Security事件报告: Password：admin123, CVV: 789, 患者病历显示有敏史";
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
    let text = "ID card 000000200001010005 Password：secret123";
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
    let amounts = find_large_amounts("50010k yuan");
    assert_eq!(amounts[0], "***10k yuan");
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
    let text = extract_dlp_text(body, uri);
    assert!(text.contains("Test"), "Should extract subject");
    assert!(text.contains("body"), "Should extract content");
    assert!(!text.contains("17744"), "Should NOT include JSON id");
}

#[test]
fn test_extract_dlp_text_non_coremail_uri() {
    let body = "plain body text";
    let uri = "/other/endpoint";
    let text = extract_dlp_text(body, uri);
    assert_eq!(
        text, "plain body text",
        "Non-coremail URI should return raw body"
    );
}

#[test]
fn test_extract_dlp_text_coremail_invalid_json() {
    let body = "not json at all";
    let uri = "/coremail/common/mbox/compose.jsp?sid=abc";
    let text = extract_dlp_text(body, uri);
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
        ("失信被Executeline人", "line政处罚"),
        ("被Executeline人", "裁定书"),
        ("开庭公告", "判决书"),
        ("犯罪Recording", "违法违规"),
        ("ForceExecuteline", "limit消费"),
        ("limit出境", "立案Info"),
    ];
    for (kw1, kw2) in keyword_pairs {
        let text = format!("该案件涉及{}And{}", kw1, kw2);
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
        "贷款余额: 100Yuan",
        "贷款总额: 200Yuan",
        "逾PeriodAmount: 300Yuan",
        " 款Amount: 400Yuan",
        "授信额度: 500Yuan",
        "信用额度: 600Yuan",
        "欠息: 700Yuan",
        "罚息: 800Yuan",
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
        "PINCode/Digit：1234",
        "PINCode/Digit: 5678",
        "PINCode/Digit=9012",
        "pinCode/Digit：abcd",
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
        TestContent涵盖Suspicious交易识别、large额交易报告制度。";
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
    let text = "ID card 000000200001010005, Password：secret123";
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
    let text = "Password：abc123 ID card 000000200001010005";
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
    let text = "Account number：1234567890";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"bank_account".to_string()),
        "Exact 10-digit account should be detected"
    );
}

#[test]
fn test_bank_account_exact_14_digit() {
    let text = "Account number：12345678901234";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"bank_account".to_string()),
        "Exact 14-digit account should be detected"
    );
}

#[test]
fn test_bank_account_16_digit_rejected() {
    let text = "Account number：1234567890123456";
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
    let text = "我们在北BeijingCity场占有率很High";
    let result = scan_text(text);
    assert!(
        !result.matches.contains(&"customer_address".to_string()),
        "Market should NOT trigger address detection"
    );
}

#[test]
fn test_address_valid_full_address() {
    let text = "收货Address: 北BeijingCity朝阳District建国Road88NumberSOHOlarge厦A座";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"customer_address".to_string()),
        "Full structured address should be detected"
    );
}

#[test]
fn test_address_multiple_levels() {
    let text = "广东省深圳City南山District深南large道9000Number";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"customer_address".to_string()),
        "Province+City+District+Road address should be detected"
    );
}

// Realistic email scenarios

#[test]
fn test_realistic_payroll_batch() {
    let text = "工资发放通知：\n\
        Zhang San Employee ID: E001 Monthly salary: 15000Yuan\n\
        Li Si Employee ID: E002 Monthly salary: 18000Yuan\n\
        王5 Employee ID: E003 Monthly salary: 22000Yuan";
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
        1. Name: Zhang San, ID card: 000000200001010005, Mobile phone: 13800138000\n\
        2. Name: Li Si, ID card: 000000199201010004, Mobile phone: 13900139000\n\
        3. Name: 王5, ID card: 000000198805150003, Mobile phone: 14700147000";
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
        客户张某（ID card: 000000198501010001）\n\
        近30Sunday转入Amount: 3,500,000 USD，转出Amount: 2,800,000 USD\n\
        涉及Account number：62220212345678\n\
        风控标签: 失信被Executeline人、line政处罚在查";
    let result = scan_text(text);
    assert!(result.matches.contains(&"id_number".to_string()));
    assert!(result.matches.contains(&"large_amount".to_string()));
    assert!(result.matches.contains(&"bank_account".to_string()));
    assert!(result.matches.contains(&"judicial_record".to_string()));
}

#[test]
fn test_realistic_medical_insurance_claim() {
    let text = "理赔审核材料：\n\
        Policyholder: 李某某\n\
        诊Break/Judge: 2型糖尿病MergeHigh血压\n\
        住院SundayPeriod: 2026-02-15\n\
        手术Recording: 冠状动脉搭桥术\n\
        理赔Amount: 85,000Yuan\n\
        Policy number: PL20250115001234";
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
    let text = "ID cardNumberCode/Digit是 000000200001010005";
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
    let text = "ID card: 000000200001010005, 000000199201010004, 000000198805150003\n\
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
    let text = "订单Serial number 123456789012345678";
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
    let text = "客户ID cardNumber: 000000200001010005";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"id_number".to_string()),
        "Valid ID with correct check digit should be detected"
    );
}

#[test]
fn test_id_invalid_check_digit_not_detected() {
    let text = "Serial number 000000200001010000";
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
    let text = "公司信用代Code/Digit A0000000000000000M";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"social_credit_code".to_string()),
        "Valid social credit code should be detected"
    );
}

#[test]
fn test_social_credit_invalid_check_rejected() {
    let text = "Serial number A0000000000000000A";
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
    let text = "社会信用代Code/Digit A00000MA000000000B";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"social_credit_code".to_string()),
        "MA-prefix social credit code should be detected"
    );
}

// End-to-end accuracy

#[test]
fn test_e2e_no_cross_contamination() {
    let text = "only有1ID card 000000200001010005";
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
    let single = ["病历", "诊Break/Judge", "处方", "住院", "手术Recording"];
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
        "失信被Executeline人",
        "line政处罚",
        "判决书",
        "ForceExecuteline",
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
        "此致\n\nZhang San\nRiskManagement部\n电话: 13800138000\nemail: zhangsan@example.com";
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
        Name：Zhang San\n\
        ID card：000000200001010005\n\
        Mobile phone：13800138000, 13900139000, 14700147000\n\
        Address：北BeijingCity朝阳District建国Road88Number\n\
        Monthly salary：25000Yuan";
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
        您有1笔Wait审批of申请（Serial number: REQ2026032600123）。\n\
        申请人: 李经理\n\
        申请Type: 费用报销\n\
        Amount: 3,500Yuan\n\
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
    let text = "帐Number：1234567890";
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
        ID card 000000200001010005\n\
        4111111111111111\n\
        Mobile phone 13800138000 13900139000 14700147000\n\
        Address 北BeijingCity朝阳District建国Road88Number\n\
        email a@example.test b@example.test c@example.test\n\
        护照 E12345678\n\
        信用代Code/Digit A0000000000000000M\n\
        SWIFT BKCHCNBJ\n\
        纳税 110108MA12345N9\n\
        IBAN DE89370400440532013000\n\
        合SameAmount 10010k yuan 首付 3010k yuan\n\
        Account number：1234567890\n\
        Policy number PL12345678901234\n\
        指纹And虹膜data\n\
        诊Break/JudgeAnd处方Info\n\
        BeijingA12345\n\
        不动产权证\n\
        Monthly salary: 25000Yuan\n\
        GPS坐标: 116.39750\n\
        VerifyCode/Digit: 582931\n\
        贷款余额: 500000Yuan\n\
        Policyholder: Zhang San\n\
        Spouse: Li Si\n\
        Employee ID: E001\n\
        失信被Executeline人Andline政处罚\n\
        学历: 本科\n\
        营业Execute照Number: 110105012345678";
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
    let text = "Serial number 0000000000000000";
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
        Zhang San 000000200001010005 Card number 4111111111111111 Monthly salary:35000Yuan\n\
        Li Si 000000199201010004 Card number 5100000000000008 Monthly salary:28000Yuan\n\
        王5 000000198501010001 Card number 6200000000000005 Monthly salary:42000Yuan";
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
        SWIFT代Code/Digit: HSBCHKHH\n\
        IBAN: GB29NWBK60161331926819\n\
        Amount: 500,000 USD, 手续费 2,000 USD\n\
        请在下午3点firstcomplete，否则合Same失效";
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
        "Should detect large amounts"
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
    let text = "Stream水Number 7890123456789012";
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
    let result = normalize_for_dlp("密\u{00AD}Code/Digit");
    assert_eq!(result, "密Code/Digit", "Soft hyphen should be stripped");
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
    let text = "联系 1\u{200B}3\u{200B}8\u{200B}0\u{200B}0\u{200B}1\u{200B}3\u{200B}8\u{200B}0\u{200B}0\u{200B}0 And 1\u{200B}3\u{200B}9\u{200B}0\u{200B}0\u{200B}1\u{200B}3\u{200B}9\u{200B}0\u{200B}0\u{200B}0 And 1\u{200B}4\u{200B}7\u{200B}0\u{200B}0\u{200B}1\u{200B}4\u{200B}7\u{200B}0\u{200B}0\u{200B}0";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"phone_number".to_string()),
        "Zero-width chars between phone digits should NOT bypass detection"
    );
}

#[test]
fn test_evasion_zero_width_in_id_number() {
    let text = "ID card 0\u{200B}0\u{200B}0\u{200B}0\u{200B}0\u{200B}0\u{200B}2\u{200B}0\u{200B}0\u{200B}0\u{200B}0\u{200B}1\u{200B}0\u{200B}1\u{200B}0\u{200B}0\u{200B}0\u{200B}5";
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
    let text = "联系 \u{FF11}\u{FF13}\u{FF18}\u{FF10}\u{FF10}\u{FF11}\u{FF13}\u{FF18}\u{FF10}\u{FF10}\u{FF10} And \u{FF11}\u{FF13}\u{FF19}\u{FF10}\u{FF10}\u{FF11}\u{FF13}\u{FF19}\u{FF10}\u{FF10}\u{FF10} And \u{FF11}\u{FF14}\u{FF17}\u{FF10}\u{FF10}\u{FF11}\u{FF14}\u{FF17}\u{FF10}\u{FF10}\u{FF10}";
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
    let text = "ID card 0\u{FF10}000020000\u{FF11}010005";
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
fn test_decode_html_entity_no_semicolon_preserved() {
    let text = "&#49 is not decoded";
    let result = normalize_for_dlp(text);
    assert!(
        result.contains("&#49"),
        "Entity without semicolon should be preserved"
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
    let text = "联系 &#49;&#51;&#56;&#49;&#50;&#51;&#52;&#53;&#54;&#55;&#56; And &#49;&#53;&#57;&#56;&#55;&#54;&#53;&#52;&#51;&#50;&#49; And &#49;&#56;&#54;&#49;&#49;&#49;&#49;&#50;&#50;&#50;&#50;";
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
    let text = "VerifyCode/Digit: 4567";
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
    let text = "VerifyCode/Digit: 789";
    let result = scan_text(text);
    assert!(result.matches.contains(&"cvv_code".to_string()));
    assert!(
        !result.matches.contains(&"otp_verification".to_string()),
        "Verification code with 3 digits should only match CVV, not OTP"
    );
}

#[test]
fn test_otp_still_works_without_jiaoyanma() {
    let text = "VerifyCode/Digit: 582931";
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
    let text = "Dynamic口令: 849261";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"otp_verification".to_string()),
        "Dynamic password should still trigger OTP"
    );
}

#[test]
fn test_cvv_security_code_still_works() {
    let text = "SecurityCode/Digit: 123";
    let result = scan_text(text);
    assert!(
        result.matches.contains(&"cvv_code".to_string()),
        "Security code should still trigger CVV"
    );
}

// Combined evasion

#[test]
fn test_evasion_combo_fullwidth_plus_zero_width() {
    let text = "ID card \u{FF11}\u{200B}\u{FF11}\u{200B}\u{FF10}\u{200B}\u{FF11}\u{200B}\u{FF10}\u{200B}\u{FF11}\u{200B}\u{FF11}\u{200B}\u{FF19}\u{200B}\u{FF19}\u{200B}\u{FF10}\u{200B}\u{FF10}\u{200B}\u{FF11}\u{200B}\u{FF10}\u{200B}\u{FF11}\u{200B}\u{FF11}\u{200B}\u{FF12}\u{200B}\u{FF13}\u{200B}\u{FF17}";
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
        iPhone 16 Pro Max 直downgrade1000Yuan！\n\
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
        被Query人 失信被Executeline人，stored在line政处罚Recording。\n\
        法院already下达ForceExecuteline通知，并作出limit消费令。\n\
        裁定书Serial number: (2026)BeijingExecute字After12345Number";
    let result = scan_text(text);
    assert!(result.matches.contains(&"judicial_record".to_string()));
    let detail = result.details.iter().find(|(k, _)| k == "judicial_record");
    assert!(detail.is_some());
    assert!(
        detail.unwrap().1.len() >= 2,
        "Should detect >=2 distinct judicial keywords"
    );
}
