//! Shared DLP (data) detect

//! ForSensitive Infomodematch: Card number, ID cardNumber, Mobile phoneNumber, BankCard number,,
//! email, Number, 1 Code/Digit,, SWIFT Code/Digit, CVV SecurityCode/Digit,
//! Number, IBAN BankAccount number, large Amount, BankAccount number(Context), / SameNumber.
//! mode content_scan ModuleMediumof1,Extract functionFordataSecurityModuleReuse.

//! Performance optimizations: Use `RegexSet` 1Time/Count, MediummodeExecutelineVerbosematch,
//! SensitivedataofText ~10x Add.

/// DLP matchfunction Verifyhandler.

/// PublicExport Test(property-based tests)Medium `luhn_check`,
/// `iban_mod97_check` wait functionofhintsTest.
pub mod finders;
mod normalize;
mod patterns;

use std::collections::HashSet;

use base64::Engine as _;
use finders::*;
use normalize::normalize_for_dlp;
use patterns::*;

// DLP Result

/// DLP Result
#[derive(Debug, Clone, Default)]
pub struct DlpScanResult {
    /// match ofSensitivedataTypeList
    pub matches: Vec<String>,
    /// match (Type -> matchvalueList)
    pub details: Vec<(String, Vec<String>)>,
    /// 命中量/耗时超上限, 结果为部分扫描产物 (B1)。
    ///
    /// 任一类别命中超过 `DLP_MAX_MATCHES_PER_CATEGORY` 或扫描超过
    /// wall-clock 预算时置位: 收集提前停止, 返回已确认的命中,
    /// 而不是无界膨胀堵塞检测通道。
    pub truncated: bool,
}

impl DlpScanResult {
    /// whether DLP Medium
    pub fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }

    /// Statistics JR/T 0197-2020 level ofmatch total

    /// `details` Medium modeofmatchInstance, Deduplicate ofmode Class.
    /// if:1 FileContains 30 Mobile phoneNumber(C3) + 5 CVV(C4),
    /// `count_items_at_level(3)` Return 35,`count_items_at_level(4)` Return 5.
    pub fn count_items_at_level(&self, min_level: u8) -> usize {
        self.details
            .iter()
            .filter(|(name, _)| crate::data_security::jrt::jrt_level(name) >= min_level)
            .map(|(_, values)| values.len())
            .sum()
    }

    /// According to JR/T level match Count

    /// Return (level -> item_count) Mapping, packetContains matchoflevel.
    pub fn items_by_jrt_level(&self) -> std::collections::HashMap<u8, usize> {
        let mut counts = std::collections::HashMap::new();
        for (name, values) in &self.details {
            let level = crate::data_security::jrt::jrt_level(name);
            if level > 0 {
                *counts.entry(level).or_insert(0) += values.len();
            }
        }
        counts
    }
}

/// 单窗扫描长度上限 (512 KiB)。
///
/// 分窗扫描的窗口大小：每个窗口独立 normalize + RegexSet 扫描，
/// 避免对超大 body 做一次性的全量归一化分配。
const DLP_MAX_SCAN_LEN: usize = 512 * 1024; // 512 KiB

/// 相邻窗口的重叠字节数，保证跨窗口边界的命中不被切断。
/// 覆盖最长的单条命中跨度：18 位身份证/16 位卡号按 `{0,2}`/`{0,4}` 分隔符
/// 分组书写时跨度可达 ~50-80 字符，256 字节提供充足余量。
const DLP_SCAN_OVERLAP: usize = 256;

/// 全文扫描总上限，跟随 body 临时文件读取上限 (50 MB)。
const DLP_MAX_TOTAL_SCAN_LEN: usize = super::MAX_TEMP_BODY_READ_BYTES;

/// 单类别命中值硬上限 (B1)。
///
/// 50MB 输入可构造数百万个互异且校验位合法的命中 (如身份证号):
/// 无上限时逐值收集 + 合并去重退化为 O(n²) 比较和数百 MB 分配,
/// 单会话即可永久堵住数据安全检测通道。finder 收集到 CAP+1 即停止
/// (留 1 个余量用于区分"恰好 CAP"与"被截断"), 合并时截断到 CAP 并置
/// `truncated` 标记。
pub(crate) const DLP_MAX_MATCHES_PER_CATEGORY: usize = 1000;

/// 单次 `scan_text` 调用的 wall-clock 预算 (B1)。
///
/// 调用方经 `spawn_blocking` 执行且不可取消 (data_security/engine.rs
/// run_detectors 串行 await), 必须代码内自查: 每个窗口扫描前检查一次,
/// 超预算返回已合并的 partial 结果并置 `truncated`。
const DLP_SCAN_TIME_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// 编码视图二级重扫 (D1-2): base64 候选段上限
const ENCODED_MAX_B64_SEGMENTS: usize = 20;
/// 编码视图二级重扫 (D1-2): hex 候选段上限
const ENCODED_MAX_HEX_SEGMENTS: usize = 10;
/// 编码视图二级重扫 (D1-2): 单段解码输入上限 (4 KiB)
const ENCODED_MAX_SEGMENT_LEN: usize = 4096;
/// 编码视图二级重扫 (D1-2): 单窗口解码总预算 (100 KB, 防 DoS)
const ENCODED_DECODE_BUDGET: usize = 100 * 1024;

// function (Use RegexSet Performance notes)

/// From HTTP SessionMediumExtractUsed for DLP ofText

/// Coremail compose.jsp of JSON body, Extract `attrs.content` + `attrs.subject`,
/// Avoid JSON Yuandata(id, CSS class name) match.
/// 非 Coremail URI 且 Content-Type 为 text/html 的 body 同样先剥标签再扫描,
/// 防止攻击者用 <span>/<style> 标签拆散身份证等敏感串绕过检测。
pub fn extract_dlp_text(body: &str, uri: &str, content_type: Option<&str>) -> String {
    // Checkwhether Coremail compose URI
    if super::coremail::is_coremail_compose_uri(uri)
        && let Some(content) = super::coremail::extract_content_for_dlp(body)
    {
        return content;
    }
    // 非 Coremail 的 text/html body: 剥掉标签/样式块后扫描
    let is_html = content_type
        .map(|ct| ct.to_ascii_lowercase().contains("text/html"))
        .unwrap_or(false);
    if is_html {
        let stripped = super::coremail::strip_html_tags(body);
        if !stripped.is_empty() {
            return stripped;
        }
    }
    // Coremail ExtractFailed,Return body
    body.to_string()
}

/// Extractuser: priority session.detected_user (Cookie),fallback Coremail JSON body of attrs.account
pub fn extract_user(session: &vigilyx_core::HttpSession) -> Option<String> {
    // priority Cookie Extractofuser
    if session.detected_user.is_some() {
        return session.detected_user.clone();
    }
    // Coremail compose URI -> From JSON body Extract attrs.account
    if super::coremail::is_coremail_compose_uri(&session.uri)
        && let Some(ref body) = session.request_body
    {
        return super::coremail::extract_user_from_body(body);
    }
    None
}

/// Text line DLP,ReturnmatchResult

/// 分窗扫描: 512 KiB 窗口 + 256 字节重叠, 覆盖全文 (总上限 50 MB),
/// 攻击者在头部填充大量无害文本无法再绕过尾部敏感数据检测。
/// 每个窗口独立 normalize, 避免对超大 body 做一次性全量归一化分配。
/// B1: 每类别命中值硬上限 `DLP_MAX_MATCHES_PER_CATEGORY` (超出截断并置
/// `truncated`), 窗口循环带 wall-clock 预算自查 (超预算返回 partial 结果)。
pub fn scan_text(text: &str) -> DlpScanResult {
    // Step 1: 总上限截断 (UTF-8 边界安全)
    let text = if text.len() > DLP_MAX_TOTAL_SCAN_LEN {
        let mut end = DLP_MAX_TOTAL_SCAN_LEN;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        &text[..end]
    } else {
        text
    };

    // Step 2: 分窗扫描并合并结果 (重叠区重复命中在合并时按值去重)
    // wall-clock 预算自查: spawn_blocking 不可取消, 超预算返回 partial 结果
    let scan_started = std::time::Instant::now();
    let mut merged = DlpScanResult::default();
    // Thresholding must use the distinct raw values, not the masked strings
    // exposed in `details`: every amount with the same unit is intentionally
    // rendered as `***<unit>` and would otherwise collapse to one value.
    let mut unique_large_amounts = HashSet::new();
    let mut start = 0usize;
    while start < text.len() {
        if scan_started.elapsed() > DLP_SCAN_TIME_BUDGET {
            merged.truncated = true;
            break;
        }
        // 窗口起点向前回退 OVERLAP 字节 (UTF-8 边界对齐), 覆盖跨窗口边界的命中
        let mut win_from = start.saturating_sub(DLP_SCAN_OVERLAP);
        while win_from > 0 && !text.is_char_boundary(win_from) {
            win_from -= 1;
        }
        let mut end = (start + DLP_MAX_SCAN_LEN).min(text.len());
        while end > start && !text.is_char_boundary(end) {
            end -= 1;
        }
        let (window_result, window_large_amounts) = scan_text_window(&text[win_from..end]);
        merge_dlp_results(&mut merged, window_result);
        for amount in window_large_amounts {
            if unique_large_amounts.len() >= DLP_MAX_MATCHES_PER_CATEGORY {
                merged.truncated = true;
                break;
            }
            unique_large_amounts.insert(amount);
        }
        start = end;
    }

    // Step 3: 计数阈值在合并后的全文结果上统一应用,
    // 避免手机号/邮箱/大金额实例被窗口边界拆散后达不到阈值
    apply_count_thresholds(&mut merged, unique_large_amounts.len());
    merged
}

/// 合并单窗结果到全文结果: 类别去重, 命中值按字符串去重 (B1)
///
/// 去重用 HashSet 而非逐值 `Vec::contains` 线性扫描 —— 原实现在命中量大时
/// 合并退化为 O(n²) (50MB 输入约 7×10^10 次比较)。每类别命中值硬上限
/// `DLP_MAX_MATCHES_PER_CATEGORY`, 超限停止合并并置 `truncated`。
fn merge_dlp_results(target: &mut DlpScanResult, src: DlpScanResult) {
    if src.truncated {
        target.truncated = true;
    }
    for (name, values) in src.details {
        let idx = match target.details.iter().position(|(n, _)| *n == name) {
            Some(i) => i,
            None => {
                target.details.push((name.clone(), Vec::new()));
                target.details.len() - 1
            }
        };
        let existing = &mut target.details[idx].1;
        let mut seen: HashSet<String> = existing.iter().cloned().collect();
        for v in values {
            if existing.len() >= DLP_MAX_MATCHES_PER_CATEGORY {
                target.truncated = true;
                break;
            }
            if seen.insert(v.clone()) {
                existing.push(v);
            }
        }
        if !target.matches.contains(&name) {
            target.matches.push(name);
        }
    }
}

/// 类别命中值硬上限收尾 (B1): finder 收集到 CAP+1 即停止, 此处截断到 CAP
/// 并置 `truncated` 标记。在单窗扫描出口统一执行, 覆盖全部类别。
fn enforce_category_caps(result: &mut DlpScanResult) {
    for (_, values) in &mut result.details {
        if values.len() > DLP_MAX_MATCHES_PER_CATEGORY {
            values.truncate(DLP_MAX_MATCHES_PER_CATEGORY);
            result.truncated = true;
        }
    }
}

/// 计数阈值: 手机号/邮箱需 >=3 个不同实例, 大金额需 >=2 个实例
fn apply_count_thresholds(result: &mut DlpScanResult, unique_large_amount_count: usize) {
    const MIN_UNIQUE: &[(&str, usize)] = &[
        ("phone_number", 3),
        ("email_address", 3),
        ("large_amount", 2),
    ];
    for &(name, min) in MIN_UNIQUE {
        let count = if name == "large_amount" {
            unique_large_amount_count
        } else {
            result
                .details
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.len())
                .unwrap_or(0)
        };
        if count > 0 && count < min {
            result.matches.retain(|m| m != name);
            result.details.retain(|(n, _)| n != name);
        }
    }
}

/// 单窗 DLP 扫描: normalize + 明文扫描 + 编码视图二级重扫
///
/// 返回原始命中 (不应用计数阈值), 阈值由 scan_text 在合并后统一应用。
fn scan_text_window(text: &str) -> (DlpScanResult, HashSet<String>) {
    // Normalize first (anti-evasion):
    // - Remove zero-width and invisible characters (such as U+200B/U+200C/U+200D/U+FEFF/U+00AD)
    // - Convert full-width characters to half-width equivalents (for example, Ａ -> A and ０ -> 0)
    let normalized = normalize_for_dlp(text);
    let mut unique_large_amounts = HashSet::new();
    let mut result = scan_plain_text(&normalized, &mut unique_large_amounts);
    // D1-2: base64/hex 编码视图二级重扫 (编码串明文扫描失明, 解码后复查明文管线)
    rescan_encoded_views(&normalized, &mut result, &mut unique_large_amounts);
    // B1: 每类别命中值硬上限收尾, 超限截断并置 truncated
    enforce_category_caps(&mut result);
    (result, unique_large_amounts)
}

/// 明文 DLP 扫描: RegexSet 一次预筛, 命中模式逐一精细匹配
///
/// 编码视图解码产物复用本函数 (不再递归编码重扫, 防止无限嵌套)。
fn scan_plain_text(text: &str, unique_large_amounts: &mut HashSet<String>) -> DlpScanResult {
    // RegexSet: 1Time/Count verdict modepossibly Medium
    let hits = DLP_REGEX_SET.matches(text);
    if !hits.matched_any() {
        return DlpScanResult::default();
    }

    let mut result = DlpScanResult::default();

    // Card number (idx 0) - Same Used forBank Deduplicate
    let cc_raw_digits = if hits.matched(0) {
        let (cc_matches, raw) = find_credit_cards(text);
        if !cc_matches.is_empty() {
            result.matches.push("credit_card".to_string());
            result.details.push(("credit_card".to_string(), cc_matches));
        }
        raw
    } else {
        HashSet::new()
    };

    // ID cardNumber (idx 1)
    if hits.matched(1) {
        let id_matches = find_chinese_ids(text);
        if !id_matches.is_empty() {
            result.matches.push("id_number".to_string());
            result.details.push(("id_number".to_string(), id_matches));
        }
    }

    // Mobile phoneNumber (idx 2) - 原始命中, >=3 不同号码阈值由 scan_text 合并后统一应用
    if hits.matched(2) {
        let phone_matches = find_chinese_phones(text);
        if !phone_matches.is_empty() {
            result.matches.push("phone_number".to_string());
            result
                .details
                .push(("phone_number".to_string(), phone_matches));
        }
    }

    // BankCard number (idx 3) - Excludealreadymatchof Card number (P1.1 Deduplicate)
    if hits.matched(3) {
        let bank_matches = find_bank_cards(text, &cc_raw_digits);
        if !bank_matches.is_empty() {
            result.matches.push("bank_card".to_string());
            result.details.push(("bank_card".to_string(), bank_matches));
        }
    }

    // (idx 4)
    if hits.matched(4) {
        let addr_matches = find_chinese_addresses(text);
        if !addr_matches.is_empty() {
            result.matches.push("customer_address".to_string());
            result
                .details
                .push(("customer_address".to_string(), addr_matches));
        }
    }

    // email (idx 5) - 原始命中, >=3 不同地址阈值由 scan_text 合并后统一应用
    if hits.matched(5) {
        let email_matches = find_emails(text);
        if !email_matches.is_empty() {
            result.matches.push("email_address".to_string());
            result
                .details
                .push(("email_address".to_string(), email_matches));
        }
    }

    // Number (idx 6)
    if hits.matched(6) {
        let passport_matches = find_passports(text);
        if !passport_matches.is_empty() {
            result.matches.push("passport_number".to_string());
            result
                .details
                .push(("passport_number".to_string(), passport_matches));
        }
    }

    // 1 Code/Digit (idx 7)
    if hits.matched(7) {
        let scc_matches = find_social_credit_codes(text);
        if !scc_matches.is_empty() {
            result.matches.push("social_credit_code".to_string());
            result
                .details
                .push(("social_credit_code".to_string(), scc_matches));
        }
    }

    // Password/ (idx 8)
    if hits.matched(8) {
        let cred_matches = find_credentials(text);
        if !cred_matches.is_empty() {
            result.matches.push("credential_leak".to_string());
            result
                .details
                .push(("credential_leak".to_string(), cred_matches));
        }
    }

    // SWIFT Code/Digit (idx 9)
    if hits.matched(9) {
        let swift_matches = find_swift_codes(text);
        if !swift_matches.is_empty() {
            result.matches.push("swift_code".to_string());
            result
                .details
                .push(("swift_code".to_string(), swift_matches));
        }
    }

    // CVV/SecurityCode/Digit (idx 10)
    if hits.matched(10) {
        let cvv_matches = find_cvv_codes(text);
        if !cvv_matches.is_empty() {
            result.matches.push("cvv_code".to_string());
            result.details.push(("cvv_code".to_string(), cvv_matches));
        }
    }

    // line Add

    // Number (idx 11)
    if hits.matched(11) {
        let tax_matches = find_tax_ids(text);
        if !tax_matches.is_empty() {
            result.matches.push("tax_id".to_string());
            result.details.push(("tax_id".to_string(), tax_matches));
        }
    }

    // IBAN BankAccount number (idx 12)
    if hits.matched(12) {
        let iban_matches = find_ibans(text);
        if !iban_matches.is_empty() {
            result.matches.push("iban".to_string());
            result.details.push(("iban".to_string(), iban_matches));
        }
    }

    // large Amount (idx 13) - 原始命中, >=2 实例阈值由 scan_text 合并后统一应用
    if hits.matched(13) {
        for amount in RE_LARGE_AMOUNT.find_iter(text) {
            if unique_large_amounts.len() >= DLP_MAX_MATCHES_PER_CATEGORY {
                result.truncated = true;
                break;
            }
            unique_large_amounts.insert(amount.as_str().to_lowercase());
        }
        let amount_matches = find_large_amounts(text);
        if !amount_matches.is_empty() {
            result.matches.push("large_amount".to_string());
            result
                .details
                .push(("large_amount".to_string(), amount_matches));
        }
    }

    // BankAccount number (Context) (idx 14)
    if hits.matched(14) {
        let acct_matches = find_bank_accounts(text);
        if !acct_matches.is_empty() {
            result.matches.push("bank_account".to_string());
            result
                .details
                .push(("bank_account".to_string(), acct_matches));
        }
    }

    // Policy number/ SameNumber (idx 15)
    if hits.matched(15) {
        let contract_matches = find_contract_numbers(text);
        if !contract_matches.is_empty() {
            result.matches.push("contract_number".to_string());
            result
                .details
                .push(("contract_number".to_string(), contract_matches));
        }
    }

    // JR/T 0197-2020 mode (idx 16-29)

    // (idx 16) - C4, At least 2 SameKeywords
    if hits.matched(16) {
        let matches = find_keyword_matches(&RE_BIOMETRIC, text, 2);
        if !matches.is_empty() {
            result.matches.push("biometric_data".to_string());
            result.details.push(("biometric_data".to_string(), matches));
        }
    }

    // (idx 17) - C4, At least 2 SameKeywords
    if hits.matched(17) {
        let matches = find_keyword_matches(&RE_MEDICAL, text, 2);
        if !matches.is_empty() {
            result.matches.push("medical_health".to_string());
            result.details.push(("medical_health".to_string(), matches));
        }
    }

    // Info (idx 18) - C3
    if hits.matched(18) {
        let matches = find_vehicle_info(text);
        if !matches.is_empty() {
            result.matches.push("vehicle_info".to_string());
            result.details.push(("vehicle_info".to_string(), matches));
        }
    }

    // Info (idx 19) - C3
    if hits.matched(19) {
        let matches = find_keyword_matches(&RE_PROPERTY, text, 1);
        if !matches.is_empty() {
            result.matches.push("property_info".to_string());
            result.details.push(("property_info".to_string(), matches));
        }
    }

    // / (idx 20) - C3
    if hits.matched(20) {
        let matches = find_context_matches(&RE_INCOME, text);
        if !matches.is_empty() {
            result.matches.push("income_info".to_string());
            result.details.push(("income_info".to_string(), matches));
        }
    }

    // bit / (idx 21) - C3
    if hits.matched(21) {
        let matches = find_context_matches(&RE_GEO, text);
        if !matches.is_empty() {
            result.matches.push("geo_location".to_string());
            result.details.push(("geo_location".to_string(), matches));
        }
    }

    // VerifyCode/Digit/OTP (idx 22) - C3
    if hits.matched(22) && !result.matches.contains(&"cvv_code".to_string()) {
        let matches = find_context_matches(&RE_OTP, text);
        if !matches.is_empty() {
            result.matches.push("otp_verification".to_string());
            result
                .details
                .push(("otp_verification".to_string(), matches));
        }
    }

    // / (idx 23) - C3
    if hits.matched(23) {
        let matches = find_context_matches(&RE_LOAN, text);
        if !matches.is_empty() {
            result.matches.push("loan_credit_info".to_string());
            result
                .details
                .push(("loan_credit_info".to_string(), matches));
        }
    }

    // (idx 24) - C3
    if hits.matched(24) {
        let matches = find_context_matches(&RE_INSURANCE, text);
        if !matches.is_empty() {
            result.matches.push("insurance_policy".to_string());
            result
                .details
                .push(("insurance_policy".to_string(), matches));
        }
    }

    // (idx 25) - C3
    if hits.matched(25) {
        let matches = find_context_matches(&RE_FAMILY, text);
        if !matches.is_empty() {
            result.matches.push("family_relation".to_string());
            result
                .details
                .push(("family_relation".to_string(), matches));
        }
    }

    // Info (idx 26) - C2
    if hits.matched(26) {
        let matches = find_context_matches(&RE_EMPLOYEE, text);
        if !matches.is_empty() {
            result.matches.push("employee_info".to_string());
            result.details.push(("employee_info".to_string(), matches));
        }
    }

    // Recording (idx 27) - C2, At least 2 SameKeywords
    if hits.matched(27) {
        let matches = find_keyword_matches(&RE_JUDICIAL, text, 2);
        if !matches.is_empty() {
            result.matches.push("judicial_record".to_string());
            result
                .details
                .push(("judicial_record".to_string(), matches));
        }
    }

    // Info (idx 28) - C2
    if hits.matched(28) {
        let matches = find_context_matches(&RE_EDUCATION, text);
        if !matches.is_empty() {
            result.matches.push("education_info".to_string());
            result.details.push(("education_info".to_string(), matches));
        }
    }

    // Execute Number (idx 29) - C2
    if hits.matched(29) {
        let matches = find_context_matches(&RE_BIZ_LICENSE, text);
        if !matches.is_empty() {
            result.matches.push("business_license".to_string());
            result
                .details
                .push(("business_license".to_string(), matches));
        }
    }

    result
}

/// 编码视图二级重扫 (D1-2)
///
/// 攻击者把身份证/卡号 base64 或 hex 编码后放入正文, 明文扫描对编码串完全失明。
/// 提取 base64/hex 候选段, 解码为文本后复用明文扫描管线 (scan_plain_text),
/// 命中时保留底层敏感类别 (severity 对齐同类) 并附加 `encoded_sensitive_data` 归因标记。
///
/// 防 DoS: base64 ≤20 段 / hex ≤10 段, 单段 ≤4 KiB, 单窗口解码总预算 ≤100 KB。
///
/// 注: 本通道有意不走 DLP_REGEX_SET 预筛 —— 预筛面向明文视图, 无法预见解码产物内容;
/// 解码段数量与预算都很小, 直接对解码产物做完整明文扫描代价可控。
fn rescan_encoded_views(
    text: &str,
    result: &mut DlpScanResult,
    unique_large_amounts: &mut HashSet<String>,
) {
    let mut budget = ENCODED_DECODE_BUDGET;

    // base64 候选段
    for m in RE_BASE64_CANDIDATE
        .find_iter(text)
        .take(ENCODED_MAX_B64_SEGMENTS)
    {
        if budget == 0 {
            break;
        }
        let segment = m.as_str();
        // 单段上限 4 KiB; 上限本身是 4 的倍数, 截断不会破坏 base64 量子对齐
        let segment = if segment.len() > ENCODED_MAX_SEGMENT_LEN {
            segment.get(..ENCODED_MAX_SEGMENT_LEN).unwrap_or(segment)
        } else {
            segment
        };
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(segment) else {
            continue; // base64url/截断残段等非法填充, 跳过
        };
        if bytes.len() > budget {
            break;
        }
        budget -= bytes.len();
        if let Some(decoded) = decoded_text(&bytes) {
            scan_decoded_view(&decoded, result, unique_large_amounts);
        }
    }

    // hex 候选段
    for m in RE_HEX_CANDIDATE
        .find_iter(text)
        .take(ENCODED_MAX_HEX_SEGMENTS)
    {
        if budget == 0 {
            break;
        }
        let segment = m.as_str();
        let hex = segment
            .strip_prefix("0x")
            .or_else(|| segment.strip_prefix("0X"))
            .unwrap_or(segment);
        // 单段上限 4 KiB; 上限本身是偶数, 截断不会留下半个字节
        let hex = if hex.len() > ENCODED_MAX_SEGMENT_LEN {
            hex.get(..ENCODED_MAX_SEGMENT_LEN).unwrap_or(hex)
        } else {
            hex
        };
        let Some(bytes) = decode_hex(hex) else {
            continue;
        };
        if bytes.len() > budget {
            break;
        }
        budget -= bytes.len();
        if let Some(decoded) = decoded_text(&bytes) {
            scan_decoded_view(&decoded, result, unique_large_amounts);
        }
    }
}

/// hex 字符串解码为字节 (奇数长度或非法字符拒绝)
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// 解码字节转文本: 严格 UTF-8 优先; 失败时仅当 ASCII 可打印占比 >=70%
/// 才 lossy 回退 (GBK 编码的中文上下文会丢失, 但卡号/身份证等 ASCII
/// 数字串仍可检出; 完整 GB18030 解码需新增 encoding_rs 依赖, 未做)。
/// 低 ASCII 占比的字节序列视为二进制 (哈希/密钥/图片), 跳过避免浪费扫描。
fn decoded_text(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8 {
        return None;
    }
    match String::from_utf8(bytes.to_vec()) {
        Ok(s) => Some(s),
        Err(_) => {
            let ascii = bytes
                .iter()
                .filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                .count();
            if ascii * 10 >= bytes.len() * 7 {
                Some(String::from_utf8_lossy(bytes).into_owned())
            } else {
                None
            }
        }
    }
}

/// 扫描单段解码产物: 明文扫描 + 合并结果 + 附加 encoded_sensitive_data 归因标记
fn scan_decoded_view(
    decoded: &str,
    result: &mut DlpScanResult,
    unique_large_amounts: &mut HashSet<String>,
) {
    let sub = scan_plain_text(decoded, unique_large_amounts);
    if sub.is_empty() {
        return;
    }
    let underlying: Vec<String> = sub.details.iter().map(|(n, _)| n.clone()).collect();
    merge_dlp_results(result, sub);
    // 归因标记: 底层敏感类别已合并 (severity 对齐同类), 此标记说明命中来自
    // 编码通道, 便于告警分析与审计
    let marker = "encoded_sensitive_data".to_string();
    if !result.matches.contains(&marker) {
        result.matches.push(marker.clone());
        result.details.push((marker.clone(), Vec::new()));
    }
    if let Some((_, values)) = result.details.iter_mut().find(|(n, _)| *n == marker) {
        for name in underlying {
            let tagged = format!("encoded:{name}");
            if !values.contains(&tagged) {
                values.push(tagged);
            }
        }
    }
}

#[cfg(test)]
mod tests;
