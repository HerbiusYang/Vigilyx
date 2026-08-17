//! ContentdetectModule - emailbodyMediumofPhishingKeywords, BEC modeAndSensitivedata

mod detectors;
pub(crate) mod html_utils;

use std::collections::HashSet;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock, Mutex};

use aho_corasick::AhoCorasick;
use unicode_normalization::UnicodeNormalization;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::module_data::module_data;

// KeywordsoverrideType (For API Andfirst Use)

/// KeywordsClassificationofoverrideConfiguration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeywordCategoryOverride {
    /// userAdd newofKeywords
    #[serde(default)]
    pub added: Vec<String>,
    /// FromSystem Medium ofKeywords
    #[serde(default)]
    pub removed: Vec<String>,
}

/// KeywordsClassificationofoverrideConfiguration (store DB config table, key = "keyword_overrides")
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeywordOverrides {
    #[serde(default)]
    pub phishing_keywords: KeywordCategoryOverride,
    #[serde(default)]
    pub weak_phishing_keywords: KeywordCategoryOverride,
    #[serde(default)]
    pub bec_phrases: KeywordCategoryOverride,
    #[serde(default)]
    pub internal_authority_phrases: KeywordCategoryOverride,
    #[serde(default)]
    pub gateway_banner_patterns: KeywordCategoryOverride,
    #[serde(default)]
    pub notice_banner_patterns: KeywordCategoryOverride,
    #[serde(default)]
    pub dsn_patterns: KeywordCategoryOverride,
    #[serde(default)]
    pub auto_reply_patterns: KeywordCategoryOverride,
}

#[derive(Debug, Clone, Default)]
pub struct EffectiveKeywordLists {
    pub phishing_keywords: Vec<String>,
    pub weak_phishing_keywords: Vec<String>,
    pub bec_phrases: Vec<String>,
    pub internal_authority_phrases: Vec<String>,
    pub gateway_banner_patterns: Vec<String>,
    pub notice_banner_patterns: Vec<String>,
    pub dsn_patterns: Vec<String>,
    pub auto_reply_patterns: Vec<String>,
}

fn fold_common_confusable(ch: char) -> char {
    match ch {
        // Cyrillic and Greek letters commonly used in mixed-script phishing text.
        'А' | 'Α' => 'A',
        'В' | 'Β' => 'B',
        'Е' | 'Ε' => 'E',
        'З' | 'Ζ' => 'Z',
        'Н' | 'Η' => 'H',
        'І' | 'Ι' => 'I',
        'К' | 'Κ' => 'K',
        'М' | 'Μ' => 'M',
        'О' | 'Ο' => 'O',
        'Р' | 'Ρ' => 'P',
        'С' => 'C',
        'Т' | 'Τ' => 'T',
        'У' | 'Υ' => 'Y',
        'Х' | 'Χ' => 'X',
        'а' | 'α' => 'a',
        'е' | 'є' => 'e',
        'і' | 'ι' => 'i',
        'ј' => 'j',
        'к' | 'κ' => 'k',
        'о' | 'ο' => 'o',
        'р' | 'ρ' => 'p',
        'с' => 'c',
        'т' | 'τ' => 't',
        'у' | 'υ' => 'y',
        'х' | 'χ' => 'x',
        'ѕ' => 's',
        'ӏ' => 'l',
        // CJK lenticular/white brackets have no NFKC decomposition; gateways
        // wrap banner tags in them ("【外部邮件】"), so fold before stripping.
        '\u{3010}' | '\u{3016}' => '[',
        '\u{3011}' | '\u{3017}' => ']',
        _ => ch,
    }
}

/// Fold the high-frequency Traditional Chinese forms used in account,
/// credential and payment lures to the Simplified forms used by the canonical
/// keyword seed.  This is intentionally a one-way detector normalization: it
/// does not rewrite displayed evidence or persisted message content.  The
/// table covers the security vocabulary and common connective characters that
/// appear in real Hong Kong/Taiwan phishing prose; it is kept local and
/// deterministic so the inline path has no language-service dependency.
fn fold_traditional_chinese(ch: char) -> char {
    match ch {
        '親' => '亲',
        '愛' => '爱',
        '帳' => '账',
        '戶' => '户',
        '統' => '统',
        '偵' => '侦',
        '測' => '测',
        '異' => '异',
        '請' => '请',
        '點' => '点',
        '擊' => '击',
        '驗' => '验',
        '證' => '证',
        '認' => '认',
        '過' => '过',
        '號' => '号',
        '碼' => '码',
        '關' => '关',
        '閉' => '闭',
        '開' => '开',
        '啟' => '启',
        '動' => '动',
        '處' => '处',
        '訪' => '访',
        '問' => '问',
        '網' => '网',
        '絡' => '络',
        '郵' => '邮',
        '電' => '电',
        '對' => '对',
        '於' => '于',
        '當' => '当',
        '現' => '现',
        '時' => '时',
        '與' => '与',
        '為' => '为',
        '這' => '这',
        '個' => '个',
        '該' => '该',
        '狀' => '状',
        '態' => '态',
        '發' => '发',
        '聯' => '联',
        '繫' => '系',
        '員' => '员',
        '訂' => '订',
        '閱' => '阅',
        '讀' => '读',
        '準' => '准',
        '備' => '备',
        '資' => '资',
        '單' => '单',
        '貨' => '货',
        '轉' => '转',
        '銀' => '银',
        '預' => '预',
        '領' => '领',
        '業' => '业',
        '務' => '务',
        '環' => '环',
        '檢' => '检',
        '尋' => '寻',
        '註' => '注',
        '冊' => '册',
        '設' => '设',
        '變' => '变',
        '復' => '复',
        '還' => '还',
        '門' => '门',
        '書' => '书',
        '報' => '报',
        '應' => '应',
        '詐' => '诈',
        '騙' => '骗',
        '釣' => '钓',
        '魚' => '鱼',
        '惡' => '恶',
        '脅' => '胁',
        '盜' => '盗',
        '竊' => '窃',
        '錄' => '录',
        '識' => '识',
        '別' => '别',
        '級' => '级',
        '簡' => '简',
        '體' => '体',
        '頁' => '页',
        '顯' => '显',
        '隱' => '隐',
        '運' => '运',
        '輸' => '输',
        '錯' => '错',
        '誤' => '误',
        '許' => '许',
        '權' => '权',
        '並' => '并',
        '無' => '无',
        '從' => '从',
        '後' => '后',
        '將' => '将',
        '終' => '终',
        '結' => '结',
        '導' => '导',
        '廣' => '广',
        '壓' => '压',
        '縮' => '缩',
        '擇' => '择',
        '擴' => '扩',
        '標' => '标',
        '題' => '题',
        '額' => '额',
        '類' => '类',
        '實' => '实',
        '際' => '际',
        '專' => '专',
        '價' => '价',
        '總' => '总',
        '數' => '数',
        '據' => '据',
        '衛' => '卫',
        '隊' => '队',
        '線' => '线',
        '則' => '则',
        '須' => '须',
        '訴' => '诉',
        '訓' => '训',
        '規' => '规',
        '範' => '范',
        '經' => '经',
        '濟' => '济',
        '營' => '营',
        '銷' => '销',
        '賬' => '账',
        '賣' => '卖',
        '買' => '买',
        '費' => '费',
        '稅' => '税',
        '雜' => '杂',
        '訊' => '讯',
        '話' => '话',
        '語' => '语',
        '義' => '义',
        '隨' => '随',
        '獲' => '获',
        '顧' => '顾',
        '慮' => '虑',
        '護' => '护',
        '療' => '疗',
        '藥' => '药',
        '醫' => '医',
        '機' => '机',
        '構' => '构',
        '組' => '组',
        '織' => '织',
        '節' => '节',
        _ => ch,
    }
}

/// Unicode NFKC + charactersCleanup + common confusable folding.
/// Prevents zero-width, full-width, separator, and mixed-script keyword evasion.
pub(crate) fn normalize_text(text: &str) -> String {
    text.nfkc()
        .map(fold_common_confusable)
        .map(fold_traditional_chinese)
        .filter(|c| {
            !matches!(
                c,
                '\u{200B}' | // Zero Width Space
            '\u{200C}' | // Zero Width Non-Joiner
            '\u{200D}' | // Zero Width Joiner
            '\u{200E}' | // Left-to-Right Mark
            '\u{200F}' | // Right-to-Left Mark
            '\u{2060}' | // Word Joiner
            '\u{FEFF}' | // BOM / Zero Width No-Break Space
            '\u{00AD}' | // Soft Hyphen
            '\u{061C}' | // Arabic Letter Mark
            '\u{2028}' | // Line Separator
            '\u{2029}' | // Paragraph Separator
            // Combining marks: visually identical to the base character
            // ("账\u{301}户" renders as "账户") but break every substring
            // keyword scan. NFKC keeps them, so strip the whole blocks.
            // U+0300..=U+036F also covers U+034F (Combining Grapheme Joiner).
            '\u{0300}'..='\u{036F}' | // Combining Diacritical Marks
            '\u{1AB0}'..='\u{1AFF}' | // Combining Diacritical Marks Extended
            '\u{20D0}'..='\u{20FF}' | // Combining Diacritical Marks for Symbols
            // The following are NOT folded by NFKC; attackers use them to
            // break keyword contiguity.
            '\u{115F}' | // Hangul Choseong Filler
            '\u{1160}' | // Hangul Jungseong Filler
            '\u{180E}' | // Mongolian Vowel Separator
            '\u{202A}'..='\u{202E}' | // Bidi embedding / override controls
            '\u{2066}'..='\u{2069}' | // Bidi isolate controls
            '\u{2800}' | // Braille Pattern Blank
            '\u{3164}' | // Hangul Filler
            '\u{FE00}'..='\u{FE0F}' | // Variation Selectors
            '\u{E0000}'..='\u{E007F}' | // Tags block
            '\u{E0100}'..='\u{E01EF}' // Variation Selectors Supplement
            )
        })
        .collect::<String>()
}

/// body 关键词扫描的单段窗口 (B3): 头/中/尾各 512 KiB, 与 NLP 三段采样对齐。
const BODY_SCAN_SEGMENT_LEN: usize = 512 * 1024;
/// body 关键词扫描的总窗口上限 (三段拼接, ~1.5MB)。
const BODY_SCAN_MAX_LEN: usize = 3 * BODY_SCAN_SEGMENT_LEN;

/// scan_text wall-clock 预算自查点 (B3): 调用方在引擎 catch_unwind 路径中
/// 不可取消, 必须代码内自查; 超预算返回已累积的 partial 分数。
const SCAN_TIME_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

static RE_PARAGRAPH_BREAK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\r?\n\s*\r?\n+").expect("valid paragraph break regex"));

/// 超长 body 的三段采样视图 (B3): 26MB body 对数千关键词逐一 contains 是
/// 平方级 CPU 炸弹; 取头/中/尾各 512 KiB 拼接, 保留对头部诱饵、中段藏匿、
/// 尾部 payload 的覆盖, 同时把扫描成本钉死在 ~1.5MB。UTF-8 边界安全。
fn windowed_body_view(text: &str) -> std::borrow::Cow<'_, str> {
    if text.len() <= BODY_SCAN_MAX_LEN {
        return std::borrow::Cow::Borrowed(text);
    }
    let head_end = text.floor_char_boundary(BODY_SCAN_SEGMENT_LEN);
    let mid_start = text.ceil_char_boundary((text.len() - BODY_SCAN_SEGMENT_LEN) / 2);
    let mid_end = text.floor_char_boundary(mid_start + BODY_SCAN_SEGMENT_LEN);
    let tail_start = text.ceil_char_boundary(text.len() - BODY_SCAN_SEGMENT_LEN);
    let mut view = String::with_capacity(BODY_SCAN_MAX_LEN + 2);
    view.push_str(&text[..head_end]);
    view.push('\n');
    view.push_str(&text[mid_start..mid_end]);
    view.push('\n');
    view.push_str(&text[tail_start..]);
    std::borrow::Cow::Owned(view)
}

/// 关键词集合的 Aho-Corasick 自动机 (B3)。
///
/// 原来的 `keywords.iter().filter(|kw| text.contains(kw))` 是
/// O(haystack × patterns × pattern_len) —— 大 body × 数千关键词是分钟级
/// CPU 炸弹。自动机一遍扫描 O(haystack + matches)。检出语义完全不变:
/// haystack 与 patterns 在调用前都已小写化 + normalize_text 归一化,
/// 因此自动机用大小写敏感匹配即可。
struct KeywordSet {
    /// 原始模式列表 (检出结果按此列表顺序返回, 与旧实现的迭代顺序一致)
    patterns: Vec<String>,
    /// 非空模式的自动机; pattern id 经 `owner` 映射回 `patterns` 下标
    automaton: Option<AhoCorasick>,
    owner: Vec<usize>,
    /// 空模式: `str::contains("")` 恒 true, 旧实现计为恒命中, 保持语义
    always_hit: Vec<usize>,
    /// CJK 关键词紧凑形式自动机 (逐字空格/隐藏分隔符二扫)
    compact_cjk: Option<AhoCorasick>,
    compact_cjk_owner: Vec<usize>,
    /// 拉丁关键词 (紧凑形式 >= 6 字符) 自动机, 仅在逐字母空格形态下启用
    compact_latin: Option<AhoCorasick>,
    compact_latin_owner: Vec<usize>,
}

impl KeywordSet {
    fn build(list: &[String]) -> Self {
        let mut ac_patterns: Vec<String> = Vec::new();
        let mut owner: Vec<usize> = Vec::new();
        let mut always_hit: Vec<usize> = Vec::new();
        let mut cjk_patterns: Vec<String> = Vec::new();
        let mut cjk_owner: Vec<usize> = Vec::new();
        let mut latin_patterns: Vec<String> = Vec::new();
        let mut latin_owner: Vec<usize> = Vec::new();

        for (idx, keyword) in list.iter().enumerate() {
            if keyword.is_empty() {
                always_hit.push(idx);
                continue;
            }
            owner.push(idx);
            ac_patterns.push(keyword.clone());

            // 紧凑二扫的入选条件与原 compact_match 闭包完全一致:
            // CJK 关键词 (非空紧凑形式) 始终参与; 拉丁关键词仅当紧凑形式
            // >= 6 字符时参与 (防英文散文坍缩误报), 且运行时还需
            // allow_latin_compact 门控。
            let contains_cjk = keyword.chars().any(is_cjk_character);
            let compact_kw: String = keyword.chars().filter(|ch| ch.is_alphanumeric()).collect();
            if compact_kw.is_empty() {
                continue;
            }
            if contains_cjk {
                cjk_owner.push(idx);
                cjk_patterns.push(compact_kw);
            } else if compact_kw.chars().count() >= 6 {
                latin_owner.push(idx);
                latin_patterns.push(compact_kw);
            }
        }

        fn build_ac(patterns: &[String]) -> Option<AhoCorasick> {
            if patterns.is_empty() {
                None
            } else {
                Some(
                    AhoCorasick::new(patterns)
                        .expect("aho-corasick build from valid UTF-8 patterns"),
                )
            }
        }

        KeywordSet {
            patterns: list.to_vec(),
            automaton: build_ac(&ac_patterns),
            owner,
            always_hit,
            compact_cjk: build_ac(&cjk_patterns),
            compact_cjk_owner: cjk_owner,
            compact_latin: build_ac(&latin_patterns),
            compact_latin_owner: latin_owner,
        }
    }

    /// 一遍扫描返回全部命中关键词 (按列表顺序, 与旧逐词 contains 语义相同)
    ///
    /// 必须用 overlapping 迭代: 关键词表存在互为前缀的条目 (如 "冻结" 与
    /// "账户冻结"), 非重叠 find_iter 的 leftmost 语义同一位置只报一个,
    /// 会少报命中数从而改变计分 —— `str::contains` 逐词判定不存在该问题。
    fn find_hits(&self, haystack: &str) -> Vec<String> {
        let mut matched = vec![false; self.patterns.len()];
        for &idx in &self.always_hit {
            matched[idx] = true;
        }
        if let Some(ac) = &self.automaton {
            for mat in ac.find_overlapping_iter(haystack.as_bytes()) {
                matched[self.owner[mat.pattern().as_usize()]] = true;
            }
        }
        self.patterns
            .iter()
            .zip(matched.iter())
            .filter(|(_, matched)| **matched)
            .map(|(pattern, _)| pattern.clone())
            .collect()
    }

    /// 紧凑视图二扫: 返回未在 `already` 中出现且紧凑形式命中的关键词
    /// (按列表顺序)。拉丁紧凑命中仅在 allow_latin_compact 时计入。
    fn find_compact_hits(
        &self,
        compact: &str,
        allow_latin_compact: bool,
        already: &[String],
    ) -> Vec<String> {
        let mut matched = vec![false; self.patterns.len()];
        if let Some(ac) = &self.compact_cjk {
            for mat in ac.find_overlapping_iter(compact.as_bytes()) {
                matched[self.compact_cjk_owner[mat.pattern().as_usize()]] = true;
            }
        }
        if allow_latin_compact
            && let Some(ac) = &self.compact_latin
        {
            for mat in ac.find_overlapping_iter(compact.as_bytes()) {
                matched[self.compact_latin_owner[mat.pattern().as_usize()]] = true;
            }
        }
        let already: HashSet<&str> = already.iter().map(String::as_str).collect();
        self.patterns
            .iter()
            .enumerate()
            .filter(|(idx, p)| matched[*idx] && !already.contains(p.as_str()))
            .map(|(_, p)| p.clone())
            .collect()
    }
}

/// 进程内 KeywordSet 缓存 (B3): 关键词列表来自 DB 配置, 跨邮件稳定;
/// 以列表内容相等命中缓存, 避免每封邮件重建自动机 (数千模式 ≈ 数十毫秒)。
/// 上限 16 项防派生列表 (如良性验证码过滤变体) 无界增长。
fn keyword_set(list: &[String]) -> Arc<KeywordSet> {
    static CACHE: Mutex<Vec<(Vec<String>, Arc<KeywordSet>)>> = Mutex::new(Vec::new());
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, set)) = guard.iter().find(|(cached, _)| cached.as_slice() == list) {
        return Arc::clone(set);
    }
    let set = Arc::new(KeywordSet::build(list));
    if guard.len() >= 16 {
        guard.clear();
    }
    guard.push((list.to_vec(), Arc::clone(&set)));
    set
}

pub struct ContentScanModule {
    meta: ModuleMetadata,
    /// ofPhishingKeywordsList (builtin - removed + added)
    phishing_keywords: Vec<String>,
    /// of PhishingKeywordsList
    weak_phishing_keywords: Vec<String>,
    /// of BEC short List
    bec_phrases: Vec<String>,
    /// ofInternal short List
    internal_authority_phrases: Vec<String>,
    gateway_banner_patterns: Vec<String>,
    notice_banner_patterns: Vec<String>,
    dsn_patterns: Vec<String>,
    auto_reply_patterns: Vec<String>,
}

impl Default for ContentScanModule {
    fn default() -> Self {
        Self::new()
    }
}

impl ContentScanModule {
    pub fn new() -> Self {
        Self::new_with_keyword_lists(EffectiveKeywordLists::default())
    }

    pub fn new_with_keyword_lists(effective: EffectiveKeywordLists) -> Self {
        // Enforce the matching invariant at the constructor boundary. Most
        // callers already pass lists built from normalized seeds, but tests,
        // reload adapters, and future callers may construct the public list
        // type directly. Normalizing once here keeps the per-message hot path
        // free of thousands of repeated Unicode transformations.
        let effective = normalize_effective_keyword_lists(effective);
        Self {
            meta: ModuleMetadata {
                id: "content_scan".to_string(),
                name: "Contentdetect".to_string(),
                description: "扫描emailbodyMediumofPhishingKeywords、BEC modeAndSensitivedata泄露"
                    .to_string(),
                pillar: Pillar::Content,
                depends_on: vec![],
                timeout_ms: 5000,
                is_remote: false,
                supports_ai: true,
                cpu_bound: true,
                inline_priority: None,
            },
            phishing_keywords: effective.phishing_keywords,
            weak_phishing_keywords: effective.weak_phishing_keywords,
            bec_phrases: effective.bec_phrases,
            internal_authority_phrases: effective.internal_authority_phrases,
            gateway_banner_patterns: effective.gateway_banner_patterns,
            notice_banner_patterns: effective.notice_banner_patterns,
            dsn_patterns: effective.dsn_patterns,
            auto_reply_patterns: effective.auto_reply_patterns,
        }
    }

    /// ReturnWhenfirst ofKeywordsList (For API Return)
    pub fn effective_keywords(&self) -> serde_json::Value {
        serde_json::json!({
            "phishing_keywords": self.phishing_keywords,
            "weak_phishing_keywords": self.weak_phishing_keywords,
            "bec_phrases": self.bec_phrases,
            "internal_authority_phrases": self.internal_authority_phrases,
            "gateway_banner_patterns": self.gateway_banner_patterns,
            "notice_banner_patterns": self.notice_banner_patterns,
            "dsn_patterns": self.dsn_patterns,
            "auto_reply_patterns": self.auto_reply_patterns,
        })
    }
}

/// Merge Keywords useroverride: (builtin - removed) + added
fn normalize_keyword_entry(value: &str) -> Option<String> {
    let normalized = normalize_text(&value.to_lowercase());
    let collapsed = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        None
    } else {
        Some(collapsed)
    }
}

fn collect_normalized_keywords<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for value in values {
        let Some(normalized) = normalize_keyword_entry(value) else {
            continue;
        };
        if seen.insert(normalized.clone()) {
            result.push(normalized);
        }
    }

    result
}

pub(crate) fn normalize_keyword_list(values: &[String]) -> Vec<String> {
    collect_normalized_keywords(values.iter().map(String::as_str))
}

fn normalize_effective_keyword_lists(effective: EffectiveKeywordLists) -> EffectiveKeywordLists {
    EffectiveKeywordLists {
        phishing_keywords: normalize_keyword_list(&effective.phishing_keywords),
        weak_phishing_keywords: normalize_keyword_list(&effective.weak_phishing_keywords),
        bec_phrases: normalize_keyword_list(&effective.bec_phrases),
        internal_authority_phrases: normalize_keyword_list(&effective.internal_authority_phrases),
        gateway_banner_patterns: normalize_keyword_list(&effective.gateway_banner_patterns),
        notice_banner_patterns: normalize_keyword_list(&effective.notice_banner_patterns),
        dsn_patterns: normalize_keyword_list(&effective.dsn_patterns),
        auto_reply_patterns: normalize_keyword_list(&effective.auto_reply_patterns),
    }
}

fn apply_overrides_to_builtin(
    builtin: &[String],
    overrides: &KeywordCategoryOverride,
) -> Vec<String> {
    let removed_set: HashSet<String> = overrides
        .removed
        .iter()
        .filter_map(|value| normalize_keyword_entry(value))
        .collect();

    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for builtin_kw in builtin {
        if removed_set.contains(builtin_kw) {
            continue;
        }
        if seen.insert(builtin_kw.clone()) {
            result.push(builtin_kw.clone());
        }
    }

    for added in &overrides.added {
        let Some(normalized) = normalize_keyword_entry(added) else {
            continue;
        };
        if seen.insert(normalized.clone()) {
            result.push(normalized);
        }
    }
    result
}

fn normalize_system_category_seed(seed: &KeywordCategoryOverride) -> KeywordCategoryOverride {
    KeywordCategoryOverride {
        added: collect_normalized_keywords(seed.added.iter().map(|value| value.as_str())),
        removed: Vec::new(),
    }
}

pub fn normalize_system_keyword_seed(system_seed: &KeywordOverrides) -> KeywordOverrides {
    KeywordOverrides {
        phishing_keywords: normalize_system_category_seed(&system_seed.phishing_keywords),
        weak_phishing_keywords: normalize_system_category_seed(&system_seed.weak_phishing_keywords),
        bec_phrases: normalize_system_category_seed(&system_seed.bec_phrases),
        internal_authority_phrases: normalize_system_category_seed(
            &system_seed.internal_authority_phrases,
        ),
        gateway_banner_patterns: normalize_system_category_seed(
            &system_seed.gateway_banner_patterns,
        ),
        notice_banner_patterns: normalize_system_category_seed(&system_seed.notice_banner_patterns),
        dsn_patterns: normalize_system_category_seed(&system_seed.dsn_patterns),
        auto_reply_patterns: normalize_system_category_seed(&system_seed.auto_reply_patterns),
    }
}

fn build_system_keyword_lists(system_seed: &KeywordOverrides) -> EffectiveKeywordLists {
    let normalized_seed = normalize_system_keyword_seed(system_seed);
    EffectiveKeywordLists {
        phishing_keywords: normalized_seed.phishing_keywords.added,
        weak_phishing_keywords: normalized_seed.weak_phishing_keywords.added,
        bec_phrases: normalized_seed.bec_phrases.added,
        internal_authority_phrases: normalized_seed.internal_authority_phrases.added,
        gateway_banner_patterns: normalized_seed.gateway_banner_patterns.added,
        notice_banner_patterns: normalized_seed.notice_banner_patterns.added,
        dsn_patterns: normalized_seed.dsn_patterns.added,
        auto_reply_patterns: normalized_seed.auto_reply_patterns.added,
    }
}

fn normalize_user_category_overrides(
    overrides: &KeywordCategoryOverride,
    builtin: &[String],
) -> KeywordCategoryOverride {
    let builtin_set: HashSet<String> = builtin.iter().cloned().collect();

    let added = overrides
        .added
        .iter()
        .filter_map(|value| normalize_keyword_entry(value))
        .filter(|value| !builtin_set.contains(value))
        .collect::<Vec<_>>();

    let removed = overrides
        .removed
        .iter()
        .filter_map(|value| normalize_keyword_entry(value))
        .filter(|value| builtin_set.contains(value))
        .collect::<Vec<_>>();

    KeywordCategoryOverride {
        added: collect_normalized_keywords(added.iter().map(|value| value.as_str())),
        removed: collect_normalized_keywords(removed.iter().map(|value| value.as_str())),
    }
}

pub fn normalize_user_keyword_overrides(
    system_seed: &KeywordOverrides,
    overrides: &KeywordOverrides,
) -> KeywordOverrides {
    let builtin = build_system_keyword_lists(system_seed);

    KeywordOverrides {
        phishing_keywords: normalize_user_category_overrides(
            &overrides.phishing_keywords,
            &builtin.phishing_keywords,
        ),
        weak_phishing_keywords: normalize_user_category_overrides(
            &overrides.weak_phishing_keywords,
            &builtin.weak_phishing_keywords,
        ),
        bec_phrases: normalize_user_category_overrides(
            &overrides.bec_phrases,
            &builtin.bec_phrases,
        ),
        internal_authority_phrases: normalize_user_category_overrides(
            &overrides.internal_authority_phrases,
            &builtin.internal_authority_phrases,
        ),
        gateway_banner_patterns: normalize_user_category_overrides(
            &overrides.gateway_banner_patterns,
            &builtin.gateway_banner_patterns,
        ),
        notice_banner_patterns: normalize_user_category_overrides(
            &overrides.notice_banner_patterns,
            &builtin.notice_banner_patterns,
        ),
        dsn_patterns: normalize_user_category_overrides(
            &overrides.dsn_patterns,
            &builtin.dsn_patterns,
        ),
        auto_reply_patterns: normalize_user_category_overrides(
            &overrides.auto_reply_patterns,
            &builtin.auto_reply_patterns,
        ),
    }
}

pub fn build_effective_keyword_lists(
    system_seed: &KeywordOverrides,
    overrides: &KeywordOverrides,
) -> EffectiveKeywordLists {
    let builtin = build_system_keyword_lists(system_seed);

    EffectiveKeywordLists {
        phishing_keywords: apply_overrides_to_builtin(
            &builtin.phishing_keywords,
            &overrides.phishing_keywords,
        ),
        weak_phishing_keywords: apply_overrides_to_builtin(
            &builtin.weak_phishing_keywords,
            &overrides.weak_phishing_keywords,
        ),
        bec_phrases: apply_overrides_to_builtin(&builtin.bec_phrases, &overrides.bec_phrases),
        internal_authority_phrases: apply_overrides_to_builtin(
            &builtin.internal_authority_phrases,
            &overrides.internal_authority_phrases,
        ),
        gateway_banner_patterns: apply_overrides_to_builtin(
            &builtin.gateway_banner_patterns,
            &overrides.gateway_banner_patterns,
        ),
        notice_banner_patterns: apply_overrides_to_builtin(
            &builtin.notice_banner_patterns,
            &overrides.notice_banner_patterns,
        ),
        dsn_patterns: apply_overrides_to_builtin(&builtin.dsn_patterns, &overrides.dsn_patterns),
        auto_reply_patterns: apply_overrides_to_builtin(
            &builtin.auto_reply_patterns,
            &overrides.auto_reply_patterns,
        ),
    }
}

/// ReturnSystem KeywordsList (For API District builtin vs custom)
pub fn get_builtin_keyword_lists(system_seed: &KeywordOverrides) -> serde_json::Value {
    let builtin = build_system_keyword_lists(system_seed);

    serde_json::json!({
        "phishing_keywords": builtin.phishing_keywords,
        "weak_phishing_keywords": builtin.weak_phishing_keywords,
        "bec_phrases": builtin.bec_phrases,
        "internal_authority_phrases": builtin.internal_authority_phrases,
        "gateway_banner_patterns": builtin.gateway_banner_patterns,
        "notice_banner_patterns": builtin.notice_banner_patterns,
        "dsn_patterns": builtin.dsn_patterns,
        "auto_reply_patterns": builtin.auto_reply_patterns,
    })
}

/// Return detectRule (For API first)
pub fn get_builtin_rules(system_seed: &KeywordOverrides) -> serde_json::Value {
    let builtin = build_system_keyword_lists(system_seed);
    // Merge KeywordsUsed forfirst
    let mut all_phishing = builtin.phishing_keywords.clone();
    all_phishing.extend(builtin.weak_phishing_keywords.clone());
    all_phishing.sort();
    all_phishing.dedup();

    serde_json::json!({
        "phishing_keywords": all_phishing,
        "bec_phrases": builtin.bec_phrases,
        "dlp_patterns": [
            {
                "id": "credit_card",
                "name": "信用Card number",
                "description": "16 bit数字 (通 Luhn Verify)",
                "pattern": r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
                "score_weight": 0.3
            },
            {
                "id": "chinese_id",
                "name": "ID cardNumber",
                "description": "18 bit数字 (末bit可  X)",
                "pattern": r"\b\d{17}[\dXx]\b",
                "score_weight": 0.25
            },
            {
                "id": "api_key",
                "name": "API Key",
                "description": "32+ contiguous字母数字 with surrounding API/secret/token context",
                "pattern": r"\b[A-Za-z0-9]{32,}\b",
                "score_weight": 0.2
            }
        ],
        "scoring": {
            "phishing_per_keyword": 0.08,
            "phishing_max": 0.5,
            "weak_phishing_per_keyword": 0.03,
            "weak_phishing_max": 0.15,
            "weak_phishing_threshold": 3,
            "bec_per_phrase": 0.15,
            "bec_max": 0.5
        }
    })
}

/// Medium large Mobile phoneNumberCode/Digit: 1[3-9] Headerof 11 bit
/// UseCapture + characters,AvoidFrom Time/CountNumber/Serial numberMedium Extract
pub(super) static RE_CHINESE_PHONE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[^0-9a-zA-Z])(1[3-9]\d{9})(?:[^0-9a-zA-Z]|$)").unwrap());

static RE_CREDIT_CARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b").unwrap());
static RE_CHINESE_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{17}[\dXx]\b").unwrap());
static RE_API_KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9]{32,}\b").unwrap());

/// Check if a string looks like it could pass the Luhn algorithm (credit card)
fn contains_credit_card(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for m in RE_CREDIT_CARD.find_iter(text) {
        let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() == 16 && luhn_check(&digits) {
            found.push(m.as_str().to_string());
        }
    }
    found
}

/// Luhn algorithm validation
fn luhn_check(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for ch in digits.chars().rev() {
        if let Some(d) = ch.to_digit(10) {
            let val = if double {
                let v = d * 2;
                if v > 9 { v - 9 } else { v }
            } else {
                d
            };
            sum += val;
            double = !double;
        } else {
            return false;
        }
    }
    sum.is_multiple_of(10)
}

/// Find Chinese national ID numbers (18 digits, last may be X)
fn find_chinese_ids(text: &str) -> Vec<String> {
    RE_CHINESE_ID
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Find potential API keys (32+ alphanumeric chars)
/// Exclude 6Base/RadixString (MD5/SHA Hash, ImageFileNamewait)
fn find_api_keys(text: &str) -> Vec<String> {
    RE_API_KEY
        .find_iter(text)
        .filter_map(|m| {
            let s = m.as_str();
            // 6Base/Radix (0-9, a-f) FileHash, API key
            let is_pure_hex = s
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c.to_ascii_lowercase()));
            if is_pure_hex
                || !looks_like_api_key_shape(s)
                || !has_api_key_context(text, m.start(), m.end())
            {
                None
            } else {
                Some(s.to_string())
            }
        })
        .collect()
}

fn looks_like_api_key_shape(candidate: &str) -> bool {
    let has_upper = candidate.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = candidate.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = candidate.chars().any(|c| c.is_ascii_digit());
    let unique_chars = candidate.chars().collect::<HashSet<_>>().len();
    let class_count = [has_upper, has_lower, has_digit]
        .into_iter()
        .filter(|present| *present)
        .count();

    class_count >= 2 && unique_chars >= 10
}

fn has_api_key_context(text: &str, start: usize, end: usize) -> bool {
    let before: String = text[..start]
        .chars()
        .rev()
        .take(48)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let after: String = text[end..].chars().take(48).collect();
    let context = format!("{before}{}{after}", &text[start..end]).to_lowercase();

    module_data()
        .get_list("api_key_context_keywords")
        .iter()
        .any(|keyword| context.contains(keyword.as_str()))
}

#[inline]
fn is_cjk_character(ch: char) -> bool {
    matches!(
        ch,
        '\u{3400}'..='\u{4DBF}'
            | '\u{4E00}'..='\u{9FFF}'
            | '\u{F900}'..='\u{FAFF}'
    )
}

/// Build the compact view used for anti-obfuscation matching.  A single
/// hidden Latin character inserted between two CJK characters is not part of
/// the rendered phrase (`账<span style="display:none">x</span>户`), so discard
/// that exact shape while retaining ordinary ASCII words and digits.
///
/// O(n) implementation (B3): the previous per-character backward/forward
/// `find` scan was O(n²) on inputs with long non-alphanumeric runs (e.g.
/// hundreds of KB of whitespace), a self-contained CPU bomb. Prev/next
/// visible characters are precomputed with one forward and one reverse pass.
pub(super) fn compact_detection_view(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut prev_visible: Vec<Option<char>> = vec![None; chars.len()];
    let mut last: Option<char> = None;
    for (index, ch) in chars.iter().copied().enumerate() {
        prev_visible[index] = last;
        if ch.is_alphanumeric() {
            last = Some(ch);
        }
    }
    let mut next_visible: Vec<Option<char>> = vec![None; chars.len()];
    let mut next: Option<char> = None;
    for index in (0..chars.len()).rev() {
        next_visible[index] = next;
        if chars[index].is_alphanumeric() {
            next = Some(chars[index]);
        }
    }

    let mut compact = String::with_capacity(text.len());
    for (index, ch) in chars.iter().copied().enumerate() {
        if !ch.is_alphanumeric() {
            continue;
        }
        let hidden_separator = ch.is_ascii_alphanumeric()
            && prev_visible[index].is_some_and(is_cjk_character)
            && next_visible[index].is_some_and(is_cjk_character);
        if !hidden_separator {
            compact.push(ch);
        }
    }
    compact
}

/// Return true only for a strongly letter-spaced Latin shape such as
/// `v e r i f y y o u r a c c o u n t`.  Compacting every English sentence
/// would manufacture matches by joining unrelated words, so this gate is
/// intentionally stricter than the CJK path.
fn looks_like_letter_spaced_latin(text: &str) -> bool {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    if tokens.len() < 6 {
        return false;
    }
    let mut single_ascii_letters = 0usize;
    let mut longest_run = 0usize;
    let mut current_run = 0usize;
    for token in &tokens {
        if token.len() == 1 && token.as_bytes()[0].is_ascii_alphabetic() {
            single_ascii_letters += 1;
            current_run += 1;
            longest_run = longest_run.max(current_run);
        } else {
            current_run = 0;
        }
    }

    // Allow ordinary lead-in words such as “Dear User” while requiring a
    // genuine per-letter run.  The run/ratio gates keep normal prose and
    // acronym-heavy business mail out of the Latin compact path.
    single_ascii_letters >= 10
        && longest_run >= 6
        && single_ascii_letters * 100 / tokens.len() >= 25
}

pub(super) fn scan_text(
    text: &str,
    phishing_kw: &[String],
    weak_phishing_kw: &[String],
    bec_ph: &[String],
    evidence: &mut Vec<Evidence>,
    categories: &mut Vec<String>,
) -> f64 {
    let scan_started = Instant::now();
    let mut score: f64 = 0.0;
    // B3: 超长 body 三段窗口采样 (头/中/尾各 512 KiB), 扫描成本钉死在 ~1.5MB
    let windowed = windowed_body_view(text);
    let text: &str = &windowed;
    // NFKC: ->, -> Standard, prevent Unicode
    let text_lower = normalize_text(&text.to_lowercase());

    // Compact second-pass view: per-character spacing breaks direct substring
    // matching, while CSS-hidden single letters can sit between CJK characters.
    // Latin compaction is enabled only for a strongly letter-spaced shape.
    let compact_text: Option<String> = {
        let chars: Vec<char> = text_lower.chars().collect();
        let has_spacing = chars.iter().any(|ch| ch.is_whitespace());
        let has_cjk_hidden_separator = chars.windows(3).any(|window| {
            is_cjk_character(window[0])
                && window[1].is_ascii_alphanumeric()
                && is_cjk_character(window[2])
        });
        if has_spacing || has_cjk_hidden_separator {
            Some(compact_detection_view(&text_lower))
        } else {
            None
        }
    };
    let allow_latin_compact = looks_like_letter_spaced_latin(&text_lower);

    // B3: 关键词命中用 Aho-Corasick 自动机一遍扫描 (O(haystack + matches)),
    // 检出语义与旧的逐词 contains 完全相同; 自动机跨邮件缓存复用。
    let phishing_set = keyword_set(phishing_kw);
    let weak_set = keyword_set(weak_phishing_kw);
    let bec_set = keyword_set(bec_ph);

    // --- PhishingKeywords (0.08/, 0.5) ---
    let mut phishing_hits: Vec<String> = phishing_set.find_hits(&text_lower);
    if let Some(compact) = &compact_text {
        let spaced_hits =
            phishing_set.find_compact_hits(compact, allow_latin_compact, &phishing_hits);
        phishing_hits.extend(spaced_hits);
    }
    if !phishing_hits.is_empty() {
        let count = phishing_hits.len();
        score += (count as f64 * 0.08).min(0.5);
        categories.push("phishing".to_string());
        evidence.push(Evidence {
            description: format!(
                "Found {} PhishingKeywords: {}",
                count,
                phishing_hits.join(", ")
            ),
            location: Some("body".to_string()),
            snippet: Some(phishing_hits.join(", ")),
        });
    }

    // --- PhishingKeywords (0.03/,>=3, 0.15) ---
    // NormalBusinessemailMedium found, stored
    let weak_hits: Vec<String> = weak_set.find_hits(&text_lower);
    // Weak entries come exclusively from the JSON-managed weak list and only
    // corroborate a primary phishing match; business vocabulary alone is not
    // malicious intent.
    if weak_hits.len() >= 3 && !phishing_hits.is_empty() {
        score += (weak_hits.len() as f64 * 0.03).min(0.15);
        categories.push("phishing".to_string());
        evidence.push(Evidence {
            description: format!(
                "Found {} 弱PhishingIndicator: {}",
                weak_hits.len(),
                weak_hits.join(", ")
            ),
            location: Some("body".to_string()),
            snippet: Some(weak_hits.join(", ")),
        });
    }

    // --- BEC impersonation ---
    // Single-token urgency words from the keyword manager (e.g. "immediately",
    // "asap") are too weak on their own. Treat them as weak BEC hints and only
    // score when multiple weak hits co-occur, while keeping multi-token phrases
    // as strong BEC evidence.
    // wall-clock 预算自查点: 超预算返回已累积 partial 分数
    if scan_started.elapsed() > SCAN_TIME_BUDGET {
        return score;
    }
    let mut bec_hits: Vec<String> = bec_set.find_hits(&text_lower);
    if let Some(compact) = &compact_text {
        let spaced_hits = bec_set.find_compact_hits(compact, allow_latin_compact, &bec_hits);
        bec_hits.extend(spaced_hits);
    }
    let (strong_bec_hits, weak_bec_hits): (Vec<String>, Vec<String>) = bec_hits
        .into_iter()
        .partition(|phrase| is_strong_bec_phrase(phrase));
    if !strong_bec_hits.is_empty() {
        let count = strong_bec_hits.len();
        score += (count as f64 * 0.15).min(0.5);
        categories.push("bec".to_string());
        evidence.push(Evidence {
            description: format!(
                "Found {} strong BEC phrases: {}",
                count,
                strong_bec_hits.join(", ")
            ),
            location: Some("body".to_string()),
            snippet: Some(strong_bec_hits.join(", ")),
        });
    } else if weak_bec_hits.len() >= 3 {
        score += (weak_bec_hits.len() as f64 * 0.05).min(0.15);
        categories.push("bec".to_string());
        evidence.push(Evidence {
            description: format!(
                "Found {} weak BEC hints that co-occur: {}",
                weak_bec_hits.len(),
                weak_bec_hits.join(", ")
            ),
            location: Some("body".to_string()),
            snippet: Some(weak_bec_hits.join(", ")),
        });
    }

    // wall-clock 预算自查点: 超预算返回已累积 partial 分数
    if scan_started.elapsed() > SCAN_TIME_BUDGET {
        return score;
    }

    // --- DLP: Credit cards ---
    let cc_matches = contains_credit_card(text);
    if !cc_matches.is_empty() {
        // DLP describes data sensitivity, not malicious intent. Keep the
        // finding for compliance visibility without inflating email threat.
        categories.push("dlp_credit_card".to_string());
        evidence.push(Evidence {
            description: format!(
                "Found {} 疑似信用Card number（通 Luhn Verify）",
                cc_matches.len()
            ),
            location: Some("body".to_string()),
            snippet: Some(
                cc_matches
                    .iter()
                    .map(|c| {
                        // mask middle digits
                        let mut masked = c.clone();
                        if masked.len() >= 12 {
                            let len = masked.len();
                            masked.replace_range(4..len - 4, &"*".repeat(len - 8));
                        }
                        masked
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        });
    }

    // --- DLP: Chinese ID ---
    let id_matches = find_chinese_ids(text);
    if !id_matches.is_empty() {
        categories.push("dlp_id_number".to_string());
        evidence.push(Evidence {
            description: format!("Found {} 疑似ID cardNumber", id_matches.len()),
            location: Some("body".to_string()),
            snippet: Some(
                id_matches
                    .iter()
                    .map(|id| {
                        let mut masked = id.clone();
                        if masked.len() >= 10 {
                            masked.replace_range(4..14, "**********");
                        }
                        masked
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        });
    }

    // --- DLP: API keys ---
    let api_keys = find_api_keys(text);
    if !api_keys.is_empty() {
        categories.push("dlp_api_key".to_string());
        evidence.push(Evidence {
            description: format!(
                "Found {} suspected API key(s) with nearby secret/token context",
                api_keys.len()
            ),
            location: Some("body".to_string()),
            snippet: Some(
                api_keys
                    .iter()
                    .map(|k| {
                        if k.len() > 8 {
                            format!("{}...{}", &k[..4], &k[k.len() - 4..])
                        } else {
                            k.clone()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        });
    }

    score
}

pub(crate) fn is_strong_bec_phrase(phrase: &str) -> bool {
    let normalized = normalize_text(&phrase.to_lowercase());
    let word_count = normalized
        .split_whitespace()
        .filter(|segment| !segment.is_empty())
        .count();
    if word_count >= 2 {
        return true;
    }

    let cjk_count = normalized
        .chars()
        .filter(|ch| ('\u{4E00}'..='\u{9FFF}').contains(ch))
        .count();
    cjk_count >= 4
}

/// patterns 在列表构建期 (normalize_keyword_entry / collect_normalized_keywords)
/// 已归一化为小写折叠形式, text_lower 同样是 normalize_text(to_lowercase)
/// 产物 —— 此处不再逐模式重复归一化 (B3: 原实现每次调用对数千模式重新
/// normalize, 是纯浪费的 CPU 热点)。
fn matches_any_pattern(text_lower: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| text_lower.contains(pattern.as_str()))
}

fn split_first_paragraph(text: &str) -> (&str, &str) {
    if let Some(m) = RE_PARAGRAPH_BREAK.find(text) {
        (&text[..m.start()], &text[m.end()..])
    } else {
        (text, "")
    }
}

fn strip_leading_notice_sections<'a>(text: &'a str, patterns: &[String]) -> (&'a str, bool) {
    let mut remaining = text.trim_start();
    let mut removed_any = false;

    for _ in 0..6 {
        if remaining.is_empty() {
            return (remaining, removed_any);
        }

        let (paragraph, rest) = split_first_paragraph(remaining);
        let paragraph_lower = normalize_text(&paragraph.to_lowercase());
        if matches_any_pattern(&paragraph_lower, patterns) {
            removed_any = true;
            remaining = rest.trim_start();
        } else {
            break;
        }
    }

    (remaining, removed_any)
}

fn separator_lead_len(line: &str) -> usize {
    line.trim_start()
        .chars()
        .take_while(|c| matches!(c, '_' | '-' | '=' | '*' | '·'))
        .count()
}

/// Well-known signature / disclaimer phrasing. Only tails dominated by these
/// markers may be truncated; anything else must stay visible to scanning.
/// Simplified/traditional variants are paired per project convention.
const FOOTER_DISCLAIMER_MARKERS: &[&str] = &[
    "声明：",
    "聲明：",
    "声明:",
    "免责声明",
    "免責聲明",
    "保密",
    "机密",
    "機密",
    "指定收件人",
    "disclaimer",
    "confidential",
    "intended recipient",
    "unauthorized use",
    "privileged",
];

/// True when the leading portion of `text` looks like a known
/// signature/disclaimer block rather than attacker-controlled prose.
fn contains_disclaimer_marker(text: &str) -> bool {
    let probe: String = text.chars().take(200).collect();
    let probe = normalize_text(&probe.to_lowercase());
    FOOTER_DISCLAIMER_MARKERS
        .iter()
        .any(|marker| probe.contains(marker))
}

/// Maximum characters allowed after a disclaimer marker for a line to count
/// as a genuine disclaimer/signature line.
const DISCLAIMER_LINE_MAX_TRAILING: usize = 40;

/// True when a single line is almost entirely disclaimer/signature phrasing:
/// a marker must appear AND the content following it must stay short. A long
/// phishing line merely prefixed with "声明：" must NOT qualify — otherwise
/// an attacker can prefix every line of a forged-banner body with a marker
/// and get the whole remainder cleared from the keyword scan.
fn is_disclaimer_line(line: &str) -> bool {
    let normalized = normalize_text(&line.to_lowercase());
    FOOTER_DISCLAIMER_MARKERS.iter().any(|marker| {
        let Some(pos) = normalized.find(marker) else {
            return false;
        };
        let after = &normalized[pos + marker.len()..];
        after.chars().count() < DISCLAIMER_LINE_MAX_TRAILING
    })
}

/// Hard cap on how much text after a "____"-style separator line is retained
/// for scanning when the tail does NOT look like a disclaimer. Without the
/// cap a forged signature separator could smuggle an arbitrarily long body
/// past the footer logic; the leading part is still scanned so quoted reply
/// chains keep most of their coverage.
const FOOTER_TAIL_MAX_RETAINED: usize = 800;

fn strip_trailing_footer_after_separator(text: &str) -> String {
    let mut offset = 0usize;
    let trimmed = text.trim();

    for line in trimmed.split_inclusive('\n') {
        let line_trimmed = line.trim();
        let separator_len = separator_lead_len(line_trimmed);
        let tail_start = offset;
        let tail = &trimmed[tail_start..];

        if separator_len >= 4 && tail.len() >= 160 && tail_start >= 48 {
            // Only truncate when the tail matches known signature/disclaimer
            // patterns. Attacker-controlled text placed after a separator
            // line must remain covered by the keyword scan.
            if contains_disclaimer_marker(tail) {
                return trimmed[..tail_start].trim_end().to_string();
            }
            // No disclaimer marker: cap the retained tail so a forged
            // separator cannot hide an over-long body from the scan.
            if tail.chars().count() > FOOTER_TAIL_MAX_RETAINED {
                let kept: String = tail.chars().take(FOOTER_TAIL_MAX_RETAINED).collect();
                return format!("{}\n{}", trimmed[..tail_start].trim_end(), kept);
            }
        }

        offset += line.len();
    }

    trimmed.to_string()
}

pub(crate) fn sanitize_body_for_keyword_scan(
    text: &str,
    gateway_banner_patterns: &[String],
    notice_banner_patterns: &[String],
    dsn_patterns: &[String],
    auto_reply_patterns: &[String],
) -> String {
    let mut notice_patterns = Vec::with_capacity(
        gateway_banner_patterns.len()
            + notice_banner_patterns.len()
            + dsn_patterns.len()
            + auto_reply_patterns.len(),
    );
    notice_patterns.extend(gateway_banner_patterns.iter().cloned());
    notice_patterns.extend(notice_banner_patterns.iter().cloned());
    notice_patterns.extend(dsn_patterns.iter().cloned());
    notice_patterns.extend(auto_reply_patterns.iter().cloned());

    let (without_notice, removed_notice) = strip_leading_notice_sections(text, &notice_patterns);
    let trimmed = without_notice.trim_start();
    if removed_notice && separator_lead_len(trimmed.lines().next().unwrap_or_default()) >= 4 {
        // Clear the body only when everything left after the stripped banner
        // is itself banner/separator/disclaimer material. Otherwise fall back
        // to scanning the remaining text, so a forged banner plus separator
        // cannot hide the real (possibly phishing) body from the scan.
        let remainder_is_only_banner_material = trimmed.lines().all(|line| {
            let line = line.trim();
            line.is_empty()
                || separator_lead_len(line) >= 4
                || is_disclaimer_line(line)
                || matches_any_pattern(&normalize_text(&line.to_lowercase()), &notice_patterns)
        });
        if remainder_is_only_banner_material {
            return String::new();
        }
    }

    strip_trailing_footer_after_separator(without_notice)
}

pub(super) fn collect_gateway_prior_hits(
    prefix_text: &str,
    gateway_banner_patterns: &[String],
) -> Vec<String> {
    let prefix_lower = normalize_text(&prefix_text.to_lowercase());
    // patterns 在列表构建期已归一化 (见 matches_any_pattern 注释), 直接匹配
    gateway_banner_patterns
        .iter()
        .filter(|pattern| prefix_lower.contains(pattern.as_str()))
        .cloned()
        .collect()
}

pub(crate) fn strip_subject_banner_prefixes(
    subject: &str,
    gateway_banner_patterns: &[String],
    notice_banner_patterns: &[String],
) -> String {
    let mut cleaned = subject.to_string();
    // B4: 小写化从"每模式每轮一次"改为"每次实际移除后重建一次" ——
    // 无移除时整个函数只做一次 to_lowercase (原实现 64KB subject × 数千
    // 模式 ≈ 数百 MB 的重复分配 + replace_range O(n) 搬运)。
    let mut lowered = cleaned.to_lowercase();
    for pattern in gateway_banner_patterns
        .iter()
        .chain(notice_banner_patterns.iter())
    {
        // Patterns are stored normalized (lowercased); match the subject
        // case-insensitively so "[External Mail]" is stripped too. Removal is
        // guarded by a byte-aligned verification because `to_lowercase` can
        // change byte lengths for exotic characters.
        let pattern_lower = pattern.to_lowercase();
        if pattern_lower.is_empty() {
            continue;
        }
        while let Some(start) = lowered.find(pattern_lower.as_str()) {
            let end = start + pattern_lower.len();
            let Some(slice) = cleaned.get(start..end) else {
                break;
            };
            if slice.to_lowercase() != pattern_lower {
                break;
            }
            cleaned.replace_range(start..end, "");
            lowered = cleaned.to_lowercase();
        }
    }
    cleaned.trim().to_string()
}

/// Normalize the subject (NFKC + invisible/combining-mark cleanup) BEFORE
/// stripping gateway banner prefixes. Patterns are stored normalized, so a
/// raw subject with full-width brackets ("【外部邮件】") would otherwise keep
/// its banner through the strip step.
pub(crate) fn normalized_subject_for_scan(
    subject: &str,
    gateway_banner_patterns: &[String],
    notice_banner_patterns: &[String],
) -> String {
    strip_subject_banner_prefixes(
        &normalize_text(subject),
        gateway_banner_patterns,
        notice_banner_patterns,
    )
}

#[async_trait]
impl SecurityModule for ContentScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;

        // Step 1: Gateway banner detection
        detectors::detect_gateway_banner(
            ctx,
            &self.gateway_banner_patterns,
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 2: Subject phishing keywords + phone numbers
        detectors::detect_subject_phishing(
            ctx,
            &self.phishing_keywords,
            &self.gateway_banner_patterns,
            &self.notice_banner_patterns,
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 2b: Subject-only off-platform contact lure
        detectors::detect_subject_contact_lure(
            ctx,
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 3: Body text preparation + keyword/DLP scanning
        let body_for_cross = detectors::prepare_body_text(
            ctx,
            &self.phishing_keywords,
            &self.weak_phishing_keywords,
            &self.bec_phrases,
            &self.gateway_banner_patterns,
            &self.notice_banner_patterns,
            &self.dsn_patterns,
            &self.auto_reply_patterns,
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 4: Image-only phishing detection
        detectors::detect_image_only_phishing(
            ctx,
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 5: Account security phishing (body + subject fallback)
        detectors::detect_account_security_phishing(
            ctx,
            body_for_cross.as_deref(),
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 6: Subsidy/tax fraud (body + subject fallback)
        detectors::detect_subsidy_fraud(
            ctx,
            body_for_cross.as_deref(),
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 7: Invoice-spam / fake invoice solicitation detection
        detectors::detect_invoice_spam(
            ctx,
            body_for_cross.as_deref(),
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 8: Payment-account-change BEC detection
        detectors::detect_payment_change_bec(
            ctx,
            body_for_cross.as_deref(),
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 9: Body phone number detection
        detectors::detect_body_phone_numbers(
            body_for_cross.as_deref(),
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 10: External impersonation detection
        detectors::detect_external_impersonation(
            ctx,
            body_for_cross.as_deref(),
            &self.internal_authority_phrases,
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 11: Language inconsistency detection
        detectors::detect_lang_inconsistency(
            body_for_cross.as_deref(),
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Cap the score at 1.0
        total_score = total_score.min(1.0);

        // Deduplicate categories
        categories.sort();
        categories.dedup();

        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(total_score);

        let dlp_only = !categories.is_empty()
            && categories
                .iter()
                .all(|category| category.starts_with("dlp_"));
        if threat_level == ThreatLevel::Safe && !dlp_only {
            return Ok(ModuleResult::safe_analyzed(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "bodyContent未Found威胁",
                duration_ms,
            ));
        }

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: 0.85,
            categories,
            summary: if threat_level == ThreatLevel::Safe {
                format!(
                    "Body content contains {} informational sensitive-data finding(s); no threat evidence",
                    evidence.len()
                )
            } else {
                format!(
                    "bodyContentdetectFound {} Item证According to，综合评分 {:.2}",
                    evidence.len(),
                    total_score
                )
            },
            evidence,
            details: serde_json::json!({
                "score": total_score,
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        })
    }
}

#[cfg(test)]
mod tests;
