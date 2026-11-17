//! Model-input text for the semantic intent model.
//!
//! Port of the training preprocessing: `normalize` and the identity rules of
//! scripts/semantic_intent_poc/poc_text.py, and `clean` plus the subject/body
//! join of prepare_ft_data.py. The deployed models were trained on exactly
//! this text, so the rules must not change without retraining. Tests compare
//! against outputs of the Python originals.
//!
//! Python `re` semantics are kept where Rust differs: `\s` is the
//! `str.isspace` set (it includes U+001C..U+001F), `\w` is letters, numbers
//! and underscore (no combining marks), `\b` before a word character is "not
//! preceded by a word character", and `strip()` uses the same space set.
//! Every rule is guarded by a one-character lookbehind so matching starts only
//! at run boundaries; a backtracking-limit error is returned, never a panic.

use std::borrow::Cow;
use std::sync::OnceLock;

use fancy_regex::{Regex, RegexBuilder};
use unicode_normalization::UnicodeNormalization;

const INVISIBLE_RANGES: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x2800, 0x2800),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xE0000, 0xE007F),
    (0xE0100, 0xE01EF),
];
const COMBINING_RANGES: &[(u32, u32)] = &[(0x0300, 0x036F), (0x1AB0, 0x1AFF), (0x20D0, 0x20FF)];

/// Python `str.isspace` characters, i.e. `\s` in `re` (class body).
const PY_SPACE: &str = r"\t\n\x0B\x0C\r\x1C-\x1F \x{85}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}";
/// Python `\w` for str patterns: letters, numbers, underscore (class body).
const PY_WORD: &str = r"\p{L}\p{N}_";
/// prepare_ft_data SPACE: `[ \t\r\f\v 　]+`.
const LINE_SPACE: &str = r"[ \t\r\x0C\x0B\x{A0}\x{3000}]+";

const TLDS: &str = "com|net|org|cn|top|xyz|info|io|co|cc|me|vip|shop|site|online|club|app|tech|biz|gov|edu|\
hk|tw|mo|us|uk|de|it|fr|es|nl|ru|jp|kr|sg|my|in|br|au|ca|eu|ch|se|no|dk|pl|ly|ai|link|\
live|icu|work|ltd|wang|ink|pro|mobi|tv|asia|cloud|email|space|store|fun|life|world|today|\
news|bank|finance|support|services|help|xin|cyou|buzz|rest|loan|win|bid|click";
const SURNAMES: &str = "王李张刘陈杨黄赵吴周徐孙马朱胡郭何高林罗郑梁谢宋唐许韩冯邓曹彭曾肖田董袁潘于蒋蔡余杜叶程\
苏魏吕丁任沈姚卢姜崔钟谭陆汪范金石廖贾夏韦付方白邹孟熊秦邱江尹薛闫段雷侯龙史陶黎贺顾毛\
郝龚邵万钱严覃武戴莫孔向汤";
/// 总 is a title only when it does not start a common word (总结, 总部, 总额 ...).
const TITLE: &str = "(?:总监|总裁|总经理|总(?![结部公司行额计体共之量价数账表会值和])|经理|主任|主管|老师|先生|女士|小姐|\
处长|科长|局长|部长|行长|董事长|律师|医生|老板|教授|博士)";

/// Matching budget per regex call; exceeding it is an error, not a hang.
const BACKTRACK_LIMIT: usize = 1_000_000;

#[derive(Debug)]
pub struct IntentTextError(String);

impl std::fmt::Display for IntentTextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

struct Rules {
    url: Regex,
    email: Regex,
    identities: Vec<(Regex, &'static str)>,
    line_space: Regex,
}

fn identity_patterns() -> Vec<(String, &'static str)> {
    let s = PY_SPACE;
    let w = PY_WORD;
    vec![
        (r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])".to_string(), " (ip) "),
        (r"(?<![A-Za-z0-9])\d{17}[\dXx](?![A-Za-z0-9])".to_string(), " (number) "),
        // Mixed letter/digit codes next, so phone rules never cut digits out of an IBAN or case number.
        (
            r"(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)+(?![A-Za-z0-9_-])"
                .to_string(),
            " (code) ",
        ),
        (
            r"(?<![A-Za-z0-9_-])(?=[A-Za-z0-9]{8,}(?![A-Za-z0-9_-]))(?=(?:[A-Za-z]*\d){4})(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]+"
                .to_string(),
            " (code) ",
        ),
        (format!(r"(?<![A-Za-z0-9])(?:\+?86[{s}-]?)?1[3-9]\d[{s}-]?\d{{4}}[{s}-]?\d{{4}}(?!\d)"), " (phone) "),
        (format!(r"(?<![A-Za-z0-9])[48]00[{s}-]?\d{{3}}[{s}-]?\d{{4}}(?!\d)"), " (phone) "),
        (format!(r"(拨打|致电|热线|电话|客服|呼叫)([:：]?[{s}]*)(?:95\d{{3,5}}|1[0-2]\d{{3}})(?!\d)"), "${1}${2}(phone)"),
        (format!(r"(?<![A-Za-z0-9])\+\d{{1,3}}[{s}.-]?\(?\d{{1,4}}\)?(?:[{s}.-]?\d{{2,4}}){{2,4}}(?!\d)"), " (phone) "),
        (format!(r"(?<![A-Za-z0-9])(?:1[{s}.-]?)?\(?[2-9]\d{{2}}\)?[{s}.-]\d{{3}}[{s}.-]\d{{4}}(?!\d)"), " (phone) "),
        (format!(r"(?<![A-Za-z0-9])\(?0\d{{2,3}}\)?[{s}-]?\d{{7,8}}(?!\d)"), " (phone) "),
        (format!(r"(?<!\d)\d{{4}}(?:[{s}-]\d{{4}}){{2,4}}(?:[{s}-]\d{{1,3}})?(?!\d)"), " (number) "),
        (r"(?<![\d.,])\d{8,}(?![\d.,])".to_string(), " (number) "),
        (
            format!(r"(?i)(?<![{w}@.-])(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{TLDS})(?![{w}-])"),
            " (domain) ",
        ),
        (format!("[{SURNAMES}](?={TITLE})"), "(name)"),
        (format!("[{SURNAMES}][一-鿿]{{1,2}}(?=先生|女士|小姐)"), "(name)"),
        (format!("(?<![一-鿿])[小老][{SURNAMES}](?=[,，。!！?？:：{s}]|你|您|$)"), "(name)"),
        (
            format!(r"(?<![{w}])(Mr|Mrs|Ms|Miss|Dr|Prof|Frau|Herr|Sig|Signor|Signora|Dott)\.?[{s}]+[A-Z][{w}'-]+(?:[{s}]+[A-Z][{w}'-]+)?"),
            "${1} (name)",
        ),
        (
            format!(r"(?<![{w}])(Dear|Hi|Hello|Hey|Gentile|Caro|Cara|Liebe|Lieber)[{s}]+[A-Z][{w}'-]+(?:[{s}]+[A-Z][{w}'-]+)?(?=[{s}]*[,!:\n])"),
            "${1} (name)",
        ),
    ]
}

fn compile(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new(pattern)
        .backtrack_limit(BACKTRACK_LIMIT)
        .build()
        .map_err(|error| format!("intent text rule does not compile: {error}"))
}

fn rules() -> Result<&'static Rules, IntentTextError> {
    static RULES: OnceLock<Result<Rules, String>> = OnceLock::new();
    RULES
        .get_or_init(|| {
            let w = PY_WORD;
            let s = PY_SPACE;
            Ok(Rules {
                url: compile(&format!(r"(?i)(?<![{w}])(?:https?://|www\.)[^{s}]+"))?,
                email: compile(&format!(r"[{w}.+-]+@[{w}-]+(?:\.[{w}-]+)+"))?,
                identities: identity_patterns()
                    .into_iter()
                    .map(|(pattern, replacement)| {
                        compile(&pattern).map(|regex| (regex, replacement))
                    })
                    .collect::<Result<_, _>>()?,
                line_space: compile(LINE_SPACE)?,
            })
        })
        .as_ref()
        .map_err(|error| IntentTextError(error.clone()))
}

fn in_ranges(character: char, ranges: &[(u32, u32)]) -> bool {
    let code = character as u32;
    ranges
        .iter()
        .any(|&(low, high)| (low..=high).contains(&code))
}

fn is_py_space(character: char) -> bool {
    matches!(
        character,
        '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | '\u{1C}'..='\u{1F}' | ' ' | '\u{85}' | '\u{A0}'
            | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}'
            | '\u{3000}'
    )
}

fn py_strip(text: &str) -> &str {
    text.trim_matches(is_py_space)
}

fn replace(regex: &Regex, text: String, replacement: &str) -> Result<String, IntentTextError> {
    let replaced = regex
        .try_replacen(&text, 0, replacement)
        .map(|result| match result {
            Cow::Borrowed(_) => None,
            Cow::Owned(replaced) => Some(replaced),
        })
        .map_err(|error| IntentTextError(format!("intent text rule failed: {error}")))?;
    Ok(replaced.unwrap_or(text))
}

/// poc_text.normalize: NFKC, drop invisible and combining characters, mask links,
/// e-mail addresses and identities.
pub fn normalize(text: &str) -> Result<String, IntentTextError> {
    let rules = rules()?;
    let mut out: String = text
        .nfkc()
        .filter(|&character| {
            !in_ranges(character, INVISIBLE_RANGES) && !in_ranges(character, COMBINING_RANGES)
        })
        .collect();
    out = replace(&rules.url, out, " (link) ")?;
    out = replace(&rules.email, out, " (email) ")?;
    for (regex, replacement) in &rules.identities {
        out = replace(regex, out, replacement)?;
    }
    Ok(out)
}

/// prepare_ft_data.clean (no symbol stripping): normalised, per-line space
/// runs collapsed and stripped, empty lines dropped.
pub fn clean(text: &str) -> Result<String, IntentTextError> {
    let rules = rules()?;
    let normalized = normalize(text)?;
    let mut lines = Vec::new();
    for raw in normalized.split('\n') {
        let collapsed = replace(&rules.line_space, raw.to_string(), " ")?;
        let line = py_strip(&collapsed);
        if !line.is_empty() {
            lines.push(line.to_string());
        }
    }
    Ok(lines.join("\n"))
}

/// The exact training input: cleaned subject, newline, cleaned body, stripped.
pub fn model_text(subject: Option<&str>, body: &str) -> Result<String, IntentTextError> {
    let joined = format!("{}\n{}", clean(subject.unwrap_or(""))?, clean(body)?);
    Ok(py_strip(&joined).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Outputs of the Python originals (poc_text.normalize + prepare_ft_data.clean)
    /// for hand-written inputs; regenerate with scripts/semantic_intent_poc/intent_text_cases.py.
    const CASES: &str = include_str!("intent_text_cases.json");

    #[derive(serde::Deserialize)]
    struct Case {
        subject: Option<String>,
        body: String,
        expected: String,
    }

    #[test]
    fn matches_python_training_preprocessing() {
        let cases: Vec<Case> = serde_json::from_str(CASES).expect("cases");
        assert!(cases.len() >= 30);
        for (index, case) in cases.iter().enumerate() {
            let actual = model_text(case.subject.as_deref(), &case.body).expect("model text");
            assert_eq!(actual, case.expected, "case {index}: {:?}", case.body);
        }
    }

    /// Full-corpus parity on 77 against scripts/semantic_intent_poc/intent_parity_cases.py (text mode):
    /// INTENT_TEXT_PARITY_CASES=cases.jsonl cargo test -p vigilyx-engine -- --ignored intent_text_parity
    #[test]
    #[ignore = "needs Python reference outputs, which contain dataset text and stay on 77"]
    fn intent_text_parity() {
        let path = std::env::var("INTENT_TEXT_PARITY_CASES").expect("INTENT_TEXT_PARITY_CASES");
        let mut total = 0;
        let mut mismatches = Vec::new();
        for line in std::fs::read_to_string(&path).expect("cases").lines() {
            let case: serde_json::Value = serde_json::from_str(line).expect("case");
            let actual = model_text(
                case["subject"].as_str(),
                case["body"].as_str().unwrap_or(""),
            );
            let expected = case["text"].as_str().expect("text");
            if actual.as_deref().ok() != Some(expected) {
                mismatches.push((
                    total,
                    expected.chars().take(120).collect::<String>(),
                    actual.map(|t| t.chars().take(120).collect::<String>()),
                ));
            }
            total += 1;
        }
        println!(
            "intent text parity: {} of {total} records differ",
            mismatches.len()
        );
        for mismatch in mismatches.iter().take(5) {
            println!("{mismatch:?}");
        }
        assert!(total > 0 && mismatches.is_empty());
    }

    #[test]
    fn python_space_set_differs_from_rust_whitespace() {
        // U+001C..U+001F are str.isspace in Python but not char::is_whitespace.
        assert!(is_py_space('\u{1C}') && !'\u{1C}'.is_whitespace());
        assert_eq!(py_strip("\u{1F} text \u{3000}"), "text");
    }

    #[test]
    fn adversarial_runs_finish_or_error_without_panicking() {
        let inputs = [
            "a.".repeat(50_000),
            "a-1_".repeat(30_000),
            "9".repeat(100_000),
            format!("{}@", "x.".repeat(40_000)),
        ];
        for input in inputs {
            let _ = model_text(None, &input);
        }
    }
}
