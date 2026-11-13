//! HTML utility functions for content scanning.

use regex::Regex;
use scraper::{ElementRef, Html, Selector};
use std::collections::HashMap;
use std::sync::LazyLock;

use crate::context::SecurityContext;
use crate::modules::common::{extract_domain_from_url, percent_decode};

static RE_EMAIL_TEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").expect("valid email regex")
});

// `html-escape` ships the WHATWG/HTML5 named-entity table (including
// semicolon-less legacy forms).  Keep a second, bounded pass for residual
// entity-shaped tokens: an unknown `&attacker;` must not leave its letters
// between two CJK characters and thereby create a keyword-break primitive.
static RE_RESIDUAL_NAMED_ENTITY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"&[A-Za-z][A-Za-z0-9]{1,31};?").expect("valid residual HTML entity regex")
});

static RE_STYLE_BLOCK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<style\b[^>]*>(.*?)</style\s*>").expect("valid style block regex")
});

static RE_CSS_RULE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)([^{}]+)\{([^{}]*)\}").expect("valid CSS rule regex"));

static RE_HIDDEN_CSS_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    // A colour value or a small but readable font is not concealment. Opacity
    // at or below 0.02 is effectively invisible in a rendered message and is
    // treated like display:none for relation-based hidden-content checks.
    Regex::new(
        r"(?is)(?:^|[;{])\s*(?:display\s*:\s*none|visibility\s*:\s*(?:hidden|collapse)|font-size\s*:\s*(?:0(?:\.0+)?(?:px)?|(?:0?\.\d+|1(?:\.0+)?)px)|opacity\s*:\s*(?:0(?:\.0+)?|0?\.0[1-2]|0\.0[1-2])|color\s*:\s*transparent|clip(?:-path)?\s*:\s*inset\s*\(\s*100%|text-indent\s*:\s*-\d{3,}px|left\s*:\s*-\d{3,}px)(?:\s*!important)?\s*(?:[;}]|$)",
    )
    .expect("valid hidden CSS declaration regex")
});

// This intentionally recognizes only actual HTML tags, leaving a bare '<'
// as literal text just as the legacy stripper does.
static RE_HTML_TAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<!--.*?-->|</?[a-z](?:[^>"']|"[^"]*"|'[^']*')*>"#)
        .expect("valid HTML tag regex")
});

static RE_CLASS_ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)(?:^|\s)class\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#)
        .expect("valid class attribute regex")
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CssCombinator {
    Descendant,
    Child,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CssCompound {
    tag: Option<String>,
    classes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HiddenCssSelector {
    compounds: Vec<CssCompound>,
    combinators: Vec<CssCombinator>,
}

fn parse_css_compound(token: &str) -> Option<CssCompound> {
    let bytes = token.as_bytes();
    let mut cursor = 0;
    let mut tag = None;
    let mut classes = Vec::new();

    if bytes.first() == Some(&b'*') {
        cursor = 1;
    } else if bytes.first().is_some_and(u8::is_ascii_alphabetic) {
        let start = cursor;
        cursor += 1;
        while bytes
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            cursor += 1;
        }
        tag = Some(token[start..cursor].to_ascii_lowercase());
    }

    while cursor < bytes.len() {
        if bytes[cursor] != b'.' {
            // Pseudo classes, IDs, attributes, escapes and namespace syntax
            // need full CSS semantics. Ignore such a rule rather than letting
            // one of its class tokens hide unrelated visible content.
            return None;
        }
        cursor += 1;
        let start = cursor;
        if !bytes
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        {
            return None;
        }
        cursor += 1;
        while bytes
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
        {
            cursor += 1;
        }
        classes.push(token[start..cursor].to_ascii_lowercase());
    }

    (tag.is_some() || !classes.is_empty()).then_some(CssCompound { tag, classes })
}

fn parse_hidden_css_selector(selector: &str) -> Option<HiddenCssSelector> {
    let bytes = selector.as_bytes();
    let mut cursor = 0;
    let mut compounds = Vec::new();
    let mut combinators = Vec::new();
    let mut pending_combinator = None;

    loop {
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if cursor == bytes.len() {
            break;
        }
        if let Some(combinator) = pending_combinator.take() {
            combinators.push(combinator);
        }

        let start = cursor;
        while bytes
            .get(cursor)
            .is_some_and(|byte| !byte.is_ascii_whitespace() && *byte != b'>')
        {
            cursor += 1;
        }
        if start == cursor {
            return None;
        }
        compounds.push(parse_css_compound(&selector[start..cursor])?);

        let mut had_whitespace = false;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            had_whitespace = true;
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b'>') {
            cursor += 1;
            pending_combinator = Some(CssCombinator::Child);
        } else if cursor < bytes.len() && had_whitespace {
            pending_combinator = Some(CssCombinator::Descendant);
        } else if cursor < bytes.len() {
            return None;
        }
    }

    (pending_combinator.is_none()
        && !compounds.is_empty()
        && combinators.len() + 1 == compounds.len())
    .then_some(HiddenCssSelector {
        compounds,
        combinators,
    })
}

fn hidden_css_selectors(html: &str) -> Vec<HiddenCssSelector> {
    let mut selectors = Vec::new();

    for style_block in RE_STYLE_BLOCK.captures_iter(html) {
        let Some(css) = style_block.get(1).map(|m| m.as_str()) else {
            continue;
        };
        for rule in RE_CSS_RULE.captures_iter(css) {
            let Some(selector) = rule.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let Some(declarations) = rule.get(2).map(|m| m.as_str()) else {
                continue;
            };
            if !RE_HIDDEN_CSS_DECLARATION.is_match(declarations) {
                continue;
            }
            for selector_group in selector.split(',') {
                if let Some(selector) = parse_hidden_css_selector(selector_group.trim()) {
                    selectors.push(selector);
                }
            }
        }
    }

    selectors
}

fn tag_name(tag: &str) -> Option<&str> {
    let mut body = tag.strip_prefix('<')?;
    body = body.strip_prefix('/').unwrap_or(body).trim_start();
    let end = body
        .find(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-' && ch != ':')
        .unwrap_or(body.len());
    (end > 0).then(|| &body[..end])
}

/// Read an actual attribute rather than matching attribute-shaped text inside
/// another value. Boolean attributes are present even without an equals sign.
pub(crate) fn html_tag_attribute(tag: &str, wanted: &str) -> Option<String> {
    let bytes = tag.as_bytes();
    let mut cursor = 1;
    while cursor < bytes.len() {
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_whitespace() || matches!(bytes[cursor], b'/' | b'>'))
        {
            cursor += 1;
        }
        let start = cursor;
        while cursor < bytes.len()
            && !bytes[cursor].is_ascii_whitespace()
            && !matches!(bytes[cursor], b'=' | b'>' | b'/')
        {
            cursor += 1;
        }
        if cursor == start {
            cursor += 1;
            continue;
        }
        let name = &tag[start..cursor];
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'=') {
            if name.eq_ignore_ascii_case(wanted) {
                return Some(String::new());
            }
            continue;
        }
        cursor += 1;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let quote = bytes
            .get(cursor)
            .copied()
            .filter(|byte| matches!(byte, b'\'' | b'"'));
        if quote.is_some() {
            cursor += 1;
        }
        let value_start = cursor;
        while cursor < bytes.len()
            && match quote {
                Some(quote) => bytes[cursor] != quote,
                None => !bytes[cursor].is_ascii_whitespace() && bytes[cursor] != b'>',
            }
        {
            cursor += 1;
        }
        let value = &tag[value_start..cursor];
        if quote.is_some() {
            cursor += usize::from(cursor < bytes.len());
        }
        if name.eq_ignore_ascii_case(wanted) {
            return Some(vigilyx_core::models::EmailContent::decode_html_attribute_entities(value));
        }
    }
    None
}

fn is_void_tag(name: &str) -> bool {
    matches!(
        name,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

/// Nearest open ancestors a descendant or child combinator inspects. Every
/// opening tag used to walk (and regex-parse) the whole open-element stack,
/// so 200k unclosed `<div>` plus `.a .b{display:none}` cost hours of CPU.
/// Real mail nests far shallower; unsupported selector syntax is already
/// ignored, so a deeper ancestor is treated the same way.
const MAX_SELECTOR_ANCESTOR_SCAN: usize = 32;

/// Compound evaluations allowed for class-based matching in one tag walk.
/// This bounds the tags × selectors product that the ancestor window does
/// not; once spent, the remaining tags are not class-matched and the walk is
/// logged as approximate.
const MAX_SELECTOR_MATCH_WORK: usize = 8_000_000;

fn tag_classes(tag: &str) -> Vec<String> {
    RE_CLASS_ATTRIBUTE
        .captures_iter(tag)
        .filter_map(|captures| {
            captures
                .get(1)
                .or_else(|| captures.get(2))
                .or_else(|| captures.get(3))
        })
        .flat_map(|value| value.as_str().split_ascii_whitespace())
        .map(str::to_ascii_lowercase)
        .collect()
}

/// One open element of the regex tag walk. The lowercase name and class list
/// are parsed once when the element opens instead of once per descendant.
#[derive(Debug)]
struct OpenElement {
    name: String,
    classes: Vec<String>,
    hidden: bool,
}

impl OpenElement {
    fn from_tag(tag: &str, hidden: bool) -> Option<Self> {
        Some(Self {
            name: tag_name(tag)?.to_ascii_lowercase(),
            classes: tag_classes(tag),
            hidden,
        })
    }
}

/// Open-element stack for the lenient regex tag walk. A close tag pops back
/// to the nearest open element with the same name, draining unclosed
/// descendants. The per-name position index keeps that O(1) amortized: a
/// flood of unmatched close tags used to `rposition` over the whole stack.
#[derive(Default)]
struct OpenElementStack {
    elements: Vec<OpenElement>,
    positions_by_name: HashMap<String, Vec<usize>>,
}

impl OpenElementStack {
    fn push(&mut self, element: OpenElement) {
        let position = self.elements.len();
        match self.positions_by_name.get_mut(element.name.as_str()) {
            Some(positions) => positions.push(position),
            None => {
                self.positions_by_name
                    .insert(element.name.clone(), vec![position]);
            }
        }
        self.elements.push(element);
    }

    /// Close the nearest open `name` element and everything opened inside
    /// it. Returns how many hidden elements were drained.
    fn close(&mut self, name: &str) -> usize {
        let Some(position) = self
            .positions_by_name
            .get(name)
            .and_then(|positions| positions.last().copied())
        else {
            return 0;
        };
        let mut hidden_drained = 0;
        while self.elements.len() > position {
            let Some(element) = self.elements.pop() else {
                break;
            };
            if let Some(positions) = self.positions_by_name.get_mut(element.name.as_str()) {
                positions.pop();
            }
            hidden_drained += usize::from(element.hidden);
        }
        hidden_drained
    }

    fn ancestors_nearest_first(&self) -> impl Iterator<Item = &OpenElement> + Clone {
        self.elements.iter().rev().take(MAX_SELECTOR_ANCESTOR_SCAN)
    }
}

struct SelectorMatchBudget {
    remaining: usize,
    exhausted: bool,
}

impl SelectorMatchBudget {
    fn new() -> Self {
        Self::with_limit(MAX_SELECTOR_MATCH_WORK)
    }

    fn with_limit(limit: usize) -> Self {
        Self {
            remaining: limit,
            exhausted: false,
        }
    }

    fn spend(&mut self) -> bool {
        if self.remaining == 0 {
            self.exhausted = true;
            return false;
        }
        self.remaining -= 1;
        true
    }
}

fn compound_matches_open(name: &str, classes: &[String], compound: &CssCompound) -> bool {
    if compound
        .tag
        .as_deref()
        .is_some_and(|expected| expected != name)
    {
        return false;
    }
    compound
        .classes
        .iter()
        .all(|expected| classes.contains(expected))
}

fn selector_matches_tag<'a>(
    selector: &HiddenCssSelector,
    name: &str,
    classes: &[String],
    mut ancestors_nearest_first: impl Iterator<Item = &'a OpenElement>,
    budget: &mut SelectorMatchBudget,
) -> bool {
    let Some(last) = selector.compounds.len().checked_sub(1) else {
        return false;
    };
    if !budget.spend() || !compound_matches_open(name, classes, &selector.compounds[last]) {
        return false;
    }

    for index in (0..last).rev() {
        match selector.combinators[index] {
            CssCombinator::Child => {
                let Some(ancestor) = ancestors_nearest_first.next() else {
                    return false;
                };
                if !budget.spend()
                    || !compound_matches_open(
                        &ancestor.name,
                        &ancestor.classes,
                        &selector.compounds[index],
                    )
                {
                    return false;
                }
            }
            CssCombinator::Descendant => {
                let mut found = false;
                for ancestor in ancestors_nearest_first.by_ref() {
                    if !budget.spend() {
                        return false;
                    }
                    if compound_matches_open(
                        &ancestor.name,
                        &ancestor.classes,
                        &selector.compounds[index],
                    ) {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return false;
                }
            }
        }
    }
    true
}

fn tag_matches_hidden_selector<'a>(
    name: &str,
    classes: &[String],
    ancestors_nearest_first: impl Iterator<Item = &'a OpenElement> + Clone,
    selectors: &[HiddenCssSelector],
    budget: &mut SelectorMatchBudget,
) -> bool {
    selectors.iter().any(|selector| {
        selector_matches_tag(
            selector,
            name,
            classes,
            ancestors_nearest_first.clone(),
            budget,
        )
    })
}

fn element_matches_compound(element: ElementRef<'_>, compound: &CssCompound) -> bool {
    if compound
        .tag
        .as_deref()
        .is_some_and(|expected| !element.value().name().eq_ignore_ascii_case(expected))
    {
        return false;
    }
    let classes = element.attr("class").unwrap_or_default();
    compound.classes.iter().all(|expected| {
        classes
            .split_ascii_whitespace()
            .any(|actual| actual.eq_ignore_ascii_case(expected))
    })
}

fn selector_matches_element(element: ElementRef<'_>, selector: &HiddenCssSelector) -> bool {
    let Some(last) = selector.compounds.len().checked_sub(1) else {
        return false;
    };
    if !element_matches_compound(element, &selector.compounds[last]) {
        return false;
    }
    let ancestors = element
        .ancestors()
        .filter_map(ElementRef::wrap)
        .collect::<Vec<_>>();
    let mut ancestor_cursor = 0;
    for index in (0..last).rev() {
        match selector.combinators[index] {
            CssCombinator::Child => {
                let Some(ancestor) = ancestors.get(ancestor_cursor) else {
                    return false;
                };
                if !element_matches_compound(*ancestor, &selector.compounds[index]) {
                    return false;
                }
                ancestor_cursor += 1;
            }
            CssCombinator::Descendant => {
                let Some(offset) = ancestors[ancestor_cursor..].iter().position(|ancestor| {
                    element_matches_compound(*ancestor, &selector.compounds[index])
                }) else {
                    return false;
                };
                ancestor_cursor += offset + 1;
            }
        }
    }
    true
}

/// A URL-bearing element that is actually hidden in the recipient's rendered
/// view, together with text from the nearest local block.  The local text is
/// deliberately bounded and is used by compound detectors to prevent a
/// footer label or subject from being borrowed into an unrelated link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HiddenAnchorFact {
    pub(crate) href: String,
    pub(crate) anchor_text: String,
    pub(crate) local_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VisibleAnchorFact {
    /// Stable ordinal in the source document, before visibility filtering.
    /// Equal href strings do not imply that two anchors have equal visibility.
    pub(crate) source_index: usize,
    pub(crate) href: String,
    pub(crate) anchor_text: String,
}

const MAX_HIDDEN_ANCHOR_FACTS: usize = 128;
const MAX_HIDDEN_ANCHOR_TEXT_CHARS: usize = 512;

fn bounded_element_text(element: ElementRef<'_>) -> String {
    element
        .text()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_HIDDEN_ANCHOR_TEXT_CHARS)
        .collect()
}

fn element_is_hidden(element: ElementRef<'_>, hidden_selectors: &[HiddenCssSelector]) -> bool {
    element.attr("hidden").is_some()
        || (element.value().name() == "details" && element.attr("open").is_none())
        || element
            .attr("style")
            .is_some_and(|style| RE_HIDDEN_CSS_DECLARATION.is_match(style))
        || hidden_selectors
            .iter()
            .any(|selector| selector_matches_element(element, selector))
}

pub(crate) fn visible_anchor_facts(html: &str) -> Vec<VisibleAnchorFact> {
    if html.len() > 2 * 1024 * 1024 {
        return Vec::new();
    }

    let hidden_selectors = hidden_css_selectors(html);
    let document = Html::parse_document(html);
    let selector = Selector::parse("a[href]").expect("valid anchor selector");

    document
        .select(&selector)
        .enumerate()
        .filter_map(|(source_index, anchor)| {
            let hidden = std::iter::once(anchor)
                .chain(anchor.ancestors().filter_map(ElementRef::wrap))
                .any(|element| element_is_hidden(element, &hidden_selectors));
            if hidden {
                return None;
            }

            let href = anchor.attr("href")?.trim();
            (!href.is_empty() && href.len() <= 16_384).then(|| VisibleAnchorFact {
                source_index,
                href: decode_html_entities(href),
                anchor_text: bounded_element_text(anchor),
            })
        })
        .take(MAX_HIDDEN_ANCHOR_FACTS)
        .collect()
}

pub(crate) fn hidden_text_region_facts(html: &str) -> Vec<String> {
    if html.len() > 2 * 1024 * 1024 {
        return Vec::new();
    }

    let hidden_selectors = hidden_css_selectors(html);
    let document = Html::parse_document(html);
    let selector = Selector::parse("*").expect("valid any-element selector");
    document
        .select(&selector)
        .filter(|element| {
            element_is_hidden(*element, &hidden_selectors)
                && !element
                    .ancestors()
                    .filter_map(ElementRef::wrap)
                    .any(|ancestor| element_is_hidden(ancestor, &hidden_selectors))
        })
        .map(bounded_element_text)
        .filter(|text| !text.trim().is_empty())
        .take(MAX_HIDDEN_ANCHOR_FACTS)
        .collect()
}

/// Extract only links that have a concrete concealment mechanism.  This is
/// separate from `strip_html_tags`: the latter models visible text, while
/// this function preserves enough DOM locality for relation detectors.
pub(crate) fn hidden_anchor_facts(html: &str) -> Vec<HiddenAnchorFact> {
    if html.len() > 2 * 1024 * 1024 {
        return Vec::new();
    }

    let hidden_selectors = hidden_css_selectors(html);
    let document = Html::parse_document(html);
    let selector = Selector::parse("a[href]").expect("valid anchor selector");

    document
        .select(&selector)
        .filter_map(|anchor| {
            let hidden = std::iter::once(anchor)
                .chain(anchor.ancestors().filter_map(ElementRef::wrap))
                .any(|element| element_is_hidden(element, &hidden_selectors));
            if !hidden {
                return None;
            }

            let href = anchor.attr("href")?.trim();
            if href.is_empty() || href.len() > 16_384 {
                return None;
            }

            let local_container = anchor
                .ancestors()
                .filter_map(ElementRef::wrap)
                .find(|element| {
                    matches!(
                        element.value().name(),
                        "p" | "div"
                            | "li"
                            | "td"
                            | "th"
                            | "section"
                            | "article"
                            | "footer"
                            | "header"
                    )
                })
                .unwrap_or(anchor);

            Some(HiddenAnchorFact {
                href: decode_html_entities(href),
                anchor_text: bounded_element_text(anchor),
                local_text: bounded_element_text(local_container),
            })
        })
        .take(MAX_HIDDEN_ANCHOR_FACTS)
        .collect()
}

/// Extract hidden or collapsed HTML regions that contain a literal HTTP(S)
/// destination. This complements `hidden_anchor_facts`: mail clients may
/// auto-link a URL only after a recipient expands a `<details>` block, and
/// attackers also place printed destinations in off-screen or nearly
/// transparent text without an `<a>` element.
pub(crate) fn hidden_external_destination_facts(html: &str) -> Vec<HiddenAnchorFact> {
    static RE_HTTP_URL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)https?://[^\s<>\"']+"#).expect("valid embedded URL regex")
    });

    if html.len() > 2 * 1024 * 1024 {
        return Vec::new();
    }

    let mut facts = hidden_anchor_facts(html);
    let hidden_selectors = hidden_css_selectors(html);
    let document = Html::parse_document(html);
    let selector = Selector::parse("*").expect("valid any-element selector");

    for element in document.select(&selector) {
        if matches!(element.value().name(), "a" | "script" | "style") {
            continue;
        }
        let is_hidden_root = element_is_hidden(element, &hidden_selectors)
            && !element
                .ancestors()
                .filter_map(ElementRef::wrap)
                .any(|ancestor| element_is_hidden(ancestor, &hidden_selectors));
        if !is_hidden_root {
            continue;
        }

        let local_text = bounded_element_text(element);
        for matched in RE_HTTP_URL.find_iter(&local_text) {
            let destination = matched
                .as_str()
                .trim_end_matches([
                    '.', ',', ';', ':', '!', '?', '，', '。', '；', '：', '！', '？', ')', '）',
                    '】',
                ])
                .to_string();
            if destination.is_empty()
                || facts.iter().any(|fact| fact.href == destination)
                || facts.len() >= MAX_HIDDEN_ANCHOR_FACTS
            {
                continue;
            }
            facts.push(HiddenAnchorFact {
                href: destination.clone(),
                anchor_text: destination,
                local_text: local_text.clone(),
            });
        }

        if facts.len() >= MAX_HIDDEN_ANCHOR_FACTS {
            break;
        }
    }

    facts
}

/// Count content-bearing elements whose class is hidden by a `<style>` rule.
/// Layout-only void/table elements are excluded to match inline CSS handling.
pub(crate) fn count_css_hidden_class_markup(html: &str) -> usize {
    let hidden_selectors = hidden_css_selectors(html);
    if hidden_selectors.is_empty() {
        return 0;
    }

    let mut count = 0;
    let mut stack = OpenElementStack::default();
    let mut budget = SelectorMatchBudget::new();
    for matched in RE_HTML_TAG.find_iter(html) {
        let tag = matched.as_str();
        let Some(element) = OpenElement::from_tag(tag, false) else {
            continue;
        };
        if tag.starts_with("</") {
            stack.close(&element.name);
            continue;
        }
        let void = is_void_tag(&element.name) || tag.trim_end().ends_with("/>");
        if !void
            && !matches!(element.name.as_str(), "td" | "th" | "tr" | "table")
            && !RE_HIDDEN_CSS_DECLARATION.is_match(tag)
        {
            count += usize::from(tag_matches_hidden_selector(
                &element.name,
                &element.classes,
                stack.ancestors_nearest_first(),
                &hidden_selectors,
                &mut budget,
            ));
        }
        if !void {
            stack.push(element);
        }
    }
    if budget.exhausted {
        tracing::warn!(
            hidden_class_count = count,
            "CSS 隐藏类匹配预算耗尽 — 计数为近似值"
        );
    }
    count
}

/// Remove hidden element subtrees before tag stripping. Existing keyword
/// scanning requests class-based filtering; semantic projections additionally
/// exclude inline and boolean concealment from the recipient-visible view.
fn remove_hidden_element_content(
    html: &str,
    hidden_selectors: &[HiddenCssSelector],
    include_inline_hidden: bool,
) -> String {
    if hidden_selectors.is_empty() && !include_inline_hidden {
        return html.to_owned();
    }

    let mut result = String::with_capacity(html.len());
    let mut cursor = 0usize;
    let mut hidden_depth = 0usize;
    let mut stack = OpenElementStack::default();
    let mut budget = SelectorMatchBudget::new();

    for matched in RE_HTML_TAG.find_iter(html) {
        if hidden_depth == 0 {
            result.push_str(&html[cursor..matched.start()]);
        }

        let tag = matched.as_str();
        if let Some(name) = tag_name(tag) {
            let name_lower = name.to_ascii_lowercase();
            if tag.starts_with("</") {
                let was_hidden = hidden_depth > 0;
                hidden_depth = hidden_depth.saturating_sub(stack.close(&name_lower));
                if !was_hidden {
                    result.push_str(tag);
                }
            } else {
                let void = is_void_tag(&name_lower) || tag.trim_end().ends_with("/>");
                // Inside a hidden subtree every element is hidden already and
                // can only ever be an ancestor of hidden elements, so neither
                // its classes nor selector matching are needed there.
                let classes = if void || hidden_depth > 0 {
                    Vec::new()
                } else {
                    tag_classes(tag)
                };
                let hidden_by_class = !void
                    && hidden_depth == 0
                    && !hidden_selectors.is_empty()
                    && tag_matches_hidden_selector(
                        &name_lower,
                        &classes,
                        stack.ancestors_nearest_first(),
                        hidden_selectors,
                        &mut budget,
                    );
                let element_hidden = !void
                    && (hidden_depth > 0
                        || hidden_by_class
                        || (include_inline_hidden
                            && (html_tag_attribute(tag, "hidden").is_some()
                                || html_tag_attribute(tag, "style").is_some_and(|style| {
                                    RE_HIDDEN_CSS_DECLARATION.is_match(&style)
                                })
                                || (name_lower == "details"
                                    && html_tag_attribute(tag, "open").is_none()))));
                if !void {
                    stack.push(OpenElement {
                        name: name_lower,
                        classes,
                        hidden: element_hidden,
                    });
                    if element_hidden {
                        hidden_depth += 1;
                    }
                }
                if hidden_depth == 0 {
                    result.push_str(tag);
                }
            }
        } else if hidden_depth == 0 {
            result.push_str(tag);
        }

        cursor = matched.end();
    }

    if hidden_depth == 0 {
        result.push_str(&html[cursor..]);
    }
    if budget.exhausted {
        tracing::warn!(
            html_bytes = html.len(),
            "CSS 隐藏类匹配预算耗尽 — 隐藏内容移除为近似结果"
        );
    }
    result
}

/// Semantic action targets must come from the recipient-visible view. Keep
/// hidden markup available to the dedicated concealment detectors while
/// preventing hidden anchor annotations from entering visible action spans.
pub(crate) fn strip_recipient_visible_html_tags(html: &str, stylesheet_source: &str) -> String {
    let html_without_comments = strip_html_comments(html);
    // Semantic annotations escape visible text. Derive CSS selectors from
    // the original source so a child combinator cannot become literal &gt;.
    let stylesheet_source = strip_html_comments(stylesheet_source);
    let hidden_selectors = hidden_css_selectors(&stylesheet_source);
    let visible_html =
        remove_hidden_element_content(&html_without_comments, &hidden_selectors, true);
    strip_html_tag_markup(&visible_html)
}

/// Remove inactive HTML comments before deriving the recipient-visible text view.
///
/// Template engines commonly leave inactive branches containing old links,
/// QR instructions, or urgency copy inside `<!-- ... -->`. Those bytes are
/// not rendered for the recipient and must not become semantic evidence.
/// Outlook conditional comments are retained because their payload is rendered
/// by a real recipient client.
/// Treat an unterminated comment as extending to the end, matching browser
/// parsing closely enough for detection purposes.
fn strip_html_comments(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut cursor = 0usize;

    while let Some(relative_start) = html[cursor..].find("<!--") {
        let start = cursor + relative_start;
        result.push_str(&html[cursor..start]);

        let comment_body_start = start + "<!--".len();
        let Some(relative_end) = html[comment_body_start..].find("-->") else {
            return result;
        };
        let comment_body_end = comment_body_start + relative_end;
        let comment_body = &html[comment_body_start..comment_body_end];
        if let Some(payload) = conditional_comment_payload(comment_body) {
            result.push_str(payload);
        }
        cursor = comment_body_start + relative_end + "-->".len();
    }

    result.push_str(&html[cursor..]);
    result
}

fn conditional_comment_payload(comment: &str) -> Option<&str> {
    let trimmed = comment.trim_start();
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("[if ") && !lower.starts_with("[if!") {
        return None;
    }

    let payload_start = trimmed.find('>')? + 1;
    let payload_end = lower.rfind("<![endif]")?;
    (payload_start <= payload_end).then(|| &trimmed[payload_start..payload_end])
}

/// Simple HTML tag stripper (does not need to be perfect; just for keyword matching)
pub(crate) fn strip_html_tags(html: &str) -> String {
    let html_without_comments = strip_html_comments(html);
    let hidden_selectors = hidden_css_selectors(&html_without_comments);
    let html = remove_hidden_element_content(&html_without_comments, &hidden_selectors, false);
    strip_html_tag_markup(&html)
}

fn strip_html_tag_markup(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut chars = html.chars().peekable();
    let mut in_tag = false;
    let mut attribute_quote = None;
    while let Some(ch) = chars.next() {
        match ch {
            '<' if !in_tag => {
                // HTML5: '<' only opens markup when followed by an ASCII
                // letter, '/' or '!'. Otherwise it is literal text — an
                // attacker must not hide the rest of the body behind a bare
                // '<' that never closes.
                match chars.peek() {
                    Some(next) if next.is_ascii_alphabetic() || *next == '/' || *next == '!' => {
                        in_tag = true;
                        attribute_quote = None;
                    }
                    _ => result.push('<'),
                }
            }
            '\'' | '"' if in_tag => {
                if attribute_quote == Some(ch) {
                    attribute_quote = None;
                } else if attribute_quote.is_none() {
                    attribute_quote = Some(ch);
                }
            }
            '>' if in_tag && attribute_quote.is_none() => {
                in_tag = false;
                result.push(' ');
            }
            _ if !in_tag => result.push(ch),
            _ => {}
        }
    }
    // HTML Decode: prevent &#x5BC6;&#x7801; (Password) Keywordsdetect
    decode_html_entities(&result)
}

/// Decode HTML,preventAttack Encode Keywordsmatch
pub(crate) fn decode_html_entities(text: &str) -> String {
    // Decode the complete HTML5 entity set instead of a six-entry allowlist.
    // This is deliberately performed before numeric compatibility handling so
    // nested/double encoded references retain the historical behavior.
    let mut result = html_escape::decode_html_entities(text).into_owned();

    // : &#; And &#x 6Base/Radix;
    // ofLoopDecode,Avoid regex Dependency
    let mut search_from = 0usize;
    while let Some(rel) = result.get(search_from..).and_then(|s| s.find("&#")) {
        let start = search_from + rel;
        let rest = &result[start + 2..];

        // HTML spec: numeric character references do NOT require a trailing
        // semicolon — browsers decode "&#36134户" as "账户". Attackers use
        // the semicolon-less form to slip past keyword scans. Parse an
        // optional x/X marker plus digits first, then optionally consume ';'.
        let (hex, digits) = match rest.strip_prefix('x').or_else(|| rest.strip_prefix('X')) {
            Some(hex_rest) => {
                let len = hex_rest
                    .chars()
                    .take_while(|c| c.is_ascii_hexdigit())
                    .count();
                (true, len)
            }
            None => {
                let len = rest.chars().take_while(|c| c.is_ascii_digit()).count();
                (false, len)
            }
        };

        if digits >= 1 {
            // Guard: at most 7 decimal / 6 hex digits can encode a Unicode
            // scalar. Longer digit runs (order numbers, IDs) are literal text.
            let marker_len = usize::from(hex);
            let within_bounds = digits <= if hex { 6 } else { 7 };
            let span_end = start + 2 + marker_len + digits;
            let digit_str = &result[start + 2 + marker_len..span_end];
            let value = if hex {
                u32::from_str_radix(digit_str, 16).ok()
            } else {
                digit_str.parse::<u32>().ok()
            };
            let decoded = within_bounds
                .then(|| value.and_then(char::from_u32))
                .flatten();
            // Consume a trailing semicolon when present.
            let consumed = span_end + usize::from(result[span_end..].starts_with(';'));
            if let Some(ch) = decoded {
                let before = &result[..start];
                let after = &result[consumed..];
                result = format!("{}{}{}", before, ch, after);
                // Re-scan from the replacement position: the decoded char may
                // complete a nested entity (e.g. "&#38;#60;" -> "<").
                search_from = start;
            } else if within_bounds && value.is_some() {
                // Out-of-range / surrogate scalar: drop the span so an
                // attacker cannot break keyword contiguity with it.
                let after = &result[consumed..];
                result = format!("{}{}", &result[..start], after);
                search_from = start;
            } else {
                // Too many digits to be a character reference: keep literal.
                search_from = start + 2;
            }
            continue;
        }

        if let Some(end) = rest.find(';') {
            let entity = &rest[..end];
            // Numeric entities are at most ~8 chars ("&#x10FFFF;"). Treat the
            // span as entity-like only when it is short and alphanumeric;
            // anything else is ordinary text that happens to contain "&#".
            let entity_like = !entity.is_empty()
                && entity.len() <= 10
                && !entity.contains("&#")
                && entity.chars().all(|c| c.is_ascii_alphanumeric());
            if entity_like {
                // Undecodable entity (e.g. "&#xZZ;"): drop the "&#...;" span
                // so an attacker cannot break keyword contiguity with it, and
                // keep decoding the rest instead of aborting the whole pass.
                let after = &result[start + 2 + end + 1..];
                result = format!("{}{}", &result[..start], after);
                search_from = start;
            } else {
                // Not entity-like: keep "&#" as literal text and continue.
                search_from = start + 2;
            }
        } else {
            // No digits and no terminating ';': keep "&#" as literal text.
            search_from = start + 2;
        }
    }

    // Browser-visible text cannot contain the literal spelling of an unknown
    // named entity.  Removing the whole residual token (rather than keeping
    // its alphabetic name) prevents `账&unknown;户` from becoming a stable
    // keyword separator.  Short ordinary ampersand text such as `R&D` is not
    // matched because the entity name requires at least two characters.
    RE_RESIDUAL_NAMED_ENTITY
        .replace_all(&result, "")
        .into_owned()
}

fn extract_normalized_email(text: &str) -> Option<String> {
    RE_EMAIL_TEXT
        .find(text)
        .map(|m| m.as_str().to_ascii_lowercase())
}

fn detect_contact_card_email(ctx: &SecurityContext) -> Option<String> {
    ctx.session
        .mail_from
        .as_deref()
        .and_then(extract_normalized_email)
        .or_else(|| {
            ctx.session
                .content
                .body_text
                .as_deref()
                .and_then(extract_normalized_email)
        })
        .or_else(|| {
            ctx.session
                .content
                .links
                .iter()
                .filter_map(|link| link.text.as_deref())
                .find_map(extract_normalized_email)
        })
}

fn is_business_card_profile_url(url: &str, contact_email: &str) -> bool {
    let decoded = percent_decode(url).to_ascii_lowercase();
    let Some(domain) = extract_domain_from_url(&decoded) else {
        return false;
    };

    matches!(domain.as_str(), "wx.mail.qq.com" | "mail.qq.com")
        && decoded.contains("readmail_businesscard_midpage")
        && decoded.contains(contact_email)
}

fn is_business_card_avatar_url(url: &str) -> bool {
    extract_domain_from_url(url).is_some_and(|domain| domain.ends_with("qlogo.cn"))
}

pub(super) fn is_embedded_contact_card_layout(ctx: &SecurityContext) -> bool {
    let Some(contact_email) = detect_contact_card_email(ctx) else {
        return false;
    };
    let Some(body_html) = ctx.session.content.body_html.as_deref() else {
        return false;
    };
    let html_lower = body_html.to_ascii_lowercase();
    let has_contact_card_markup = html_lower.contains("xm_write_card")
        || html_lower.contains("readmail_businesscard_midpage")
        || html_lower.contains("qlogo.cn");

    if !has_contact_card_markup {
        return false;
    }

    let mut business_card_links = 0usize;
    for link in &ctx.session.content.links {
        if is_business_card_profile_url(&link.url, &contact_email) {
            business_card_links += 1;
            continue;
        }
        if is_business_card_avatar_url(&link.url) {
            continue;
        }
        return false;
    }

    business_card_links > 0
}

#[cfg(test)]
mod tests {
    use super::{
        count_css_hidden_class_markup, decode_html_entities, hidden_anchor_facts,
        hidden_external_destination_facts, hidden_text_region_facts, strip_html_tags,
        visible_anchor_facts,
    };

    #[test]
    fn hidden_anchor_facts_require_actual_concealment_and_keep_local_scope() {
        let ordinary_signature = r#"
            <p><span style="color:#000000">邮箱：support@example.com</span><br>
            官网：<a href="https://example.net/home">https://example.net/home</a></p>
        "#;
        assert!(hidden_anchor_facts(ordinary_signature).is_empty());

        let hidden_action = r#"
            <p>服务通知：<a href="https://example.net/preferences" style="display:none">退订</a></p>
        "#;
        let facts = hidden_anchor_facts(hidden_action);
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].href, "https://example.net/preferences");
        assert_eq!(facts[0].anchor_text, "退订");
        assert!(facts[0].local_text.contains("服务通知"));

        let hidden_by_class = r#"
            <style>.cloak { visibility:hidden; }</style>
            <p>系统维护：<a class="cloak" href="https://example.net/update">下载</a></p>
        "#;
        assert_eq!(hidden_anchor_facts(hidden_by_class).len(), 1);

        let unmatched_descendant_selector = r#"
            <style>.outer .never { display: none; }</style>
            <p><a class="outer" href="https://example.net/visible">正常入口</a></p>
        "#;
        assert!(hidden_anchor_facts(unmatched_descendant_selector).is_empty());
        assert_eq!(visible_anchor_facts(unmatched_descendant_selector).len(), 1);
    }

    #[test]
    fn hidden_external_destinations_cover_offscreen_opacity_and_collapsed_details() {
        let html = r#"
            <p>可见通知</p>
            <div style="position:absolute;left:-9999px">账号需登录完成安全验证 https://job-sec.example.vip/r</div>
            <p style="opacity:0.02">系统维护：重新激活邮箱 https://mail-sec.example.info/a</p>
            <p style="font-size:0.3px;color:#fff">隐藏：重新绑定 API Key 与 U盾 https://risk.example.info/a</p>
            <details><summary>点击展开详情</summary><p>需完成身份补录 https://id-check.example.info/f</p></details>
        "#;

        let facts = hidden_external_destination_facts(html);
        assert_eq!(facts.len(), 4, "facts={facts:?}");
        assert!(
            facts
                .iter()
                .any(|fact| fact.href == "https://job-sec.example.vip/r")
        );
        assert!(
            facts
                .iter()
                .any(|fact| fact.href == "https://mail-sec.example.info/a")
        );
        assert!(
            facts
                .iter()
                .any(|fact| fact.href == "https://id-check.example.info/f")
        );
        assert!(
            facts
                .iter()
                .any(|fact| fact.href == "https://risk.example.info/a")
        );
    }

    #[test]
    fn hidden_text_and_visible_anchor_keep_separate_provenance() {
        let html = r#"
            <p><a href="https://risk.example/rms">登录风控系统处理</a></p>
            <p style="font-size:0.3px;color:#fff">全部交易员需重新绑定 API Key 与 U盾，绑定入口同上。</p>
            <p style="font-size:12px"><a href="https://news.example/unsub">退订</a></p>
        "#;

        let hidden = hidden_text_region_facts(html);
        let visible = visible_anchor_facts(html);
        assert_eq!(hidden.len(), 1, "hidden={hidden:?}");
        assert!(hidden[0].contains("API Key"));
        assert_eq!(visible.len(), 2, "visible={visible:?}");
        assert!(visible.iter().any(|fact| {
            fact.href == "https://risk.example/rms" && fact.anchor_text.contains("登录")
        }));
    }

    #[test]
    fn readable_small_and_low_contrast_footer_is_not_hidden_content() {
        let html = r#"<p style="font-size:11px;color:#bbb"><a href="https://news.example/unsub">退订/管理</a></p>
            <details open><p>官网 https://news.example/info</p></details>"#;
        assert!(hidden_external_destination_facts(html).is_empty());
    }

    #[test]
    fn strip_html_tags_removes_text_hidden_by_css_class() {
        let html = r#"
            <style>.cloak { display: none; }</style>
            <p>您的账<span class="cloak">kq</span>户存在异常</p>
        "#;
        let stripped = strip_html_tags(html);
        assert!(stripped.contains("账户存在异常"), "got {stripped:?}");
        assert!(!stripped.contains("kq"), "hidden text leaked: {stripped:?}");
    }

    #[test]
    fn recipient_visible_projection_drops_inline_hidden_anchor_text_and_url() {
        let url = "http://192.0.2.60/verify/login";
        let html = format!(
            "<p>请立即点击下方链接验证身份。</p><a style='display:none' href='{url}'>{url}</a>"
        );
        let visible = super::strip_recipient_visible_html_tags(&html, &html);

        assert!(visible.contains("请立即点击下方链接验证身份"));
        assert!(
            !visible.contains(url),
            "inline-hidden href and label are not recipient-visible: {visible:?}"
        );
    }

    #[test]
    fn css_hidden_descendant_selector_does_not_hide_unmatched_ancestor() {
        let html = r#"
            <style>.outer .never, .outer > .cloak { display: none; }</style>
            <div class="outer">
                <span>可见账户通知</span>
                <span class="cloak">kq</span>
            </div>
        "#;
        let selectors = super::hidden_css_selectors(html);
        assert_eq!(selectors.len(), 2, "selectors={selectors:?}");
        let ancestor =
            super::OpenElement::from_tag(r#"<div class="outer">"#, false).expect("ancestor");
        let mut budget = super::SelectorMatchBudget::new();
        assert!(super::tag_matches_hidden_selector(
            "span",
            &["cloak".to_string()],
            std::iter::once(&ancestor),
            &selectors,
            &mut budget,
        ));
        let stripped = strip_html_tags(html);
        assert!(stripped.contains("可见账户通知"), "got {stripped:?}");
        assert!(
            !stripped.contains("kq"),
            "matching hidden child leaked: {stripped:?}"
        );
        assert_eq!(count_css_hidden_class_markup(html), 1);
    }

    #[test]
    fn deep_unclosed_nesting_stays_bounded() {
        // Regression: every opening tag used to walk the whole open-element
        // stack, so deep unclosed nesting with a descendant selector was
        // quadratic. The ancestor window keeps this linear.
        let depth = 20_000;
        let html = format!(
            "<style>.a .b {{ display: none; }}</style>{}<span class=\"b\">x</span>",
            "<div class=\"a\">".repeat(depth)
        );
        assert_eq!(count_css_hidden_class_markup(&html), 1);
        assert!(!strip_html_tags(&html).contains('x'));
    }

    #[test]
    fn counts_only_content_bearing_hidden_class_elements() {
        let html = r#"
            <style>.cloak { visibility: hidden; }</style>
            <img class="cloak" src="logo.png">
            <span class="cloak">one</span>
            <div class="other cloak">two</div>
        "#;
        assert_eq!(count_css_hidden_class_markup(html), 2);
    }

    #[test]
    fn decode_html_entities_skips_invalid_entity_and_continues() {
        // PoC: before the fix, a single undecodable entity aborted decoding
        // for the rest of the text, so "密&#xZZ;&#x7801;" never became "密码".
        assert_eq!(decode_html_entities("密&#xZZ;&#x7801;"), "密码");
        assert_eq!(decode_html_entities("&#x5BC6;&#x7801;"), "密码");
        // Nested double-encoding still resolves.
        assert_eq!(decode_html_entities("&#38;#60;"), "<");
        // Ordinary text that merely contains "&#" is left untouched.
        assert_eq!(decode_html_entities("fish &# chips"), "fish &# chips");
    }

    #[test]
    fn decode_html_entities_decodes_numeric_entity_without_semicolon() {
        // PoC: before the fix, only "&#36134;" (with semicolon) decoded;
        // browsers also decode the semicolon-less form, so attackers could
        // hide "账户" as "&#36134;户" -> "账&#36134户" and bypass keyword scans.
        // 36134 = U+8D26 账, 25143 = U+6237 户.
        assert_eq!(decode_html_entities("验证您的&#36134户"), "验证您的账户");
        assert_eq!(
            decode_html_entities("您的&#36134;&#25143;存在异常"),
            "您的账户存在异常"
        );
        // Hex form without semicolon: 0x7801 = 码.
        assert_eq!(decode_html_entities("密&#x7801码?"), "密码码?");
        // Digits stop at the first non-digit, per HTML spec.
        assert_eq!(decode_html_entities("&#65B"), "AB");
        // Long digit runs are order numbers, not character references.
        assert_eq!(
            decode_html_entities("订单 &#12345678 号"),
            "订单 &#12345678 号"
        );
        // Plain "&#" text is still left untouched.
        assert_eq!(decode_html_entities("fish &# chips"), "fish &# chips");
    }

    #[test]
    fn strip_html_tags_keeps_quoted_attribute_urls_out_of_visible_text() {
        for quote in ['\'', '"'] {
            let html = format!(
                "<p><a data-note={quote}one > two < three{quote} href={quote}https://attribute.example.invalid/login{quote}>Visible request.</a></p><p>https://visible.example.invalid/report</p>"
            );
            let stripped = strip_html_tags(&html);
            assert!(stripped.contains("Visible request."), "{stripped:?}");
            assert!(
                stripped.contains("https://visible.example.invalid/report"),
                "{stripped:?}"
            );
            assert!(
                !stripped.contains("attribute.example.invalid"),
                "{stripped:?}"
            );
            assert!(!stripped.contains("one > two"), "{stripped:?}");
        }
    }

    #[test]
    fn strip_html_tags_treats_bare_angle_bracket_as_literal_text() {
        // PoC: before the fix, a bare '<' swallowed everything up to the next
        // '>' (possibly the rest of the body), hiding phishing prose.
        let stripped = strip_html_tags("成本 < 预算。您的账户异常，请立即登录处理。");
        assert!(
            stripped.contains("请立即登录处理"),
            "text after a bare '<' must survive stripping, got: {stripped:?}"
        );
        assert!(stripped.contains('<'));

        // HTML5: '<' only opens markup before [a-zA-Z/!]; '>' outside a tag
        // is literal text.
        let stripped = strip_html_tags("a < b > c");
        assert_eq!(stripped, "a < b > c");

        // Real tags are still stripped.
        assert_eq!(strip_html_tags("<div>Hello</div>World"), " Hello World");
    }

    #[test]
    fn strip_html_tags_excludes_inactive_html_comment_text() {
        let html = r#"
            <p>电子发票已开具，请在税务 App 查看。</p>
            <!-- <p>请点击下方链接或扫描二维码下载并查看。</p>
                 <img src="https://fixture.invalid/qr.png">
                 <p>请尽快扫码领票。</p> -->
        "#;
        let stripped = strip_html_tags(html);

        assert!(
            stripped.contains("电子发票已开具"),
            "visible text lost: {stripped:?}"
        );
        assert!(
            !stripped.contains("扫描二维码"),
            "comment text leaked: {stripped:?}"
        );
        assert!(
            !stripped.contains("尽快扫码"),
            "comment text leaked: {stripped:?}"
        );
    }

    #[test]
    fn strip_html_tags_treats_unterminated_comment_as_inactive() {
        let stripped = strip_html_tags("<p>visible</p><!-- stale QR instruction");
        assert!(
            stripped.contains("visible"),
            "visible text lost: {stripped:?}"
        );
        assert!(
            !stripped.contains("stale QR"),
            "unterminated comment leaked: {stripped:?}"
        );
    }

    #[test]
    fn strip_html_tags_preserves_outlook_conditional_comment_payload() {
        let stripped = strip_html_tags(
            "<!--[if mso]><p>请在 Outlook 中查看发票</p><![endif]--><p>可见正文</p>",
        );

        assert!(stripped.contains("请在 Outlook 中查看发票"));
        assert!(stripped.contains("可见正文"));
    }

    #[test]
    fn decode_html_entities_covers_html5_named_whitespace_entities() {
        let decoded = decode_html_entities("您的账&hairsp;户&Tab;存在&NewLine;异常&thinsp;登录");
        assert_eq!(decoded, "您的账\u{200A}户\u{0009}存在\n异常\u{2009}登录");
    }

    #[test]
    fn unknown_named_entity_cannot_break_keyword_contiguity() {
        assert_eq!(
            decode_html_entities("您的账&unknownentity;户存在异常"),
            "您的账户存在异常"
        );
    }
}
