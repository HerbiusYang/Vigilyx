//! Bounded action certificates for policy decisions. These records do not
//! add detector score or claim that a destination was fetched/authenticated.

use super::*;

fn without_code_quotes(text: &str) -> String {
    static CODE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?s)```.*?```|`[^`]*`").expect("code quote regex"));
    // Preserve a quoted boundary rather than joining the surrounding prose.
    CODE.replace_all(text, "\n> quoted code\n").into_owned()
}

fn visible_account_action(text: &str) -> bool {
    let prose = semantic_prose_without_transport_tokens(text);
    let (normalized, compact) = normalized_and_compact(&prose);
    let md = module_data();
    let phrase_or_action_prefix = |terms: &[String]| {
        count_config_terms(&normalized, &compact, terms) > 0
            || (normalized.trim().chars().count() >= 3
                && terms.iter().any(|term| {
                    normalize_text(&term.to_lowercase())
                        .strip_prefix(normalized.trim())
                        .is_some_and(|suffix| {
                            suffix.chars().next().is_some_and(char::is_whitespace)
                        })
                }))
    };
    // Some legacy account-action lists also contain account state phrases.
    // Those can support threat context but cannot make a navigation label a CTA.
    if !phrase_or_action_prefix(md.get_list("recipient_directed_action_markers")) {
        return false;
    }
    [
        "account_security_action_phrases_body",
        "account_security_extra_action_phrases_body",
        "external_action_link_locale_action_terms",
        "credential_cta_action_phrases",
    ]
    .iter()
    .any(|name| {
        let terms = md.get_list(name);
        phrase_or_action_prefix(terms)
    }) || account_security_actions().is_match(&normalized)
}

fn explicitly_refers_to_link(text: &str) -> bool {
    let prose = semantic_prose_without_transport_tokens(text);
    let normalized = normalized_and_compact(&prose).0;
    prose.trim_end().ends_with([':', '：'])
        || module_data()
            .get_list("qualified_account_action_link_reference_terms_v1")
            .iter()
            .any(|term| {
                !term.trim().is_empty()
                    && normalized.contains(&normalize_text(&term.to_lowercase()))
            })
}

fn current_action_text(ctx: &SecurityContext, text: &str) -> Option<String> {
    if text.chars().count() > 768
        || text.contains('`')
        || text.contains("[content-window-gap]")
        || is_counter_context_segment(text)
    {
        return None;
    }
    let (actionable, _) = crate::semantic::exclude_non_action_claims(
        &ctx.session,
        text,
        vigilyx_core::security::SemanticSourcePart::PlainText,
    );
    // A certificate must not silently join the two sides of an excluded
    // report/anti-action clause. Other windows are considered separately.
    if actionable != text || actionable.trim().is_empty() {
        return None;
    }
    Some(actionable)
}

fn action_record(
    category: &str,
    action: &str,
    text: &str,
    part: &str,
    score: f64,
) -> serde_json::Value {
    let digest = hex::encode(Sha256::digest(text.as_bytes()));
    serde_json::json!({
        "schema_version": 1, "category": category, "action_kind": action,
        "score": score, "confidence": 0.85,
        "source_span_id": format!("body:{digest}"), "source_part": part,
        "source_text_sha256": digest, "source_length": text.chars().count(),
        "actor_role": "sender", "target_role": "recipient", "speech_act": "request",
        "polarity": "action", "quote_or_forward_status": "original", "counter_context_ids": [],
        "link_transport_status": "not_attempted", "link_content_status": "not_observed",
        "link_ownership_status": "unknown",
        "basis": {"explicit_recipient_request": true, "current_action": true,
            "external_sender": true, "bounded_same_action": true}
    })
}

fn record_account_link(
    ctx: &SecurityContext,
    text: &str,
    original_url: &str,
    source: &str,
    score: f64,
    matches_account_request: &impl Fn(&str) -> bool,
    records: &mut Vec<serde_json::Value>,
) {
    let Some(text) = current_action_text(ctx, text) else {
        return;
    };
    if !matches_account_request(&text)
        || !has_recipient_directed_action(&text)
        || !is_untrusted_clickable_link(ctx, original_url)
    {
        return;
    }
    let effective_url = effective_structural_url(original_url);
    let Ok(parsed) = url::Url::parse(&effective_url) else {
        return;
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return;
    }
    let Some(host) = parsed.host_str() else {
        return;
    };
    let causal_key = format!("host:{}", host.to_ascii_lowercase());
    if records.iter().any(|record| {
        record["category"] == "account_security_phishing" && record["causal_key"] == causal_key
    }) {
        return;
    }
    let mut record = action_record(
        "account_security_phishing",
        "account_takeover",
        &text,
        if source == "plain_text" {
            "plain_text"
        } else {
            "html_visible_text"
        },
        score,
    );
    record["causal_key"] = serde_json::json!(causal_key);
    record["original_url"] = serde_json::json!(original_url);
    record["effective_url"] = serde_json::json!(effective_url);
    record["link_extraction_source"] = serde_json::json!(source);
    record["coverage_reason"] = serde_json::json!("destination_not_fetched");
    record["basis"]["account_threat"] = serde_json::json!(true);
    record["basis"]["untrusted_observed_destination"] = serde_json::json!(true);
    records.push(record);
}

pub(super) fn record_account_actions(
    ctx: &SecurityContext,
    score: f64,
    matches_account_request: impl Fn(&str) -> bool,
    records: &mut Vec<serde_json::Value>,
) {
    if let Some(body) = ctx.session.content.body_text.as_deref() {
        let body = without_code_quotes(&bounded_detector_text(body));
        for paragraph in semantic_paragraphs(&body) {
            // Keep the original sentence boundaries for target attribution.
            // bounded_actionable_windows joins segments after removing their
            // delimiters; splitting that joined projection would turn two
            // unrelated sentences into one apparent action clause.
            let source_segments = semantic_segments(paragraph)
                .map(|segment| segment.text)
                .collect::<Vec<_>>();
            for window in bounded_actionable_windows(paragraph, 4, 512) {
                let urls = RE_HTML_ALT_URL
                    .find_iter(&window)
                    .map(|m| trim_printed_url_punctuation(m.as_str()))
                    .collect::<HashSet<_>>();
                // A single observed route in the same actionable window is
                // required; the message-wide URL inventory is never borrowed.
                if urls.len() == 1 {
                    let url = urls.into_iter().next().unwrap();
                    let target_is_account_action =
                        source_segments.iter().enumerate().any(|(index, target)| {
                            let bare_target = semantic_prose_without_transport_tokens(target)
                                .chars()
                                .all(|character| {
                                    character.is_whitespace()
                                        || character.is_ascii_punctuation()
                                        || matches!(
                                            character,
                                            '：' | '。' | '，' | '（' | '）' | '【' | '】'
                                        )
                                });
                            target.contains(url)
                                && window.contains(target)
                                && (visible_account_action(target)
                                    || matches_account_request(target)
                                    || (index > 0
                                        && bare_target
                                        && window.contains(&source_segments[index - 1])
                                        && visible_account_action(&source_segments[index - 1])
                                        && explicitly_refers_to_link(&source_segments[index - 1])))
                        });
                    if target_is_account_action {
                        record_account_link(
                            ctx,
                            &window,
                            url,
                            "plain_text",
                            score,
                            &matches_account_request,
                            records,
                        );
                    }
                }
            }
        }
    }
    record_html_account_actions(ctx, score, &matches_account_request, records);
}

pub(super) fn record_html_account_actions(
    ctx: &SecurityContext,
    score: f64,
    matches_account_request: &impl Fn(&str) -> bool,
    records: &mut Vec<serde_json::Value>,
) {
    use scraper::{ElementRef, Html, Selector};
    let Some(html) = ctx
        .session
        .content
        .body_html
        .as_deref()
        .filter(|h| h.len() <= 2 * 1024 * 1024)
    else {
        return;
    };
    let document = Html::parse_document(html);
    let anchors = Selector::parse("a[href]").expect("anchor selector");
    let visible = visible_anchor_facts(html);
    let base_selector = Selector::parse("base[href]").expect("base selector");
    let base = document
        .select(&base_selector)
        .next()
        .and_then(|base| base.attr("href"))
        .and_then(|base| url::Url::parse(base).ok());
    let rendered = |element: ElementRef<'_>| {
        super::super::html_utils::strip_recipient_visible_html_tags(&element.html(), html)
    };
    for (source_index, anchor) in document.select(&anchors).enumerate().take(128) {
        let href = decode_html_entities(anchor.attr("href").unwrap_or_default());
        if !visible.iter().any(|fact| fact.source_index == source_index)
            || anchor
                .ancestors()
                .filter_map(ElementRef::wrap)
                .any(|ancestor| {
                    matches!(
                        ancestor.value().name(),
                        "blockquote" | "q" | "footer" | "header" | "code" | "pre"
                    )
                })
        {
            continue;
        }
        let resolved = url::Url::parse(&href)
            .ok()
            .or_else(|| base.as_ref().and_then(|base| base.join(&href).ok()));
        let Some(resolved) = resolved else {
            continue;
        };
        let Some(block) = anchor
            .ancestors()
            .filter_map(ElementRef::wrap)
            .find(|parent| matches!(parent.value().name(), "p" | "li" | "td" | "div" | "body"))
        else {
            continue;
        };
        // Keep nested blocks separate; their requests cannot be attributed to
        // an unrelated anchor in an enclosing container.
        let nested =
            Selector::parse("p,li,td,div,blockquote,q,section,article,footer,header,code,pre")
                .expect("block selector");
        if block.select(&nested).any(|child| child.id() != block.id()) {
            continue;
        }
        if block.select(&anchors).count() != 1 {
            continue;
        }
        let local = rendered(block);
        let label = rendered(anchor);
        let label_is_action = visible_account_action(&label);
        let label_is_url = label.trim() == href || label.trim() == resolved.as_str();
        let displayed_target_mismatch =
            url::Url::parse(label.trim()).ok().is_some_and(|displayed| {
                matches!(displayed.scheme(), "http" | "https")
                    && displayed.host_str().is_some()
                    && displayed.host_str() != resolved.host_str()
            });
        // In-block evidence can certify itself. A short preceding sibling can
        // supply the warning only for an explicit verification CTA or a bare
        // URL whose preceding request explicitly refers to a link/ends in ':'.
        let mut windows = Vec::new();
        if label_is_action
            || (label_is_url && explicitly_refers_to_link(&local))
            || (displayed_target_mismatch && visible_account_action(&local))
        {
            windows.push(local.clone());
        }
        if label_is_action || label_is_url || displayed_target_mismatch {
            let previous = block.prev_siblings().filter_map(ElementRef::wrap).next();
            if let Some(previous) = previous.filter(|previous| {
                matches!(previous.value().name(), "p" | "div")
                    && previous.select(&anchors).next().is_none()
                    && previous
                        .select(&nested)
                        .all(|child| child.id() == previous.id())
            }) {
                let previous = rendered(previous);
                let refers_to_link = explicitly_refers_to_link(&previous);
                if label_is_action
                    || refers_to_link
                    || (displayed_target_mismatch
                        && visible_account_action(&previous)
                        && matches_account_request(&previous))
                {
                    windows.push(format!("{previous}\n{local}"));
                }
            }
        }
        for window in windows {
            for bounded in bounded_actionable_windows(&window, 4, 512) {
                // Require the actual destination-bearing anchor's visible
                // label in this window, not an earlier request elsewhere.
                if !label.trim().is_empty() && bounded.contains(label.trim()) {
                    let before = records.len();
                    record_account_link(
                        ctx,
                        &bounded,
                        resolved.as_str(),
                        "href",
                        score,
                        matches_account_request,
                        records,
                    );
                    if records.len() > before && displayed_target_mismatch {
                        let record = records.last_mut().expect("new account action record");
                        record["link_binding_basis"] =
                            serde_json::json!("displayed_url_target_mismatch");
                        record["basis"]["displayed_url_target_mismatch"] = serde_json::json!(true);
                    }
                }
            }
        }
    }
}

pub(super) fn record_payment_actions(
    ctx: &SecurityContext,
    score: f64,
    records: &mut Vec<serde_json::Value>,
) {
    let source = if let Some(body) = ctx.session.content.body_text.as_deref() {
        (bounded_detector_text(body).into_owned(), "plain_text")
    } else if let Some(html) = ctx.session.content.body_html.as_deref() {
        let (projection, limited) = crate::semantic::semantic_text_projection_with_coverage(
            html,
            vigilyx_core::security::SemanticSourcePart::Html,
        );
        if limited {
            return;
        }
        (
            bounded_detector_text(&projection).into_owned(),
            "html_visible_text",
        )
    } else {
        return;
    };
    // A phone, order number or unrelated signature is not a payment target.
    // Retain the native account-label line and match that complete line in
    // the same bounded request window before using its destination digest.
    let payment_source = without_code_quotes(&source.0);
    let bank_destinations = payment_source
        .lines()
        .filter_map(|line| {
            let (label, value) = line.split_once([':', '：'])?;
            let account_line = format!("{}:{value}", label.trim().trim_end_matches('.'));
            if !has_explicit_account_destination(&account_line) {
                return None;
            }
            if value
                .chars()
                .any(|ch| !ch.is_ascii_alphanumeric() && !ch.is_whitespace() && ch != '-')
            {
                return None;
            }
            let compact_value = value
                .chars()
                .filter(|ch| !ch.is_whitespace() && *ch != '-')
                .collect::<String>()
                .to_ascii_uppercase();
            let is_iban = RE_IBAN.find(&compact_value).is_some_and(|matched| {
                matched.start() == 0 && matched.end() == compact_value.len()
            });
            let is_account = (6..=34).contains(&compact_value.len())
                && compact_value.bytes().all(|byte| byte.is_ascii_digit());
            if !is_iban && !is_account {
                return None;
            }
            Some((line.trim().to_string(), compact_value))
        })
        .collect::<Vec<_>>();
    // Establish uniqueness before enumerating overlapping windows. Otherwise
    // a short window could hide the second (old/new) account and incorrectly
    // certify the first one. Quoted HTML/plain lines retain their quote prefix
    // and code quotes are removed before fields enter this inventory.
    if bank_destinations
        .iter()
        .map(|(_, destination)| destination)
        .collect::<HashSet<_>>()
        .len()
        != 1
    {
        return;
    }
    let md = module_data();
    for window in bounded_actionable_windows(&payment_source, 8, 768)
        .into_iter()
        .rev()
    {
        let Some(text) = current_action_text(ctx, &window) else {
            continue;
        };
        let (normalized, compact) = normalized_and_compact(&text);
        let change = count_config_terms(
            &normalized,
            &compact,
            md.get_list("payment_change_keywords"),
        ) > 0;
        let redirect = super::super::has_explicit_payment_change_redirect(&text);
        let action = count_config_terms(
            &normalized,
            &compact,
            md.get_list("bec_payment_action_terms"),
        ) > 0;
        if !change || !redirect || !action {
            continue;
        }
        let Some((_, destination)) = bank_destinations
            .iter()
            .find(|(line, _)| text.contains(line))
        else {
            continue;
        };
        if bank_destinations
            .iter()
            .filter(|(line, _)| text.contains(line))
            .map(|(_, destination)| destination)
            .collect::<HashSet<_>>()
            .len()
            != 1
        {
            continue;
        }
        let mut local_score = 0.38_f64 + 0.10;
        for (name, contribution) in [
            ("bec_authority_terms", 0.08),
            ("transaction_urgency_keywords", 0.08),
            ("bec_confidentiality_terms", 0.10),
        ] {
            if count_config_terms(&normalized, &compact, md.get_list(name)) > 0 {
                local_score += contribution;
            }
        }
        if ctx.session.content.links.is_empty() && ctx.session.content.attachments.is_empty() {
            local_score += 0.05;
        }
        let local_score = local_score.min(score);
        let destination_sha256 = hex::encode(Sha256::digest(destination.as_bytes()));
        let key = format!("body_relation:{destination_sha256}");
        if records.iter().any(|record| {
            record["category"] == "bec_payment_change"
                && record["causal_key"] == key
                && record["score"]
                    .as_f64()
                    .is_some_and(|previous| previous >= local_score)
        }) {
            continue;
        }
        records.retain(|record| {
            !(record["category"] == "bec_payment_change" && record["causal_key"] == key)
        });
        let mut record = action_record(
            "bec_payment_change",
            "payment_diversion",
            &text,
            source.1,
            local_score,
        );
        record["causal_key"] = serde_json::json!(key);
        record["destination_kind"] = serde_json::json!("bank_account");
        record["destination_sha256"] = serde_json::json!(destination_sha256);
        record["original_url"] = serde_json::Value::Null;
        record["effective_url"] = serde_json::Value::Null;
        record["link_extraction_source"] = serde_json::json!("none");
        record["coverage_reason"] = serde_json::json!("not_link_applicable");
        record["basis"]["payment_change"] = serde_json::json!(true);
        record["basis"]["payment_redirect"] = serde_json::json!(true);
        record["basis"]["concrete_payment_destination"] = serde_json::json!(true);
        records.push(record);
    }
}
