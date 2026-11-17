//! Local coercive-purpose relations, independent of authenticity/reputation.
//! The current operation is the anchor. Authority, pressure, a new telephone
//! number, or a subject category is never an independent scoring feature.

use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vigilyx_core::security::{
    SemanticClaim, SemanticMessageContext, SemanticQuoteStatus, SemanticSourcePart,
    SemanticSpeechAct, SemanticTargetRole,
};

use super::budget::SemanticCpuBudget;
use super::compiled::CompiledSemanticData;
use super::context::UNVERIFIED_THREAD_PROVENANCE;
use super::risk::{RiskAnalysis, current, eligible, own_account_destination};
use super::solicitation::NativeSolicitationFinding;
use super::source::SemanticSource;
use super::text::{normalized_lowercase_body, semantic_phrase_at};

const POLICY: &str = "semantic_coercive_intent_policy_v1";

#[derive(Default, Deserialize)]
#[serde(default)]
struct Policy {
    enabled: bool,
    max_relation_bytes: usize,
    max_paragraphs: usize,
    max_witnesses: usize,
    score: f64,
    lexical_objects: Vec<String>,
    payment_actions: Vec<String>,
    remote_actions: Vec<String>,
    collection_actions: Vec<String>,
    authorities: Vec<String>,
    financial_assets: Vec<String>,
    financial_allegations: Vec<String>,
    investigation_purposes: Vec<String>,
    custodial_accounts: Vec<String>,
    investigation_bonds: Vec<String>,
    illegal_status_purposes: Vec<String>,
    own_accounts: Vec<String>,
    ordinary_payment_purposes: Vec<String>,
    remote_control: Vec<String>,
    control_assignment_actions: Vec<String>,
    controller_targets: Vec<String>,
    identity_claim_roles: Vec<String>,
    self_claim_prefixes: Vec<String>,
    contact_changes: Vec<String>,
    prohibition_markers: Vec<String>,
    independent_verification_targets: Vec<String>,
    verification_predicates: Vec<String>,
    loan_operations: Vec<String>,
    loan_status_purposes: Vec<String>,
    debt_repayment: Vec<String>,
    im_channels: Vec<String>,
    full_identity: Vec<String>,
    identity_portrait: Vec<String>,
    memo_arguments: Vec<String>,
    existing_one_time_secrets: Vec<String>,
    explicit_request: Vec<String>,
    past_or_inspection: Vec<String>,
    counter_context: Vec<String>,
    proof_documents: Vec<String>,
    payee_arguments: Vec<String>,
    future_transfer_receipts: Vec<String>,
    nontransactional_verification_goals: Vec<String>,
    credit_limit_goals: Vec<String>,
    immediate_bonus_terms: Vec<String>,
    rapid_return_markers: Vec<String>,
    future_fulfillment_markers: Vec<String>,
    historical_proof_markers: Vec<String>,
    completed_payment_markers: Vec<String>,
    collateral_deposits: Vec<String>,
    commercial_payment_purposes: Vec<String>,
    min_material_transfer: f64,
    personal_accusations: Vec<String>,
    recipient_references: Vec<String>,
    loan_request_predicates: Vec<String>,
    warning_condition_frames: Vec<String>,
    warning_avoidance_actions: Vec<String>,
    exculpatory_predicates: Vec<String>,
    criminal_materials: Vec<String>,
    noninvolvement_predicates: Vec<String>,
}

impl Policy {
    fn valid(&self) -> bool {
        if !self.enabled {
            return true;
        }
        (128..=8192).contains(&self.max_relation_bytes)
            && self.max_paragraphs <= 2
            && (2..=12).contains(&self.max_witnesses)
            && self.score.is_finite()
            && (0.15..=0.34).contains(&self.score)
            && self.min_material_transfer.is_finite()
            && self.min_material_transfer >= 100.0
            && self.lexical_objects.len() <= 256
            && self
                .lexical_objects
                .iter()
                .all(|s| !s.trim().is_empty() && s.len() <= 128)
            && [
                &self.payment_actions,
                &self.remote_actions,
                &self.collection_actions,
                &self.authorities,
                &self.financial_assets,
                &self.financial_allegations,
                &self.investigation_purposes,
                &self.custodial_accounts,
                &self.investigation_bonds,
                &self.illegal_status_purposes,
                &self.own_accounts,
                &self.ordinary_payment_purposes,
                &self.remote_control,
                &self.control_assignment_actions,
                &self.controller_targets,
                &self.identity_claim_roles,
                &self.self_claim_prefixes,
                &self.contact_changes,
                &self.prohibition_markers,
                &self.independent_verification_targets,
                &self.verification_predicates,
                &self.loan_operations,
                &self.loan_status_purposes,
                &self.debt_repayment,
                &self.im_channels,
                &self.full_identity,
                &self.identity_portrait,
                &self.memo_arguments,
                &self.existing_one_time_secrets,
                &self.explicit_request,
                &self.past_or_inspection,
                &self.counter_context,
                &self.proof_documents,
                &self.payee_arguments,
                &self.future_transfer_receipts,
                &self.nontransactional_verification_goals,
                &self.credit_limit_goals,
                &self.immediate_bonus_terms,
                &self.rapid_return_markers,
                &self.future_fulfillment_markers,
                &self.historical_proof_markers,
                &self.completed_payment_markers,
                &self.collateral_deposits,
                &self.commercial_payment_purposes,
                &self.personal_accusations,
                &self.recipient_references,
                &self.loan_request_predicates,
                &self.warning_condition_frames,
                &self.warning_avoidance_actions,
                &self.exculpatory_predicates,
                &self.criminal_materials,
                &self.noninvolvement_predicates,
            ]
            .iter()
            .all(|terms| {
                !terms.is_empty()
                    && terms.len() <= 128
                    && terms.iter().all(|s| !s.trim().is_empty() && s.len() <= 128)
            })
    }
}

struct Fact<'a> {
    claim: &'a SemanticClaim,
    text: String,
}

fn has(text: &str, terms: &[String]) -> bool {
    terms.iter().any(|term| {
        text.match_indices(term.as_str())
            .any(|(at, _)| semantic_phrase_at(text, term, at))
    })
}

fn live_predicate(fact: &Fact<'_>, verb: &str, at: usize, p: &Policy) -> bool {
    if !semantic_phrase_at(&fact.text, verb, at) {
        return false;
    }
    if counter_role_at(fact, at) {
        return false;
    }
    if p.payment_actions.iter().any(|operation| operation == verb) {
        let after = fact.text[at + verb.len()..].trim_start();
        let nominal = after.strip_prefix('的').unwrap_or(after);
        if [
            "凭证",
            "回单",
            "记录",
            "截图",
            "流水",
            "账单",
            "备注",
            "附言",
            "编号",
            "方式",
            "延迟",
            "超时",
            "逾期",
            "账凭证",
            "账回单",
            "账记录",
            "账截图",
            "账流水",
            "款凭证",
            "款记录",
            "receipt",
            "record",
            "confirmation",
            "proof",
            "statement",
            "history",
            "screenshot",
            "delay",
        ]
        .iter()
        .any(|object| nominal.starts_with(object))
            || after.starts_with("的证明")
        {
            return false;
        }
        let relative = after
            .split(['，', ';', '；', '。', '!', '！', '?', '？', '\n'])
            .next()
            .unwrap_or("");
        let material_relative = ["的凭证", "的回单", "的截图", "的流水", "的记录", "的证明"]
            .iter()
            .any(|document| relative.find(document).is_some_and(|pos| pos <= 192));
        let payment_then_material = ["后把", "后再", "然后", "之后再"]
            .iter()
            .any(|sequence| relative.contains(sequence));
        if material_relative && !payment_then_material {
            let before = fact.text[..at]
                .rsplit(['，', ';', '；', '。', '!', '！', '?', '？', '\n'])
                .next()
                .unwrap_or("");
            let collection = p
                .collection_actions
                .iter()
                .flat_map(|action| {
                    before
                        .match_indices(action.as_str())
                        .filter_map(move |(pos, _)| {
                            semantic_phrase_at(before, action, pos).then_some(pos + action.len())
                        })
                })
                .max();
            let post_collection = ["的凭证", "的回单", "的截图", "的流水", "的记录", "的证明"]
                .iter()
                .any(|document| {
                    relative.split_once(document).is_some_and(|(_, tail)| {
                        [
                            "发来", "发给", "传来", "传给", "交来", "交给", "提交", "上传", "提供",
                            "发送",
                        ]
                        .iter()
                        .any(|delivery| tail.find(delivery).is_some_and(|at| at <= 96))
                    })
                });
            if post_collection
                || collection.is_some_and(|end| {
                    let continuation = &before[end..];
                    continuation.len() <= 256
                        && ![
                            "然后请",
                            "随后请",
                            "并请",
                            "再请",
                            "同时请",
                            "并立即",
                            "然后现在",
                            "now please",
                            "then please",
                        ]
                        .iter()
                        .any(|fresh| continuation.contains(fresh))
                })
            {
                return false;
            }
        }
    }
    // A verb-shaped word inside a statute title is a nominal reference,
    // such as 支付 in 《支付结算办法》, rather than a payment command.
    let before = &fact.text[..at];
    if let Some(open) = before.rfind('《')
        && before.rfind('》').is_none_or(|close| close < open)
        && let Some(close) = fact.text[at..].find('》')
    {
        let title = &fact.text[open..at + close];
        if ["法", "办法", "条例", "规定"]
            .iter()
            .any(|law| title.contains(law))
        {
            return false;
        }
    }
    let prefix = before
        .rsplit([',', '，', ';', '；', ':', '：', '\n'])
        .next()
        .unwrap_or("");
    // A later explicit fresh instruction owns its own tense; submitting an
    // old receipt before it neither creates nor cancels that new payment.
    let reset = [
        "现在",
        "现请",
        "随后请",
        "然后请",
        "now please",
        "then now",
        "now transfer",
    ]
    .iter()
    .filter_map(|fresh| prefix.rfind(fresh).map(|pos| pos + fresh.len()))
    .max()
    .unwrap_or(0);
    let prefix = &prefix[reset..];
    if has(prefix, &p.past_or_inspection)
        || [
            "不",
            "未",
            "没有",
            "没",
            "无需",
            "不需",
            "不存在",
            "并无",
            "无",
            "并非",
            "不是",
            "never",
            "not",
            "without",
        ]
        .iter()
        .any(|negative| prefix.trim_end().ends_with(negative))
    {
        return false;
    }
    // In "if someone asks you to X, terminate/report it", X is a
    // counterfactual scenario; the live instruction is the warning response.
    let conditional = p.warning_condition_frames.iter().any(|frame| {
        before
            .match_indices(frame.as_str())
            .any(|(pos, _)| semantic_phrase_at(before, frame, pos) && at.saturating_sub(pos) <= 256)
    });
    let after = fact.text[at + verb.len()..]
        .split(['。', '.', '!', '！', '?', '？', '\n'])
        .next()
        .unwrap_or("");
    !(conditional && has(after, &p.warning_avoidance_actions))
}

fn counter_role_at(fact: &Fact<'_>, at: usize) -> bool {
    let before = fact.text[..at]
        .rsplit(['。', '.', '!', '！', '?', '？', ';', '；', '\n'])
        .next()
        .unwrap_or("");
    let reset = ["但是", "但请", "现在请", "本次请", "however", "but now"]
        .iter()
        .filter_map(|reset| before.rfind(reset).map(|pos| pos + reset.len()))
        .max()
        .unwrap_or(0);
    let before = &before[reset..];
    if ["谨防", "警惕", "提防", "beware", "watch out", "be wary"]
        .iter()
        .any(|warning| {
            before.match_indices(warning).any(|(pos, _)| {
                semantic_phrase_at(before, warning, pos) && before.len() - pos <= 256
            })
        })
    {
        return true;
    }
    let local = fact.text[..at]
        .rsplit(['。', '.', '\n'])
        .next()
        .unwrap_or("");
    [
        "任何要求",
        "凡是要求",
        "凡要求",
        "any request",
        "anyone asking",
    ]
    .iter()
    .any(|frame| {
        local.match_indices(frame).any(|(pos, _)| {
            semantic_phrase_at(local, frame, pos)
                && local.len() - pos <= 256
                && [
                    "均属诈骗",
                    "均为诈骗",
                    "都是诈骗",
                    "就是诈骗",
                    "is a scam",
                    "is fraud",
                ]
                .iter()
                .any(|classification| fact.text.contains(classification))
        })
    })
}

fn live_role_terms(fact: &Fact<'_>, terms: &[String], p: &Policy) -> bool {
    eligible(fact.claim)
        && terms.iter().any(|term| {
            fact.text
                .match_indices(term.as_str())
                .any(|(at, _)| live_predicate(fact, term, at, p))
        })
}

fn active(fact: &Fact<'_>, actions: &[String], p: &Policy) -> bool {
    if !current(fact.claim) || has(&fact.text, &p.counter_context) {
        return false;
    }
    actions.iter().any(|verb| {
        let required = match verb.as_str() {
            "转" => Some("semantic_compact_transfer_predicate_v1"),
            "借" => Some("semantic_compact_borrow_predicate_v1"),
            _ => None,
        };
        if required.is_some_and(|tag| !fact.claim.provenance.iter().any(|v| v == tag)) {
            return false;
        }
        fact.claim.actions.contains(verb)
            && fact
                .text
                .match_indices(verb.as_str())
                .any(|(at, _)| live_predicate(fact, verb, at, p))
    })
}

fn boundaries(text: &str) -> usize {
    let mut previous_blank = false;
    text.lines()
        .filter(|line| {
            let blank = line.trim().is_empty();
            let boundary = blank && !previous_blank;
            previous_blank = blank;
            boundary
        })
        .count()
}

fn connected(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    witnesses: &[&Fact<'_>],
    p: &Policy,
) -> bool {
    if witnesses.is_empty() || witnesses.len() > p.max_witnesses {
        return false;
    }
    let start = witnesses
        .iter()
        .map(|f| f.claim.span.start_byte)
        .min()
        .unwrap_or(0);
    let end = witnesses
        .iter()
        .map(|f| f.claim.span.end_byte)
        .max()
        .unwrap_or(0);
    if end.saturating_sub(start) > p.max_relation_bytes {
        return false;
    }
    let Some(text) = source.text.get(start..end) else {
        return false;
    };
    if boundaries(text) > p.max_paragraphs {
        return false;
    }
    if text.lines().skip(1).any(|line| {
        let line = line.trim();
        let divider = line.len() >= 3 && line.chars().all(|c| matches!(c, '-' | '_' | '*' | '='));
        divider || line.starts_with('#') || line.starts_with("**")
    }) {
        return false;
    }
    if source.part != SemanticSourcePart::PlainText
        && witnesses.iter().any(|f| {
            f.claim.source_block_id.is_none()
                || f.claim.source_block_id != witnesses[0].claim.source_block_id
        })
    {
        return false;
    }
    !context.claims.iter().any(|claim| {
        claim.source_part == source.part
            && claim.span.start_byte < end
            && start < claim.span.end_byte
            && !eligible(claim)
            && !witnesses.iter().any(|f| {
                f.claim.source_span_id == claim.source_span_id
                    && forbids_independent_verification(f, p)
            })
    })
}

fn support<'a, 'c>(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &'a [Fact<'c>],
    anchors: &[&Fact<'c>],
    terms: &[String],
    p: &Policy,
) -> Option<&'a Fact<'c>> {
    facts
        .iter()
        .filter(|f| !has(&f.text, &p.counter_context) && live_role_terms(f, terms, p))
        .filter(|f| {
            let mut witnesses = anchors.to_vec();
            witnesses.push(f);
            connected(source, context, &witnesses, p)
        })
        .min_by_key(|f| {
            f.claim
                .span
                .start_byte
                .abs_diff(anchors[0].claim.span.start_byte)
        })
}

fn authority_rank(fact: &Fact<'_>, p: &Policy) -> Option<u8> {
    if !eligible(fact.claim) {
        return None;
    }
    let mut rank = None;
    for term in &p.authorities {
        for (at, _) in fact.text.match_indices(term.as_str()) {
            if !live_predicate(fact, term, at, p) {
                continue;
            }
            let before = &fact.text[..at];
            let clause = before
                .rsplit([',', '，', ';', '；', '。', '\n'])
                .next()
                .unwrap_or("");
            let after = &fact.text[at + term.len()..];
            if ["卡", "card", "账户", "account", "流程", "程序", "凭证"]
                .iter()
                .any(|argument| after.trim_start().starts_with(argument))
            {
                continue;
            }
            if [
                "进入",
                "登录",
                "拨打",
                "联系",
                "访问",
                "通过",
                "扫码",
                "添加",
                "关注",
                "搜索",
                "发送至",
                "抄送",
                "移交",
                "转交",
                "报告给",
                "call",
                "contact",
                "visit",
                "log in to",
                "enter",
                "forward to",
                "report to",
            ]
            .iter()
            .any(|operation| {
                clause.match_indices(operation).any(|(pos, _)| {
                    semantic_phrase_at(clause, operation, pos) && clause.len() - pos <= 128
                })
            }) {
                continue;
            }
            let self_identity = p.self_claim_prefixes.iter().any(|intro| {
                clause.match_indices(intro.as_str()).any(|(pos, _)| {
                    semantic_phrase_at(clause, intro, pos) && clause.len() - pos <= 96
                })
            });
            if self_identity {
                rank = Some(0);
                continue;
            }
            // An institution named as an account owner, payment channel or
            // affected asset does not identify the speaker's authority.
            if [
                "户名",
                "开户行",
                "开户银行",
                "账户名称",
                "收款账户",
                "转入",
                "划转",
                "转账",
                "网银",
                "手机银行",
                "登录",
                "银行卡",
                "银行账户",
                "bank card",
                "bank account",
                "online banking",
                "mobile banking",
            ]
            .iter()
            .any(|argument| clause.contains(argument))
            {
                continue;
            }
            let delegated = [
                "接到",
                "收到",
                "受",
                "代表",
                "received",
                "on behalf of",
                "authorized by",
            ]
            .iter()
            .any(|intro| clause.contains(intro))
                && [
                    "通知",
                    "授权",
                    "委托",
                    "要求",
                    "notice",
                    "report",
                    "authorization",
                ]
                .iter()
                .any(|voice| after.contains(voice));
            let institutional_voice = [
                "联合开展",
                "联合调查",
                "监测到",
                "监测发现",
                "调查发现",
                "通知",
                "通告",
                "联合发布",
                "警告",
                "requires",
                "notifies",
                "has found",
            ]
            .iter()
            .any(|voice| after.contains(voice));
            let agency_title = [
                "公安局",
                "公安机关",
                "公安部",
                "检察院",
                "检察机关",
                "人民法院",
                "警察局",
                "银监会",
                "金融监管局",
                "大使馆",
                "使领馆",
                "刑事侦查支队",
                "public security bureau",
                "embassy",
                "consulate",
                "反诈中心",
                "反诈调查科",
                "反洗钱中心",
                "反洗钱监测分析中心",
                "社保局",
                "社会保险基金管理局",
            ]
            .iter()
            .any(|name| fact.text.contains(name))
                && !["根据《", "依据《", "办法", "条例", "刑法"]
                    .iter()
                    .any(|citation| fact.text.contains(citation))
                && fact.text.len() <= 240;
            let candidate = if delegated {
                Some(1)
            } else if agency_title {
                Some(2)
            } else if institutional_voice && term != "司法" {
                Some(3)
            } else {
                None
            };
            if let Some(candidate) = candidate {
                rank = Some(rank.map_or(candidate, |old| old.min(candidate)));
            }
        }
    }
    if rank.is_none()
        && ["我局", "本局"].iter().any(|voice| {
            fact.text
                .match_indices(voice)
                .any(|(at, _)| !counter_role_at(fact, at))
        })
        && ["正在侦办", "反诈中心", "刑侦", "经侦", "刑事侦查"]
            .iter()
            .any(|investigation| fact.text.contains(investigation))
    {
        rank = Some(1);
    }
    rank
}

fn authority_support<'a, 'c>(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &'a [Fact<'c>],
    anchors: &[&Fact<'c>],
    p: &Policy,
) -> Option<&'a Fact<'c>> {
    facts
        .iter()
        .filter_map(|fact| {
            let rank = authority_rank(fact, p)?;
            let mut witnesses = anchors.to_vec();
            witnesses.push(fact);
            connected(source, context, &witnesses, p).then_some((rank, fact))
        })
        .min_by_key(|(rank, fact)| {
            (
                *rank,
                fact.claim
                    .span
                    .start_byte
                    .abs_diff(anchors[0].claim.span.start_byte),
            )
        })
        .map(|(_, fact)| fact)
}

fn accusation_subject(fact: &Fact<'_>, p: &Policy) -> Option<&'static str> {
    if !eligible(fact.claim) {
        return None;
    }
    for accusation in &p.personal_accusations {
        for (at, _) in fact.text.match_indices(accusation.as_str()) {
            if !live_predicate(fact, accusation, at, p) {
                continue;
            }
            let before = fact.text[..at]
                .rsplit([';', '；', '。', '!', '！', '?', '？', '\n'])
                .next()
                .unwrap_or("");
            if before.len() > 1024 {
                continue;
            }
            // Account-opening bank/address metadata does not replace the
            // affected account as the subject of a following accusation.
            let mut clause = String::new();
            let mut depth = 0usize;
            for ch in before.chars() {
                match ch {
                    '(' | '（' | '[' | '【' | '《' => depth += 1,
                    ')' | '）' | ']' | '】' | '》' => depth = depth.saturating_sub(1),
                    _ if depth == 0 => clause.push(ch),
                    _ => {}
                }
            }
            if depth != 0 {
                continue;
            }
            for recipient in &p.recipient_references {
                for (pos, _) in clause.match_indices(recipient.as_str()) {
                    let subject = &clause[pos..];
                    let latest_clause = subject.rsplit([',', '，']).next().unwrap_or("").trim();
                    let new_subject = subject.len() != latest_clause.len()
                        && [
                            "and any",
                            "but any",
                            "any",
                            "someone",
                            "a third party",
                            "the attacker",
                            "任何",
                            "有人",
                            "第三方",
                            "他人",
                            "对方",
                        ]
                        .iter()
                        .any(|head| {
                            latest_clause.starts_with(head)
                                && semantic_phrase_at(latest_clause, head, 0)
                        });
                    if !semantic_phrase_at(&clause, recipient, pos)
                        || new_subject
                        || subject.len() > 512
                        || subject.matches([',', '，']).count() > 2
                        || [
                            "转账", "转入", "划转", "汇款", "汇至", "缴纳", "交纳", "transfer",
                            "remit",
                        ]
                        .iter()
                        .any(|operation| subject.contains(operation))
                        || ["户名", "账户名称", "监管账户", "监管专户"]
                            .iter()
                            .any(|argument| subject.contains(argument))
                    {
                        continue;
                    }
                    let family = [
                        "父母",
                        "父亲",
                        "母亲",
                        "家人",
                        "亲属",
                        "子女",
                        "孩子",
                        "配偶",
                        "your parents",
                        "your father",
                        "your mother",
                        "your family",
                    ]
                    .iter()
                    .any(|relative| subject.contains(relative));
                    return Some(if family {
                        "recipient_family_investigation_pressure"
                    } else {
                        "personal_investigation_or_clearance_purpose"
                    });
                }
            }
        }
    }
    None
}

fn node(role: &str, fact: &Fact<'_>) -> Value {
    json!({"role":role,"claim_id":fact.claim.source_span_id,
        "source_part":fact.claim.source_part,"span":fact.claim.span})
}

fn diagnostic(
    family: &str,
    anchor: &Fact<'_>,
    witnesses: &[(&str, &Fact<'_>)],
    missing: &[&str],
    score: Option<f64>,
) -> Value {
    json!({"layer":"static_coercive_intent_v1","family":family,
        "status":if score.is_some(){"risk_hint"}else{"not_admitted"},
        "anchor_claim_id":anchor.claim.source_span_id,
        "evidence_tier":"risk_combination",
        "feature_groups":witnesses.iter().map(|(role,f)|node(role,f)).collect::<Vec<_>>(),
        "missing_groups":missing,"score":score,
        "interpretation":"Source-bound operation and coercive-purpose risk; claimed authority was not authenticated"})
}

fn emit(
    analysis: &mut RiskAnalysis,
    family: &'static str,
    anchor: &Fact<'_>,
    witnesses: &[(&str, &Fact<'_>)],
    cause: &str,
    p: &Policy,
) {
    let mut supports = Vec::new();
    for (_, f) in witnesses {
        if f.claim.source_span_id != anchor.claim.source_span_id
            && !supports
                .iter()
                .any(|c: &SemanticClaim| c.source_span_id == f.claim.source_span_id)
        {
            supports.push(f.claim.clone());
        }
    }
    let normalized = anchor.text.split_whitespace().collect::<Vec<_>>().join(" ");
    analysis.findings.push(NativeSolicitationFinding {
        source_part: anchor.claim.source_part,
        claim: anchor.claim.clone(),
        supporting_claims: supports,
        admission_rule: family,
        category: "scam".into(),
        score: p.score,
        causal_key: format!(
            "body_relation:{cause}:{}",
            hex::encode(Sha256::digest(normalized.as_bytes()))
        ),
    });
    analysis
        .diagnostics
        .push(diagnostic(family, anchor, witnesses, &[], Some(p.score)));
}

fn exculpatory_purpose(fact: &Fact<'_>, p: &Policy) -> bool {
    if !eligible(fact.claim) {
        return false;
    }
    p.exculpatory_predicates.iter().any(|predicate| {
        fact.text.match_indices(predicate.as_str()).any(|(at, _)| {
            if !live_predicate(fact, predicate, at, p) {
                return false;
            }
            let after = &fact.text[at + predicate.len()..];
            p.criminal_materials.iter().any(|material| {
                after.match_indices(material.as_str()).any(|(object, _)| {
                    if !semantic_phrase_at(after, material, object) {
                        return false;
                    }
                    let tail = &after[object + material.len()..];
                    p.noninvolvement_predicates.iter().any(|relation| {
                        tail.match_indices(relation.as_str()).any(|(end, _)| {
                            semantic_phrase_at(tail, relation, end)
                                && object + material.len() + end + relation.len() <= 160
                                && !after[..object + material.len() + end].contains([
                                    ',', '，', ';', '；', '。', '.', '!', '！', '?', '？', '\n',
                                ])
                        })
                    })
                })
            })
        })
    })
}

fn reported_actor_payment(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    anchor: &Fact<'_>,
    p: &Policy,
) -> bool {
    let Some(prefix) = source.text.get(..anchor.claim.span.end_byte) else {
        return false;
    };
    let Some(before) = source.text.get(..anchor.claim.span.start_byte) else {
        return false;
    };
    let start = before
        .rfind(['。', '.', '!', '！', '?', '？', ';', '；', '\n'])
        .map_or(0, |at| {
            at + before[at..].chars().next().map_or(0, char::len_utf8)
        });
    if anchor.claim.span.end_byte.saturating_sub(start) > 768
        || context.claims.iter().any(|claim| {
            claim.source_part == source.part
                && claim.span.start_byte < anchor.claim.span.end_byte
                && start < claim.span.end_byte
                && (claim.quote_or_forward_status != SemanticQuoteStatus::Original
                    || claim.source_block_id != anchor.claim.source_block_id)
        })
    {
        return false;
    }
    let text = normalized_lowercase_body(&prefix[start..]);
    // The reported actor owns this request only through an unbroken local
    // chain: third party -> false identity -> that party's demand -> payment.
    // A warning footer after a live request cannot supply this preceding chain.
    [
        "有人",
        "骗子",
        "不法分子",
        "诈骗者",
        "攻击者",
        "对方",
        "someone",
        "a scammer",
    ]
    .iter()
    .any(|actor| {
        text.match_indices(actor).any(|(actor_at, _)| {
            if !semantic_phrase_at(&text, actor, actor_at)
                || ["没", "没有", "并无", "不是", "no "]
                    .iter()
                    .any(|negation| text[..actor_at].trim_end().ends_with(negation))
            {
                return false;
            }
            let after_actor = &text[actor_at + actor.len()..];
            ["冒称", "冒充", "假冒", "pretends to be", "impersonates"]
                .iter()
                .any(|identity| {
                    after_actor.match_indices(identity).any(|(identity_at, _)| {
                        if identity_at > 48
                            || after_actor[..identity_at].contains([',', '，', ':', '：'])
                        {
                            return false;
                        }
                        let after_identity = &after_actor[identity_at + identity.len()..];
                        ["要求", "诱导", "让", "asks", "demands", "instructs"]
                            .iter()
                            .any(|demand| {
                                after_identity.match_indices(demand).any(|(demand_at, _)| {
                                    if demand_at > 192
                                        || !semantic_phrase_at(after_identity, demand, demand_at)
                                    {
                                        return false;
                                    }
                                    let operation = &after_identity[demand_at + demand.len()..];
                                    ![
                                        "但是",
                                        "但请",
                                        "但现在",
                                        "现在请",
                                        "现要求",
                                        "现请",
                                        "我们要求",
                                        "我要求",
                                        "我将",
                                        "however",
                                        "but",
                                        "now",
                                    ]
                                    .iter()
                                    .any(|reset| {
                                        after_identity.match_indices(reset).any(|(at, _)| {
                                            semantic_phrase_at(after_identity, reset, at)
                                        })
                                    }) && !has(after_identity, &p.self_claim_prefixes)
                                        && operation.matches([',', '，']).count() <= 2
                                        && p.payment_actions.iter().any(|verb| {
                                            anchor.claim.actions.contains(verb)
                                                && operation.match_indices(verb.as_str()).any(
                                                    |(at, _)| {
                                                        semantic_phrase_at(operation, verb, at)
                                                    },
                                                )
                                        })
                                })
                            })
                    })
                })
        })
    })
}

fn clearance_witness<'a, 'c>(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &'a [Fact<'c>],
    anchor: &Fact<'c>,
    p: &Policy,
) -> Option<&'a Fact<'c>> {
    let status = |fact: &Fact<'_>| {
        [
            "违规",
            "违法",
            "刑事处罚",
            "刑事责任",
            "涉案",
            "洗钱",
            "征信记录",
            "贷款记录",
            "授信记录",
        ]
        .iter()
        .any(|term| {
            fact.text
                .match_indices(term)
                .any(|(at, _)| live_predicate(fact, term, at, p))
        })
    };
    facts
        .iter()
        .filter(|f| eligible(f.claim) && !has(&f.text, &p.counter_context))
        .filter(|f| {
            exculpatory_purpose(f, p)
                || p.illegal_status_purposes.iter().any(|term| {
                    f.text.match_indices(term.as_str()).any(|(at, _)| {
                        if !live_predicate(f, term, at, p) {
                            return false;
                        }
                        if !["清空数据", "清空异常", "清空额度"].contains(&term.as_str())
                        {
                            return true;
                        }
                        // Unqualified data/limit erasure also occurs in ordinary
                        // inventory notices. Bind it to the payment's actual goal
                        // and to a financial or criminal status in its own scope.
                        let prefix = f.text[..at].trim_end();
                        let payment_goal = ["以", "用于", "用来", "从而", "以便"]
                            .iter()
                            .any(|join| prefix.ends_with(join))
                            && (f.claim.source_span_id == anchor.claim.source_span_id
                                || source
                                    .text
                                    .get(anchor.claim.span.end_byte..f.claim.span.start_byte)
                                    .is_some_and(|gap| {
                                        gap.len() <= 96
                                            && !gap.contains([
                                                '。', '.', '!', '！', '?', '？', ';', '；', '\n',
                                            ])
                                    }));
                        payment_goal
                            && (status(f)
                                || facts.iter().any(|prior| {
                                    prior.claim.span.end_byte <= anchor.claim.span.start_byte
                                        && anchor.claim.span.start_byte - prior.claim.span.end_byte
                                            <= 384
                                        && eligible(prior.claim)
                                        && has(&prior.text, &p.financial_assets)
                                        && has(&prior.text, &p.recipient_references)
                                        && status(prior)
                                        && connected(source, context, &[prior, anchor, f], p)
                                }))
                    })
                })
        })
        .filter(|f| connected(source, context, &[anchor, f], p))
        .min_by_key(|f| {
            f.claim
                .span
                .start_byte
                .abs_diff(anchor.claim.span.start_byte)
        })
}

fn custody_payment(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[Fact<'_>],
    anchor: &Fact<'_>,
    p: &Policy,
    out: &mut RiskAnalysis,
) {
    if reported_actor_payment(source, context, anchor, p)
        || own_account_destination(&anchor.text, &p.own_accounts)
        || has(&anchor.text, &p.ordinary_payment_purposes)
    {
        return;
    }
    let clear = clearance_witness(source, context, facts, anchor, p);
    // A civil-case reference, transport insurance or generic "fund safety"
    // cannot authorize the criminal-investigation payment relation.
    let accusation = facts.iter().find(|f| {
        accusation_subject(f, p).is_some()
            && (has(&f.text, &p.financial_assets)
                || [
                    "洗钱",
                    "犯罪",
                    "刑事",
                    "诈骗",
                    "资金清白",
                    "money laundering",
                    "criminal",
                    "suspected fraud",
                ]
                .iter()
                .any(|crime| {
                    f.text
                        .match_indices(crime)
                        .any(|(at, _)| semantic_phrase_at(&f.text, crime, at))
                }))
            && connected(source, context, &[anchor, f], p)
    });
    let Some(purpose) = clear.or(accusation) else {
        return;
    };
    let authority = authority_support(source, context, facts, &[anchor, purpose], p);
    let custody = has(&anchor.text, &p.custodial_accounts);
    let bond = has(&anchor.text, &p.investigation_bonds);
    let clearing = clear.is_some();
    if !(custody || bond || clearing) {
        out.diagnostics.push(diagnostic(
            "coercive_investigation_payment_risk_v1",
            anchor,
            &[
                ("current_recipient_payment", anchor),
                ("investigation_purpose", purpose),
            ],
            &["custodial_account_or_investigation_bond_or_illegal_status_erasure"],
            None,
        ));
        return;
    }
    // This Low relation is the current financial control in exchange for
    // clearing an allegation. A claimed agency is context, not a required
    // proof of authority; missing identity must never borrow a bank channel.
    let mut witnesses = vec![
        ("current_recipient_payment", anchor),
        (
            accusation_subject(purpose, p).unwrap_or("personal_investigation_or_clearance_purpose"),
            purpose,
        ),
    ];
    if let Some(authority) = authority {
        witnesses.push(("claimed_regulatory_or_investigative_authority", authority));
    }
    let claims: Vec<_> = witnesses.iter().map(|(_, fact)| *fact).collect();
    if connected(source, context, &claims, p) {
        emit(
            out,
            "coercive_investigation_payment_risk_v1",
            anchor,
            &witnesses,
            "funds_solicitation",
            p,
        );
        if authority.is_none()
            && let Some(diagnostic) = out.diagnostics.last_mut()
        {
            diagnostic["authority_context_status"] = json!("unknown_or_unverified");
            diagnostic["authority_required_for_this_funds_control_relation"] = json!(false);
        }
    }
}

fn fresh_loan(fact: &Fact<'_>, p: &Policy) -> bool {
    if !current(fact.claim) || has(&fact.text, &p.counter_context) {
        return false;
    }
    // A loan noun in "update your information or future loan access is
    // restricted" is not the current borrowing predicate.
    if active(fact, &p.loan_operations, p) {
        return true;
    }
    if !fact
        .claim
        .actions
        .iter()
        .any(|a| ["申请", "办理", "apply", "get", "take"].contains(&a.as_str()))
    {
        return false;
    }
    p.loan_request_predicates.iter().any(|predicate| {
        fact.text.match_indices(predicate.as_str()).any(|(at, _)| {
            if !live_predicate(fact, predicate, at, p) {
                return false;
            }
            let before = fact.text[..at]
                .rsplit([',', '，', ';', '；', ':', '：', '。', '.', '\n'])
                .next()
                .unwrap_or("");
            let last = |terms: &[&str]| {
                terms
                    .iter()
                    .flat_map(|term| before.match_indices(term).map(|(at, _)| at))
                    .max()
            };
            match (
                last(&[
                    "查询", "核对", "确认", "查看", "了解", "讨论", "check", "confirm", "discuss",
                ]),
                last(&["重新", "并", "再", "然后", "and", "then", "again"]),
            ) {
                (Some(inspect), Some(fresh)) => fresh > inspect,
                (Some(_), None) => false,
                _ => true,
            }
        })
    })
}

fn loan_disposition(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[Fact<'_>],
    anchor: &Fact<'_>,
    p: &Policy,
    out: &mut RiskAnalysis,
) {
    if has(&anchor.text, &p.debt_repayment)
        || own_account_destination(&anchor.text, &p.own_accounts)
    {
        return;
    }
    let Some(purpose) = support(
        source,
        context,
        facts,
        &[anchor],
        &p.loan_status_purposes,
        p,
    ) else {
        return;
    };
    let loan = facts
        .iter()
        .find(|f| fresh_loan(f, p) && connected(source, context, &[anchor, purpose, f], p));
    let Some(loan) = loan else {
        out.diagnostics.push(diagnostic(
            "borrow_then_transfer_for_status_risk_v1",
            anchor,
            &[
                ("current_transfer", anchor),
                ("status_fix_purpose", purpose),
            ],
            &["current_new_borrowing_operation"],
            None,
        ));
        return;
    };
    emit(
        out,
        "borrow_then_transfer_for_status_risk_v1",
        anchor,
        &[
            ("current_transfer", anchor),
            ("new_borrowing_operation", loan),
            ("nonrepayment_identity_or_credit_fix", purpose),
        ],
        "funds_solicitation",
        p,
    );
}

fn supplied_secret(text: &str, terms: &[String]) -> bool {
    terms.iter().any(|term| {
        text.match_indices(term.as_str()).any(|(at, _)| {
            if !semantic_phrase_at(text, term, at) {
                return false;
            }
            let tail = text[at + term.len()..].trim_start_matches(|c: char| {
                c.is_whitespace() || matches!(c, ':' | '：' | '=' | '\'' | '"' | '“' | '[' | '【')
            });
            let token = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect::<String>();
            token.len() >= 4 && token.bytes().any(|b| b.is_ascii_digit())
        })
    })
}

fn transfer_secret(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[Fact<'_>],
    anchor: &Fact<'_>,
    p: &Policy,
    out: &mut RiskAnalysis,
) {
    let memo = facts.iter().find(|f| {
        eligible(f.claim)
            && has(&f.text, &p.memo_arguments)
            && has(&f.text, &p.existing_one_time_secrets)
            && !supplied_secret(&f.text, &p.existing_one_time_secrets)
            && !has(&f.text, &p.counter_context)
            && f.claim.source_block_id.is_some()
            && f.claim.source_block_id == anchor.claim.source_block_id
            && f.claim
                .span
                .start_byte
                .abs_diff(anchor.claim.span.start_byte)
                <= 768
            && connected(source, context, &[anchor, f], p)
    });
    if let Some(memo) = memo {
        emit(
            out,
            "transfer_memo_discloses_live_secret_risk_v1",
            anchor,
            &[
                ("current_money_transfer", anchor),
                ("live_secret_in_payment_argument", memo),
            ],
            "secret_return",
            p,
        );
    }
}

fn live_remote_argument(fact: &Fact<'_>, p: &Policy) -> bool {
    p.remote_actions
        .iter()
        .filter(|verb| fact.claim.actions.contains(verb))
        .any(|verb| {
            fact.text.match_indices(verb.as_str()).any(|(at, _)| {
                if !live_predicate(fact, verb, at, p) {
                    return false;
                }
                let before = fact.text[..at]
                    .rsplit([',', '，', ';', '；', ':', '：', '。', '.', '\n'])
                    .next()
                    .unwrap_or("");
                let after = fact.text[at..]
                    .split([',', '，', ';', '；', '。', '.', '\n'])
                    .next()
                    .unwrap_or("");
                has(&format!("{before}{after}"), &p.remote_control)
            })
        })
}

fn official_remote_access(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[Fact<'_>],
    anchor: &Fact<'_>,
    p: &Policy,
    out: &mut RiskAnalysis,
) {
    let explicit_control = if live_remote_argument(anchor, p) {
        Some(anchor)
    } else {
        facts.iter().find(|f| {
            eligible(f.claim)
                && has(&f.text, &p.remote_control)
                && p.remote_control.iter().any(|term| {
                    f.text
                        .match_indices(term.as_str())
                        .any(|(at, _)| live_predicate(f, term, at, p))
                })
                && has(&f.text, &p.control_assignment_actions)
                && has(&f.text, &p.controller_targets)
                && f.claim.source_block_id.is_some()
                && f.claim.source_block_id == anchor.claim.source_block_id
                && f.claim.span.start_byte >= anchor.claim.span.end_byte
                && source
                    .text
                    .get(anchor.claim.span.end_byte..f.claim.span.start_byte)
                    .is_some_and(|gap| {
                        gap.len() <= 192
                            && !gap.contains(['\n', '。', '.', ';', '；', '!', '！', '?', '？'])
                    })
                && connected(source, context, &[anchor, f], p)
        })
    };
    let Some(control) = explicit_control else {
        return;
    };
    let purpose = facts.iter().find(|f| {
        live_role_terms(f, &p.investigation_purposes, p)
            && (live_role_terms(f, &p.financial_allegations, p)
                || [
                    "涉案",
                    "案件",
                    "涉嫌",
                    "调查",
                    "侦查",
                    "刑事",
                    "suspected",
                    "investigation",
                    "criminal",
                ]
                .iter()
                .any(|term| {
                    f.text
                        .match_indices(term)
                        .any(|(at, _)| live_predicate(f, term, at, p))
                }))
            && connected(source, context, &[anchor, control, f], p)
    });
    let Some(purpose) = purpose else {
        return;
    };
    let Some(authority) = authority_support(source, context, facts, &[anchor, purpose], p) else {
        return;
    };
    emit(
        out,
        "investigative_authority_remote_control_risk_v1",
        anchor,
        &[
            ("current_remote_control_installation", anchor),
            ("explicit_remote_control_argument", control),
            ("investigation_purpose", purpose),
            ("claimed_investigative_authority", authority),
        ],
        "remote_access_solicitation",
        p,
    );
}

fn forbids_independent_verification(fact: &Fact<'_>, p: &Policy) -> bool {
    let original = fact.claim.quote_or_forward_status == SemanticQuoteStatus::Original
        || fact
            .claim
            .provenance
            .iter()
            .any(|v| v == UNVERIFIED_THREAD_PROVENANCE);
    if !original
        || matches!(
            fact.claim.speech_act,
            SemanticSpeechAct::Report | SemanticSpeechAct::Quotation
        )
        || fact.claim.target_role == SemanticTargetRole::NamedThirdParty
        || !fact.claim.counter_context_ids.is_empty()
        || has(&fact.text, &p.counter_context)
    {
        return false;
    }
    p.prohibition_markers.iter().any(|negative| {
        fact.text.match_indices(negative.as_str()).any(|(at, _)| {
            if !semantic_phrase_at(&fact.text, negative, at) {
                return false;
            }
            let before = fact.text[..at]
                .rsplit([',', '，', ';', '；', '。', '.', '\n'])
                .next()
                .unwrap_or("")
                .trim_end();
            if ["不会", "没有", "不应", "not", "never"]
                .iter()
                .any(|counter| before.ends_with(counter))
            {
                return false;
            }
            if has(before, &p.past_or_inspection) {
                return false;
            }
            if [
                "提醒", "警惕", "谨防", "防范", "识别", "有人", "凡是", "任何", "beware",
                "someone", "anyone",
            ]
            .iter()
            .any(|report| before.contains(report))
            {
                return false;
            }
            let tail = fact.text[at + negative.len()..]
                .split([',', '，', ';', '；', '。', '.', '!', '！', '?', '？', '\n'])
                .next()
                .unwrap_or("");
            let end = tail
                .char_indices()
                .map(|(at, _)| at)
                .take_while(|at| *at <= 160)
                .last()
                .unwrap_or(0);
            let window = if tail.len() <= 160 {
                tail
            } else {
                &tail[..end]
            };
            has(window, &p.independent_verification_targets)
                && has(window, &p.verification_predicates)
                && !["请", "你可以", "您可以", "you can", "please"]
                    .iter()
                    .any(|fresh| window.contains(fresh))
        })
    })
}

fn identity_change_payment(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[Fact<'_>],
    anchor: &Fact<'_>,
    p: &Policy,
    out: &mut RiskAnalysis,
) {
    let role = facts.iter().find(|f| {
        eligible(f.claim)
            && has(&f.text, &p.self_claim_prefixes)
            && has(&f.text, &p.identity_claim_roles)
            && connected(source, context, &[anchor, f], p)
    });
    let Some(role) = role else {
        return;
    };
    let Some(change) = support(
        source,
        context,
        facts,
        &[anchor, role],
        &p.contact_changes,
        p,
    ) else {
        return;
    };
    let block = facts.iter().find(|f| {
        forbids_independent_verification(f, p)
            && connected(source, context, &[anchor, role, change, f], p)
    });
    let Some(block) = block else {
        return;
    };
    emit(
        out,
        "changed_identity_payment_forbids_verification_risk_v1",
        anchor,
        &[
            ("current_financial_operation", anchor),
            ("claimed_known_identity", role),
            ("changed_contact_channel", change),
            ("independent_verification_explicitly_forbidden", block),
        ],
        "funds_solicitation",
        p,
    );
}

fn independent_material_route(fact: &Fact<'_>) -> bool {
    [
        "银行app",
        "官方app",
        "银行网点",
        "银行柜台",
        "线下出示",
        "现场出示",
        "另一份表格",
        "另一表单",
        "official app",
        "bank app",
        "branch counter",
        "another form",
    ]
    .iter()
    .any(|route| {
        fact.text
            .match_indices(route)
            .any(|(at, _)| semantic_phrase_at(&fact.text, route, at))
    })
}

fn coordinated_material(
    anchor: &Fact<'_>,
    field: &Fact<'_>,
    source: SemanticSource<'_>,
    p: &Policy,
) -> bool {
    if anchor.claim.source_span_id == field.claim.source_span_id {
        return true;
    }
    let delivery = p
        .collection_actions
        .iter()
        .filter(|action| {
            [
                "提供", "提交", "发送", "上传", "provide", "submit", "send", "upload",
            ]
            .contains(&action.as_str())
        })
        .cloned()
        .collect::<Vec<_>>();
    if !active(field, &delivery, p)
        || independent_material_route(field)
        || field.claim.source_block_id.is_none()
        || field.claim.source_block_id != anchor.claim.source_block_id
        || field.claim.span.start_byte < anchor.claim.span.end_byte
    {
        return false;
    }
    let Some(gap) = source
        .text
        .get(anchor.claim.span.end_byte..field.claim.span.start_byte)
    else {
        return false;
    };
    if gap.len() > 192 || gap.contains(['\n', '。', '.', '；', ';', '!', '！', '?', '？']) {
        return false;
    }
    let field_text = field
        .text
        .trim_start_matches(|c: char| c.is_whitespace() || matches!(c, ',' | '，'));
    ["并", "同时", "以及", "and", "also"]
        .iter()
        .any(|join| field_text.starts_with(join) && semantic_phrase_at(field_text, join, 0))
        && !has(&field.text, &p.counter_context)
}

fn investigative_identity(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[Fact<'_>],
    anchor: &Fact<'_>,
    p: &Policy,
    out: &mut RiskAnalysis,
) {
    // A named IM route is an actual argument of this collection/contact
    // operation. A footer containing WeChat cannot supply that argument.
    if !has(&anchor.text, &p.im_channels) {
        return;
    }
    let allegation = facts.iter().find(|f| {
        live_role_terms(f, &p.financial_assets, p)
            && live_role_terms(f, &p.financial_allegations, p)
            && connected(source, context, &[anchor, f], p)
    });
    let Some(allegation) = allegation else {
        return;
    };
    let Some(authority) = authority_support(source, context, facts, &[anchor, allegation], p)
    else {
        return;
    };
    let identity = support(
        source,
        context,
        facts,
        &[anchor, allegation, authority],
        &p.full_identity,
        p,
    );
    let Some(identity) = identity else {
        return;
    };
    let portrait = support(
        source,
        context,
        facts,
        &[anchor, allegation, authority, identity],
        &p.identity_portrait,
        p,
    );
    let Some(portrait) = portrait else {
        return;
    };
    if independent_material_route(identity) || independent_material_route(portrait) {
        return;
    }
    // Later documents must be explicitly presented as the verification
    // material for this operation, not a separate application in the email.
    let later = identity.claim.span.start_byte > anchor.claim.span.end_byte
        || portrait.claim.span.start_byte > anchor.claim.span.end_byte;
    if later
        && !(coordinated_material(anchor, identity, source, p)
            && coordinated_material(anchor, portrait, source, p))
    {
        let lo = anchor.claim.span.end_byte;
        let hi = identity
            .claim
            .span
            .start_byte
            .max(portrait.claim.span.start_byte);
        let Some(gap) = source.text.get(lo..hi) else {
            return;
        };
        let gap = normalized_lowercase_body(gap);
        if ![
            "核验需准备材料",
            "核验材料",
            "验证材料",
            "认证材料",
            "需提供材料",
            "所需材料",
            "verification documents",
            "required documents",
        ]
        .iter()
        .any(|heading| gap.contains(heading))
        {
            return;
        }
    }
    emit(
        out,
        "investigative_im_identity_bundle_risk_v1",
        anchor,
        &[
            ("current_im_collection_route", anchor),
            ("personal_financial_allegation", allegation),
            ("claimed_regulatory_authority", authority),
            ("full_identity_document", identity),
            ("identity_portrait", portrait),
        ],
        "identity_collection",
        p,
    );
}

fn material_amount(text: &str, p: &Policy) -> bool {
    static AMOUNT: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let amount=AMOUNT.get_or_init(||Regex::new(r"(?:(?:人民币|cny|usd|rmb|us\$|\$|¥|￥)\s*(?P<p>[0-9]{1,15}(?:[,，][0-9]{3})*(?:\.[0-9]{1,4})?)\s*(?P<ps>万|million)?|(?P<s>[0-9]{1,15}(?:[,，][0-9]{3})*(?:\.[0-9]{1,4})?)\s*(?P<ss>万|million)?\s*(?:元|美元|dollars?|cny|usd|rmb))").expect("static transfer amount grammar"));
    amount.captures_iter(text).any(|cap| {
        let Some(number) = cap.name("p").or_else(|| cap.name("s")) else {
            return false;
        };
        let Ok(value) = number.as_str().replace([',', '，'], "").parse::<f64>() else {
            return false;
        };
        let multiplier = match cap
            .name("ps")
            .or_else(|| cap.name("ss"))
            .map(|v| v.as_str())
        {
            Some("万") => 10000.0,
            Some("million") => 1000000.0,
            _ => 1.0,
        };
        value * multiplier >= p.min_material_transfer
    })
}

fn concrete_payee(fact: &Fact<'_>, p: &Policy) -> bool {
    if !eligible(fact.claim)
        || !has(&fact.text, &p.payee_arguments)
        || own_account_destination(&fact.text, &p.own_accounts)
    {
        return false;
    }
    static ACCOUNT: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    ACCOUNT
        .get_or_init(|| {
            Regex::new(r"[0-9][0-9 \-]{8,40}[0-9]").expect("static payee account grammar")
        })
        .find_iter(&fact.text)
        .any(|capture| {
            capture
                .as_str()
                .bytes()
                .filter(|b| b.is_ascii_digit())
                .count()
                >= 10
        })
}

fn payee_argument<'a, 'c>(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &'a [Fact<'c>],
    anchor: &Fact<'c>,
    p: &Policy,
) -> Option<&'a Fact<'c>> {
    facts
        .iter()
        .filter(|f| {
            concrete_payee(f, p)
                && f.claim.source_block_id.is_some()
                && f.claim.source_block_id == anchor.claim.source_block_id
                && f.claim
                    .span
                    .start_byte
                    .abs_diff(anchor.claim.span.start_byte)
                    <= 768
                && connected(source, context, &[anchor, f], p)
        })
        .min_by_key(|f| {
            f.claim
                .span
                .start_byte
                .abs_diff(anchor.claim.span.start_byte)
        })
}

fn affirmed(text: &str, terms: &[String]) -> bool {
    terms.iter().any(|term| {
        text.match_indices(term.as_str()).any(|(at, _)| {
            if !semantic_phrase_at(text, term, at) {
                return false;
            }
            let before = text[..at].trim_end();
            ![
                "不",
                "没有",
                "无需",
                "不用",
                "不涉及",
                "无须",
                "not",
                "no",
                "without",
            ]
            .iter()
            .any(|negative| before.ends_with(negative))
        })
    })
}

fn future_receipt(fact: &Fact<'_>, p: &Policy) -> bool {
    eligible(fact.claim)
        && has(&fact.text, &p.future_transfer_receipts)
        && !has(&fact.text, &p.historical_proof_markers)
        && !has(&fact.text, &p.completed_payment_markers)
}

fn conditional_goal(source: SemanticSource<'_>, condition: &Fact<'_>, goal: &Fact<'_>) -> bool {
    if condition.claim.source_span_id == goal.claim.source_span_id {
        return true;
    }
    if condition.claim.source_block_id.is_none()
        || condition.claim.source_block_id != goal.claim.source_block_id
        || goal.claim.span.start_byte < condition.claim.span.end_byte
    {
        return false;
    }
    let Some(gap) = source
        .text
        .get(condition.claim.span.end_byte..goal.claim.span.start_byte)
    else {
        return false;
    };
    if gap.len() > 768 || gap.contains(['。', '.', '!', '！', '?', '？', ';', '；']) {
        return false;
    }
    if !gap.contains('\n') {
        return true;
    }
    let head = goal.text.trim_start();
    condition.text.trim_end().ends_with([':', '：'])
        && head.starts_with(['-', '•', '▪', '▸', '✅', '①', '②', '③', '④'])
        && !gap.lines().any(|line| line.trim().starts_with('#'))
}

fn proof_requires_new_verification_transfer(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[Fact<'_>],
    anchor: &Fact<'_>,
    p: &Policy,
    out: &mut RiskAnalysis,
) {
    if !has(&anchor.text, &p.proof_documents)
        || !material_amount(&anchor.text, p)
        || has(&anchor.text, &p.historical_proof_markers)
        || has(&anchor.text, &p.completed_payment_markers)
        || affirmed(&anchor.text, &p.ordinary_payment_purposes)
        || affirmed(&anchor.text, &p.commercial_payment_purposes)
        || affirmed(&anchor.text, &p.debt_repayment)
    {
        return;
    }
    // Requesting another receipt for an already completed local payment is
    // evidence collection, not a request to make a fresh transfer.
    if facts.iter().any(|f| {
        f.claim.source_block_id.is_some()
            && f.claim.source_block_id == anchor.claim.source_block_id
            && f.claim.span.end_byte <= anchor.claim.span.start_byte
            && anchor.claim.span.start_byte - f.claim.span.end_byte <= 512
            && has(&f.text, &p.completed_payment_markers)
    }) {
        return;
    }
    let Some(payee) = payee_argument(source, context, facts, anchor, p) else {
        return;
    };
    for condition in facts.iter().filter(|f| future_receipt(f, p)) {
        let goal = facts.iter().find(|f| {
            eligible(f.claim)
                && has(&f.text, &p.nontransactional_verification_goals)
                && conditional_goal(source, condition, f)
                && (has(&condition.text, &p.future_fulfillment_markers)
                    || has(&f.text, &p.future_fulfillment_markers))
                && connected(source, context, &[anchor, payee, condition, f], p)
        });
        if let Some(goal) = goal {
            emit(
                out,
                "proof_submission_presupposes_verification_transfer_risk_v1",
                anchor,
                &[
                    ("current_transfer_proof_submission", anchor),
                    ("material_amount", anchor),
                    ("defined_payee_account", payee),
                    ("future_transfer_receipt_condition", condition),
                    (
                        "nontransactional_identity_or_illegal_status_processing",
                        goal,
                    ),
                ],
                "funds_solicitation",
                p,
            );
            return;
        }
    }
}

fn credit_upgrade_transfer_bonus(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[Fact<'_>],
    anchor: &Fact<'_>,
    p: &Policy,
    out: &mut RiskAnalysis,
) {
    if !material_amount(&anchor.text, p)
        || own_account_destination(&anchor.text, &p.own_accounts)
        || affirmed(&anchor.text, &p.debt_repayment)
        || affirmed(&anchor.text, &p.ordinary_payment_purposes)
        || affirmed(&anchor.text, &p.commercial_payment_purposes)
        || affirmed(&anchor.text, &p.collateral_deposits)
    {
        return;
    }
    let Some(payee) = payee_argument(source, context, facts, anchor, p) else {
        return;
    };
    for condition in facts.iter().filter(|f| future_receipt(f, p)) {
        let goal = facts.iter().find(|f| {
            eligible(f.claim)
                && has(&f.text, &p.credit_limit_goals)
                && has(&f.text, &p.immediate_bonus_terms)
                && conditional_goal(source, condition, f)
                && (has(&condition.text, &p.rapid_return_markers)
                    || has(&f.text, &p.rapid_return_markers))
                && (has(&condition.text, &p.future_fulfillment_markers)
                    || has(&f.text, &p.future_fulfillment_markers))
                && !affirmed(&f.text, &p.debt_repayment)
                && !affirmed(&f.text, &p.collateral_deposits)
                && !affirmed(&f.text, &p.commercial_payment_purposes)
                && connected(source, context, &[anchor, payee, condition, f], p)
        });
        if let Some(goal) = goal {
            emit(
                out,
                "transfer_for_credit_upgrade_and_immediate_bonus_risk_v1",
                anchor,
                &[
                    ("current_material_transfer", anchor),
                    ("defined_payee_account", payee),
                    ("transfer_success_as_prerequisite", condition),
                    ("credit_increase_with_immediate_bonus", goal),
                ],
                "funds_solicitation",
                p,
            );
            return;
        }
    }
}

pub(super) fn analyze(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    budget: &SemanticCpuBudget,
    data: &CompiledSemanticData,
) -> Result<RiskAnalysis, String> {
    let compiled = data.cached(POLICY, |registry| {
        registry
            .get_structured(POLICY)
            .cloned()
            .and_then(|v| serde_json::from_value::<Policy>(v).ok())
            .filter(Policy::valid)
    });
    let Some(p) = compiled.as_ref() else {
        return if data.get_structured(POLICY).is_some() {
            Err("coercive intent policy is malformed".into())
        } else {
            Ok(RiskAnalysis::default())
        };
    };
    if !p.enabled {
        return Ok(RiskAnalysis::default());
    }
    let mut facts = Vec::new();
    for claim in &context.claims {
        if budget.exhausted() {
            return Err("coercive intent preparation exceeded CPU budget".into());
        }
        if claim.source_part != source.part {
            continue;
        }
        if facts.len() == 512 {
            return Err("coercive intent fact count exceeded budget".into());
        }
        let text = source
            .claim_text(claim)
            .ok_or("coercive intent source span is invalid")?;
        facts.push(Fact {
            claim,
            text: normalized_lowercase_body(text),
        });
    }
    facts.sort_by_key(|f| (f.claim.span.start_byte, f.claim.span.end_byte));
    let mut out = RiskAnalysis::default();
    for anchor in &facts {
        if budget.exhausted() {
            return Err("coercive intent relations exceeded CPU budget".into());
        }
        if !current(anchor.claim) {
            continue;
        }
        if active(anchor, &p.payment_actions, p) {
            custody_payment(source, context, &facts, anchor, p, &mut out);
            loan_disposition(source, context, &facts, anchor, p, &mut out);
            transfer_secret(source, context, &facts, anchor, p, &mut out);
            identity_change_payment(source, context, &facts, anchor, p, &mut out);
            credit_upgrade_transfer_bonus(source, context, &facts, anchor, p, &mut out);
        }
        if active(anchor, &p.loan_operations, p) && !active(anchor, &p.payment_actions, p) {
            identity_change_payment(source, context, &facts, anchor, p, &mut out);
        }
        if active(anchor, &p.remote_actions, p) {
            official_remote_access(source, context, &facts, anchor, p, &mut out);
        }
        if active(anchor, &p.collection_actions, p) {
            investigative_identity(source, context, &facts, anchor, p, &mut out);
            proof_requires_new_verification_transfer(source, context, &facts, anchor, p, &mut out);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::{compiled::compiled_semantic_data, extract_semantic_context};
    use vigilyx_core::models::{EmailContent, EmailSession, Protocol};
    fn run(body: &str) -> RiskAnalysis {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.1".into(),
            40000,
            "192.0.2.1".into(),
            25,
        );
        session.content = EmailContent {
            body_text: Some(body.into()),
            is_complete: true,
            ..Default::default()
        };
        let context = extract_semantic_context(&session, body, SemanticSourcePart::PlainText);
        analyze(
            SemanticSource::new(body, SemanticSourcePart::PlainText),
            &context,
            &SemanticCpuBudget::new(),
            &compiled_semantic_data(),
        )
        .unwrap()
    }
    #[test]
    fn policy_is_bounded_and_low_only() {
        let data = compiled_semantic_data();
        let raw = data.get_structured(POLICY).unwrap().clone();
        let p: Policy = serde_json::from_value(raw.clone()).unwrap();
        assert!(p.valid());
        let mut invalid = raw.clone();
        invalid["score"] = json!(0.8);
        assert!(!serde_json::from_value::<Policy>(invalid).unwrap().valid());
        let mut invalid = raw;
        invalid["max_relation_bytes"] = json!(100000);
        assert!(!serde_json::from_value::<Policy>(invalid).unwrap().valid());
    }
    #[test]
    fn clear_current_coercive_operations_are_source_bound_risks() {
        for body in [
            "您好，我是公安局办案人员，您的银行卡涉嫌洗钱。请将资金转入指定安全账户，以证明资金清白。",
            "我是中国银监会的工作人员，发现您的贷款额度存在违规行为。请立即转账至指定账户以清空数据，否则将面临刑事处罚。",
            "我是公安局工作人员，您的银行卡涉及案件。请缴纳案件调查保证金以配合调查。",
            "检察机关正在调查您的账户。请在两小时内向本案工作人员个人账户101-550缴纳6000元调查保证金，以证明与犯罪资金无关；未转账将立即签发拘捕令。",
            "检察机关正在调查您的账户。请向本案工作人员个人账户缴纳6000元调查保证金，以证明与犯罪资金无关。反诈提醒：有人冒称警方要求缴纳保证金，请勿向陌生人转账。",
            "反诈提醒：有人冒称检察机关，要求缴纳保证金。现在我是公安局工作人员，您的银行卡涉嫌洗钱。请将资金转入指定安全账户，以证明资金清白。",
            "我们接到通知称您的手机号涉及一宗案件，现需要您配合公安局调查。请点击链接下载手机远程桌面APP，以便进行远程协助调查。",
            "请先从微粒贷借款八万元，再转账到指定账户完成学生身份解绑。",
            "您的银行卡涉嫌洗钱，我是银行客服。请添加警方微信Police_Work，并提供您的身份证正反面和手持身份证自拍照。",
            "请转账至指定账户，转账附言请填写您手机收到的实时验证码。",
            "我是你领导，旧号码停用了。现在请先从网贷额度借20000元，转到我发的私人账户作项目核验款；不能联系公司财务或打原电话核实，这件事必须保密。",
        ] {
            let out = run(body);
            assert!(!out.findings.is_empty(), "{body}\n{:?}", out.diagnostics);
            assert!(out.findings.iter().all(|f| f.score <= 0.34));
        }
    }
    #[test]
    fn ordinary_business_reports_and_independent_materials_do_not_score() {
        for body in [
            "公安局提醒：不要向所谓安全账户转账，不要下载远程桌面配合电话调查。",
            "安全事件报告：攻击者曾要求用户向安全账户转账以证明清白。本文没有要求您操作。",
            "请通过税务APP缴纳本期税款，逾期将产生滞纳金。如有疑问请到办税大厅查询。",
            "人民法院通知：请到法院现场缴纳诉讼费500元，凭案件编号领取正式收据。",
            "公安交警调解通知：请按事故调解协议向法院托管账户缴纳医疗赔偿保证金50000元，以证明已履行民事调解协议；凭正式收据办理后续结算。",
            "反诈提醒：有人冒称检察机关，要求向工作人员个人账户缴纳调查保证金，以证明与犯罪资金无关。请勿转账，立即报警。",
            "有人冒充公安局工作人员，要求将资金转入指定安全账户，以证明资金清白。这是被害人报告的电话内容。",
            "爸爸，我换了手机号，你可以拨打原来的号码核实。请借我五千元用于交房租。",
            "公司IT支持：请安装远程桌面以修复打印机；不涉及银行、借贷或资金验证。",
            "银行IT部门为保障账户安全，请安装远程桌面以修复打印机；我们不会查看你的银行账户。",
            "我是公安局工作人员，您的银行卡涉嫌洗钱。如遇有人要求下载远程桌面请立即终止操作，但请下载正常银行APP提交案件进度查询。",
            "请按照合同向供货商支付货款三万元，付款后提交发票。",
            "请归还上月已借的贷款，贷款还清后即可关闭账户。",
            "为了核实银行卡安全，请将资金转到您自己的同名账户。",
            "请转账至指定账户，转账附言请填写此实时验证码：AB1234。",
            "公安局案件调查请添加工作微信。\n\n另一份普通表格列有身份证正反面和自拍照。",
            "请在银行官方APP上传身份证照片完成普通KYC认证，不收取费用。",
            "我是你爸爸，我换了新手机号。请转账五千元用于交房租；你可以拨打原来的号码核实。",
            "我是你经理，我换了新手机号。请转账五千元。警方提醒：请警惕不许联系公司财务核实的借款消息。",
            "我是你经理，我换了新手机号。请转账五千元。我现在不能联系公司财务，请你打原来的号码核实。",
            "我是银行客服，您的银行卡涉嫌洗钱。请添加警方微信Police_Work以咨询进度，并在银行官方APP上传身份证正反面和手持身份证自拍照。",
        ] {
            assert!(run(body).findings.is_empty(), "{body}");
        }
    }

    #[test]
    fn real_counterfactual_warning_historical_loan_and_business_bonds_are_not_risks() {
        let body_0 = r####"

武汉公安局网络安全监察支队
协查通知书（第2024-068号）

尊敬的市民朋友： 

经系统监测到您近期可能存在网络财产异常操作记录，根据《中华人民共和国网络安全法》第四十二条规定，我单位已启动网络诈骗案件协查机制。为保障您的合法权益，现提供以下正规维权渠道：

【协查流程说明】
1. 请于48小时内通过QQ（123456789）提交涉案平台截图、转账流水等基础证据材料；
2. 值班警员将使用带有「网络警察」认证标识的账号与您对接；
3. 材料审核通过后，我单位将向中国人民银行反诈中心提交资金止付申请；
4. 全程不收取任何服务费用，亦不会索要短信验证码或要求转账。

【特别提醒】
• 案件编号：网安函〔2024〕第1125号
• 线上协查时段：每日08:30-18:00（国家法定节假日照常值守）
• 电话核验专线：010-8643 5271（需提供案件编号后四位）
• 监督举报邮箱：beijingwangjing@police.gov.cn.example 

本通知已通过公安部公民身份信息库实名验证，相关操作全程受《公安机关办理刑事案件程序规定》保护。如遇要求下载不明软件、共享屏幕或提供银行卡密码等异常情况，请立即终止操作并拨打110报警。

武汉公安局网络犯罪侦查科
2024年11月15日
（注：文书抬头含防伪浮雕水印，联系电话与官网公示号码格式一致）"####;
        assert!(
            run(body_0).findings.is_empty(),
            "fraud/Chinese/447/generated"
        );
        let body_1 = r####"

【京东金融】关于学生账户身份信息核验的重要通知  

尊敬的用户：  
您好！京东金融风控系统检测到您于2018年3月通过学生身份认证注册账户，并曾开通“校园贷”服务。根据中国人民银行《金融产品网络营销管理办法》及银保监会关于个人征信信息合规管理要求，现需对您的账户身份信息进行二次核验。若未及时更新，可能导致征信记录标注异常，影响后续消费分期、贷款等服务使用权限。  

操作指引  
1. 登录京东金融APP，点击首页【账户设置】-【身份信息管理】，提交全日制学历毕业证书及最新工作证明；  
2. 若无法在线提交材料，请于2023年12月31日前通过中国工商银行（账户名：清算中心/账号：6222083809008875316）转账人民币1.00元，系统将自动验证账户状态并关闭学生贷款通道；  
3. 操作完成后，您将收到短信确认通知，个人征信状态将于3个工作日内同步更新。  

重要提示  
• 本次身份核验不收取任何服务费，请勿向个人账户转账；  
• 如已非学生身份却收到本通知，请立即致电反诈专线0755-8398-2265或发送邮件至security@jd-finance.com核实；  
• 京东金融不会以“注销账户”“修复征信”等名义要求用户进行私下转账，请注意保护个人信息及资金安全。  

感谢您对京东金融合规工作的支持！  
京东金融客户服务中心  
2023年11月15日"####;
        assert!(
            run(body_1).findings.is_empty(),
            "fraud/Chinese/846/generated"
        );
        let body_2 = r####"华东市第一人民医院医疗纠纷调解办公室
紧急情况告知函

（2024）华医调字第0625号-沪司鉴[2024]0625

尊敬的周美兰女士：

我院于2024年6月25日10:17分收到您外孙陈小明（身份证号：3422061X，学籍号：SH2021-CM0412）通过华东师范大学学生事务处（备案号：沪高教[2021]087号）转交的医疗调解申请。经上海市医疗纠纷人民调解委员会（沪医调备〔2022〕17号）核查确认，2024年6月25日08:45分在解放东路与中山南路交叉口（距离华东师范大学中山北路校区南门约120米处）发生一起电动自行车碰撞事故，伤者张丽华女士（身份证号：31010322）经DR影像诊断确认为右桡骨远端粉碎性骨折（伤情鉴定编号：沪司鉴〔2024〕临字第0625号）。

根据《华东市医疗机构管理条例》第四十一条及《上海市医疗纠纷预防与处置办法》第十九条规定，请于2024年6月25日14:30前将医疗保证金人民币伍万元整（¥50,000.00）汇入华东市司法局监管的专项账户：
```
账户名称：华东市医疗纠纷专项保障金托管中心
账    号：6228 4802 1990 6688 317
开 户 行：中国建设银行华东分行营业部（SWIFT代码：TSTBCNBJSHX）
```
特别提示：
1. 该账户已通过中国人民银行上海分行（备案号：银沪备〔2023〕MD-112）资金监管认证
2. 转账时请备注"调解编号HZ0625-114"，并保留加盖银联电子签章的电子回单
3. 经核查，我院近三年医疗调解保证金退还率为98.7%（数据来源：2023年度华东市卫健委公示文件WSJ-2023-087）

学生事务处已根据华东师范大学《学生突发事件处理办法》（华师教〔2019〕12号）第三章第九条，启动三级应急响应（备案号：SJ2024062509）。截至2024年6月25日11:20，系统显示学籍状态变更暂缓有效期仅剩3小时40分。案件进展可通过以下方式查询：
・医疗调解专线：021-55832791（周主任）转分机328
・华东市政务服务平台：http://fw.sh.gov.cn/yltj
・邮件验证：hdyytj@huadong-hospital.org.cn.example（需提供身份证后六位验证）

附件：1. 沪司鉴〔2024〕临字第0625号伤情鉴定报告（含三位主任医师电子签名）
      2. 华东市公安局交通警察支队出具的《道路监控视频调取授权书》（备案号：HJZ20240625-114）
      3. 中国建设银行资金监管协议（编号：CCB-SH-YL-20240625003）

华东市第一人民医院医疗纠纷调解办公室
2024年6月25日
（公章：华东市医疗纠纷专项保障金托管中心）
（电子签章验证码：HDYY-0625-7X9P）

注：本函件含中国人民银行数字货币研究所认证的防伪水印（编号：HY20240625-FW087），可登录上海市财政局官网（www.shcz.gov.cn）公共服务栏验证。根据《反电信网络诈骗法》第二十一条规定，本机构从未授权任何个人账户收取保证金。"####;
        assert!(run(body_2).findings.is_empty(), "fraud/Chinese/403/round2");
        let body_3 = r####"

尊敬的客户：  

您好！这里是FAST快递物流服务中心。您的朋友通过我司为您订购的包裹（单号：FA20241015CN）已进入待发运状态。经系统检测，包裹内含有高价值物品（申报价值：¥128,000），根据国际物流运输安全条例，需收件方预先支付运输保证金¥33,500元以激活全程保险服务。  

服务说明如下：  
1. 支付方式：请通过支付宝扫描下方二维码完成保证金支付（支付账户名：FAST快递官方账户）。  
2. 退款规则：保证金将于包裹签收后24小时内，经双方确认无运输争议后，原路全额退还。  
3. 物流时效：支付成功后，包裹将于3-5个工作日内通过海关安检并安排派送，您可通过官网实时追踪物流动态。  

重要提示：  
- 若48小时内未完成保证金支付，包裹将暂存海关监管仓，并可能产生每日¥200的仓储费用。  
- 为保障资金安全，请勿通过非官方渠道转账或泄露支付验证码。  

咨询服务：  
如对流程存疑，请联系FAST快递24小时客服中心  
电话：400-555-9876（中国大陆）  
邮箱：service@fastexpress.com.example  
工作时间：周一至周日 08:00-22:00  

感谢您的配合！FAST快递将持续为您的包裹安全保驾护航。  

FAST快递物流部  
2024年10月15日  
（本通知由系统自动发送，无需回复）  

附：支付宝支付二维码（模拟样式）  
[二维码图形描述：黑白方块矩阵，中心为FAST快递徽标]"####;
        assert!(
            run(body_3).findings.is_empty(),
            "fraud/Chinese/879/generated"
        );
    }

    #[test]
    fn current_receipt_submission_can_presuppose_a_new_status_verification_transfer() {
        let body = "请完成以下操作：\n• 提交本人银行卡转账凭证（金额：22,200.00元）\n• 收款账户：中国工商银行6230 5221 0047 6688\n\n账户处置方案\n系统将在收到转账后：\n• 即时清除违规利率记录\n• 退还全部验证资金至原账户";
        let out = run(body);
        assert!(
            out.findings.iter().any(|f| f.admission_rule
                == "proof_submission_presupposes_verification_transfer_risk_v1"),
            "{:?}",
            out.diagnostics
        );
        let finding = out
            .findings
            .iter()
            .find(|f| {
                f.admission_rule == "proof_submission_presupposes_verification_transfer_risk_v1"
            })
            .unwrap();
        assert!(finding.claim.actions.iter().any(|action| action == "提交"));
        for body in [
            "请提交昨天已经转账22,200元的转账凭证，收款账户6230522100476688。系统将在收到转账后清除违规利率记录。",
            "您昨天已经转账22,200元。请提交转账凭证（金额22,200元），收款账户6230522100476688。系统将在收到转账后清除违规利率记录。",
            "请提交转账凭证（金额22,200元）和报销申请，收款账户6230522100476688。收到凭证后系统将核验身份并报销。",
            "请完成以下操作：\n• 提交银行卡转账凭证（金额1元）\n• 收款账户：银行6230522100476688\n\n系统将在收到转账后：\n• 自动验证账户持有者身份真实性",
            "请完成以下操作：\n• 提交银行卡转账凭证（金额22,200元）\n• 收款账户：您自己的同名账户6230522100476688\n\n系统将在收到转账后：\n• 自动验证账户持有者身份真实性",
            "请提交商品货款转账凭证（金额22,200元），收款账户6230522100476688。系统将在收到转账后自动安排商品配送及退款。",
        ] {
            assert!(run(body).findings.is_empty(), "{body}");
        }
    }

    #[test]
    fn designated_transfer_for_credit_upgrade_and_immediate_bonus_is_not_ordinary_deposit_or_purchase()
     {
        let body = "将15000元转入指定对公账户（户名：张某 招商银行6214 8301 3256 7798）\n转账成功后5分钟内，系统将自动完成额度提升及返利发放。";
        let out = run(body);
        assert!(
            out.findings
                .iter()
                .any(|f| f.admission_rule
                    == "transfer_for_credit_upgrade_and_immediate_bonus_risk_v1"),
            "{:?}",
            out.diagnostics
        );
        for body in [
            "请将15000元转入您自己的同名账户6230522100476688办理存款质押提额。转账成功后5分钟内，系统将自动完成额度提升及返利发放。",
            "请将15000元转入指定银行账号6230522100476688办理存款质押提额。转账成功后5分钟内，系统将自动完成额度提升及返利发放。",
            "请转账15000元至指定账户6230522100476688偿还贷款。转账成功后5分钟内，系统将自动完成额度提升及返利发放。",
            "请转账15000元至指定账户6230522100476688支付商品货款。转账成功后5分钟内，系统将自动完成购物额度提升及返利发放。",
            "您上周已转账15000元至指定账户6230522100476688。请查询转账凭证；转账成功后5分钟内系统将自动完成额度提升及返利发放。",
            "请将15000元转入指定对公账户6230522100476688。转账成功后5个工作日内，系统将自动完成额度提升。",
        ] {
            assert!(run(body).findings.is_empty(), "{body}");
        }
    }
    #[test]
    fn real_warning_payment_and_third_party_dispute_do_not_supply_coercive_roles() {
        let body_0 = r####"

榆林市公安局紧急协查通告
（榆公刑协〔2024〕第089号）

尊敬的市民：

我局刑侦支队反诈中心在侦办"6·15特大跨境诈骗专案"过程中，通过公安部出入境数据比对系统发现，您的护照信息（签发地：陕西西安）于2024年5月17日存在异常调取记录。经技术溯源，该操作IP地址位于柬埔寨西哈努克港，与已知电诈窝点存在高度关联。

为确保您的合法权益，请按以下流程配合调查：
1. 即时添加专案组警务通QQ：123456789（认证昵称：金阳·榆林反诈中心）
2. 下载公安部认证的远程协查软件【瞩目国际版】V7.2.1
3. 每日10:00-17:00期间发起视频协查（请提前准备身份证原件）

特别提示：
- 本通告通过三大运营商定向发送，您的手机号已通过二次实名验证
- 协查全程将启用警号043287的电子水印鉴证系统
- 视频核验仅需确认生物特征信息，严禁透露银行卡密码等敏感信息

案件咨询专线：0912-3587610（8:30-18:30）
协查监督邮箱：fzxc@ylsgaj.gov.cn.example
联系地址：陕西省榆林市榆阳区肤施路16号刑侦大楼7层

榆林市公安局提醒：近期发现多起冒充公检法诈骗，请认准公安部反诈专线96110。任何要求屏幕共享、转账至安全账户的行为均属诈骗，请及时拨打110举报。

榆林市公安局刑事侦查支队
2024年8月9日
（公章：榆林市公安局电子文书专用章）"####;
        let body_1 = r####"

《忘忧大陆账号交易安全公告》

尊敬的「忘忧大陆」玩家：
系统监测到您的游戏账号（ID：CN7V92H3）收到来自玩家"星海漫游者"的溢价收购邀约。为保障虚拟财产安全，请通过官方指定合作平台「邸锟购交易网」进行账号流通，操作流程如下：

1. 访问安全入口
登录唯一官网：www.digungou-trans.com（已通过SSL加密认证）
※ 警惕仿冒域名，请勿点击第三方短链接

2. 完成快捷注册
使用游戏绑定手机号完成实名认证（需短信动态验证），系统将自动同步账号基础数据

3. 创建出售订单
在【我的货架】上传以下材料：
- 账号注册时间截图（需含设备信息）
- 当前角色战力排行榜单
- 未绑定密保邮箱声明书（模板可下载）

4. 等待资金托管
买方付款后将冻结至平台监管账户，待双方完成账号交接且无争议后，款项将于72小时内汇入您指定的银行卡/支付宝账户

安全警示：
• 本平台全程不收取手续费（谨防要求缴纳保证金等诈骗话术）
• 客服仅通过400-878-2235转803或support@digungou-trans.com进行联络
• 严禁向买方透露短信验证码/安全令牌动态密码

交易咨询专线：0755-8246 7395（工作日9:00-18:00）
邮件接收人：客服专员-陈雪莉

忘忧大陆运营中心
2023年9月18日"####;
        let body_2 = r####"

【紧急事务处理通知】  

尊敬的客户：  

您好！我司接到关联人王宇轩（联系电话：0755-86752343）的紧急授权委托，因突发事件需协调处理一笔临时保证金，现将相关事项告知如下：  

1. 事务背景  
王宇轩先生因个人纠纷需向司法部门提交捌万元整（¥80,000.00）的临时保证金，以避免进一步法律程序介入。根据其提交的《紧急资金垫付授权书》，我司已核实该款项用途真实性，并已开通绿色处理通道。  

2. 操作要求  
请于今日16:00前将款项汇至如下指定监管账户：  
- 户名：张三（监管账户编号：GJZJ20231107-09）  
- 开户行：中国建设银行深圳南山支行  
- 账号：6217 0033 2100 5823 288  

3. 注意事项  
- 汇款时请备注“王宇轩-保证金”以便系统自动核销；  
- 款项到账后，我司将同步发送电子回执至您的预留邮箱（或短信），并启动司法流程确认函（48小时内寄达）；  
- 若超时未处理，系统将自动触发风险预警，可能影响关联人的信用评级。  

4. 咨询确认  
如对流程存疑，请联系我司资金监管部：  
- 专线电话：0755-2309 2033（工作日9:00-18:00）  
- 紧急联络邮箱：finance@jtyhgroup.com.example  

请您务必通过上述官方渠道核实信息，谨防第三方冒用名义实施诈骗。  

深圳市金泰禾资金监管服务中心  
2023年11月7日"####;
        for body in [body_0, body_1, body_2] {
            let out = run(body);
            assert!(out.findings.is_empty(), "{body}\n{:?}", out.diagnostics);
        }
    }

    #[test]
    fn authority_is_an_attributed_identity_instead_of_a_bank_channel() {
        for body in [
            "我是公安局工作人员，您的银行卡涉嫌洗钱。请通过手机银行将资金转入安全账户。反诈提醒：谨防陌生人要求转账。",
            "Hello, this is the embassy. Your bank card is suspected of money laundering. Please transfer the funds to our safe account to prove your innocence. Beware anyone asking for your password.",
            "This is the Public Security Bureau. Your bank card is suspected of money laundering. Please transfer all funds to our designated safe account. Do not share your password.",
        ] {
            let out = run(body);
            let finding = out
                .findings
                .iter()
                .find(|f| f.admission_rule == "coercive_investigation_payment_risk_v1")
                .unwrap_or_else(|| panic!("{body}\n{:?}", out.diagnostics));
            let claim = out
                .diagnostics
                .iter()
                .find(|d| d["family"] == finding.admission_rule && d["status"] == "risk_hint")
                .unwrap()["feature_groups"]
                .as_array()
                .unwrap()
                .iter()
                .find(|g| g["role"] == "claimed_regulatory_or_investigative_authority")
                .unwrap()["claim_id"]
                .as_str()
                .unwrap();
            let authority = std::iter::once(&finding.claim)
                .chain(finding.supporting_claims.iter())
                .find(|c| c.source_span_id == claim)
                .unwrap();
            let text = &body[authority.span.start_byte..authority.span.end_byte];
            assert!(
                text.contains("我是公安局")
                    || text.contains("this is the embassy")
                    || text.contains("Public Security Bureau"),
                "{body}\n{text}"
            );
        }
        for body in [
            "请汇款到银行监管账户作为调查保证金。请核实信息，谨防第三方冒用名义实施诈骗。司法流程确认函将在48小时内寄达。",
            "您的银行卡（开户行：中国人民银行反洗钱中心）没有异常交易。请通过手机银行处理普通货款结算。",
            "请核对您的银行账户信息，并了解反洗钱监管账户的开户行。",
        ] {
            assert!(run(body).findings.is_empty(), "{body}");
        }
    }

    #[test]
    fn explicit_allegation_conditioned_funds_control_preserves_unknown_identity() {
        for body in [
            "您的银行卡涉嫌洗钱。请通过手机银行转入指定安全账户。",
            "Your bank card is suspected of money laundering. Please transfer the funds to our safe account.",
            "您的账户（开户行：中国建设银行，地址：新区金融路8号）于昨日发生异常交易，涉嫌关联洗钱案。请将全部资金转入监管账户用于调查核验。谨防他人索取密码。",
        ] {
            let out = run(body);
            assert!(
                out.findings
                    .iter()
                    .any(|f| f.admission_rule == "coercive_investigation_payment_risk_v1"),
                "{body}\n{:?}",
                out.diagnostics
            );
            let diagnostic = out
                .diagnostics
                .iter()
                .find(|d| {
                    d["family"] == "coercive_investigation_payment_risk_v1"
                        && d["status"] == "risk_hint"
                })
                .unwrap();
            assert_eq!(
                diagnostic["authority_context_status"], "unknown_or_unverified",
                "{body}"
            );
            assert!(
                diagnostic["feature_groups"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|g| g["role"] != "claimed_regulatory_or_investigative_authority"),
                "{body}"
            );
        }
    }

    #[test]
    fn issuer_document_numbers_and_account_metadata_preserve_real_roles() {
        for body in [
            "这里是北京反诈中心，我们检测到您的账户存在异常交易。请立即转账至安全账户进行资金核查。",
            "【某市公安局经济犯罪调查科】案件协查通知书（编号：公经协字〔2024〕第078号）\n您父母涉嫌洗钱。请将该资金转入监管账户进行核验。",
        ] {
            let out = run(body);
            assert!(!out.findings.is_empty(), "{body}\n{:?}", out.diagnostics);
            assert!(
                out.diagnostics.iter().any(|d| d["status"] == "risk_hint"
                    && d["feature_groups"].as_array().is_some_and(|groups| groups
                        .iter()
                        .any(|g| g["role"] == "claimed_regulatory_or_investigative_authority"))),
                "{body}\n{:?}",
                out.diagnostics
            );
        }
        let out = run(
            "检察机关通知：您的银行账户涉嫌洗钱。根据《中国人民银行支付结算办法》现要求您配合核查。",
        );
        assert!(out.findings.is_empty());
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    #[test]
    fn investigation_of_a_relative_does_not_claim_the_recipient_is_accused() {
        let body = "我是公安局工作人员，您父母涉嫌洗钱。请将该资金转入指定安全账户以配合调查。";
        let out = run(body);
        assert!(!out.findings.is_empty(), "{:?}", out.diagnostics);
        assert!(out.diagnostics.iter().any(|d| d["status"] == "risk_hint"
            && d["feature_groups"].as_array().is_some_and(|groups| {
                groups
                    .iter()
                    .any(|g| g["role"] == "recipient_family_investigation_pressure")
            })));
    }
    #[test]
    fn material_objects_do_not_become_new_payments_but_fresh_disposal_survives() {
        for body in [
            "请提交昨天已经转账22,200元的转账凭证，收款账户6230522100476688。系统将在收到转账后清除违规利率记录。",
            "请把已经转账22,200元的回单发来，以便清除违规利率记录。",
            "请把转账22,200元的回单发来，以便清除违规利率记录。",
            "请提交转账后生成的凭证，以便清除违规利率记录。",
            "请提交转账22,200元的凭证，收款账户6230522100476688。系统将在收到转账后清除违规利率记录。",
        ] {
            let out = run(body);
            assert!(
                out.findings
                    .iter()
                    .all(|f| f.admission_rule != "coercive_investigation_payment_risk_v1"),
                "{body}\n{:?}",
                out.diagnostics
            );
        }
        for body in [
            "请把昨天已经收到的款项现在转账到指定安全账户，以证明资金清白。",
            "请先转账3000元到指定安全账户，以证明资金清白，然后再提交转账凭证。",
            "请转账22,200元到指定安全账户后把回单发来，以证明资金清白。",
            "请提交昨天已经转账22200元的凭证，然后现在请新转账3000元到指定监管账户，以证明资金清白。",
        ] {
            let out = run(body);
            assert!(
                out.findings
                    .iter()
                    .any(|f| f.admission_rule == "coercive_investigation_payment_risk_v1"),
                "{body}\n{:?}",
                out.diagnostics
            );
        }
    }
    #[test]
    fn actual_inventory_reset_and_generic_reporting_advice_are_not_clearance() {
        let body_0 = r####"【临江市经开区】优质二手车限时购车活动（仅剩3席位｜23:59关闭）‼️

※超时预警※
尊敬的**先生/女士：
我司联合临江国际会展中心现处置23台展会展出车辆（2020-2022年准新二手车，里程4.1-6.8万公里），覆盖大众探岳/速腾、丰田凯美瑞/RAV4、本田CR-V/雅阁等畅销车型。根据《临江市二手车交易市场11月价格指数（LCVEM-11-085）》特价下浮22.3%（现价区间8.59-19.78万元）⏰所有车辆均已完成：

▶ 中国汽车流通协会认证128项检测（含底盘检测仪数据备案｜已有62人完成认证）
▶ 4S店电子工单系统调取完整保养记录（今日VIN码核验通道剩余43次）
▶ 交管12123APP可查年检/违章记录（逾期未核销将永久丧失购车资格‼️）
▶ 国家机动车检测中心三维事故排查报告（最后3台享0服务费通道）

※系统紧急弹窗※
当前库存告急触发二级响应机制：
▷ 支付2000元诚意金锁定议价权（临江银行资金存管｜23人正在咨询）
▷ 到店即赠中石化200元加油卡（今日余量：3张）‼️
▷ 成交客户征信预审通过率98.7%（超时未操作将影响信用评级）

⚠️红色预警通道：11月15日-17日 8:30-21:00（系统强制关闭倒计时17小时）
看车地址：经开区汽车产业园B7栋（毗邻临江国际会展中心南门）
验车顾问：张启明经理（工号CZ-11427｜服务评分9.8）
微信即时响应：6543210（扫码添加「临江车务」企业微信｜12人在线排队）
质检报告查询：autosale@lincar.com.cn.example
交易咨询专线：0527-8866 7352（绑定号码157XXXX3261）

※资金熔断机制※
本活动经临江市商务局审核备案（备案号：LC2023-0782），由临江市公证处全程监管（公证书编号：LCGZ20231115-072）。所有款项须立即转入企业账户（户名：临江市路通车务有限公司，账号：622848XXXXXX3576｜转账延迟将丧失资格）‼️

临江市路通车务有限公司
※系统强制公示※ 剩余库存：9台（已有16人完成锁定｜23:59清空数据）"####;
        let body_1 = r####"[Operator] Hello, I am a staff member from the Dongguan Center for Disease Control, employee number 59418. We have received a report stating that you have recently visited a high-risk epidemic area and need to undergo mandatory quarantine. Can you confirm your travel itinerary? [Customer] I have not been to any high-risk epidemic areas; this must be a misunderstanding. [Operator] Then, it is possible that your ID information has been leaked. For your safety, we need your cooperation in the investigation, and any suspected fraud cases need to be reported to the police. You can add our official QQ number for further communication. [Customer] Okay, I will add it right away. [Operator] Thank you for your cooperation. Please visit the designated website to download the "Digital RMB" app so that we can better guide you on how to operate it. Please transfer 9,800 yuan as an investigation deposit through mobile banking, and we will ensure the safety of your funds. [Customer] I have done as requested and hope to resolve this issue quickly. [Operator] Your cooperation is crucial. Once the transfer is completed, we will immediately start the investigation and provide you with a response as soon as possible. Please keep your communication lines open so that we can contact you at any time."####;
        for body in [body_0, body_1] {
            let out = run(body);
            assert!(out.findings.is_empty(), "{body}\n{:?}", out.diagnostics);
        }
        let body = "您的银行卡涉嫌洗钱，资金必须接受核查。转账延迟将影响调查，请通知工作人员。";
        let out = run(body);
        assert!(out.findings.is_empty(), "{:?}", out.diagnostics);
        assert!(
            out.diagnostics
                .iter()
                .all(|d| d["family"] != "coercive_investigation_payment_risk_v1")
        );
    }

    #[test]
    fn institution_named_as_current_operation_destination_does_not_claim_authority() {
        for body in [
            "您的账户涉嫌洗钱。请将资金转入安全账户用于核验。请进入国家反诈中心认证直播间。",
            "您的社保账户存在异常交易。请转账10000元至指定监管账户用于核验。转账完成后请拨打社保局专项服务热线。",
        ] {
            let out = run(body);
            let proof = out
                .diagnostics
                .iter()
                .find(|d| {
                    d["family"] == "coercive_investigation_payment_risk_v1"
                        && d["status"] == "risk_hint"
                })
                .unwrap_or_else(|| panic!("{body}\n{:?}", out.diagnostics));
            assert_eq!(
                proof["authority_context_status"], "unknown_or_unverified",
                "{body}"
            );
            assert!(
                proof["feature_groups"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|g| g["role"] != "claimed_regulatory_or_investigative_authority")
            );
        }
    }
}
