//! CJK character, entropy, and bigram observations.

use std::collections::{HashMap, HashSet};

use crate::module::Evidence;

use super::budget::SemanticCpuBudget;

/// Minimum CJK character count to begin analysis (short emails are skipped)
const MIN_CJK_CHARS: usize = 10;
/// Finite-sample entropy is strongly biased on short notices. This gate
/// affects statistical observations only, never native threat relations.
const MIN_ENTROPY_CJK_CHARS: usize = 128;

/// Below this Shannon entropy (bits per character) the text is dominated by
/// repeated characters.
const ENTROPY_NORMAL_LOW: f64 = 4.0;

// UNCALIBRATED (conservative placeholders, to be evaluated on the remote
// corpus): the high-entropy, bigram and rare-ratio thresholds below were
// chosen from a small measurement of normal documents, not from a labelled
// benchmark.
//
// Chinese single-character entropy grows with sample length (median on normal
// documents: 128 chars ~6.45 bits, 200 ~6.80, 500 ~7.63, >=800 ~7.9-8.6), so a
// fixed upper bound flags long legitimate mail. The high-entropy rule therefore
// requires the text to be nearly all-distinct relative to its own length
// (entropy close to log2(N)) or to exceed an absolute saturation ceiling.
/// Distance below the all-distinct maximum log2(N) that still counts as random.
const ENTROPY_HIGH_DISTINCT_MARGIN: f64 = 0.15;
/// Absolute ceiling: above this, the character distribution is saturated.
const ENTROPY_HIGH_CEILING: f64 = 10.5;
/// Excess (bits) over the high threshold that maps to a full anomaly. Equal to
/// the margin so an exactly all-distinct sample saturates the anomaly.
const ENTROPY_HIGH_ANOMALY_SCALE: f64 = ENTROPY_HIGH_DISTINCT_MARGIN;

/// Rare CJK character ratio threshold to trigger detection
const RARE_CJK_THRESHOLD: f64 = 0.05;
/// One rare character in a personal name must not dominate a short mail: the
/// ratio is only meaningful with several rare characters in a larger sample.
const MIN_RARE_CJK_COUNT: usize = 3;
const MIN_RARE_RATIO_CJK_CHARS: usize = 32;

/// Bigram uniqueness threshold: normal text reuses bigrams; gibberish has near
/// 100% unique bigrams. Normal medians: 128 chars ~0.937, 200 ~0.889, 500 ~0.830.
const BIGRAM_UNIQUE_THRESHOLD: f64 = 0.975;
/// Short, well-written Chinese announcements naturally have almost no repeated
/// bigrams. High uniqueness is meaningful only after a larger language sample.
const MIN_HIGH_UNIQUENESS_BIGRAMS: usize = 160;

// Unicode range detection

/// Check whether a character is in the CJK basic block (U+4E00..U+9FFF)
fn is_cjk_basic(ch: char) -> bool {
    ('\u{4E00}'..='\u{9FFF}').contains(&ch)
}

/// Check whether a character is in a CJK extended block (rare characters)
/// Includes Ext-A through Ext-I, Compatibility Ideographs, and the radical
/// blocks (radical look-alikes are an obfuscation vector for ideographs).
fn is_cjk_rare(ch: char) -> bool {
    let c = ch as u32;
    // CJK Radicals Supplement: U+2E80..U+2EFF
    (0x2E80..=0x2EFF).contains(&c)
   // Kangxi Radicals: U+2F00..U+2FDF
    || (0x2F00..=0x2FDF).contains(&c)
   // CJK Ext-A: U+3400..U+4DBF
    || (0x3400..=0x4DBF).contains(&c)
   // CJK Ext-B: U+20000..U+2A6DF
    || (0x20000..=0x2A6DF).contains(&c)
   // CJK Ext-C: U+2A700..U+2B73F
    || (0x2A700..=0x2B73F).contains(&c)
   // CJK Ext-D: U+2B740..U+2B81F
    || (0x2B740..=0x2B81F).contains(&c)
   // CJK Ext-E: U+2B820..U+2CEAF
    || (0x2B820..=0x2CEAF).contains(&c)
   // CJK Ext-F: U+2CEB0..U+2EBEF
    || (0x2CEB0..=0x2EBEF).contains(&c)
   // CJK Ext-I: U+2EBF0..U+2EE5F
    || (0x2EBF0..=0x2EE5F).contains(&c)
   // CJK Ext-G: U+30000..U+3134F
    || (0x30000..=0x3134F).contains(&c)
   // CJK Ext-H: U+31350..U+323AF
    || (0x31350..=0x323AF).contains(&c)
   // CJK Compatibility Ideographs: U+F900..U+FAFF
    || (0xF900..=0xFAFF).contains(&c)
   // CJK Compatibility Ideographs Supplement: U+2F800..U+2FA1F
    || (0x2F800..=0x2FA1F).contains(&c)
}

/// Check whether a character is any CJK ideograph (basic or extended)
pub(super) fn is_cjk_any(ch: char) -> bool {
    is_cjk_basic(ch) || is_cjk_rare(ch)
}

// CJK gibberish analysis dimensions

/// Length-aware high-entropy threshold: `min(log2(N) - margin, ceiling)`.
/// Normal prose stays well below log2(N) because common characters repeat.
fn high_entropy_threshold(total_cjk: usize) -> f64 {
    ((total_cjk as f64).log2() - ENTROPY_HIGH_DISTINCT_MARGIN).min(ENTROPY_HIGH_CEILING)
}

/// Collect all CJK statistics in one cooperatively bounded traversal.
/// Partial statistics are discarded: a truncated distribution is not proof
/// of malicious intent and must not manufacture an anomaly score.
struct SemanticStatistics {
    rare_count: usize,
    total_cjk: usize,
    entropy: f64,
    bigram_unique: f64,
    bigram_total: usize,
    rare_samples: String,
}

fn semantic_statistics(text: &str, budget: &SemanticCpuBudget) -> Option<SemanticStatistics> {
    let mut rare_count = 0usize;
    let mut total_cjk = 0usize;
    let mut frequencies = HashMap::<char, usize>::new();
    let mut bigrams = HashSet::<(char, char)>::new();
    let mut bigram_total = 0usize;
    let mut previous = None;
    let mut rare_samples = String::new();
    let mut sampled_rare_count = 0;
    for (index, character) in text.chars().enumerate() {
        if index % 1024 == 0 && budget.exhausted() {
            return None;
        }
        if !is_cjk_any(character) {
            // Whitespace, punctuation, Latin, or kana ends the CJK run; pairing
            // across it would fabricate bigrams that never occur in the text.
            previous = None;
            continue;
        }
        total_cjk += 1;
        *frequencies.entry(character).or_default() += 1;
        if let Some(left) = previous {
            bigrams.insert((left, character));
            bigram_total += 1;
        }
        previous = Some(character);
        if is_cjk_rare(character) {
            rare_count += 1;
            if sampled_rare_count < 10 {
                rare_samples.push(character);
                sampled_rare_count += 1;
            }
        }
    }
    if budget.exhausted() {
        return None;
    }
    let entropy = if total_cjk == 0 {
        0.0
    } else {
        frequencies
            .values()
            .map(|count| {
                let probability = *count as f64 / total_cjk as f64;
                -probability * probability.log2()
            })
            .sum()
    };
    Some(SemanticStatistics {
        rare_count,
        total_cjk,
        entropy,
        bigram_unique: if bigram_total == 0 {
            0.0
        } else {
            bigrams.len() as f64 / bigram_total as f64
        },
        bigram_total,
        rare_samples,
    })
}

/// Score actionable CJK anomalies while retaining benign structural observations.
///
/// Low bigram uniqueness is common in long templates and quoted report history.
/// It remains analyst-visible but must not contribute to the threat score.
#[cfg(test)]
pub(super) fn score_semantics(text: &str) -> (f64, Vec<Evidence>, Vec<Evidence>) {
    score_semantics_with_budget(text, &SemanticCpuBudget::new()).unwrap_or_default()
}

pub(super) fn score_semantics_with_budget(
    text: &str,
    budget: &SemanticCpuBudget,
) -> Option<(f64, Vec<Evidence>, Vec<Evidence>)> {
    let mut evidence = Vec::new();
    let mut observations = Vec::new();
    let mut score = 0.0f64;

    let statistics = semantic_statistics(text, budget)?;
    let rare_count = statistics.rare_count;
    let total_cjk = statistics.total_cjk;
    let rare_ratio = if total_cjk == 0 {
        0.0
    } else {
        rare_count as f64 / total_cjk as f64
    };

    if total_cjk < MIN_CJK_CHARS {
        return Some((0.0, evidence, observations));
    }

    // Dimension 1: Rare character ratio (weight 0.4)
    if rare_ratio > RARE_CJK_THRESHOLD
        && rare_count >= MIN_RARE_CJK_COUNT
        && total_cjk >= MIN_RARE_RATIO_CJK_CHARS
    {
        let normalized = ((rare_ratio - RARE_CJK_THRESHOLD) / 0.25).min(1.0);
        let dim_score = (normalized * 0.4).min(0.4);
        score += dim_score;

        evidence.push(Evidence {
            description: format!(
                "Rare CJK character ratio {:.1}% ({}/{} characters), exceeds {}% threshold",
                rare_ratio * 100.0,
                rare_count,
                total_cjk,
                (RARE_CJK_THRESHOLD * 100.0) as u32,
            ),
            location: Some("body".to_string()),
            snippet: Some(format!(
                "Rare character samples: {}",
                statistics.rare_samples
            )),
        });
    }

    // Dimension 2: Entropy anomaly (weight 0.3)
    let entropy = statistics.entropy;
    let entropy_high = high_entropy_threshold(total_cjk);
    let entropy_anomaly = if entropy < ENTROPY_NORMAL_LOW && entropy > 0.0 {
        ((ENTROPY_NORMAL_LOW - entropy) / ENTROPY_NORMAL_LOW).min(1.0)
    } else if entropy > entropy_high {
        ((entropy - entropy_high) / ENTROPY_HIGH_ANOMALY_SCALE).min(1.0)
    } else {
        0.0
    };

    if total_cjk >= MIN_ENTROPY_CJK_CHARS && entropy_anomaly > 0.1 {
        let dim_score = (entropy_anomaly * 0.3).min(0.3);
        score += dim_score;

        let anomaly_type = if entropy < ENTROPY_NORMAL_LOW {
            "low (excessive character repetition)"
        } else {
            "high (overly random characters)"
        };

        evidence.push(Evidence {
            description: format!(
                "CJK character entropy {:.2} bits {}, normal range {:.1}-{:.2} bits for {} characters",
                entropy, anomaly_type, ENTROPY_NORMAL_LOW, entropy_high, total_cjk,
            ),
            location: Some("body".to_string()),
            snippet: None,
        });
    }

    // Dimension 3: Bigram uniqueness anomaly (weight 0.3)
    let bigram_unique = statistics.bigram_unique;
    let bigram_total = statistics.bigram_total;
    if bigram_total >= 50 {
        let high_uniqueness_anomaly = if bigram_total >= MIN_HIGH_UNIQUENESS_BIGRAMS
            && bigram_unique > BIGRAM_UNIQUE_THRESHOLD
        {
            ((bigram_unique - BIGRAM_UNIQUE_THRESHOLD) / (1.0 - BIGRAM_UNIQUE_THRESHOLD)).min(1.0)
        } else {
            0.0
        };

        if high_uniqueness_anomaly > 0.1 {
            let dim_score = (high_uniqueness_anomaly * 0.3).min(0.3);
            score += dim_score;

            evidence.push(Evidence {
                description: format!(
                    "Bigram uniqueness ratio {:.1}% ({} bigrams), anomalously high (character pairs almost never repeat)",
                    bigram_unique * 100.0,
                    bigram_total,
                ),
                location: Some("body".to_string()),
                snippet: None,
            });
        } else if bigram_unique < 0.1 {
            observations.push(Evidence {
                description: format!(
                    "Repetitive template structure observed: bigram uniqueness {:.1}% across {} bigrams; retained as context only",
                    bigram_unique * 100.0,
                    bigram_total,
                ),
                location: Some("body:structure".to_string()),
                snippet: None,
            });
        }
    }

    Some((score.min(1.0), evidence, observations))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Varied, realistic business prose (meeting notice, project report,
    /// training logistics). Deliberately not a repeated sentence: repetition
    /// would lower entropy and hide the long-sample false positive.
    const LONG_NORMAL_CHINESE: &str = concat!(
        "各部门负责人：为做好第三季度经营工作总结和第四季度重点任务部署，经公司研究决定，",
        "定于十月二十八日下午两点在总部三楼第一会议室召开季度经营分析会。",
        "请各部门提前准备本部门的工作汇报材料，内容包括主要指标完成情况、重点项目推进进度、",
        "存在的问题及原因分析、下一阶段工作计划和需要协调解决的事项。",
        "汇报时间控制在十分钟以内，材料请于会前两个工作日发送至综合办公室邮箱，以便统一汇总印发。",
        "参会人员请提前十分钟签到入场，会议期间请将手机调至静音状态。",
        "如因特殊情况无法参会，须向分管领导书面请假，并指定熟悉业务的同事代为参加。\n\n",
        "关于客户服务平台升级项目的进展，现将有关情况报告如下。",
        "项目自今年五月启动以来，团队围绕需求调研、方案设计、系统开发和联调测试四个阶段有序推进。",
        "目前已完成用户中心、工单管理、知识库检索和数据看板等核心模块的开发，",
        "单元测试覆盖率达到百分之八十五，累计修复缺陷两百余个。",
        "九月中旬我们邀请了华东和华南两个区域的二十位一线客服人员参与试用，收集到改进建议六十多条，",
        "其中关于搜索响应速度、批量导出功能和移动端适配的意见最为集中，已全部纳入后续迭代计划。\n\n",
        "在推进过程中也暴露出一些不足。一是部分历史数据格式不统一，迁移脚本需要反复调整，",
        "导致数据清洗工作比原计划延后约两周；二是与财务系统的接口规范尚未最终确定，",
        "双方技术人员正在逐项核对字段定义；三是测试环境的服务器资源偏紧，高峰时段经常出现排队等待的情况。",
        "针对上述问题，项目组已制定专项整改措施，计划增派两名数据工程师协助清洗工作，并申请临时扩容测试资源。\n\n",
        "下一步，我们将重点做好以下几项工作：第一，十一月底前完成全部模块的集成测试和性能压测，",
        "确保系统在并发访问量翻倍的情况下仍能稳定运行；第二，组织编写操作手册和培训课件，",
        "分批次对各地分支机构的业务骨干开展线上培训；第三，与信息安全团队共同开展渗透测试和权限审计，",
        "及时修补发现的漏洞；第四，制定详细的上线切换方案和应急回退预案，力争在年底前实现平稳上线。\n\n",
        "另外，根据人力资源部的统一安排，新员工入职培训将于下月初在城东培训中心举行，为期三天，",
        "课程涵盖企业文化、规章制度、办公软件使用技巧以及职业素养提升等内容。",
        "培训期间统一提供午餐和往返班车，班车每天早上七点半从公司正门出发。",
        "请各用人部门督促新入职同事按时报到，培训结束后将组织闭卷考核，成绩将记入个人试用期评价档案。\n\n",
        "感谢大家一直以来对各项工作的理解和支持。年终将至，希望各部门继续保持良好的工作状态，",
        "加强沟通协作，注意劳逸结合，在确保安全生产的前提下全力冲刺全年目标。",
        "如对上述安排有任何疑问，请随时与综合办公室联系，联系人张女士，电话分机八零一六。",
        "此外，行政部提醒各位同事，近期气温变化较大，请注意防寒保暖；",
        "园区停车场东侧正在进行路面修缮，施工期间请绕行西门进出，车辆按指示牌有序停放。",
        "食堂自本周起推出健康轻食窗口，提供低油低盐的套餐和新鲜水果，欢迎大家品尝并提出宝贵意见。",
        "工会将于月中组织羽毛球和乒乓球友谊赛，有意参加的同事请在周三之前向本部门联络员报名。",
    );

    fn statistics_of(text: &str) -> SemanticStatistics {
        semantic_statistics(text, &SemanticCpuBudget::new()).expect("fresh budget")
    }

    fn has_evidence(evidence: &[Evidence], needle: &str) -> bool {
        evidence
            .iter()
            .any(|item| item.description.contains(needle))
    }

    #[test]
    fn long_normal_chinese_prose_has_no_entropy_or_bigram_evidence() {
        let statistics = statistics_of(LONG_NORMAL_CHINESE);
        assert!(
            statistics.total_cjk >= 900,
            "fixture must be a long sample, got {} CJK characters",
            statistics.total_cjk
        );

        let (score, evidence, _) = score_semantics(LONG_NORMAL_CHINESE);

        assert!(
            !has_evidence(&evidence, "entropy"),
            "long normal prose must not be flagged as high entropy (entropy {:.2}): {evidence:?}",
            statistics.entropy
        );
        assert!(
            !has_evidence(&evidence, "Bigram uniqueness ratio"),
            "long normal prose must not be flagged for bigram uniqueness ({:.3}): {evidence:?}",
            statistics.bigram_unique
        );
        assert!(!has_evidence(&evidence, "Rare CJK"), "{evidence:?}");
        assert_eq!(score, 0.0, "{evidence:?}");
    }

    #[test]
    fn short_mail_with_one_rare_name_character_has_no_rare_evidence() {
        // 15 CJK characters, one of them an Ext-A character from a name.
        let text = format!("请将{}先生的报销单交给财务部门", '\u{3400}');
        let statistics = statistics_of(&text);
        assert_eq!(statistics.total_cjk, 15);
        assert_eq!(statistics.rare_count, 1);

        let (_, evidence, _) = score_semantics(&text);

        assert!(!has_evidence(&evidence, "Rare CJK"), "{evidence:?}");
    }

    #[test]
    fn deterministic_rare_extension_sequence_still_produces_evidence() {
        // Step through CJK Ext-B with a fixed stride: a reproducible stand-in
        // for randomly drawn rare characters.
        let text: String = (0..200u32)
            .filter_map(|offset| char::from_u32(0x20000 + offset * 7))
            .collect();
        let statistics = statistics_of(&text);
        assert_eq!(statistics.total_cjk, 200);
        assert_eq!(statistics.rare_count, 200);

        let (score, evidence, _) = score_semantics(&text);

        assert!(has_evidence(&evidence, "Rare CJK"), "{evidence:?}");
        assert!(
            has_evidence(&evidence, "Bigram uniqueness ratio"),
            "{evidence:?}"
        );
        assert!(
            has_evidence(&evidence, "high (overly random characters)"),
            "an all-distinct sample must still trip the length-aware entropy rule: {evidence:?}"
        );
        assert!(score > 0.0);
    }

    #[test]
    fn radical_and_new_extension_blocks_count_as_rare_cjk() {
        for character in [
            '\u{2E80}',
            '\u{2EFF}',
            '\u{2F00}',
            '\u{2FD5}',
            '\u{2EBF0}',
            '\u{2EE5D}',
            '\u{31350}',
            '\u{323AF}',
        ] {
            assert!(is_cjk_any(character), "{:X}", character as u32);
            assert!(is_cjk_rare(character), "{:X}", character as u32);
        }
        assert!(!is_cjk_rare('\u{4E00}'));
        assert!(!is_cjk_any('\u{3042}'), "kana is not a CJK ideograph");

        // Kangxi radical look-alikes substituted into an otherwise normal
        // notice must be visible to the rare-character ratio.
        let radicals: String = (0..8u32)
            .filter_map(|offset| char::from_u32(0x2F00 + offset * 3))
            .collect();
        let text = format!(
            "请各位同事于本周五下班前登录财务系统核对{radicals}本月工资明细并确认无误后提交"
        );
        let statistics = statistics_of(&text);
        assert!(statistics.total_cjk >= 32, "{}", statistics.total_cjk);
        assert_eq!(statistics.rare_count, 8);

        let (_, evidence, _) = score_semantics(&text);

        assert!(has_evidence(&evidence, "Rare CJK"), "{evidence:?}");
    }

    #[test]
    fn non_cjk_characters_reset_the_bigram_predecessor() {
        // Kana separates the ideograph runs: only 東京 and 会議 are bigrams.
        let statistics = statistics_of("東京のホテルで会議を開きます");
        assert_eq!(statistics.total_cjk, 5);
        assert_eq!(statistics.bigram_total, 2);

        let statistics = statistics_of("甲あ乙 丙,丁z戊");
        assert_eq!(statistics.total_cjk, 5);
        assert_eq!(
            statistics.bigram_total, 0,
            "kana, whitespace, punctuation, and Latin must not form bigrams"
        );
        assert_eq!(statistics.bigram_unique, 0.0);
    }
}
