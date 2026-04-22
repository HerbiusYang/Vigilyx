//! Pure utility functions for domain heuristic analysis.
//!
//! Contains: domain parsing, URL redirect extraction, and
//! heuristic scoring for suspicious domain characteristics.

use super::data::RE_RANDOM_DOMAIN;
use crate::module_data::module_data;
use crate::modules::common::extract_redirect_target_urls;

/// Extract redirect target URLs from tracking/security-gateway links.
pub(super) fn extract_redirect_target_urls_full(url: &str) -> Vec<String> {
    extract_redirect_target_urls(url)
}

/// Returns the number of labels in the TLD (2 for compound like `.com.cn`, 1 for simple like `.com`).
/// Compound TLD list is loaded from `engine_module_data_seed.json` → `compound_tlds`.
fn tld_label_count(domain: &str) -> usize {
    let lower = domain.to_ascii_lowercase();
    for compound in module_data().get_list("compound_tlds") {
        if lower.ends_with(compound.as_str()) {
            let prefix_len = lower.len() - compound.len();
            if prefix_len == 0 || lower.as_bytes()[prefix_len - 1] == b'.' {
                return 2;
            }
        }
    }
    1
}

/// Get registered domain (TLD+1), handling compound TLDs correctly.
///
/// - `sub.example.com` → `example.com`
/// - `notice01.cloud.huawei.com.cn` → `huawei.com.cn`
/// - `dn.admin.co.jp` → `admin.co.jp`
pub(super) fn get_registered_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    let tld_count = tld_label_count(domain);
    let min_parts = tld_count + 1;
    if parts.len() >= min_parts {
        parts[parts.len() - min_parts..].join(".")
    } else {
        domain.to_string()
    }
}

/// Get TLD
pub(super) fn get_tld(domain: &str) -> &str {
    domain.rsplit('.').next().unwrap_or("")
}

/// HeuristicAnalyze Domain (Contains detect - detect analyze MediumAsynchronousExecuteline)
pub(super) fn analyze_domain_heuristics(domain: &str) -> (f64, Vec<(String, String)>) {
    let mut score: f64 = 0.0;
    let mut findings: Vec<(String, String)> = Vec::new();
    let reg_domain = get_registered_domain(domain);
    let tld = get_tld(domain);
    let parts: Vec<&str> = domain.split('.').collect();

    // 1. Suspicious TLD
    if module_data().contains("suspicious_tlds", tld) {
        score += 0.15;
        findings.push((
            format!("Suspicious顶levelDomain .{}", tld),
            "suspicious_tld".to_string(),
        ));
    }

    // 2. www first (if wwwkp.domain.com, www-secure.domain.com)
    if parts.len() >= 2 {
        let subdomain = parts[0];
        let www_suffix = subdomain
            .strip_prefix("www")
            .unwrap_or_default()
            .trim_matches('-');
        let is_numbered_www =
            !www_suffix.is_empty() && www_suffix.chars().all(|c| c.is_ascii_digit());
        if subdomain.starts_with("www")
            && subdomain.len() > 3
            && subdomain != "www"
            && !is_numbered_www
        {
            score += 0.25;
            findings.push((
                format!("www first缀伪装: \"{}\" (疑似假冒官网子Domain)", subdomain),
                "www_impersonation".to_string(),
            ));
        }
    }

    // 3. Free hosting / Dynamic DNS
    for host in module_data().get_list("free_hosting_domains") {
        if domain.ends_with(host) || domain == host {
            score += 0.20;
            findings.push((
                format!("免费托管/Dynamic DNS Domain: {}", host),
                "free_hosting".to_string(),
            ));
            break;
        }
    }

    // 4. longDomain (Used for)
    if domain.len() > 40 {
        score += 0.15;
        findings.push((
            format!("Domainlong: {} characters", domain.len()),
            "long_domain".to_string(),
        ));
    }

    // 5. Domain level (if a.b.c.d.evil.com)
    if parts.len() > 4 {
        score += 0.15;
        findings.push((
            format!("子Domain层level深: {} 层", parts.len()),
            "deep_subdomain".to_string(),
        ));
    }

    // 6. random/DGA domain detection
    // Extract the registrable domain label (the label just above the TLD).
    // For compound TLDs like .com.cn, this correctly skips the TLD parts.
    let tld_count = tld_label_count(domain);
    let main_part = if parts.len() > tld_count {
        parts[parts.len() - tld_count - 1]
    } else if !parts.is_empty() {
        parts[0]
    } else {
        domain
    };
    // 6a. Consecutive consonant cluster (4+) - classic DGA pattern
    if main_part.len() >= 6
        && RE_RANDOM_DOMAIN.is_match(main_part)
        && !crate::modules::identity_anomaly::is_human_readable_domain_label(main_part)
    {
        score += 0.20;
        findings.push((
            format!("Domain contains random character sequence: {}", main_part),
            "random_domain".to_string(),
        ));
    }
    // 6b. High consonant ratio - catches DGA domains where a single vowel breaks
    // the consecutive run (e.g., "fdtujh" has 5/6 = 83% consonants but only 3
    // consecutive). Threshold:>=70% consonants in 5+ char domain.
    else if main_part.len() >= 5
        && !crate::modules::identity_anomaly::is_human_readable_domain_label(main_part)
    {
        let consonants = main_part
            .chars()
            .filter(|c| c.is_ascii_alphabetic() && !"aeiou".contains(*c))
            .count();
        let ratio = consonants as f64 / main_part.len() as f64;
        if ratio >= 0.70 {
            score += 0.20;
            findings.push((
                format!(
                    "Domain has high consonant ratio ({:.0}%): {}",
                    ratio * 100.0,
                    main_part
                ),
                "random_domain".to_string(),
            ));
        }
    }

    // 7. Numeric domain (known exceptions like 163.com)
    if main_part.chars().all(|c| c.is_ascii_digit())
        && main_part.len() > 3
        && !module_data().contains("known_numeric_domains", &reg_domain)
    {
        score += 0.15;
        findings.push((
            format!("纯数字Domain: {}", reg_domain),
            "numeric_domain".to_string(),
        ));
    }

    // 8. DomainMediumpacketContains IP (if 192-168-1-1.evil.com)
    if domain.contains('-') {
        let dash_part = parts[0];
        let octets: Vec<&str> = dash_part.split('-').collect();
        if octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok()) {
            score += 0.20;
            findings.push((
                format!("DomainMedium嵌入 IP Address: {}", dash_part),
                "embedded_ip".to_string(),
            ));
        }
    }

    (score, findings)
}
