//! Static data lists for link reputation analysis.

//! Contains: suspicious TLDs, brand anchor domains, DNS provider lists,
//! free hosting domains, redirect service domains, and related constants.

use regex::Regex;
use std::sync::LazyLock;

/// matchrandomDomain: contiguous 4+
pub(super) static RE_RANDOM_DOMAIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[bcdfghjklmnpqrstvwxyz]{4,}").unwrap());

/// Suspicious levelDomain
pub(super) const SUSPICIOUS_TLDS: &[&str] = &[
    "tk", "ml", "ga", "cf", "gq", // TLD ()
    "xyz", "top", "buzz", "icu", "club", // TLD (High)
    "work", "click", "link", "surf", // / TLD
    "info", "biz", "online", "site", // TLD
    "pw", "cc", "ws", // small TLD ()
];

/// Keywords -> of Domain (Used for DNS NS)
/// DetectedDomainpacketContains Keywords, Query DomainAnd Domainof NS Recording,
/// NS Same -> Same1 ->;NS Same ->.
pub(super) const BRAND_ANCHOR_DOMAINS: &[(&str, &str)] = &[
    
    ("qq", "qq.com"),
    ("tencent", "tencent.com"),
    ("wechat", "wechat.com"),
    
    ("microsoft", "microsoft.com"),
    ("apple", "apple.com"),
    ("google", "google.com"),
    ("amazon", "amazon.com"),
    ("paypal", "paypal.com"),
    ("netflix", "netflix.com"),
   // Meta /
    ("facebook", "facebook.com"),
    ("instagram", "instagram.com"),
    ("whatsapp", "whatsapp.com"),
    ("linkedin", "linkedin.com"),
    ("twitter", "twitter.com"),
   // Medium
    ("alibaba", "alibaba.com"),
    ("alipay", "alipay.com"),
    ("taobao", "taobao.com"),
    ("jd", "jd.com"),
    ("baidu", "baidu.com"),
    ("163", "163.com"),
    ("126", "126.com"),
    ("sina", "sina.com"),
    ("sohu", "sohu.com"),
   // Medium Bank
    ("icbc", "icbc.com.cn"),
    ("ccb", "ccb.com"),
    ("boc", "boc.cn"),
    ("abc", "abchina.com"),
   // Stream
    ("dhl", "dhl.com"),
    ("fedex", "fedex.com"),
    ("ups", "ups.com"),
    ("ems", "ems.com.cn"),
   // store/
    ("office365", "microsoft.com"),
    ("outlook", "microsoft.com"),
    ("onedrive", "microsoft.com"),
    ("dropbox", "dropbox.com"),
];

/// DNS RegisterDomain - Same possiblySharedSame1 DNS For,
/// due to Shared NS DescriptionDomain Same1.
pub(super) const SHARED_DNS_PROVIDERS: &[&str] = &[
    "dnspod.net",
    "dnspod.com",
    "cloudflare.com",
    "awsdns.com",
    "awsdns.net",
    "awsdns.org",
    "awsdns.co.uk",
    "azure-dns.com",
    "azure-dns.net",
    "azure-dns.org",
    "azure-dns.info",
    "alidns.com",
    "hichina.com",
    "domaincontrol.com",
    "registrar-servers.com",
    "dnsv5.com",
    "dnsv4.com",
    "dnsv3.com",
    "ns.cloudflare.com",
    "googledomains.com",
    "name-services.com",
    "ultradns.com",
    "ultradns.net",
    "nsone.net",
];

/// / Dynamic DNS For
pub(super) const FREE_HOSTING_DOMAINS: &[&str] = &[
    
    "000webhostapp.com",
    "weebly.com",
    "wixsite.com",
    "blogspot.com",
    "wordpress.com",
   // (Phishing)
    "herokuapp.com",
    "netlify.app",
    "vercel.app",
    "firebaseapp.com",
    "web.app",
    "pages.dev",
    "workers.dev",
   // /Port
    "serveo.net",
    "ngrok.io",
    "ngrok-free.app",
   // No-IP Dynamic DNS
    "no-ip.com",
    "ddns.net",
    "hopto.org",
    "zapto.org",
    "sytes.net",
    "myftp.biz",
    "myftp.org",
    "myvnc.com",
    "serveftp.com",
    "servequake.com",
    "servegame.com",
   // DuckDNS
    "duckdns.org",
   // FreeDNS (afraid.org) - High
    "mooo.com",
    "afraid.org",
    "us.to",
    "chickenkiller.com",
    "ignorelist.com",
    "strangled.net",
    "twillightparadox.com",
   // Dynu / ChangeIP wait DDNS
    "dynu.com",
    "dynu.net",
    "changeip.com",
    "changeip.net",
    "ddns.me",
    "freedns.org",
    
    "privcat.com",
    "myds.me",
    "synology.me", // NAS DDNS ()
];

/// SuspiciousemailServicehandlerDomain (SendingDomain emailContent)
pub(super) const SUSPICIOUS_SENDING_DOMAINS: &[&str] = &["xianlai-inc.com"];

/// already ofTrace/ ServiceDomain - Outer layer URL DomainLegitimate,But Parameter Target
pub(super) const REDIRECT_SERVICE_DOMAINS: &[&str] = &[
    "adnxs.com",       // AppNexus/Microsoft Trace
    "doubleclick.net", // Google Trace
    "googleadservices.com",
    "go.microsoft.com",
    "click.email.", // email Tracefirst
    "track.",       // GeneralTracefirst
    "redirect.",    // General first
    "r.email.",     // email
    "links.m.",     // Mailchimp Trace
    "sendgrid.net", // SendGrid Trace
];
