//! DLP Verbosematchfunction Verifyhandler

//! `find_*` functionFromTextMediumExtract VerifySensitivedata,
//! `*_check` / `is_*` functionExecutelineVerifybit/first Verify.

use regex::Regex;
use std::collections::HashSet;

use super::patterns::*;


// modeVerbosematchfunction


/// lookup Card number (BIN first + Luhn Verify)

/// Luhn Verify,AddAdd BIN (Bank Identification Number) first Verify:
/// - Visa: 4xxx
/// - Mastercard: 51-55xx 2221-2720xx
/// - UnionPay: 62xx
/// - Amex: 34xx, 37xx (15bit,But16bit stored)
/// - Discover: 6011, 65xx
/// - JCB: 35xx

/// random 16 bit Luhn-valid of.
pub(super) fn find_credit_cards(text: &str) -> (Vec<String>, HashSet<String>) {
    let mut found = Vec::new();
    let mut raw_digits = HashSet::new();
    for m in RE_CREDIT_CARD.find_iter(text) {
        let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() == 16 && luhn_check(&digits) && is_valid_card_bin(&digits) {
            let masked = format!("{}****{}", &digits[..4], &digits[12..]);
            found.push(masked);
            raw_digits.insert(digits);
        }
    }
    (found, raw_digits)
}

/// Verify / BIN first whether already
pub(super) fn is_valid_card_bin(digits: &str) -> bool {
    if digits.len() < 4 {
        return false;
    }
    let d1 = digits.as_bytes()[0] - b'0';
    let d2 = digits.as_bytes()[1] - b'0';
    let prefix4: u16 = digits[..4].parse().unwrap_or(0);
    let _prefix6: u32 = digits[..6].parse().unwrap_or(0);

   // Visa: 4xxx
    if d1 == 4 {
        return true;
    }
   // Mastercard: 51-55 2221-2720
    if d1 == 5 && (1..=5).contains(&d2) {
        return true;
    }
    if (2221..=2720).contains(&prefix4) {
        return true;
    }
   // UnionPay (): 62xxxx
    if d1 == 6 && d2 == 2 {
        return true;
    }
   // Amex: 34, 37
    if d1 == 3 && (d2 == 4 || d2 == 7) {
        return true;
    }
   // Discover: 6011, 65xx
    if prefix4 == 6011 || (d1 == 6 && d2 == 5) {
        return true;
    }
   // JCB: 35xx
    if d1 == 3 && d2 == 5 {
        return true;
    }
   // Medium Bank first (): 9xxx (District)
    if d1 == 9 {
        return true;
    }
   // already first (Diners: 36, 38)
    if d1 == 3 && (d2 == 6 || d2 == 8) {
        return true;
    }

    false
}

/// Luhn Verify
pub fn luhn_check(digits: &str) -> bool {
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

/// lookupID cardNumber (VerifybitVerify + Desensitize)

/// Use GB 11643-1999 Verify VerifyAfter 18 bitVerifyCode/Digit,
/// large random 18 bit of.
pub(super) fn find_chinese_ids(text: &str) -> Vec<String> {
    RE_CHINESE_ID
        .find_iter(text)
        .filter(|m| {
            let s = m.as_str();
            s.len() == 18 && chinese_id_check(s)
        })
        .map(|m| {
            let s = m.as_str();
            format!("{}****{}", &s[..6], &s[14..])
        })
        .collect()
}

/// Medium ID card 18 bitVerify (GB 11643-1999)

/// first 17 bit And mod 11,Mapping VerifyCode/Digit.

/// VerifyCode/DigitMapping: [1, 0, X, 9, 8, 7, 6, 5, 4, 3, 2]
pub(super) fn chinese_id_check(id: &str) -> bool {
    if id.len() != 18 {
        return false;
    }
    const WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const CHECK_CHARS: [char; 11] = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];

    let chars: Vec<char> = id.chars().collect();
    let mut sum: u32 = 0;
    for i in 0..17 {
        if let Some(d) = chars[i].to_digit(10) {
            sum += d * WEIGHTS[i];
        } else {
            return false;
        }
    }
    let expected = CHECK_CHARS[(sum % 11) as usize];
    let actual = chars[17].to_ascii_uppercase();
    actual == expected
}

/// lookupMobile phoneNumber (Deduplicate + Desensitize)

/// NumberCode/DigitDeduplicate Desensitize,AvoidSame1NumberCode/Digit found N Time/Count Threshold.
/// ThresholdCheck SameNumberCode/Digit, email 1.
pub(super) fn find_chinese_phones(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    RE_CHINESE_PHONE
        .find_iter(text)
        .filter_map(|m| {
            let s = m.as_str();
            if seen.insert(s.to_string()) {
                if s.len() == 11 {
                    Some(format!("{}****{}", &s[..3], &s[7..]))
                } else {
                    Some("***".to_string())
                }
            } else {
                None // NumberCode/Digithops
            }
        })
        .collect()
}

/// lookupBankCard number (16-19 bit, Luhn Verify, Excludealreadymatch, Desensitize)
pub(super) fn find_bank_cards(text: &str, exclude: &HashSet<String>) -> Vec<String> {
    let mut found = Vec::new();
    for m in RE_BANK_CARD.find_iter(text) {
        let digits = m.as_str();
        let len = digits.len();
        if (16..=19).contains(&len) && luhn_check(digits) && !exclude.contains(digits) {
            let masked = format!("{}****{}", &digits[..4], &digits[len - 4..]);
            found.push(masked);
        }
    }
    found
}

/// lookupMedium (Desensitize: keep City, VerboseAddress)
pub(super) fn find_chinese_addresses(text: &str) -> Vec<String> {
    RE_CHINESE_ADDRESS
        .find_iter(text)
        .map(|m| {
            let s = m.as_str();
            let chars: Vec<char> = s.chars().collect();
            if chars.len() > 6 {
               // keepfirst 6 characters, ***
                let prefix: String = chars[..6].iter().collect();
                format!("{}***", prefix)
            } else {
                "***Address***".to_string()
            }
        })
        .collect()
}

/// lookup emailAddress (Deduplicate + ExcludeSystememail + Desensitize: u***@domain.com)

/// emailAddressDeduplicate(sizewrite),AvoidSame1Address found Threshold.
pub(super) fn find_emails(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    RE_EMAIL
        .find_iter(text)
        .filter_map(|m| {
            let email = m.as_str();
            let lower = email.to_lowercase();
           // Deduplicate(sizewrite)
            if !seen.insert(lower.clone()) {
                return None;
            }
           // ExcludeSystememail
            let local = lower.split('@').next().unwrap_or("");
            if SYSTEM_EMAIL_PREFIXES.contains(&local) {
                return None;
            }
           // Desensitize: userName characters + *** + @domain
            if let Some(at_pos) = email.find('@') {
                let user_part = &email[..at_pos];
                let domain_part = &email[at_pos..];
                let first_char: String = user_part.chars().take(1).collect();
                Some(format!("{}***{}", first_char, domain_part))
            } else {
                None
            }
        })
        .collect()
}

/// lookupMedium Number (Desensitize: first 2 + **** + 2)
pub(super) fn find_passports(text: &str) -> Vec<String> {
    RE_PASSPORT
        .find_iter(text)
        .map(|m| {
            let s = m.as_str();
            if s.len() >= 9 {
                format!("{}****{}", &s[..2], &s[7..])
            } else {
                "***".to_string()
            }
        })
        .collect()
}

/// lookup 1 Code/Digit (18 bit + VerifybitVerify + Desensitize)

/// Use GB 32100-2015 Verify VerifyAfter 18 bitVerifyCode/Digit,.
pub(super) fn find_social_credit_codes(text: &str) -> Vec<String> {
    RE_SOCIAL_CREDIT
        .find_iter(text)
        .filter(|m| {
            let s = m.as_str();
            s.len() == 18 && social_credit_check(s)
        })
        .map(|m| {
            let s = m.as_str();
            format!("{}****{}", &s[..4], &s[14..])
        })
        .collect()
}

/// 1 Code/DigitVerify (GB 32100-2015)

/// characters: 0-9 + A-H + J-N + P-R + T-U + W (Exclude I/O/Z/S/V)

/// VerifyCode/Digit = (31 - Add And % 31) % 31
pub(super) fn social_credit_check(code: &str) -> bool {
    if code.len() != 18 {
        return false;
    }
    const CHARSET: &[u8] = b"0123456789ABCDEFGHJKLMNPQRTUW";
    const WEIGHTS: [u32; 17] = [
        1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28,
    ];

    let chars: Vec<u8> = code
        .as_bytes()
        .iter()
        .map(|b| b.to_ascii_uppercase())
        .collect();
    let mut sum: u32 = 0;
    for i in 0..17 {
        if let Some(pos) = CHARSET.iter().position(|&c| c == chars[i]) {
            sum += pos as u32 * WEIGHTS[i];
        } else {
            return false; // characters
        }
    }
    let check_val = (31 - sum % 31) % 31;
    if check_val >= CHARSET.len() as u32 {
        return false;
    }
    let expected = CHARSET[check_val as usize];
    chars[17] == expected
}

/// lookupPassword/ mode (Desensitize: keepKeywords, value)
/// PasswordConfigurationvalue (true/false/null wait), SystemlogFileof
pub(super) fn find_credentials(text: &str) -> Vec<String> {
    RE_CREDENTIAL
        .find_iter(text)
        .filter_map(|m| {
            let s = m.as_str();
           // Extractdelimited firstofKeywords
            let keyword: String = s
                .chars()
                .take_while(|c| *c != '：' && *c != ':' && *c != '=')
                .collect();
           // Extractdelimited ofvalue
            let sep_pos = keyword.len();
            let value: String = s.chars().skip(sep_pos + 1).collect();
            let value_trimmed = value.trim();
           // PasswordConfigurationvalue
            if is_non_secret_value(value_trimmed) {
                return None;
            }
            Some(format!("{}: ****", keyword.trim()))
        })
        .collect()
}

/// Judgewhether PasswordConfigurationvalue(Systemlog/ConfigurationFileMediumof value, bit wait)
pub(super) fn is_non_secret_value(value: &str) -> bool {
   // value characters Password
    if value.is_empty() || value.len() <= 1 {
        return true;
    }
    let lower = value.to_lowercase();
    const NON_SECRETS: &[&str] = &[
        "true",
        "false",
        "yes",
        "no",
        "on",
        "off",
        "null",
        "none",
        "nil",
        "undefined",
        "n/a",
        "****",
        "***",
        "**",
        "*",
        "[filtered]",
        "[redacted]",
        "[hidden]",
        "[masked]",
        "enabled",
        "disabled",
    ];
    NON_SECRETS.contains(&lower.as_str())
}

/// lookup SWIFT/BIC Code/Digit (8 11 bit + ISO Code/Digit + Exclude, Desensitize: first 4 + ****)
pub(super) fn find_swift_codes(text: &str) -> Vec<String> {
    RE_SWIFT
        .find_iter(text)
        .filter(|m| {
            let s = m.as_str();
            let len = s.len();
            if len != 8 && len != 11 {
                return false;
            }
           // Verifybit 5-6 Legitimate ISO 3166-1 alpha-2 Code/Digit
            let country = &s[4..6];
            if !is_valid_swift_country(country) {
                return false;
            }
           // Exclude / Bank Code/Digit(bit 0-3)
            let bank_code = &s[..4];
            !is_common_word_prefix(bank_code)
        })
        .map(|m| {
            let s = m.as_str();
            format!("{}****", &s[..4])
        })
        .collect()
}

/// ISO 3166-1 alpha-2 Code/DigitSet(Used for SWIFT bit 5-6 Verify)
pub(super) fn is_valid_swift_country(code: &str) -> bool {
    const CODES: &[&str] = &[
        "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
        "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BR", "BS",
        "BT", "BW", "BY", "BZ", "CA", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO",
        "CR", "CU", "CV", "CW", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG",
        "ER", "ES", "ET", "EU", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
        "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GT", "GU", "GW", "GY", "HK", "HN",
        "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IQ", "IR", "IS", "IT", "JE", "JM", "JO",
        "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC",
        "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MK",
        "ML", "MM", "MN", "MO", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NC",
        "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG",
        "PH", "PK", "PL", "PM", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
        "SA", "SB", "SC", "SD", "SE", "SG", "SI", "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST",
        "SV", "SX", "SY", "SZ", "TC", "TD", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR",
        "TT", "TV", "TW", "TZ", "UA", "UG", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI", "VN",
        "VU", "WF", "WS", "XK", "YE", "YT", "ZA", "ZM", "ZW",
    ];
    CODES.contains(&code)
}

/// / first, possibly SWIFT Bank Code/Digit
pub(super) fn is_common_word_prefix(bank_code: &str) -> bool {
    const WORDS: &[&str] = &[
        "PASS", "TRUE", "FILE", "CERT", "NULL", "VOID", "TEST", "AUTO", "SELF", "NONE", "ENUM",
        "TYPE", "BOOL", "CHAR", "BYTE", "DATA", "EXEC", "LOAD", "SAVE", "OPEN", "READ", "SEND",
        "SIZE", "MODE", "FLAG", "LOCK", "SYNC", "INIT", "EXIT", "HASH", "SORT", "LIST", "NEXT",
        "PUSH", "PULL", "WAIT", "DONE", "FAIL", "WARN", "INFO", "STOP", "SKIP", "DROP", "DUMP",
        "FUNC", "PROC", "CALL", "GOTO", "LOOP", "CASE", "ELSE", "EACH", "WITH", "FROM", "INTO",
        "OVER", "BACK", "UNDO", "COPY", "MOVE", "FIND", "SHOW", "HIDE", "HELP", "MENU", "ITEM",
        "VIEW", "EDIT", "FORM", "PAGE", "TEXT", "FONT", "ICON", "PATH", "ROOT", "USER", "HOST",
        "PORT", "BASE", "HOME", "TEMP", "WORK", "MAIN", "CORE", "UTIL", "HTTP", "SMTP", "IMAP",
    ];
    WORDS.contains(&bank_code)
}

/// lookup CVV/SecurityCode/Digit (ContextKeywords, Desensitize: CVV: ***)
pub(super) fn find_cvv_codes(text: &str) -> Vec<String> {
    RE_CVV_CONTEXT
        .find_iter(text)
        .map(|_| "CVV: ***".to_string())
        .collect()
}

// line Add matchfunction

/// lookup Number (15 bit, Desensitize: first 4 + **** + 3)

/// 15 bit: 6 bitline District Code/Digit + 9 bit Code/Digit
/// 18 bitNew alreadyBy `find_social_credit_codes` override
pub(super) fn find_tax_ids(text: &str) -> Vec<String> {
    RE_TAX_ID_15
        .find_iter(text)
        .filter(|m| m.as_str().len() == 15)
        .map(|m| {
            let s = m.as_str();
            format!("{}****{}", &s[..4], &s[12..])
        })
        .collect()
}

/// according to Code/Digitlookup IBAN Length
pub(super) fn iban_expected_length(country: &str) -> Option<usize> {
    IBAN_COUNTRY_LENGTHS
        .iter()
        .find(|(c, _)| *c == country)
        .map(|(_, len)| *len)
}

/// lookup IBAN NumberCode/Digit (Verify + LengthVerify + mod-97 Verify, Desensitize)
pub(super) fn find_ibans(text: &str) -> Vec<String> {
    RE_IBAN
        .find_iter(text)
        .filter(|m| {
            let s = m.as_str();
            let country = &s[..2];
            match iban_expected_length(country) {
                Some(expected_len) => s.len() == expected_len && iban_mod97_check(s),
                None => false, // Unknown Code/Digit
            }
        })
        .map(|m| {
            let s = m.as_str();
            let len = s.len();
            format!("{}****{}", &s[..4], &s[len.saturating_sub(4)..])
        })
        .collect()
}

/// IBAN mod-97 Verify (ISO 13616)

/// : first 4 bit -> (A=10..Z=35) -> mod 97 == 1
pub fn iban_mod97_check(iban: &str) -> bool {
    if iban.len() < 5 {
        return false;
    }
   // first 4 bit
    let rearranged = format!("{}{}", &iban[4..], &iban[..4]);
   // characters mod 97, Avoidlarge
    let mut remainder: u32 = 0;
    for ch in rearranged.chars() {
        if ch.is_ascii_digit() {
            remainder = (remainder * 10 + (ch as u32 - '0' as u32)) % 97;
        } else if ch.is_ascii_uppercase() {
            let val = (ch as u32) - ('A' as u32) + 10;
           // bit: Process bit Processbit
            remainder = (remainder * 10 + val / 10) % 97;
            remainder = (remainder * 10 + val % 10) % 97;
        } else {
            return false;
        }
    }
    remainder == 1
}

/// lookuplarge Amount (Amount + / bit, Desensitize: value, keep)
pub(super) fn find_large_amounts(text: &str) -> Vec<String> {
    // Known currency unit keywords from the regex (order: longest first for correct matching)
    const UNIT_PATTERNS: &[&str] = &[
        "10k yuan", "亿Yuan", "SundayYuan", "美Yuan", "欧Yuan",
        "USD", "CNY", "RMB", "EUR", "GBP", "JPY", "英镑",
    ];
    RE_LARGE_AMOUNT
        .find_iter(text)
        .map(|m| {
            let s = m.as_str();
            let lower = s.to_lowercase();
            // Find the currency unit by matching known suffixes (case-insensitive)
            let unit = UNIT_PATTERNS
                .iter()
                .find_map(|p| {
                    let pl = p.to_lowercase();
                    lower.rfind(&pl).map(|pos| &s[pos..])
                })
                .unwrap_or("");
            format!("***{}", unit)
        })
        .collect()
}

/// lookupBankAccount number (ContextKeywords, Desensitize: first 4 + **** + 2)
pub(super) fn find_bank_accounts(text: &str) -> Vec<String> {
    RE_BANK_ACCOUNT_CONTEXT
        .captures_iter(text)
        .filter_map(|cap| {
            let acct = cap.get(1)?.as_str();
            let len = acct.len();
            if len >= 10 {
                Some(format!("{}****{}", &acct[..4], &acct[len - 2..]))
            } else {
                None
            }
        })
        .collect()
}

/// lookupPolicy number/ SameNumber (ContextKeywords, Desensitize: first 4 + ****)
pub(super) fn find_contract_numbers(text: &str) -> Vec<String> {
    RE_CONTRACT_NUMBER
        .captures_iter(text)
        .filter_map(|cap| {
            let num = cap.get(1)?.as_str();
            if num.len() >= 8 {
                Some(format!("{}****", &num[..4]))
            } else {
                None
            }
        })
        .collect()
}


// JR/T modematchfunction (General +)


/// GeneralKeywordsmatch: ReturnDeduplicate ofKeywordsList, min_distinct SameKeywords
pub(super) fn find_keyword_matches(re: &Regex, text: &str, min_distinct: usize) -> Vec<String> {
    let matches: Vec<String> = re.find_iter(text).map(|m| m.as_str().to_string()).collect();
   // Deduplicate Checkwhether small Class
    let mut unique: Vec<String> = matches.clone();
    unique.sort();
    unique.dedup();
    if unique.len() >= min_distinct {
        unique
    } else {
        Vec::new()
    }
}

/// GeneralContextmatch: Returnmatch ofContext Segment (Get <= 60 characters)
pub(super) fn find_context_matches(re: &Regex, text: &str) -> Vec<String> {
    re.find_iter(text)
        .map(|m| {
            let s = m.as_str();
            if s.len() > 60 {
                format!("{}...", &s[..s.floor_char_boundary(57)])
            } else {
                s.to_string()
            }
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect()
}

/// Vehicle information (C3)
pub(super) fn find_vehicle_info(text: &str) -> Vec<String> {
    let mut found = HashSet::new();
    // 1. Detect Chinese license plates (CN plate format)
    for m in RE_VEHICLE.find_iter(text) {
        let s = m.as_str();
        let chars: Vec<char> = s.chars().collect();
        let prefix: String = chars.iter().take(3).collect();
        found.insert(format!("{}***", prefix));
    }
    // 2. VIN detection (17-char alphanumeric, excluding I/O/Q)
    for m in RE_VIN.find_iter(text) {
        let s = m.as_str();
        // VIN must contain both letters and digits (pure digits could be other IDs)
        if s.chars().any(|c| c.is_ascii_alphabetic()) && s.chars().any(|c| c.is_ascii_digit()) {
            let prefix = &s[..4.min(s.len())];
            found.insert(format!("{}*****", prefix));
        }
    }
    found.into_iter().collect()
}
