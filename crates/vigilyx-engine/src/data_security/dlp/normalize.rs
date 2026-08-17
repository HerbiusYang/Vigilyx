//! DLP TextNormalize (Anti-Evasion Normalization)

use unicode_normalization::UnicodeNormalization;

/// DLP firstofTextNormalize

/// preventAttack Use Segment match:
/// 1. characters: `1\u{200B}3\u{200B}8` -> `138`
/// 2. /: `` -> `138`, `` -> `ABC`
/// 3. characters: ` \u{00AD}Code/Digit` -> `Password`
/// 4. HTML: `&#49;&#51;&#56;` -> `138`, `&#x31;` -> `1`
/// 5. homoglyphs: Cyrillic/Greek → Latin, ⁰¹²³ → 0123 (CWE-176)

/// Performance: O(n) (Decode + charactersNormalize).
pub(super) fn normalize_for_dlp(text: &str) -> String {
    // After1: HTML Decode (WhenpacketContains & Executeline, 数字 + 命名)
    let text = if text.contains('&') {
        decode_html_entities(text)
    } else {
        text.to_string()
    };

    // After2: characters +
    let mut result = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            // characters -
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{200E}' | '\u{200F}' | '\u{FEFF}'
            | '\u{00AD}' | '\u{2060}' | '\u{2061}' | '\u{2062}' | '\u{2063}' | '\u{2064}'
            | '\u{180E}' | '\u{034F}'
            // bidi 控制字符 (LRE/RLE/PDF/LRO/RLO + LRI/RLI/FSI/PDI + ALM)
            | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{061C}'
            // tag 字符 (U+E0001, U+E0020-E007F)
            | '\u{E0001}' | '\u{E0020}'..='\u{E007F}'
            // 变体选择符 (U+FE00-FE0F + 补充平面 U+E0100-E01EF)
            | '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}'
            // Hangul 填充符 (谚文字母填充, 视觉空白但可拆散关键词)
            | '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}'
            // 盲文空白 (U+2800, 视觉空白)
            | '\u{2800}'
            // C0 控制字符 (\x00-\x08, \x0B, \x0C, \x0E-\x1F; 保留 \t \n \r)
            // 攻击者在敏感词中夹带控制符 (如 "身份\x07证") 拆散关键词绕过匹配
            | '\u{0000}'..='\u{0008}' | '\u{000B}' | '\u{000C}' | '\u{000E}'..='\u{001F}' => {}

            '\u{FF10}'..='\u{FF19}' => {
                result.push((b'0' + (ch as u8 - 0x10)) as char);
            }
            // largewrite ->
            '\u{FF21}'..='\u{FF3A}' => {
                result.push((b'A' + (ch as u32 - 0xFF21) as u8) as char);
            }
            // smallwrite ->
            '\u{FF41}'..='\u{FF5A}' => {
                result.push((b'a' + (ch as u32 - 0xFF41) as u8) as char);
            }
            // Number/waitNumber ->
            '\u{FF1A}' => result.push(':'),
            '\u{FF1D}' => result.push('='),

            // --- Homoglyph normalization (CWE-176 defense) ---
            // Cyrillic -> Latin (most common homoglyphs)
            'а' => result.push('a'), // U+0430
            'е' => result.push('e'), // U+0435
            'о' => result.push('o'), // U+043E
            'р' => result.push('p'), // U+0440
            'с' => result.push('c'), // U+0441
            'у' => result.push('y'), // U+0443
            'х' => result.push('x'), // U+0445
            'А' => result.push('A'), // U+0410
            'В' => result.push('B'), // U+0412
            'Е' => result.push('E'), // U+0415
            'К' => result.push('K'), // U+041A
            'М' => result.push('M'), // U+041C
            'Н' => result.push('H'), // U+041D
            'О' => result.push('O'), // U+041E
            'Р' => result.push('P'), // U+0420
            'С' => result.push('C'), // U+0421
            'Т' => result.push('T'), // U+0422
            'Х' => result.push('X'), // U+0425

            // Greek -> Latin
            'Α' => result.push('A'), // U+0391
            'Β' => result.push('B'), // U+0392
            'Ε' => result.push('E'), // U+0395
            'Ζ' => result.push('Z'), // U+0396
            'Η' => result.push('H'), // U+0397
            'Ι' => result.push('I'), // U+0399
            'Κ' => result.push('K'), // U+039A
            'Μ' => result.push('M'), // U+039C
            'Ν' => result.push('N'), // U+039D
            'Ο' => result.push('O'), // U+039F
            'Ρ' => result.push('P'), // U+03A1
            'Τ' => result.push('T'), // U+03A4
            'Υ' => result.push('Y'), // U+03A5
            'Χ' => result.push('X'), // U+03A7
            'ο' => result.push('o'), // U+03BF Greek small omicron

            // Superscript/subscript digits -> ASCII
            '⁰' => result.push('0'), // U+2070
            '¹' => result.push('1'), // U+00B9
            '²' => result.push('2'), // U+00B2
            '³' => result.push('3'), // U+00B3
            '⁴' => result.push('4'), // U+2074
            '⁵' => result.push('5'), // U+2075
            '⁶' => result.push('6'), // U+2076
            '⁷' => result.push('7'), // U+2077
            '⁸' => result.push('8'), // U+2078
            '⁹' => result.push('9'), // U+2079
            '₀' => result.push('0'), // U+2080
            '₁' => result.push('1'), // U+2081
            '₂' => result.push('2'), // U+2082
            '₃' => result.push('3'), // U+2083
            '₄' => result.push('4'), // U+2084
            '₅' => result.push('5'), // U+2085
            '₆' => result.push('6'), // U+2086
            '₇' => result.push('7'), // U+2087
            '₈' => result.push('8'), // U+2088
            '₉' => result.push('9'), // U+2089

            // --- NFKC compatibility fold (D1-1) ---
            // 攻击者用数学字母数字 (𝟏𝟐𝟑/𝐩𝐚𝐬𝐬)、带圈字母数字 (①②③/ⓟⓐⓢⓢ)、
            // 装饰数字 (❶❷❸) 打散卡号/身份证正则与 credential 关键词,
            // 手工折叠表无法覆盖这些区块, NFKC 将其折叠回 ASCII。
            // 只折叠攻击常用的兼容性区块, 不做全串 NFKC: 全串 NFKC 会把
            // 全角标点 (，等) 一并改写, 超出 DLP 归一化所需范围。
            _ if ('\u{1D400}'..='\u{1D7FF}').contains(&ch)      // 数学字母数字
                || ('\u{2460}'..='\u{24FF}').contains(&ch)      // 带圈/括号字母数字
                || ('\u{2700}'..='\u{27BF}').contains(&ch)      // 装饰符号 (含 ❶-❿)
                || ('\u{1F100}'..='\u{1F1FF}').contains(&ch)    // 补充带圈字母数字
            =>
            {
                result.extend(ch.nfkc());
            }

            _ => result.push(ch),
        }
    }
    result
}

/// Decode HTML: `&#49;` (Base/Radix), `&#x31;` (6Base/Radix) And最小命名(如 `&colon;`)

/// Decode characters,Avoid Dangercharacters.
fn decode_html_entities(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.char_indices().peekable();

    while let Some((_i, ch)) = chars.next() {
        if ch == '&' {
            // Checkwhether &#
            if let Some(&(_, '#')) = chars.peek() {
                chars.next();
                let is_hex = matches!(chars.peek(), Some(&(_, 'x')) | Some(&(_, 'X')));
                if is_hex {
                    chars.next(); // 'x'/'X'
                }

                let mut num_str = String::new();
                let mut found_semi = false;
                let mut overflow = false;
                while let Some(&(_, c)) = chars.peek() {
                    if c == ';' {
                        chars.next();
                        found_semi = true;
                        break;
                    }
                    if num_str.len() > 8 {
                        overflow = true;
                        break;
                    } // Prevent DoS
                    if is_hex && c.is_ascii_hexdigit() || !is_hex && c.is_ascii_digit() {
                        num_str.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                // 浏览器对无分号形式 (&#49) 同样解码, 此处对齐:
                // 只要数字串有效且未超长, 无论是否以 ';' 结尾都解码
                if !overflow && !num_str.is_empty() {
                    let code_point = if is_hex {
                        u32::from_str_radix(&num_str, 16).ok()
                    } else {
                        num_str.parse::<u32>().ok()
                    };
                    if let Some(cp) = code_point
                        && let Some(decoded) = char::from_u32(cp)
                        && (!decoded.is_control() || decoded == '\n' || decoded == '\t')
                    {
                        result.push(decoded);
                        continue;
                    }
                }
                // ParseFailed: Output &#...
                result.push('&');
                result.push('#');
                if is_hex {
                    result.push('x');
                }
                result.push_str(&num_str);
                if found_semi {
                    result.push(';');
                }
            } else if let Some(decoded) = decode_named_entity(&mut chars) {
                // 命名实体 (&colon; &equals; &Tab; &NewLine; &amp; &lt; &gt; &quot;)
                // 攻击者用 password&colon; 等形式拆散 credential 关键词与分隔符
                result.push_str(decoded);
            } else {
                result.push('&');
            }
        } else {
            result.push(ch);
        }
    }
    result
}

/// 最小命名实体表: 只覆盖可拆散关键词/分隔符语义的条目
fn named_entity_value(name: &str) -> Option<&'static str> {
    match name {
        "colon" => Some(":"),
        "equals" => Some("="),
        "Tab" => Some("\t"),
        "NewLine" => Some("\n"),
        "amp" | "AMP" => Some("&"),
        "lt" | "LT" => Some("<"),
        "gt" | "GT" => Some(">"),
        "quot" | "QUOT" => Some("\""),
        _ => None,
    }
}

/// 尝试从 `&` 之后解析命名实体 (如 `colon;`), 成功则消费并返回替换文本,
/// 失败不消费任何字符 (调用方原样输出 `&`)
fn decode_named_entity(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
) -> Option<&'static str> {
    let mut probe = chars.clone();
    let mut name = String::new();
    while let Some(&(_, c)) = probe.peek() {
        if c.is_ascii_alphanumeric() && name.len() < 10 {
            name.push(c);
            probe.next();
        } else {
            break;
        }
    }
    if !name.is_empty()
        && matches!(probe.peek(), Some(&(_, ';')))
        && let Some(decoded) = named_entity_value(&name)
    {
        probe.next(); // consume ';'
        *chars = probe;
        return Some(decoded);
    }
    None
}
