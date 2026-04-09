//! DLP TextNormalize (Anti-Evasion Normalization)

/// DLP firstofTextNormalize

/// preventAttack Use Segment match:
/// 1. characters: `1\u{200B}3\u{200B}8` -> `138`
/// 2. /: `` -> `138`, `` -> `ABC`
/// 3. characters: ` \u{00AD}Code/Digit` -> `Password`
/// 4. HTML: `&#49;&#51;&#56;` -> `138`, `&#x31;` -> `1`

/// Performance: O(n) (Decode + charactersNormalize).
pub(super) fn normalize_for_dlp(text: &str) -> String {
   // After1: HTML Decode (WhenpacketContains &# Executeline)
    let text = if text.contains("&#") {
        decode_html_numeric_entities(text)
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
            | '\u{180E}' | '\u{034F}' => {}

            
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

            _ => result.push(ch),
        }
    }
    result
}

/// Decode HTML: `&#49;` (Base/Radix) And `&#x31;` (6Base/Radix)

/// Decode characters,Avoid Dangercharacters.
fn decode_html_numeric_entities(text: &str) -> String {
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
                while let Some(&(_, c)) = chars.peek() {
                    if c == ';' {
                        chars.next();
                        found_semi = true;
                        break;
                    }
                    if num_str.len() > 8 {
                        break;
                    } // Prevent DoS
                    if is_hex && c.is_ascii_hexdigit() || !is_hex && c.is_ascii_digit() {
                        num_str.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if found_semi && !num_str.is_empty() {
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
            } else {
                result.push('&');
            }
        } else {
            result.push(ch);
        }
    }
    result
}
