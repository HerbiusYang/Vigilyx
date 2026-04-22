//! SMTP ProtocolParsehandler

/// largeParsedatasize (Prevent DoS)
const MAX_PARSE_SIZE: usize = 4096;

/// largeemailAddressLength (RFC 5321: 256 characters)
const MAX_EMAIL_LENGTH: usize = 256;

/// SMTP Parsehandler
pub struct SmtpParser;

impl SmtpParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse SMTP data
    pub fn parse(&self, data: &[u8]) -> Option<String> {
        // SecurityCheck: limitParsedatasize
        let data = if data.len() > MAX_PARSE_SIZE {
            &data[..MAX_PARSE_SIZE]
        } else {
            data
        };

        // Security UTF-8 Convert (InvalidSequence)
        let text = match std::str::from_utf8(data) {
            Ok(s) => s.trim(),
            Err(_) => {
                // onlyParse ASCII
                let ascii_end = data.iter().position(|&b| b > 127).unwrap_or(data.len());
                std::str::from_utf8(&data[..ascii_end]).ok()?.trim()
            }
        };

        if text.is_empty() {
            return None;
        }

        // Parse Response (Header)
        if let Some(first_char) = text.chars().next()
            && first_char.is_ascii_digit()
        {
            return self.parse_response(text);
        }

        // Parse Command
        self.parse_command(text)
    }

    /// Parse SMTP Command
    fn parse_command(&self, text: &str) -> Option<String> {
        let upper = text.to_uppercase();
        let parts: Vec<&str> = text.splitn(2, ' ').collect();
        let cmd = parts[0].to_uppercase();
        let arg = parts.get(1).map(|s| s.to_string()).unwrap_or_default();

        let parsed = match cmd.as_str() {
            "HELO" => format!("HELO {}", arg),
            "EHLO" => format!("EHLO {}", arg),
            "MAIL" if upper.contains("FROM:") => {
                let email = self.extract_email(text);
                format!("MAIL FROM: <{}>", email.unwrap_or_default())
            }
            "RCPT" if upper.contains("TO:") => {
                let email = self.extract_email(text);
                format!("RCPT TO: <{}>", email.unwrap_or_default())
            }
            "DATA" => "DATA".to_string(),
            "QUIT" => "QUIT".to_string(),
            "RSET" => "RSET".to_string(),
            "NOOP" => "NOOP".to_string(),
            "AUTH" => format!("AUTH {}", arg),
            "STARTTLS" => "STARTTLS".to_string(),
            _ => {
                // Checkwhether emailContent
                if text.len() > 50 {
                    format!("[DATA: {} bytes]", text.len())
                } else {
                    format!("[CMD: {}]", text.chars().take(30).collect::<String>())
                }
            }
        };

        Some(parsed)
    }

    /// Parse SMTP Response
    fn parse_response(&self, text: &str) -> Option<String> {
        let code: u16 = text.chars().take(3).collect::<String>().parse().ok()?;

        let message = match code {
            220 => "Service就绪",
            221 => "ServiceClose",
            235 => "AuthenticationSuccess",
            250 => "Operationscomplete",
            251 => "user不在本地",
            252 => "无法Verifyuser",
            334 => "waitWaitAuthenticationdata",
            354 => "StartemailInput",
            421 => "Service不可用",
            450 => "email不可用",
            451 => "ProcessError",
            452 => "store空间不足",
            500 => "语法Error",
            501 => "Parameter语法Error",
            502 => "Command未implementation",
            503 => "Command顺序Error",
            504 => "Parameter未implementation",
            530 => "Need/RequireAuthentication",
            535 => "AuthenticationFailed",
            550 => "email不stored在",
            551 => "user不在本地",
            552 => "store空间超限",
            553 => "emailNameInvalid",
            554 => "事务Failed",
            _ => "UnknownResponse",
        };

        Some(format!("{} {}", code, message))
    }

    /// FromTextMediumExtractemailAddress (withSecurityCheck)
    fn extract_email(&self, text: &str) -> Option<String> {
        let start = text.find('<')?;
        let end = text.find('>')?;
        if start < end {
            let email = &text[start + 1..end];
            // SecurityCheck: VerifyemailLength
            if email.len() > MAX_EMAIL_LENGTH {
                return None;
            }
            // SecurityCheck: only Validofemailcharacters
            if email
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "@.-_+".contains(c))
            {
                Some(email.to_string())
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl Default for SmtpParser {
    fn default() -> Self {
        Self::new()
    }
}
