//! POP3 ProtocolParsehandler

/// POP3 Parsehandler
pub struct Pop3Parser;

impl Pop3Parser {
    pub fn new() -> Self {
        Self
    }

    /// Parse POP3 data
    pub fn parse(&self, data: &[u8]) -> Option<String> {
        let text = String::from_utf8_lossy(data);
        let text = text.trim();

        if text.is_empty() {
            return None;
        }

        // Checkwhether Response
        if text.starts_with("+OK") {
            return Some(self.parse_ok_response(text));
        }
        if text.starts_with("-ERR") {
            return Some(self.parse_err_response(text));
        }

        // ParseCommand
        self.parse_command(text)
    }

    /// Parse POP3 Command
    fn parse_command(&self, text: &str) -> Option<String> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }

        let cmd = parts[0].to_uppercase();
        let arg1 = parts.get(1).copied();
        let arg2 = parts.get(2).copied();

        let parsed = match cmd.as_str() {
            "USER" => format!("USER {}", arg1.unwrap_or("***")),
            "PASS" => "PASS ***".to_string(),
            "STAT" => "STAT (QueryemailStatus)".to_string(),
            "LIST" => match arg1 {
                Some(n) => format!("LIST {} (Queryemail {})", n, n),
                None => "LIST (列出所有email)".to_string(),
            },
            "RETR" => format!(
                "RETR {} (Getemail {})",
                arg1.unwrap_or("?"),
                arg1.unwrap_or("?")
            ),
            "DELE" => format!(
                "DELE {} (deleteemail {})",
                arg1.unwrap_or("?"),
                arg1.unwrap_or("?")
            ),
            "NOOP" => "NOOP".to_string(),
            "RSET" => "RSET (重置)".to_string(),
            "QUIT" => "QUIT".to_string(),
            "TOP" => format!(
                "TOP {} {} (Getemail {} Header + {} line)",
                arg1.unwrap_or("?"),
                arg2.unwrap_or("?"),
                arg1.unwrap_or("?"),
                arg2.unwrap_or("?")
            ),
            "UIDL" => match arg1 {
                Some(n) => format!("UIDL {} (Queryemail {} 唯1 ID)", n, n),
                None => "UIDL (列出所有email唯1 ID)".to_string(),
            },
            "APOP" => format!("APOP {} (MD5 Authentication)", arg1.unwrap_or("***")),
            "AUTH" => format!("AUTH {}", arg1.unwrap_or("?")),
            "CAPA" => "CAPA (QueryServiceDevice/Handler能力)".to_string(),
            "STLS" => "STLS (Start TLS)".to_string(),
            _ => format!("[POP3 CMD: {}]", cmd),
        };

        Some(parsed)
    }

    /// Parse +OK Response
    fn parse_ok_response(&self, text: &str) -> String {
        let message = text.strip_prefix("+OK").unwrap_or("").trim();
        if message.is_empty() {
            "+OK".to_string()
        } else if message.len() > 50 {
            // Use floor_char_boundary to avoid panicking on multi-byte UTF-8
            let end = message.floor_char_boundary(50);
            format!("+OK {}...", &message[..end])
        } else {
            format!("+OK {}", message)
        }
    }

    /// Parse -ERR Response
    fn parse_err_response(&self, text: &str) -> String {
        let message = text.strip_prefix("-ERR").unwrap_or("").trim();
        if message.is_empty() {
            "-ERR".to_string()
        } else if message.len() > 50 {
            let end = message.floor_char_boundary(50);
            format!("-ERR {}...", &message[..end])
        } else {
            format!("-ERR {}", message)
        }
    }
}

impl Default for Pop3Parser {
    fn default() -> Self {
        Self::new()
    }
}
