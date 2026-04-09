//! IMAP ProtocolParsehandler

/// IMAP Parsehandler
pub struct ImapParser;

impl ImapParser {
    pub fn new() -> Self {
        Self
    }

   /// Parse IMAP data
    pub fn parse(&self, data: &[u8]) -> Option<String> {
        let text = String::from_utf8_lossy(data);
        let text = text.trim();

        if text.is_empty() {
            return None;
        }

       // IMAP Response * Header (Mark) + Status
        if text.starts_with('*') {
            return Some(self.parse_untagged_response(text));
        }

       // Checkwhether MarkResponse (A001 OK, A001 NO, A001 BAD)
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() >= 2 {
            let status = parts[1].to_uppercase();
            if status == "OK" || status == "NO" || status == "BAD" {
                return Some(self.parse_tagged_response(text));
            }
        }

       // ParseCommand
        self.parse_command(text)
    }

   /// Parse IMAP Command
    fn parse_command(&self, text: &str) -> Option<String> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() < 2 {
            return Some(format!(
                "[IMAP: {}]",
                text.chars().take(30).collect::<String>()
            ));
        }

        let tag = parts[0];
        let cmd = parts[1].to_uppercase();
        let args: Vec<&str> = parts[2..].to_vec();

        let parsed = match cmd.as_str() {
            "CAPABILITY" => format!("{} CAPABILITY", tag),
            "NOOP" => format!("{} NOOP", tag),
            "LOGOUT" => format!("{} LOGOUT", tag),
            "STARTTLS" => format!("{} STARTTLS", tag),
            "AUTHENTICATE" => format!("{} AUTHENTICATE {}", tag, args.first().unwrap_or(&"?")),
            "LOGIN" => format!("{} LOGIN {} ***", tag, args.first().unwrap_or(&"***")),
            "SELECT" => format!("{} SELECT {}", tag, args.first().unwrap_or(&"?")),
            "EXAMINE" => format!("{} EXAMINE {}", tag, args.first().unwrap_or(&"?")),
            "CREATE" => format!("{} CREATE {}", tag, args.first().unwrap_or(&"?")),
            "DELETE" => format!("{} DELETE {}", tag, args.first().unwrap_or(&"?")),
            "RENAME" => format!(
                "{} RENAME {} {}",
                tag,
                args.first().unwrap_or(&"?"),
                args.get(1).unwrap_or(&"?")
            ),
            "SUBSCRIBE" => format!("{} SUBSCRIBE {}", tag, args.first().unwrap_or(&"?")),
            "UNSUBSCRIBE" => format!("{} UNSUBSCRIBE {}", tag, args.first().unwrap_or(&"?")),
            "LIST" => format!(
                "{} LIST {} {}",
                tag,
                args.first().unwrap_or(&"?"),
                args.get(1).unwrap_or(&"?")
            ),
            "LSUB" => format!(
                "{} LSUB {} {}",
                tag,
                args.first().unwrap_or(&"?"),
                args.get(1).unwrap_or(&"?")
            ),
            "STATUS" => format!(
                "{} STATUS {} ({})",
                tag,
                args.first().unwrap_or(&"?"),
                args[1..].join(" ")
            ),
            "APPEND" => format!("{} APPEND {}", tag, args.first().unwrap_or(&"?")),
            "CHECK" => format!("{} CHECK", tag),
            "CLOSE" => format!("{} CLOSE", tag),
            "EXPUNGE" => format!("{} EXPUNGE", tag),
            "SEARCH" => format!("{} SEARCH {}", tag, args.join(" ")),
            "FETCH" => format!(
                "{} FETCH {} {}",
                tag,
                args.first().unwrap_or(&"?"),
                args[1..].join(" ")
            ),
            "STORE" => format!(
                "{} STORE {} {} {}",
                tag,
                args.first().unwrap_or(&"?"),
                args.get(1).unwrap_or(&"?"),
                args.get(2).unwrap_or(&"?")
            ),
            "COPY" => format!(
                "{} COPY {} {}",
                tag,
                args.first().unwrap_or(&"?"),
                args.get(1).unwrap_or(&"?")
            ),
            "UID" => format!("{} UID {}", tag, args.join(" ")),
            "IDLE" => format!("{} IDLE", tag),
            _ => format!("{} [CMD: {}]", tag, cmd),
        };

        Some(parsed)
    }

   /// Parse MarkResponse
    fn parse_untagged_response(&self, text: &str) -> String {
        let content = text.strip_prefix('*').unwrap_or(text).trim();

       // Check ResponseType
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.is_empty() {
            return "* (空Response)".to_string();
        }

        let first = parts[0].to_uppercase();

        match first.as_str() {
            "OK" => format!(
                "* OK {}",
                parts[1..].join(" ").chars().take(50).collect::<String>()
            ),
            "NO" => format!(
                "* NO {}",
                parts[1..].join(" ").chars().take(50).collect::<String>()
            ),
            "BAD" => format!(
                "* BAD {}",
                parts[1..].join(" ").chars().take(50).collect::<String>()
            ),
            "PREAUTH" => "* PREAUTH (already预Authentication)".to_string(),
            "BYE" => format!(
                "* BYE {}",
                parts[1..].join(" ").chars().take(50).collect::<String>()
            ),
            "CAPABILITY" => format!("* CAPABILITY {}", parts[1..].join(" ")),
            "LIST" => format!("* LIST {}", parts[1..].join(" ")),
            "LSUB" => format!("* LSUB {}", parts[1..].join(" ")),
            "STATUS" => format!("* STATUS {}", parts[1..].join(" ")),
            "SEARCH" => format!("* SEARCH {}", parts[1..].join(" ")),
            "FLAGS" => format!("* FLAGS {}", parts[1..].join(" ")),
            _ => {
               // Checkwhether (EXISTS, RECENT, EXPUNGE, FETCH)
                if let Ok(num) = first.parse::<u32>() {
                    if parts.len() > 1 {
                        let second = parts[1].to_uppercase();
                        match second.as_str() {
                            "EXISTS" => format!("* {} EXISTS (emailMedium有 {} 封email)", num, num),
                            "RECENT" => format!("* {} RECENT ({} 封Newemail)", num, num),
                            "EXPUNGE" => format!("* {} EXPUNGE (email {} alreadydelete)", num, num),
                            "FETCH" => format!(
                                "* {} FETCH {}",
                                num,
                                parts[2..].join(" ").chars().take(40).collect::<String>()
                            ),
                            _ => format!(
                                "* {} {}",
                                num,
                                parts[1..].join(" ").chars().take(40).collect::<String>()
                            ),
                        }
                    } else {
                        format!("* {}", num)
                    }
                } else {
                    format!("* {}", content.chars().take(60).collect::<String>())
                }
            }
        }
    }

   /// ParseMarkResponse
    fn parse_tagged_response(&self, text: &str) -> String {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() < 2 {
            return text.to_string();
        }

        let tag = parts[0];
        let status = parts[1].to_uppercase();
        let message = parts[2..].join(" ");

        let status_desc = match status.as_str() {
            "OK" => "Success",
            "NO" => "Failed",
            "BAD" => "Error",
            _ => &status,
        };

        if message.is_empty() {
            format!("{} {} ({})", tag, status, status_desc)
        } else {
            format!(
                "{} {} ({}) {}",
                tag,
                status,
                status_desc,
                message.chars().take(40).collect::<String>()
            )
        }
    }
}

impl Default for ImapParser {
    fn default() -> Self {
        Self::new()
    }
}
