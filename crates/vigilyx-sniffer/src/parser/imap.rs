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
                args.get(1..).unwrap_or(&[]).join(" ")
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
                args.get(1..).unwrap_or(&[]).join(" ")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_without_args_does_not_panic() {
        let parser = ImapParser::new();
        let result = parser.parse(b"A1 STATUS\r\n");
        assert_eq!(result, Some("A1 STATUS ? ()".to_string()));
    }

    #[test]
    fn test_fetch_without_args_does_not_panic() {
        let parser = ImapParser::new();
        let result = parser.parse(b"A1 FETCH\r\n");
        assert_eq!(result, Some("A1 FETCH ? ".to_string()));
    }

    #[test]
    fn test_fetch_with_single_arg_does_not_panic() {
        let parser = ImapParser::new();
        let result = parser.parse(b"A1 FETCH 1\r\n");
        assert_eq!(result, Some("A1 FETCH 1 ".to_string()));
    }

    #[test]
    fn test_status_with_args_parses_normally() {
        let parser = ImapParser::new();
        let result = parser.parse(b"A1 STATUS INBOX (MESSAGES 2 RECENT 1)\r\n");
        assert_eq!(
            result,
            Some("A1 STATUS INBOX ((MESSAGES 2 RECENT 1))".to_string())
        );
    }

    #[test]
    fn test_fetch_with_args_parses_normally() {
        let parser = ImapParser::new();
        let result = parser.parse(b"A1 FETCH 1 FLAGS\r\n");
        assert_eq!(result, Some("A1 FETCH 1 FLAGS".to_string()));
    }

    #[test]
    fn test_empty_input_returns_none() {
        let parser = ImapParser::new();
        assert_eq!(parser.parse(b""), None);
        assert_eq!(parser.parse(b"\r\n"), None);
    }

    #[test]
    fn test_tag_only_command_does_not_panic() {
        let parser = ImapParser::new();
        let result = parser.parse(b"A1\r\n");
        assert_eq!(result, Some("[IMAP: A1]".to_string()));
    }

    #[test]
    fn test_other_commands_without_args_do_not_panic() {
        let parser = ImapParser::new();
        // 这些命令分支都访问 args，缺参数时必须走 unwrap_or 兜底而不是 panic
        for cmd in [
            "A1 AUTHENTICATE",
            "A1 LOGIN",
            "A1 SELECT",
            "A1 RENAME",
            "A1 LIST",
            "A1 STORE",
            "A1 COPY",
            "A1 SEARCH",
            "A1 UID",
        ] {
            let input = format!("{}\r\n", cmd);
            assert!(
                parser.parse(input.as_bytes()).is_some(),
                "command should parse without panic: {}",
                cmd
            );
        }
    }

    #[test]
    fn test_command_with_excessive_args_does_not_panic() {
        let parser = ImapParser::new();
        let args = (0..10_000)
            .map(|i| format!("arg{}", i))
            .collect::<Vec<_>>()
            .join(" ");
        let input = format!("A1 FETCH 1:{}\r\n", args);
        let result = parser.parse(input.as_bytes());
        assert!(result.is_some());
        assert!(result.unwrap().starts_with("A1 FETCH"));
    }

    #[test]
    fn test_untagged_response_single_word_does_not_panic() {
        let parser = ImapParser::new();
        // "* OK" 没有后续内容，parts[1..] 必须安全返回空
        let result = parser.parse(b"* OK\r\n");
        assert_eq!(result, Some("* OK ".to_string()));
    }

    #[test]
    fn test_untagged_numeric_response_without_keyword() {
        let parser = ImapParser::new();
        let result = parser.parse(b"* 3\r\n");
        assert_eq!(result, Some("* 3".to_string()));
    }

    #[test]
    fn test_tagged_response_without_message() {
        let parser = ImapParser::new();
        let result = parser.parse(b"A1 OK\r\n");
        assert_eq!(result, Some("A1 OK (Success)".to_string()));
    }

    #[test]
    fn test_normal_login_masks_password() {
        let parser = ImapParser::new();
        let result = parser.parse(b"A1 LOGIN user@example.com secret\r\n");
        assert_eq!(result, Some("A1 LOGIN user@example.com ***".to_string()));
    }
}
