//! ProtocolParseModule

//! SMTP/MIME vigilyx-parser crate.
//! sniffer, vigilyx-parser.

pub mod file_protocol;
pub mod http;
pub mod http_state;
pub mod pcapng;

mod imap;
mod pop3;

// vigilyx-parser
pub use vigilyx_parser::mime;
pub use vigilyx_parser::smtp_state;

pub use imap::ImapParser;
pub use pop3::Pop3Parser;
pub use vigilyx_parser::SmtpParser;

use vigilyx_core::Protocol;

/// ProtocolParsehandler
pub struct ProtocolParser {
    smtp: SmtpParser,
    pop3: Pop3Parser,
    imap: ImapParser,
}

impl ProtocolParser {
   /// CreateNewofProtocolParsehandler
    pub fn new() -> Self {
        Self {
            smtp: SmtpParser::new(),
            pop3: Pop3Parser::new(),
            imap: ImapParser::new(),
        }
    }

   /// Parsedatapacket
    pub fn parse(&self, data: &[u8], protocol: Protocol) -> Option<String> {
        match protocol {
            Protocol::Smtp => self.smtp.parse(data),
            Protocol::Pop3 => self.pop3.parse(data),
            Protocol::Imap => self.imap.parse(data),
            Protocol::Http => {
               // HTTP Command: Extract method + URI command Segment
                http::parse_http_request(data).map(|req| format!("{} {}", req.method, req.uri))
            }
            Protocol::Unknown => None,
        }
    }
}

impl Default for ProtocolParser {
    fn default() -> Self {
        Self::new()
    }
}
