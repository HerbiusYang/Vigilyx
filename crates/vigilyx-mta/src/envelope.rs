use lettre::Address;

pub(crate) fn extract_domain(addr_or_domain: &str) -> Option<&str> {
    let domain = addr_or_domain
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .unwrap_or(addr_or_domain)
        .trim()
        .trim_end_matches('.');

    if domain.is_empty() || domain.len() > 253 || domain.chars().any(char::is_whitespace) {
        return None;
    }

    Some(domain)
}

pub(crate) fn is_valid_envelope_address(addr: &str) -> bool {
    if addr.len() > 256 || addr.chars().any(char::is_whitespace) {
        return false;
    }

    let Some((local, domain)) = addr.rsplit_once('@') else {
        return false;
    };

    is_valid_local_part(local)
        && !local.contains('@')
        && is_valid_domain(domain)
        && addr.parse::<Address>().is_ok()
}

fn is_valid_local_part(local: &str) -> bool {
    !local.is_empty()
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(
                    ch,
                    '!' | '#'
                        | '$'
                        | '%'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '/'
                        | '='
                        | '?'
                        | '^'
                        | '_'
                        | '`'
                        | '{'
                        | '|'
                        | '}'
                        | '~'
                        | '.'
                )
        })
}

fn is_valid_domain(domain: &str) -> bool {
    let Some(domain) = extract_domain(domain) else {
        return false;
    };

    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_sender_domain_rejected() {
        assert!(!is_valid_envelope_address("user@bad_domain"));
    }

    #[test]
    fn test_invalid_sender_local_part_rejected() {
        assert!(!is_valid_envelope_address("a..b@example.com"));
    }

    #[test]
    fn test_valid_sender_accepted() {
        assert!(is_valid_envelope_address("user.name+tag@example.com"));
    }
}
