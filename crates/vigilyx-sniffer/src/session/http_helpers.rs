//! HTTP function

//! formcredentialsExtract, Cookie Parse, sid -> user MappingExtract, tempFilewrite waitModulelevel function.

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{fs::OpenOptions, io::Write};
use uuid::Uuid;


// HTTP Body tempFilewrite


/// HTTP body tempFileDirectory
const HTTP_TEMP_DIR: &str = "data/tmp/http";

/// large body write disktempFile
///
/// ReturnFilepath `data/tmp/http/{session_id}.bin`
pub(super) fn write_body_temp_file(session_id: &Uuid, body: &[u8]) -> std::io::Result<String> {
   // EnsureDirectorystored
    std::fs::create_dir_all(HTTP_TEMP_DIR)?;
    #[cfg(unix)]
    std::fs::set_permissions(HTTP_TEMP_DIR, std::fs::Permissions::from_mode(0o700))?;

    let path = format!("{}/{}.bin", HTTP_TEMP_DIR, session_id);
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&path)?;
    file.write_all(body)?;
    #[cfg(unix)]
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(path)
}


// HTTP formcredentialsExtract


/// From URL-encoded form body MediumExtractuserNameAndPassword
///
/// match SegmentName: username, user, login, email, uid, account, passwd, password, pass, pwd
pub(super) fn extract_form_credentials(body: &[u8]) -> Option<(String, String)> {
   // limitParseLength,prevent large POST body
    let len = body.len().min(4096);
    let body_str = std::str::from_utf8(&body[..len]).ok()?;

    let mut username = None;
    let mut password = None;

    for pair in body_str.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next()?.to_lowercase();
        let value = parts.next().unwrap_or("");
        let decoded = urldecode(value);

        match key.as_str() {
            "username" | "user" | "login" | "email" | "uid" | "account" => {
                username = Some(decoded);
            }
            "password" | "passwd" | "pass" | "pwd" => {
                password = Some(decoded);
            }
            _ => {}
        }
    }

    match (username, password) {
        (Some(u), Some(p)) if !u.is_empty() => Some((u, p)),
        _ => None,
    }
}

/// URL Decode (+ ->, %XX -> Byte)
pub(super) fn urldecode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'+' => result.push(' '),
            b'%' => {
                let h1 = bytes.next().and_then(|c| (c as char).to_digit(16));
                let h2 = bytes.next().and_then(|c| (c as char).to_digit(16));
                if let (Some(h1), Some(h2)) = (h1, h2) {
                    result.push((h1 * 16 + h2) as u8 as char);
                }
            }
            _ => result.push(b as char),
        }
    }
    result
}

/// From Cookie StringMediumExtractuser
///
/// match webmail ofuser cookie: uid, username, user, sid wait
pub(super) fn extract_user_from_cookie(cookie: &str) -> Option<String> {
    for pair in cookie.split(';') {
        let pair = pair.trim();
        let mut parts = pair.splitn(2, '=');
        let key = match parts.next() {
            Some(k) => k.trim().to_lowercase(),
            None => continue,
        };
        let value = parts.next().unwrap_or("").trim();

        match key.as_str() {
            "uid" | "username" | "user" | "login_name" | "coremail_uid" | "coremail.uid"
            | "loginemail" | "login_email" | "login_user" | "mailuser"
                if !value.is_empty() =>
            {
                return Some(urldecode(value));
            }
            _ => {}
        }
    }
    None
}

/// From URL MediumExtract Coremail sid Parameter
///
/// match `?sid=xxx` `&sid=xxx`,Coremail of sid 32 bit
pub(super) fn extract_sid_from_uri(uri: &str) -> Option<String> {
    let query = uri.find('?').map(|i| &uri[i + 1..])?;
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        let key = kv.next()?;
        let val = kv.next().unwrap_or("");
        if key == "sid" && !val.is_empty() {
            return Some(val.to_string());
        }
    }
    None
}

/// From socket.io auth MessageMediumExtractuseremail
///
/// : `42["auth",{"clientId":"...","sid":"...","username":"user@domain.com"}]`
pub(super) fn extract_socketio_auth_user(body: &str) -> Option<String> {
   // Exclude: packetContains "auth" And "username"
    if !body.contains("\"auth\"") || !body.contains("\"username\"") {
        return None;
    }
   // find JSON
    let start = body.find('{').unwrap_or(body.len());
    let end = body.rfind('}').map(|i| i + 1).unwrap_or(body.len());
    if start >= end {
        return None;
    }
    let json_str = &body[start..end];
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str)
        && let Some(username) = val.get("username").and_then(|v| v.as_str())
        && username.contains('@')
        && !username.is_empty()
    {
        return Some(username.to_string());
    }
    None
}

/// From Coremail compose JSON body Extract attrs.account useremail
///
/// Coremail compose.jsp POST body: `{"attrs":{"account":"<user@domain.com>",...}, "action":"deliver"}`
pub(super) fn extract_coremail_account_from_body(body: &str) -> Option<String> {
   // Exclude:compose body packetContains "attrs" And "account"
    if !body.contains("\"attrs\"") || !body.contains("\"account\"") {
        return None;
    }
   // limitParseLength
    let end = body.len().min(4096);
    let mut safe_end = end;
    while safe_end > 0 && !body.is_char_boundary(safe_end) {
        safe_end -= 1;
    }
    let val: serde_json::Value = serde_json::from_str(&body[..safe_end]).ok()?;
    let account = val.get("attrs")?.get("account")?.as_str()?;
   // Extract <email> Mediumofemail
    if let Some(start) = account.find('<')
        && let Some(end_pos) = account.find('>')
    {
        let email = account[start + 1..end_pos].trim();
        if !email.is_empty() && email.contains('@') {
            return Some(email.to_lowercase());
        }
    }
   // email
    let trimmed = account.trim().trim_matches('"').trim();
    if trimmed.contains('@') {
        Some(trimmed.to_lowercase())
    } else {
        None
    }
}
