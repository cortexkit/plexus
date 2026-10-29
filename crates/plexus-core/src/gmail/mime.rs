//! The send-only MIME boundary: no caller-controlled headers or raw message.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub body: String,
}

fn header(value: &str) -> Result<(), &'static str> {
    if value.contains(['\r', '\n']) {
        Err("gmail_header_injection")
    } else if value.chars().any(|c| c.is_control()) {
        Err("gmail_invalid_header")
    } else {
        Ok(())
    }
}

/// Accept bare ASCII dot-atom mailboxes and DNS domains, not display names,
/// comments, address groups, quoted local parts or internationalized addresses.
/// Keeping this subset explicit avoids interpreting a recipient differently
/// from the allowlist gate or the receiving mail server.
pub fn address(value: &str) -> Result<(), &'static str> {
    header(value)?;
    let Some((local, domain)) = value.split_once('@') else {
        return Err("gmail_invalid_address");
    };
    let atom = |c: u8| c.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&c);
    if value.len() > 254
        || local.is_empty()
        || local.len() > 64
        || !local
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(atom))
        || domain.len() > 253
        || !domain.contains('.')
        || !domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err("gmail_invalid_address");
    }
    Ok(())
}

impl Message {
    pub fn parse(args: &serde_json::Value) -> Result<Self, &'static str> {
        serde_json::from_value(args.clone()).map_err(|_| "gmail_invalid_arguments")
    }

    pub fn compose(&self, mailbox: &str, at_ms: i64) -> Result<Vec<u8>, &'static str> {
        address(mailbox)?;
        header(&self.subject)?;
        if self.subject.chars().count() > 200
            || self.body.chars().count() > 200_000
            || self.to.len() + self.cc.len() + self.bcc.len() == 0
            || [&self.to, &self.cc, &self.bcc]
                .iter()
                .any(|list| list.len() > 100)
        {
            return Err("gmail_invalid_arguments");
        }
        for value in self.to.iter().chain(&self.cc).chain(&self.bcc) {
            address(value)?;
        }
        let at = std::time::UNIX_EPOCH
            .checked_add(std::time::Duration::from_millis(
                u64::try_from(at_ms).map_err(|_| "gmail_invalid_clock")?,
            ))
            .ok_or("gmail_invalid_clock")?;
        let mut mime = format!(
            "From: {mailbox}\r\nDate: {}\r\n",
            httpdate::fmt_http_date(at)
        );
        for (name, list) in [("To", &self.to), ("Cc", &self.cc), ("Bcc", &self.bcc)] {
            // Folding between mailboxes keeps even the longest accepted list
            // below RFC 5322's hard line limit without splitting an address.
            if !list.is_empty() {
                mime.push_str(&format!("{name}: {}\r\n", list.join(",\r\n ")));
            }
        }
        mime.push_str("Subject: ");
        if self.subject.is_ascii() {
            mime.push_str(&self.subject);
        } else {
            // Each encoded word is at most 72 bytes, below RFC 2047's 75.
            // Split on UTF-8 boundaries, so every word decodes independently.
            let mut words = Vec::new();
            let mut chunk = String::new();
            for ch in self.subject.chars() {
                if chunk.len() + ch.len_utf8() > 45 {
                    words.push(format!("=?UTF-8?B?{}?=", STANDARD.encode(chunk.as_bytes())));
                    chunk.clear();
                }
                chunk.push(ch);
            }
            if !chunk.is_empty() {
                words.push(format!("=?UTF-8?B?{}?=", STANDARD.encode(chunk.as_bytes())));
            }
            mime.push_str(&words.join("\r\n "));
        }
        mime.push_str("\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n");
        let body = self
            .body
            .replace("\r\n", "\n")
            .replace('\r', "\n")
            .replace('\n', "\r\n");
        let encoded = STANDARD.encode(body.as_bytes());
        for line in encoded.as_bytes().chunks(76) {
            mime.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            mime.push_str("\r\n");
        }
        Ok(mime.into_bytes())
    }
}
