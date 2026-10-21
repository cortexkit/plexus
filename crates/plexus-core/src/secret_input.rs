//! Shared facade and durable-argument secret-input screening.
//!
//! Credential material may only enter Plexus through the binding-ticket
//! ceremony, so an argument whose NAME says it carries a credential is
//! refused. The decision is by name, matched on whole words, because a
//! substring match both refuses ordinary arguments (`page_token`,
//! `max_tokens`) and misses real credentials (`api_key`, `authorization`).
//!
//! Values are never grounds for refusing a call: a legitimate write may quote
//! something that looks like a token. They are only grounds for withholding a
//! value from a consent-card preview, which costs nothing; see
//! [`withhold_from_preview`].

use serde_json::Value;

/// True when `key` names a credential, or `child` holds an entry that does.
pub fn contains_secret_entry(key: &str, child: &Value) -> bool {
    is_secret_key(key) || contains_secret_input(child)
}

/// True when any object key anywhere inside `value` names a credential.
pub fn contains_secret_input(value: &Value) -> bool {
    match value {
        Value::Object(object) => object
            .iter()
            .any(|(key, child)| contains_secret_entry(key, child)),
        Value::Array(values) => values.iter().any(contains_secret_input),
        _ => false,
    }
}

/// True when a consent-card preview must not show `child` under `key`: the
/// key names a credential, or some string inside the value has the shape of
/// one. Never used to refuse a call.
pub fn withhold_from_preview(key: &str, child: &Value) -> bool {
    contains_secret_entry(key, child) || contains_secret_shaped_value(child)
}

/// True when any string anywhere inside `value` contains a word shaped like
/// a known credential format.
pub fn contains_secret_shaped_value(value: &Value) -> bool {
    match value {
        Value::String(text) => text.split_whitespace().any(looks_like_secret),
        Value::Object(object) => object.values().any(contains_secret_shaped_value),
        Value::Array(values) => values.iter().any(contains_secret_shaped_value),
        _ => false,
    }
}

/// Whole keys that name a credential, after normalization (lowercased, words
/// joined with no separator, so `api_key`, `apiKey` and `API-KEY` are all
/// `apikey`).
const SECRET_KEYS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "passphrase",
    "credential",
    "credentials",
    "credentialhandle",
    "ckh",
    "apikey",
    "xapikey",
    "privatekey",
    "secretkey",
    "accesskey",
    "signingkey",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "authtoken",
    "bearertoken",
    "sessiontoken",
    "apitoken",
    "privatetoken",
    "clientsecret",
    "authorization",
    "proxyauthorization",
    "cookie",
    "setcookie",
];

/// A key whose LAST word is one of these names a credential
/// (`client_password`, `session_cookie`).
const SECRET_LAST_WORDS: &[&str] = &[
    "secret",
    "password",
    "passwd",
    "passphrase",
    "credential",
    "credentials",
    "cookie",
    "authorization",
];

/// A key whose last TWO words are one of these names a credential
/// (`stripe_api_key`, `github_access_token`). Pagination and limit names
/// (`page_token`, `sync_token`, `max_tokens`) are deliberately absent.
const SECRET_LAST_PAIRS: &[(&str, &str)] = &[
    ("api", "key"),
    ("private", "key"),
    ("secret", "key"),
    ("access", "key"),
    ("signing", "key"),
    ("access", "token"),
    ("refresh", "token"),
    ("id", "token"),
    ("auth", "token"),
    ("bearer", "token"),
    ("session", "token"),
    ("client", "secret"),
];

/// A key ending in the word `token` names a credential (`github_token`,
/// `bot_token`) unless the word before it is one of these, which make it a
/// pagination cursor or a size limit (`page_token`, `next_page_token`,
/// `sync_token`, `max_token`).
const NON_SECRET_TOKEN_QUALIFIERS: &[&str] = &[
    "page",
    "next",
    "prev",
    "previous",
    "sync",
    "continuation",
    "cursor",
    "max",
    "min",
    "num",
    "count",
];

/// True when the argument name `key` says it carries a credential.
pub fn is_secret_key(key: &str) -> bool {
    let words = key_words(key);
    if words.is_empty() {
        return false;
    }
    if SECRET_KEYS.contains(&words.concat().as_str()) {
        return true;
    }
    let last = words[words.len() - 1].as_str();
    if SECRET_LAST_WORDS.contains(&last) {
        return true;
    }
    let before = (words.len() >= 2).then(|| words[words.len() - 2].as_str());
    if last == "token" {
        return !before.is_some_and(|word| NON_SECRET_TOKEN_QUALIFIERS.contains(&word));
    }
    before.is_some_and(|before| {
        SECRET_LAST_PAIRS
            .iter()
            .any(|(first, second)| *first == before && *second == last)
    })
}

/// Split a key into lowercase words at any non-alphanumeric character and at
/// camelCase boundaries: `xApiKey` and `X-API-Key` both give `x`, `api`,
/// `key`, and `APIKey` gives `api`, `key`.
fn key_words(key: &str) -> Vec<String> {
    let chars: Vec<char> = key.chars().collect();
    let mut words = Vec::new();
    let mut current = String::new();
    for (index, &ch) in chars.iter().enumerate() {
        if !ch.is_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            continue;
        }
        let boundary = ch.is_uppercase()
            && index > 0
            && (chars[index - 1].is_lowercase()
                || chars[index - 1].is_ascii_digit()
                || (chars[index - 1].is_uppercase()
                    && chars.get(index + 1).is_some_and(|next| next.is_lowercase())));
        if boundary && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        current.extend(ch.to_lowercase());
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// `text` with each whitespace-separated word that has the shape of a known
/// credential format replaced by `[redacted]`, and whether any was. The
/// whitespace between words is kept as it was. Used where free text a caller
/// wrote is stored, such as a search query in the audit journal.
pub(crate) fn redact_secret_shaped_words(text: &str) -> (String, bool) {
    let mut redacted = String::with_capacity(text.len());
    let mut any = false;
    let mut rest = text;
    while !rest.is_empty() {
        let word_start = rest
            .find(|ch: char| !ch.is_whitespace())
            .unwrap_or(rest.len());
        redacted.push_str(&rest[..word_start]);
        rest = &rest[word_start..];
        let word_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let word = &rest[..word_end];
        if looks_like_secret(word) {
            redacted.push_str("[redacted]");
            any = true;
        } else {
            redacted.push_str(word);
        }
        rest = &rest[word_end..];
    }
    (redacted, any)
}

/// True when `word` has the shape of a known credential format.
fn looks_like_secret(word: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "ckh_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "sk-",
        "sk_live_",
        "xoxb-",
        "xoxp-",
    ];
    let word = word.trim_matches(|ch: char| matches!(ch, '"' | '\'' | '`' | ',' | ';'));
    if PREFIXES
        .iter()
        .any(|prefix| word.len() > prefix.len() + 8 && word.starts_with(prefix))
    {
        return true;
    }
    // AWS access key id: AKIA followed by 16 upper-case letters or digits.
    if word.len() == 20
        && word.starts_with("AKIA")
        && word[4..]
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
    {
        return true;
    }
    // A JSON Web Token: three base64url segments, the header starting `eyJ`.
    let segments: Vec<&str> = word.split('.').collect();
    segments.len() == 3
        && segments[0].starts_with("eyJ")
        && segments.iter().all(|segment| {
            segment.len() >= 4
                && segment
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn credential_names_are_refused_whatever_their_spelling() {
        for key in [
            "token",
            "secret",
            "password",
            "passwd",
            "passphrase",
            "credential",
            "credentials",
            "credential_handle",
            "api_key",
            "apiKey",
            "API-KEY",
            "x-api-key",
            "xApiKey",
            "private_key",
            "secret_key",
            "access_key",
            "signing_key",
            "access_token",
            "refresh_token",
            "id_token",
            "auth_token",
            "bearer_token",
            "session_token",
            "api_token",
            "private-token",
            "client_secret",
            "authorization",
            "Authorization",
            "proxy-authorization",
            "cookie",
            "Set-Cookie",
            "stripe_api_key",
            "github_access_token",
            "admin_password",
            "session_cookie",
            "oauth_client_secret",
            "db_credentials",
            "github_token",
            "bot_token",
            "gh_token",
            "npm_token",
            "slackToken",
        ] {
            assert!(is_secret_key(key), "{key} names a credential");
            assert!(
                contains_secret_input(&json!({"outer": {key: "x"}})),
                "{key} is found nested too"
            );
        }
    }

    #[test]
    fn ordinary_argument_names_pass() {
        for key in [
            // A vendor's username or product handle is not a credential. Only
            // credential-specific handle names are refused; previews still
            // redact values shaped like secret credential references.
            "handle",
            "user_handle",
            "page_token",
            "sync_token",
            "next_page_token",
            "nextPageToken",
            "continuation_token",
            "max_tokens",
            "maxTokens",
            "max_token",
            "prev_page_token",
            "previous_token",
            "cursor_token",
            "call_key",
            "event_key",
            "app_key",
            "key",
            "credential_id",
            "ticket_id",
            "author",
            "keyword",
            "passage",
            "secretary",
            "cookie_count",
            "tokenizer",
        ] {
            assert!(!is_secret_key(key), "{key} is an ordinary argument");
        }
    }

    #[test]
    fn a_secret_shaped_value_is_withheld_from_previews_but_never_refused() {
        let quoted = json!(format!("rotate ghp_{} today", "a".repeat(36)));
        assert!(
            withhold_from_preview("body", &quoted),
            "a token-shaped value is withheld from a card preview"
        );
        assert!(
            !contains_secret_entry("body", &quoted),
            "the same value under an innocent key does not refuse the call"
        );
        for shaped in [
            json!(format!("github_pat_{}", "b".repeat(40))),
            json!(format!("sk-{}", "c".repeat(40))),
            json!(format!("sk_live_{}", "d".repeat(24))),
            json!(format!("xoxb-{}", "1".repeat(30))),
            json!(format!("AKIA{}", "EXAMPLE123456789")),
            json!([
                "eyJhbGciOiJIUzI1NiJ9",
                "eyJzdWIiOiIxIn0",
                "EXAMPLEsignature"
            ]
            .join(".")),
            json!({"nested": [format!("gho_{}", "e".repeat(36))]}),
        ] {
            assert!(
                withhold_from_preview("note", &shaped),
                "{shaped} is withheld"
            );
            assert!(
                !contains_secret_entry("note", &shaped),
                "{shaped} is not refused"
            );
        }
        for plain in [
            json!("an ordinary comment about sk- prefixes"),
            json!("version 1.2.3"),
            json!(42),
            json!({"title": "AKIA is a prefix"}),
        ] {
            assert!(!withhold_from_preview("note", &plain), "{plain} is shown");
        }
    }

    #[test]
    fn free_text_redaction_replaces_only_credential_shaped_words() {
        assert_eq!(
            redact_secret_shaped_words("is  ghp_abcdefghijklmnop leaked?\tAKIAABCDEFGHIJKLMNOP"),
            ("is  [redacted] leaked?\t[redacted]".to_string(), true),
            "credential-shaped words are replaced and spacing is kept"
        );
        assert_eq!(
            redact_secret_shaped_words("rust async book"),
            ("rust async book".to_string(), false)
        );
    }
}
