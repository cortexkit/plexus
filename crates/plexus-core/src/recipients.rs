//! Recipient declarations and the shared allowlist key normalization.

use serde_json::Value;

/// Trim surrounding whitespace and lowercase email addresses (strings containing
/// `@`). Other identifiers retain their case. Phone numbers are stored as given
/// after trimming; no country-code, punctuation, or phone canonicalization is
/// attempted yet. Use this function for both management writes and send checks.
pub fn normalize_recipient(recipient: &str) -> String {
    let recipient = recipient.trim();
    if recipient.contains('@') {
        recipient.to_lowercase()
    } else {
        recipient.to_owned()
    }
}

/// Resolve every declared pointer, refusing missing, empty or non-string values.
pub fn collect_recipients(pointers: &[String], args: &Value) -> Result<Vec<String>, String> {
    let mut recipients = Vec::new();
    for pointer in pointers {
        // Selecting a single array element would leave other destinations unchecked.
        if pointer
            .split('/')
            .skip(1)
            .any(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Err(pointer.clone());
        }
        let values = match args.pointer(pointer) {
            Some(Value::String(value)) => vec![value.as_str()],
            Some(Value::Array(values)) => values
                .iter()
                .map(Value::as_str)
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| pointer.clone())?,
            _ => return Err(pointer.clone()),
        };
        for value in values {
            let value = normalize_recipient(value);
            if value.is_empty() {
                return Err(pointer.clone());
            }
            recipients.push(value);
        }
    }
    recipients.sort();
    recipients.dedup();
    // Empty optional arrays are valid alongside actual recipients, but an
    // entirely empty declaration must not admit a provider's default destination.
    if recipients.is_empty() {
        return Err(pointers.first().cloned().unwrap_or_default());
    }
    Ok(recipients)
}

/// Resolve an RFC 6901 pointer against an explicit reviewed schema. Ambiguous
/// schemas ($ref, unions, unspecified types) are not evidence of a recipient
/// shape and fail closed. A declaration must cover the whole recipient array.
pub fn recipient_pointer_valid(schema: &Value, pointer: &str) -> bool {
    if !pointer.starts_with('/') {
        return false;
    }
    let mut node = schema;
    for token in pointer[1..].split('/') {
        let mut decoded = String::new();
        let mut chars = token.chars();
        while let Some(ch) = chars.next() {
            if ch == '~' {
                match chars.next() {
                    Some('0') => decoded.push('~'),
                    Some('1') => decoded.push('/'),
                    _ => return false,
                }
            } else {
                decoded.push(ch);
            }
        }
        node = match node.get("type").and_then(Value::as_str) {
            Some("object") => match node.get("properties").and_then(|p| p.get(&decoded)) {
                Some(node) => node,
                None => return false,
            },
            _ => return false,
        };
    }
    match node.get("type").and_then(Value::as_str) {
        Some("string") => true,
        Some("array") => node.pointer("/items/type").and_then(Value::as_str) == Some("string"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn recipient_pointers_cannot_select_only_one_array_element() {
        let schema =
            json!({"type":"object","properties":{"to":{"type":"array","items":{"type":"string"}}}});
        assert!(!recipient_pointer_valid(&schema, "/to/0"));
        assert!(recipient_pointer_valid(&schema, "/to"));
        assert!(
            collect_recipients(&["/to/0".into()], &json!({"to":["safe@x","other@y"]})).is_err()
        );
    }

    #[test]
    fn normalization_trims_emails_but_preserves_phone_and_chat_identifiers() {
        assert_eq!(
            normalize_recipient(" Alice@Example.COM \n"),
            "alice@example.com"
        );
        assert_eq!(
            normalize_recipient(" +1 (555) 001-0023 "),
            "+1 (555) 001-0023"
        );
        assert_eq!(normalize_recipient(" ChannelAbC "), "ChannelAbC");
    }

    #[test]
    fn pointers_resolve_nested_escaped_properties_and_arrays() {
        let schema = json!({"type":"object","properties":{"a/b":{"type":"object","properties":{"~to":{"type":"array","items":{"type":"string"}}}}}});
        assert!(recipient_pointer_valid(&schema, "/a~1b/~0to"));
        assert!(!recipient_pointer_valid(&schema, "/a~1b/~0to/0"));
        for pointer in [
            "/a~2b",
            "/missing",
            "/a~1b",
            "",
            "to",
            "/a~1b/~0to/01",
            "/a~1b/~0to/+1",
        ] {
            assert!(!recipient_pointer_valid(&schema, pointer), "{pointer}");
        }
        assert_eq!(
            collect_recipients(
                &["/to".into(), "/cc".into()],
                &json!({"to":"A@B.COM","cc":[" a@b.com ","C@D.COM"]})
            )
            .unwrap(),
            vec!["a@b.com", "c@d.com"]
        );
        assert_eq!(
            collect_recipients(
                &["/to".into(), "/cc".into()],
                &json!({"to":"A@B.COM","cc":[]})
            )
            .unwrap(),
            vec!["a@b.com"]
        );
        assert!(collect_recipients(&["/to".into()], &json!({"to":[]})).is_err());
    }
}
