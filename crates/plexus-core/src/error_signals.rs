//! Closed predicates over raw vendor errors. Only the fixed signal leaves transport.

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;

use crate::manifest::{
    AppManifest, ErrorMatch, ErrorSignal, ErrorSignalRule, HeaderCondition, ManifestError,
};

pub(crate) fn from_manifest(
    manifest: &AppManifest,
) -> std::collections::HashMap<String, Vec<ErrorSignalRule>> {
    manifest
        .actions_baseline
        .iter()
        .filter_map(|action| {
            action
                .error_signals
                .as_ref()
                .map(|rules| (action.name.clone(), rules.clone()))
        })
        .collect()
}

pub(crate) fn evaluate(
    rules: &[ErrorSignalRule],
    status: u16,
    headers: &HeaderMap,
    body: Option<&Value>,
) -> Option<ErrorSignal> {
    rules.iter().find_map(|rule| {
        if rule.status != status {
            return None;
        }
        let matched = match &rule.matches {
            ErrorMatch::Json { pointer, value } => {
                body.and_then(|body| body.pointer(pointer)) == Some(value)
            }
            ErrorMatch::Header { name, condition } => {
                // Repeated headers are ambiguous; never pick whichever value
                // happened to arrive first as an authority-bearing signal.
                let mut values = headers.get_all(name).iter();
                let value = values.next().and_then(|value| value.to_str().ok());
                values.next().is_none()
                    && value.is_some_and(|value| match condition {
                        HeaderCondition::Exact { value: expected } => value == expected,
                        HeaderCondition::CommaSeparatedElement {
                            index,
                            value: expected,
                        } => {
                            value
                                .split(',')
                                .nth(*index)
                                .map(|part| part.trim_matches([' ', '\t']))
                                == Some(expected.as_str())
                        }
                    })
            }
        };
        matched.then_some(rule.signal)
    })
}

pub(crate) fn validate(rules: &[ErrorSignalRule]) -> Result<(), ManifestError> {
    let invalid = |reason: &str| ManifestError::InvalidField(format!("error_signals {reason}"));
    for (index, rule) in rules.iter().enumerate() {
        if !(200..=599).contains(&rule.status) {
            return Err(invalid("status must be in 200..=599"));
        }
        match &rule.matches {
            ErrorMatch::Json { pointer, .. } => {
                if !valid_pointer(pointer) {
                    return Err(invalid("requires a valid JSON pointer"));
                }
            }
            ErrorMatch::Header { name, condition } => {
                if HeaderName::from_bytes(name.as_bytes()).is_err() {
                    return Err(invalid("requires a valid response header name"));
                }
                let (HeaderCondition::Exact { value }
                | HeaderCondition::CommaSeparatedElement { value, .. }) = condition;
                if HeaderValue::from_str(value).is_err()
                    || matches!(condition, HeaderCondition::CommaSeparatedElement { .. })
                        && (value.contains(',') || value.trim_matches([' ', '\t']) != value)
                {
                    return Err(invalid("requires an exact header value"));
                }
            }
        }
        for previous in &rules[..index] {
            if previous.status == rule.status && !disjoint(&previous.matches, &rule.matches) {
                return Err(invalid("contains overlapping matches for one status"));
            }
        }
    }
    Ok(())
}

fn valid_pointer(pointer: &str) -> bool {
    if !pointer.is_empty() && !pointer.starts_with('/') {
        return false;
    }
    let mut chars = pointer.chars();
    while let Some(ch) = chars.next() {
        if ch == '~' && !matches!(chars.next(), Some('0' | '1')) {
            return false;
        }
    }
    true
}

/// Different fields may coexist, so reject them conservatively. Only unequal
/// exact values of the same field (or same header element) prove disjointness.
fn disjoint(left: &ErrorMatch, right: &ErrorMatch) -> bool {
    match (left, right) {
        (
            ErrorMatch::Json {
                pointer: a,
                value: av,
            },
            ErrorMatch::Json {
                pointer: b,
                value: bv,
            },
        ) => a == b && av != bv,
        (
            ErrorMatch::Header {
                name: a,
                condition: ac,
            },
            ErrorMatch::Header {
                name: b,
                condition: bc,
            },
        ) if a.eq_ignore_ascii_case(b) => match (ac, bc) {
            (HeaderCondition::Exact { value: a }, HeaderCondition::Exact { value: b }) => a != b,
            (
                HeaderCondition::CommaSeparatedElement {
                    index: ai,
                    value: a,
                },
                HeaderCondition::CommaSeparatedElement {
                    index: bi,
                    value: b,
                },
            ) => ai == bi && a != b,
            _ => false,
        },
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn predicates_match_exact_values_not_vendor_wording() {
        let rule: ErrorSignalRule =
            serde_json::from_value(json!({"status":422,"signal":"no_results",
            "matches":{"kind":"json","pointer":"/error/a~1b~0c","value":"EMPTY"}}))
            .unwrap();
        for (status, body, expected) in [
            (
                422,
                json!({"error":{"a/b~c":"EMPTY"}}),
                Some(ErrorSignal::NoResults),
            ),
            (400, json!({"error":{"a/b~c":"EMPTY"}}), None),
            (422, json!({"error":{"a/b~c":"EMPTY extra"}}), None),
            (422, json!({"detail":"EMPTY"}), None),
            (422, json!({"error":{"a/b~c":null}}), None),
        ] {
            assert_eq!(
                evaluate(
                    std::slice::from_ref(&rule),
                    status,
                    &HeaderMap::new(),
                    Some(&body)
                ),
                expected,
                "JSON error signals must match only the exact reviewed pointer and value"
            );
        }
    }

    #[test]
    fn monthly_header_requires_the_exact_second_element() {
        let rule: ErrorSignalRule =
            serde_json::from_value(json!({"status":429,"signal":"quota_exhausted",
            "matches":{"kind":"header","name":"X-RateLimit-Remaining","condition":{
                "kind":"comma_separated_element","index":1,"value":"0"}}}))
            .unwrap();
        for (value, expected) in [
            ("1, 0", Some(ErrorSignal::QuotaExhausted)),
            ("0, 100", None),
            ("0", None),
            ("1, 00", None),
            ("1, 0 remaining", None),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-ratelimit-remaining",
                HeaderValue::from_str(value).unwrap(),
            );
            assert_eq!(
                evaluate(std::slice::from_ref(&rule), 429, &headers, None),
                expected,
                "monthly quota must match only the second exact header element"
            );
            headers.append("x-ratelimit-remaining", HeaderValue::from_static("1, 0"));
            assert_eq!(
                evaluate(std::slice::from_ref(&rule), 429, &headers, None),
                None
            );
        }
        let exact: ErrorSignalRule = serde_json::from_value(json!({"status":403,"signal":"credential_rejected",
            "matches":{"kind":"header","name":"X-Key-State","condition":{"kind":"exact","value":"revoked"}}})).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-key-state", HeaderValue::from_static("revoked"));
        assert_eq!(
            evaluate(&[exact], 403, &headers, None),
            Some(ErrorSignal::CredentialRejected)
        );
    }
}
