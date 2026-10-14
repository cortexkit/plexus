//! Closed projection of GitHub REST validation errors, never free vendor text.
use serde_json::{json, Value};

// GitHub documents these codes at:
// https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api#validation-failed
// https://docs.github.com/en/rest/overview/resources-in-the-rest-api#client-errors
// `custom` deliberately retains only its code: its meaning lives in `message`,
// which is free vendor text and must not cross the agent-facing boundary.
pub(crate) fn errors(body: &str) -> Vec<Value> {
    let Ok(body) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let Some(entries) = body.get("errors").and_then(Value::as_array) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| {
            let object = entry.as_object()?;
            // Known free-text properties are discarded; unknown shapes fail closed.
            if object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "resource" | "field" | "code" | "message" | "documentation_url"
                )
            }) {
                return None;
            }
            let resource = object.get("resource")?.as_str()?;
            let field = object.get("field")?.as_str()?;
            let code = object.get("code")?.as_str()?;
            let identifier = |s: &str| {
                !s.is_empty()
                    && s.len() <= 64
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
            };
            if !identifier(resource)
                || !identifier(field)
                || !matches!(
                    code,
                    "missing"
                        | "missing_field"
                        | "invalid"
                        | "already_exists"
                        | "unprocessable"
                        | "custom"
                )
            {
                return None;
            }
            Some(json!({"resource": resource, "field": field, "code": code}))
        })
        .take(10)
        .collect()
}
