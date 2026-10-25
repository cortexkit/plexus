//! Caller-pinned bot authority, separate from the GitHub request payload.
use super::request_map::MappedRequest;
use serde_json::{json, Value};

pub(super) struct Expectation {
    pub app_handle_id: String,
    pub repo_binding_generation: u64,
}

impl Expectation {
    pub fn parse(value: &Value) -> Result<Self, String> {
        let invalid = |field: &str| field.to_owned();
        let object = value.as_object().ok_or_else(|| invalid("expect"))?;
        for field in object.keys() {
            if !matches!(field.as_str(), "app_handle_id" | "repo_binding_generation") {
                return Err(invalid(&format!("expect.{field}")));
            }
        }
        let app_handle_id = object
            .get("app_handle_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("expect.app_handle_id"))?
            .to_owned();
        let repo_binding_generation = object
            .get("repo_binding_generation")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("expect.repo_binding_generation"))?;
        Ok(Self {
            app_handle_id,
            repo_binding_generation,
        })
    }

    pub fn fingerprint(&self, mapped: &mut MappedRequest) {
        // Only callers that supply an expectation enter this hash domain. The
        // legacy request-only fingerprint remains byte-for-byte unchanged.
        let mut exact = json!({
            "request": mapped.canonical,
            "expect": {
                "app_handle_id": self.app_handle_id,
                "repo_binding_generation": self.repo_binding_generation,
            },
        });
        exact.sort_all_objects();
        mapped.fingerprint = format!(
            "exact-json-expect-v1:{}",
            crate::jcs::sha256_hex(exact.to_string().as_bytes())
        );
    }
}
