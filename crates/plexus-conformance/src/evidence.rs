//! Typed evidence records and leak-scan for harness output surfaces.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One step of the connector conformance checklist, run in declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceStep {
    Connect,
    DiscoverCatalog,
    AllowedRead,
    AskFirstWrite,
    /// Floor-S3 write path: NeedsDecisionPlane with a populated envelope.
    S3Escalation,
    DeniedCalls,
    StaleAuthorizationAbort,
    Revoke,
    AuditCompleteness,
    SecretSafety,
}

impl ConformanceStep {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::DiscoverCatalog => "discover_catalog",
            Self::AllowedRead => "allowed_read",
            Self::AskFirstWrite => "ask_first_write",
            Self::S3Escalation => "s3_escalation",
            Self::DeniedCalls => "denied_calls",
            Self::StaleAuthorizationAbort => "stale_authorization_abort",
            Self::Revoke => "revoke",
            Self::AuditCompleteness => "audit_completeness",
            Self::SecretSafety => "secret_safety",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepEvidence {
    pub step: ConformanceStep,
    pub passed: bool,
    pub detail: String,
    pub audit_row_ids: Vec<i64>,
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunEvidence {
    pub fixture: String,
    pub started_at_ms: i64,
    pub finished_at_ms: i64,
    pub passed: bool,
    pub failed_step: Option<String>,
    pub steps: Vec<StepEvidence>,
    pub audit_dump: Vec<Value>,
    pub harness_log: Vec<String>,
}

impl RunEvidence {
    pub fn new(fixture: impl Into<String>) -> Self {
        Self {
            fixture: fixture.into(),
            started_at_ms: now_ms(),
            finished_at_ms: 0,
            passed: false,
            failed_step: None,
            steps: Vec::new(),
            audit_dump: Vec::new(),
            harness_log: Vec::new(),
        }
    }

    pub fn log(&mut self, message: impl Into<String>) {
        self.harness_log.push(message.into());
    }

    pub fn finish(&mut self) {
        self.finished_at_ms = now_ms();
        self.passed = self.steps.iter().all(|step| step.passed);
        if !self.passed {
            self.failed_step = self
                .steps
                .iter()
                .find(|step| !step.passed)
                .map(|step| step.step.as_str().to_string());
        }
    }

    pub fn human_summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "fixture={} overall={}",
            self.fixture,
            if self.passed { "PASS" } else { "FAIL" }
        ));
        for step in &self.steps {
            let status = if step.passed {
                if step.skipped.is_some() {
                    "SKIP"
                } else {
                    "PASS"
                }
            } else {
                "FAIL"
            };
            lines.push(format!(
                "  [{status}] {} ({}ms) — {}",
                step.step.as_str(),
                step.duration_ms,
                step.detail
            ));
        }
        if let Some(failed) = &self.failed_step {
            lines.push(format!("failed_step={failed}"));
        }
        lines.join("\n")
    }
}

/// Text leak-scan over harness evidence surfaces. Raw handles must never appear
/// in evidence JSON, audit dumps, or harness logs. Authorization headers are
/// not part of these surfaces.
pub fn leak_scan(surfaces: &[&str], forbidden: &[&str]) -> Result<(), Vec<String>> {
    let mut hits = Vec::new();
    for surface in surfaces {
        for needle in forbidden {
            if needle.is_empty() {
                continue;
            }
            let escaped = zeroize::Zeroizing::new(
                serde_json::to_string(needle).expect("strings serialize to JSON"),
            );
            let escaped = &escaped[1..escaped.len() - 1];
            let double =
                zeroize::Zeroizing::new(serde_json::to_string(escaped).expect("strings serialize"));
            let double = &double[1..double.len() - 1];
            if surface.contains(needle) || surface.contains(escaped) || surface.contains(double) {
                hits.push(format!(
                    "forbidden pattern present in evidence surface (len={})",
                    needle.len()
                ));
            }
        }
    }
    if hits.is_empty() {
        Ok(())
    } else {
        Err(hits)
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or(0)
}

pub fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[test]
fn elapsed_time_is_measured_from_a_monotonic_start() {
    let started = Instant::now() - std::time::Duration::from_millis(125);
    assert!(
        elapsed_ms(started) >= 125,
        "duration must come from the monotonic clock"
    );
}

/// Common wire encodings of the exact bytes served, including binary payloads.
pub(crate) fn secret_variants(bytes: &[u8]) -> Vec<zeroize::Zeroizing<String>> {
    use zeroize::Zeroizing;
    if bytes.is_empty() {
        return Vec::new();
    }
    let mut variants = Vec::new();
    if let Ok(text) = std::str::from_utf8(bytes) {
        variants.push(Zeroizing::new(text.to_owned()));
    }
    variants.push(Zeroizing::new(hex::encode(bytes)));
    variants.push(Zeroizing::new(hex::encode_upper(bytes)));
    let percent: String = bytes.iter().map(|byte| format!("%{byte:02X}")).collect();
    variants.push(Zeroizing::new(percent.to_ascii_lowercase()));
    variants.push(Zeroizing::new(percent));
    let selective: String = bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(byte) {
                char::from(*byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect();
    variants.push(Zeroizing::new(selective.replace("%20", "+")));
    variants.push(Zeroizing::new(selective));
    let encoded = Zeroizing::new(base64_encode(bytes));
    variants.push(Zeroizing::new(encoded.trim_end_matches('=').to_owned()));
    variants.push(Zeroizing::new(
        encoded
            .replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('=')
            .to_owned(),
    ));
    variants.push(Zeroizing::new(encoded.replace('+', "-").replace('/', "_")));
    variants.push(encoded);
    variants.push(Zeroizing::new(
        serde_json::to_string(bytes).expect("byte array serializes"),
    ));
    variants
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for shift in [18, 12, 6, 0] {
            encoded.push(char::from(TABLE[((n >> shift) & 63) as usize]));
        }
        if chunk.len() < 3 {
            encoded.pop();
            encoded.push('=');
        }
        if chunk.len() < 2 {
            let end = encoded.len();
            encoded.replace_range(end - 2..end - 1, "=");
        }
    }
    encoded
}

#[test]
fn encoded_binary_secrets_are_scanned_without_lossy_conversion() {
    let variants = secret_variants(&[0xff, 0x00, 0x81, 0x20]);
    let needles: Vec<_> = variants.iter().map(|text| text.as_str()).collect();
    for surface in [
        "/wCBIA==",
        "_wCBIA",
        "ff008120",
        "%FF%00%81%20",
        "[255,0,129,32]",
    ] {
        assert!(
            leak_scan(&[surface], &needles).is_err(),
            "encoded binary secret was missed: {surface}"
        );
    }
}

#[test]
fn escaped_secrets_are_detected_in_json_evidence() {
    for secret in [
        "token\"suffix",
        "token\\suffix",
        "token\nsuffix",
        "token\tsuffix",
    ] {
        let surface = serde_json::to_string(&serde_json::json!({"nested":[secret]})).unwrap();
        assert!(
            leak_scan(&[&surface], &[secret]).is_err(),
            "JSON escaping must not hide a secret"
        );
    }
    assert!(leak_scan(&["safe evidence"], &["token\"suffix"]).is_ok());
}
