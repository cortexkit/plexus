//! Interface for external approval decisions and execution reports.
//!
//! Production wiring leaves remote operation names unspecified: without a
//! configured decision service, high-severity calls are refused. Tests and local
//! harnesses can enable an in-process stub with the `test-support` feature.

#[cfg(any(test, feature = "test-support"))]
use std::collections::VecDeque;
#[cfg(any(test, feature = "test-support"))]
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::governance::Severity;
use crate::jcs::{self, JcsError};
use crate::manifest::Risk;

/// Errors from the decision-plane seam (local verification or peer failure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionPlaneError {
    /// Local recomputation of `grant_hash` disagreed with the peer's claim.
    GrantHashMismatch { expected: String, received: String },
    /// JCS canonicalization failed while building or verifying a hash.
    Canonicalization(String),
    /// The peer rejected or could not process the request.
    Peer(String),
}

impl std::fmt::Display for DecisionPlaneError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GrantHashMismatch { expected, received } => write!(
                formatter,
                "grant_hash mismatch: expected {expected}, received {received}"
            ),
            Self::Canonicalization(reason) => {
                write!(
                    formatter,
                    "decision-plane canonicalization failed: {reason}"
                )
            }
            Self::Peer(reason) => write!(formatter, "decision-plane peer error: {reason}"),
        }
    }
}

impl std::error::Error for DecisionPlaneError {}

impl From<JcsError> for DecisionPlaneError {
    fn from(error: JcsError) -> Self {
        Self::Canonicalization(error.to_string())
    }
}

/// Envelope handed to the decision plane for an S3/S4 invoke.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionEnvelope {
    pub acting_principal: String,
    /// Fingerprint of the connection identity — never a credential handle.
    pub connection_fingerprint: String,
    pub app_key: String,
    pub action: String,
    pub risk: Risk,
    pub severity: Severity,
    pub args_snapshot: Value,
    pub args_snapshot_hash: String,
    pub schema_hash: String,
    pub reversibility_class: String,
    /// Stable logical-write id (`action_request` row id).
    pub intent_id: String,
    pub requested_at_ms: i64,
}

/// Verdict returned by the decision plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Allow {
        decision_id: String,
        grant_hash: String,
    },
    Deny {
        reason: String,
    },
    NeedsQuorum {
        decision_id: String,
    },
}

/// Terminal outcome reported back for a decision-authorized invoke.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutcomeTerminal {
    Executed {
        outcome_ref: String,
    },
    Refused {
        reason: String,
    },
    Expired,
    /// Honest unknown: the vendor may have acted; the decision plane burns the grant.
    OutcomeUnknown {
        outcome_ref: String,
    },
}

/// Mandatory report leg keyed on `decision_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeReport {
    pub decision_id: String,
    pub terminal: OutcomeTerminal,
}

/// Trait seam for the external decision plane. No wire binding in this crate.
pub trait DecisionPlane: Send + Sync {
    fn request_verdict(&self, envelope: &DecisionEnvelope) -> Result<Verdict, DecisionPlaneError>;

    fn report_outcome(&self, report: &OutcomeReport) -> Result<(), DecisionPlaneError>;
}

/// Inputs required to compute the contract `grant_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantHashInput<'a> {
    pub decision_id: &'a str,
    pub app_key: &'a str,
    pub action: &'a str,
    pub args_snapshot_hash: &'a str,
    pub schema_hash: &'a str,
}

/// Strict-JCS SHA-256 over
/// `{decision_id, app_key, action, args_snapshot_hash, schema_hash}`.
pub fn compute_grant_hash(input: GrantHashInput<'_>) -> Result<String, JcsError> {
    let value = json!({
        "decision_id": input.decision_id,
        "app_key": input.app_key,
        "action": input.action,
        "args_snapshot_hash": input.args_snapshot_hash,
        "schema_hash": input.schema_hash,
    });
    jcs::jcs_sha256(&value)
}

/// Verify a peer-supplied grant hash against a local recomputation.
pub fn verify_grant_hash(
    input: GrantHashInput<'_>,
    received: &str,
) -> Result<(), DecisionPlaneError> {
    let expected = compute_grant_hash(input)?;
    if expected != received {
        return Err(DecisionPlaneError::GrantHashMismatch {
            expected,
            received: received.to_string(),
        });
    }
    Ok(())
}

/// Map action risk onto the advisory reversibility class sent with the envelope.
pub fn reversibility_class_for_risk(risk: Risk) -> &'static str {
    match risk {
        Risk::Read => "high",
        Risk::Write => "medium",
        Risk::Destructive => "low",
    }
}

/// Configurable in-process decision plane for harness assertions.
#[derive(Clone, Default)]
#[cfg(any(test, feature = "test-support"))]
pub struct StubDecisionPlane {
    inner: Arc<Mutex<StubDecisionPlaneState>>,
}

#[derive(Default)]
#[cfg(any(test, feature = "test-support"))]
struct StubDecisionPlaneState {
    /// FIFO verdicts returned by `request_verdict`. When empty, defaults to Allow.
    verdicts: VecDeque<Result<Verdict, DecisionPlaneError>>,
    /// Optional forced grant_hash override on Allow (for mismatch tests).
    force_grant_hash: Option<String>,
    /// Fail the next N outcome reports before succeeding.
    report_failures_remaining: usize,
    envelopes: Vec<DecisionEnvelope>,
    reports: Vec<OutcomeReport>,
    next_decision_seq: u64,
}

#[cfg(any(test, feature = "test-support"))]
impl StubDecisionPlane {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_verdict(&self, verdict: Verdict) {
        if let Ok(mut state) = self.inner.lock() {
            state.verdicts.push_back(Ok(verdict));
        }
    }

    pub fn push_error(&self, error: DecisionPlaneError) {
        if let Ok(mut state) = self.inner.lock() {
            state.verdicts.push_back(Err(error));
        }
    }

    /// Force the next Allow path to claim this grant_hash (mismatch harness).
    pub fn force_next_grant_hash(&self, grant_hash: impl Into<String>) {
        if let Ok(mut state) = self.inner.lock() {
            state.force_grant_hash = Some(grant_hash.into());
        }
    }

    pub fn fail_next_reports(&self, count: usize) {
        if let Ok(mut state) = self.inner.lock() {
            state.report_failures_remaining = count;
        }
    }

    pub fn envelopes(&self) -> Vec<DecisionEnvelope> {
        self.inner
            .lock()
            .map(|state| state.envelopes.clone())
            .unwrap_or_default()
    }

    pub fn reports(&self) -> Vec<OutcomeReport> {
        self.inner
            .lock()
            .map(|state| state.reports.clone())
            .unwrap_or_default()
    }

    pub fn clear(&self) {
        if let Ok(mut state) = self.inner.lock() {
            state.envelopes.clear();
            state.reports.clear();
            state.verdicts.clear();
            state.force_grant_hash = None;
            state.report_failures_remaining = 0;
        }
    }

    fn mint_decision_id(state: &mut StubDecisionPlaneState) -> String {
        state.next_decision_seq = state.next_decision_seq.saturating_add(1);
        format!("dec_org_{:08x}", state.next_decision_seq)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl DecisionPlane for StubDecisionPlane {
    fn request_verdict(&self, envelope: &DecisionEnvelope) -> Result<Verdict, DecisionPlaneError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| DecisionPlaneError::Peer("stub lock poisoned".to_string()))?;
        state.envelopes.push(envelope.clone());

        let queued = state.verdicts.pop_front();
        let decision_id = Self::mint_decision_id(&mut state);

        let verdict = match queued {
            Some(result) => result?,
            None => {
                let grant_hash = compute_grant_hash(GrantHashInput {
                    decision_id: &decision_id,
                    app_key: &envelope.app_key,
                    action: &envelope.action,
                    args_snapshot_hash: &envelope.args_snapshot_hash,
                    schema_hash: &envelope.schema_hash,
                })?;
                Verdict::Allow {
                    decision_id: decision_id.clone(),
                    grant_hash,
                }
            }
        };

        match verdict {
            Verdict::Allow {
                decision_id: existing_id,
                grant_hash: _,
            } => {
                let id = if existing_id.is_empty() {
                    decision_id
                } else {
                    existing_id
                };
                // The override is taken only here, once the verdict is known to
                // be an Allow: a Deny, quorum or error verdict queued ahead of it
                // must leave it armed for the Allow it was meant for.
                let grant_hash = if let Some(forced) = state.force_grant_hash.take() {
                    forced
                } else {
                    compute_grant_hash(GrantHashInput {
                        decision_id: &id,
                        app_key: &envelope.app_key,
                        action: &envelope.action,
                        args_snapshot_hash: &envelope.args_snapshot_hash,
                        schema_hash: &envelope.schema_hash,
                    })?
                };
                Ok(Verdict::Allow {
                    decision_id: id,
                    grant_hash,
                })
            }
            Verdict::NeedsQuorum {
                decision_id: existing_id,
            } => {
                let id = if existing_id.is_empty() {
                    decision_id
                } else {
                    existing_id
                };
                Ok(Verdict::NeedsQuorum { decision_id: id })
            }
            other => Ok(other),
        }
    }

    fn report_outcome(&self, report: &OutcomeReport) -> Result<(), DecisionPlaneError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| DecisionPlaneError::Peer("stub lock poisoned".to_string()))?;
        if state.report_failures_remaining > 0 {
            state.report_failures_remaining -= 1;
            return Err(DecisionPlaneError::Peer(
                "injected report failure".to_string(),
            ));
        }
        state.reports.push(report.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_hash_is_order_independent_over_object_keys() {
        let left = compute_grant_hash(GrantHashInput {
            decision_id: "dec_org_1",
            app_key: "notion",
            action: "create_page",
            args_snapshot_hash: "sha256:abc",
            schema_hash: "sha256:def",
        })
        .expect("hash");
        let right = jcs::jcs_sha256(&json!({
            "schema_hash": "sha256:def",
            "action": "create_page",
            "args_snapshot_hash": "sha256:abc",
            "decision_id": "dec_org_1",
            "app_key": "notion",
        }))
        .expect("hash");
        assert_eq!(left, right);
    }

    #[test]
    fn verify_grant_hash_rejects_mismatch() {
        let err = verify_grant_hash(
            GrantHashInput {
                decision_id: "dec_org_1",
                app_key: "notion",
                action: "create_page",
                args_snapshot_hash: "sha256:abc",
                schema_hash: "sha256:def",
            },
            "sha256:deadbeef",
        )
        .expect_err("mismatch");
        assert!(matches!(err, DecisionPlaneError::GrantHashMismatch { .. }));
    }

    fn sample_envelope() -> DecisionEnvelope {
        DecisionEnvelope {
            acting_principal: "principal".into(),
            connection_fingerprint: "ckfp_000000000000".into(),
            app_key: "notion".into(),
            action: "create_page".into(),
            risk: Risk::Write,
            severity: Severity::S3,
            args_snapshot: json!({}),
            args_snapshot_hash: "sha256:abc".into(),
            schema_hash: "sha256:def".into(),
            reversibility_class: "medium".into(),
            intent_id: "req_1".into(),
            requested_at_ms: 1,
        }
    }

    /// A forced grant hash is meant for the next Allow. Verdicts that are not
    /// an Allow (a queued Deny, a quorum request, a peer error) must not use it
    /// up, or the Allow it was armed for silently carries the honest hash and a
    /// mismatch scenario stops testing anything.
    #[test]
    fn forced_grant_hash_survives_non_allow_verdicts_until_the_next_allow() {
        let plane = StubDecisionPlane::new();
        plane.force_next_grant_hash("sha256:forced");
        plane.push_verdict(Verdict::Deny {
            reason: "no".into(),
        });
        plane.push_verdict(Verdict::NeedsQuorum {
            decision_id: String::new(),
        });
        plane.push_error(DecisionPlaneError::Peer("down".into()));
        let envelope = sample_envelope();
        assert!(matches!(
            plane.request_verdict(&envelope),
            Ok(Verdict::Deny { .. })
        ));
        assert!(matches!(
            plane.request_verdict(&envelope),
            Ok(Verdict::NeedsQuorum { .. })
        ));
        assert!(plane.request_verdict(&envelope).is_err());
        match plane.request_verdict(&envelope) {
            Ok(Verdict::Allow { grant_hash, .. }) => assert_eq!(
                grant_hash, "sha256:forced",
                "the override must reach the first Allow, not be consumed by earlier verdicts"
            ),
            other => panic!("expected an Allow, got {other:?}"),
        }
        // Used once, then gone.
        match plane.request_verdict(&envelope) {
            Ok(Verdict::Allow { grant_hash, .. }) => assert_ne!(grant_hash, "sha256:forced"),
            other => panic!("expected an Allow, got {other:?}"),
        }
    }
}
