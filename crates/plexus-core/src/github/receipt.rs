//! Durable, nonce-keyed progress for ordered GitHub write effects.
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Effect {
    pub effect: String,
    pub dispatch_attempted_at: Option<i64>,
    pub request_id: Option<String>,
    pub outcome: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub agent_id: String,
    pub request_nonce: String,
    pub request_fingerprint: String,
    pub state: String,
    pub claim_owner: Option<String>,
    pub claim_lease_expires_at: Option<i64>,
    pub authority_baseline: Value,
    pub effects: Vec<Effect>,
    pub action_request_id: Option<String>,
    pub outcome: Option<Value>,
    pub refusal_code: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    Owned(Receipt),
    InFlight,
    PayloadMismatch,
    Replay(Receipt),
    Unknown(Receipt),
    PendingApproval(Receipt),
}

/// How long a claim on a nonce is held when the caller does not ask for a
/// different lease.
pub const DEFAULT_CLAIM_LEASE_SECONDS: i64 = 120;
/// The GitHub request shim may retry a nonce up to 20 seconds after the first
/// write. A lease is never shorter than this 60-second floor and never ends
/// sooner than 60 seconds after the nonce's first claim, so another owner
/// cannot take over while those retries are active.
pub const MIN_CLAIM_LEASE_SECONDS: i64 = 60;
pub const RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;

pub fn lease_expires_at(first_claim_ms: i64, now_ms: i64, seconds: i64) -> i64 {
    now_ms
        .saturating_add(seconds.max(MIN_CLAIM_LEASE_SECONDS).saturating_mul(1000))
        .max(first_claim_ms.saturating_add(MIN_CLAIM_LEASE_SECONDS * 1000))
}

/// Uncertain effects cannot be retried without a read-back reconciliation.
pub fn has_uncertain_effect(receipt: &Receipt) -> bool {
    receipt
        .effects
        .iter()
        .any(|effect| effect.dispatch_attempted_at.is_some() && effect.outcome.is_none())
}
