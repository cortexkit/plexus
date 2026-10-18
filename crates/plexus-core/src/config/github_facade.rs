//! Configuration for the GitHub facade receipt lease.
pub const CLAIM_LEASE_SECONDS: i64 = crate::github::receipt::DEFAULT_CLAIM_LEASE_SECONDS;

#[cfg(any(test, feature = "test-support"))]
pub fn claim_lease_seconds(value: Option<i64>) -> i64 {
    value
        .unwrap_or(CLAIM_LEASE_SECONDS)
        .max(crate::github::receipt::MIN_CLAIM_LEASE_SECONDS)
}
