//! Configuration for the GitHub facade receipt lease.
use crate::github::receipt::{DEFAULT_CLAIM_LEASE_SECONDS, MIN_CLAIM_LEASE_SECONDS};

pub fn claim_lease_seconds(value: Option<i64>) -> i64 {
    value
        .unwrap_or(DEFAULT_CLAIM_LEASE_SECONDS)
        .max(MIN_CLAIM_LEASE_SECONDS)
}
