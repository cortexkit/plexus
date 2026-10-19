//! First-match outcome classification. Vendor diagnostics never leave this module.

use super::*;
use crate::governance::DispatchOutcome;

pub(super) const UNAVAILABLE_COOLDOWN_MS: u64 = 60_000;
pub(super) const CREDENTIAL_COOLDOWN_MS: u64 = 60_000;
pub(super) const THROTTLED_COOLDOWN_MS: u64 = 60_000;
pub(super) const QUOTA_COOLDOWN_MS: u64 = 3_600_000;
pub(super) const MAX_THROTTLED_COOLDOWN_MS: u64 = 3_600_000;

pub(super) enum Classified {
    Serve(Vec<WebSearchResult>),
    Reject,
    MoveOn {
        reason: SkipReason,
        cooldown_ms: u64,
    },
}

/// Only a private transport classification may supply this signal. Error
/// messages are redacted before dispatch returns and must never be unredacted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum QuotaSignal {
    Absent,
    // The transport does not expose this signal yet; keep its classification
    // separate from caller-facing diagnostics when that seam becomes available.
    #[allow(dead_code)]
    Exhausted,
}

pub(super) fn classify(
    backend: &dyn WebSearchBackend,
    dispatched: &DispatchOutcome,
    quota_signal: QuotaSignal,
    max_results: usize,
    fetched_at_ms: i64,
) -> Classified {
    let (code, mcp_error) = match &dispatched.outcome {
        TransportOutcome::Completed {
            response: Some(body),
        } => {
            if body.get("isError").and_then(Value::as_bool) == Some(true) {
                (None, true)
            } else {
                return match backend.map_reply(body, max_results, fetched_at_ms) {
                    Ok(results) => Classified::Serve(results),
                    Err(_) => Classified::MoveOn {
                        reason: SkipReason::Unavailable,
                        cooldown_ms: UNAVAILABLE_COOLDOWN_MS,
                    },
                };
            }
        }
        TransportOutcome::VendorFailed { code, .. } | TransportOutcome::NotSent { code, .. } => {
            (Some(code.as_str()), code.starts_with("mcp_"))
        }
        _ => (None, false),
    };
    let status = code.and_then(|code| code.strip_prefix("http_")?.parse::<u16>().ok());
    // Request errors stop the walk before any body inspection or retry hint.
    if matches!(status, Some(400 | 422)) {
        return Classified::Reject;
    }
    let throttled = code == Some("throttled") || status == Some(429);
    if let Some(retry_after_ms) = dispatched
        .retry_after_ms
        .filter(|_| throttled || matches!(dispatched.outcome, TransportOutcome::NotSent { .. }))
    {
        return Classified::MoveOn {
            reason: SkipReason::Throttled,
            cooldown_ms: retry_after_ms.min(MAX_THROTTLED_COOLDOWN_MS),
        };
    }
    if throttled {
        return Classified::MoveOn {
            reason: SkipReason::Throttled,
            cooldown_ms: THROTTLED_COOLDOWN_MS,
        };
    }
    if status == Some(402)
        || ((matches!(status, Some(400..=499)) && status != Some(401) || mcp_error)
            && quota_signal == QuotaSignal::Exhausted)
    {
        return Classified::MoveOn {
            reason: SkipReason::Quota,
            cooldown_ms: QUOTA_COOLDOWN_MS,
        };
    }
    if status == Some(401) {
        return Classified::MoveOn {
            reason: SkipReason::Credential,
            cooldown_ms: CREDENTIAL_COOLDOWN_MS,
        };
    }
    Classified::MoveOn {
        reason: SkipReason::Unavailable,
        cooldown_ms: UNAVAILABLE_COOLDOWN_MS,
    }
}

#[cfg(test)]
mod tests;
