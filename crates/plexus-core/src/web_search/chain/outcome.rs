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

/// Whether a provider's failed reply said its quota or credit is used up, for a
/// provider that reports that with a status other than 402. Only the HTTP
/// transport may set this, from the raw reply, because the error text this
/// classifier receives has already had vendor wording removed; recovering the
/// signal by reading that text is not possible and must not be attempted.
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
    // MCP transport diagnostics have already discarded vendor prose. A fixed
    // code preserves its quota observation; direct isError bodies are still
    // available here and must be inspected before mapping ordinary results.
    let mcp_quota = code == Some("mcp_quota_exhausted")
        || (mcp_error
            && matches!(&dispatched.outcome, TransportOutcome::Completed { response: Some(body) }
                if crate::mcp_remote::names_exhausted_quota(body)));
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
    // A refused key is decided before any quota rule, so no backend's
    // exhausted-status list can turn a 401 into a quota skip.
    if status == Some(401) {
        return Classified::MoveOn {
            reason: SkipReason::Credential,
            cooldown_ms: CREDENTIAL_COOLDOWN_MS,
        };
    }
    if status == Some(402)
        || mcp_quota
        || status.is_some_and(|status| backend.exhausted_statuses().contains(&status))
        || ((matches!(status, Some(400..=499)) && status != Some(401) || mcp_error)
            && quota_signal == QuotaSignal::Exhausted)
    {
        return Classified::MoveOn {
            reason: SkipReason::Quota,
            cooldown_ms: QUOTA_COOLDOWN_MS,
        };
    }
    Classified::MoveOn {
        reason: SkipReason::Unavailable,
        cooldown_ms: UNAVAILABLE_COOLDOWN_MS,
    }
}

#[cfg(test)]
mod tests;
