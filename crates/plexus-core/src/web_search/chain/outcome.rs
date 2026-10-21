//! Classification consumes fixed transport signals, never raw vendor diagnostics.

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

pub(super) fn classify(
    backend: &dyn WebSearchBackend,
    dispatched: &DispatchOutcome,
    max_results: usize,
    fetched_at_ms: i64,
) -> Classified {
    let code = match &dispatched.outcome {
        TransportOutcome::Completed {
            response: Some(body),
        } => {
            if body.get("isError").and_then(Value::as_bool) == Some(true) {
                None
            } else {
                return match backend.map_reply(body, max_results, fetched_at_ms) {
                    Ok(results) => Classified::Serve(crate::web_search::backend::sanitize_results(results)),
                    Err(_) => Classified::MoveOn {
                        reason: SkipReason::Unavailable,
                        cooldown_ms: UNAVAILABLE_COOLDOWN_MS,
                    },
                };
            }
        }
        TransportOutcome::VendorFailed { code, .. } | TransportOutcome::NotSent { code, .. } => {
            Some(code.as_str())
        }
        _ => None,
    };
    let status = code.and_then(|code| code.strip_prefix("http_")?.parse::<u16>().ok());
    // HTTP 401 is authoritative even when a manifest declares a different signal.
    if status == Some(401) || code == Some("handle_credential_rejected") {
        return Classified::MoveOn {
            reason: SkipReason::Credential,
            cooldown_ms: CREDENTIAL_COOLDOWN_MS,
        };
    }
    if let Some(signal) = dispatched.error_signal {
        use crate::manifest::ErrorSignal;
        return match signal {
            ErrorSignal::QuotaExhausted => Classified::MoveOn {
                reason: SkipReason::Quota,
                cooldown_ms: QUOTA_COOLDOWN_MS,
            },
            ErrorSignal::CredentialRejected => Classified::MoveOn {
                reason: SkipReason::Credential,
                cooldown_ms: CREDENTIAL_COOLDOWN_MS,
            },
            ErrorSignal::NoResults => Classified::Serve(Vec::new()),
        };
    }
    // Undeclared request errors still stop the walk before any retry hint.
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
        || status.is_some_and(|status| backend.exhausted_statuses().contains(&status))
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
