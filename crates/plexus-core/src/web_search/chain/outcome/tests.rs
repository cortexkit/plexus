use super::*;
use crate::transport::{Retryability, TransmissionState};

fn dispatch(outcome: TransportOutcome, retry_after_ms: Option<u64>) -> DispatchOutcome {
    DispatchOutcome {
        reservation_id: "fixture".into(),
        reconciliation: None,
        transmission: TransmissionState::Sent,
        retryability: Retryability::Terminal,
        retry_after_ms,
        outcome,
    }
}

fn failed(code: &str, message: &str) -> TransportOutcome {
    TransportOutcome::VendorFailed {
        code: code.into(),
        message: message.into(),
    }
}

fn classify_fixture(outcome: TransportOutcome, retry: Option<u64>) -> Classified {
    classify(
        &ExaRestBackend,
        &dispatch(outcome, retry),
        QuotaSignal::Absent,
        5,
        1_790_000_000_000,
    )
}

fn assert_move(outcome: TransportOutcome, retry: Option<u64>, reason: SkipReason, duration: u64) {
    let Classified::MoveOn {
        reason: actual,
        cooldown_ms,
    } = classify_fixture(outcome, retry)
    else {
        panic!("expected a failed attempt")
    };
    assert_eq!((actual, cooldown_ms), (reason, duration));
}

#[test]
fn completed_with_results_serves() {
    let Classified::Serve(results) = classify_fixture(
        TransportOutcome::Completed {
            response: Some(
                json!({"results":[{"url":"https://example.org", "title":"News", "text":"report"}]}),
            ),
        },
        None,
    ) else {
        panic!("expected results")
    };
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "https://example.org");
}

#[test]
fn completed_empty_serves() {
    let Classified::Serve(results) = classify_fixture(
        TransportOutcome::Completed {
            response: Some(json!({"results":[]})),
        },
        None,
    ) else {
        panic!("expected empty success")
    };
    assert!(results.is_empty());
}

#[test]
fn request_rejection_precedes_quota_and_retry() {
    for code in ["http_400", "http_422"] {
        assert!(matches!(
            classify_fixture(failed(code, "credits quota insufficient balance"), Some(30)),
            Classified::Reject
        ));
    }
}

#[test]
fn throttled_retry_is_capped_and_not_sent_retry_is_throttled() {
    for code in ["throttled", "http_429"] {
        assert_move(
            failed(code, "quota"),
            Some(u64::MAX),
            SkipReason::Throttled,
            3_600_000,
        );
        assert_move(
            failed(code, "quota"),
            Some(2_500),
            SkipReason::Throttled,
            2_500,
        );
    }
    assert_move(
        TransportOutcome::NotSent {
            code: "transport_transient".into(),
            message: "quota".into(),
        },
        Some(7_000),
        SkipReason::Throttled,
        7_000,
    );
}

#[test]
fn throttled_without_retry_uses_one_minute() {
    assert_move(
        failed("throttled", "quota"),
        None,
        SkipReason::Throttled,
        60_000,
    );
}

#[test]
fn quota_signal_matches_only_eligible_errors() {
    assert_move(
        failed("http_402", "payment required"),
        None,
        SkipReason::Quota,
        3_600_000,
    );
    for outcome in [
        failed("http_403", "redacted"),
        failed("http_409", "redacted"),
        failed("mcp_tool_error", "redacted"),
        TransportOutcome::Completed {
            response: Some(json!({"isError":true, "content":[]})),
        },
    ] {
        assert!(matches!(
            classify(
                &ExaRestBackend,
                &dispatch(outcome, None),
                QuotaSignal::Exhausted,
                5,
                0
            ),
            Classified::MoveOn {
                reason: SkipReason::Quota,
                cooldown_ms: 3_600_000
            }
        ));
    }
    for (code, reason) in [
        ("http_400", None),
        ("http_422", None),
        ("http_429", Some(SkipReason::Throttled)),
        ("http_401", Some(SkipReason::Credential)),
        ("http_500", Some(SkipReason::Unavailable)),
    ] {
        let classified = classify(
            &ExaRestBackend,
            &dispatch(failed(code, "redacted"), None),
            QuotaSignal::Exhausted,
            5,
            0,
        );
        match reason {
            None => assert!(matches!(classified, Classified::Reject)),
            Some(expected) => assert!(
                matches!(classified, Classified::MoveOn { reason, .. } if reason == expected)
            ),
        }
    }
    assert_move(
        failed("http_403", "quota"),
        None,
        SkipReason::Unavailable,
        60_000,
    );
}

#[test]
fn provider_declared_exhausted_statuses_are_quota() {
    use crate::web_search::backend::TavilyRestBackend;
    let classified = |backend: &dyn WebSearchBackend, code: &str| match classify(
        backend,
        &dispatch(failed(code, "redacted"), None),
        QuotaSignal::Absent,
        5,
        0,
    ) {
        Classified::MoveOn {
            reason,
            cooldown_ms,
        } => (reason, cooldown_ms),
        _ => panic!("expected a failed attempt for {code}"),
    };
    for code in ["http_432", "http_433"] {
        assert_eq!(
            classified(&TavilyRestBackend, code),
            (SkipReason::Quota, 3_600_000),
            "a status the provider declares as exhausted is quota, like 402"
        );
        assert_eq!(
            classified(&ExaRestBackend, code),
            (SkipReason::Unavailable, 60_000),
            "the same status from a provider that does not declare it is another client error"
        );
    }
    // Declaring exhaustion statuses leaves every other status where it was.
    assert_eq!(
        classified(&TavilyRestBackend, "http_402"),
        (SkipReason::Quota, 3_600_000)
    );
    assert_eq!(
        classified(&TavilyRestBackend, "http_401"),
        (SkipReason::Credential, 60_000)
    );
    assert_eq!(
        classified(&TavilyRestBackend, "http_403"),
        (SkipReason::Unavailable, 60_000)
    );
    assert!(matches!(
        classify(
            &TavilyRestBackend,
            &dispatch(failed("http_400", "redacted"), None),
            QuotaSignal::Absent,
            5,
            0
        ),
        Classified::Reject
    ));
}

/// A backend that wrongly declares 401 among its exhausted statuses.
struct DeclaresCredentialStatusExhausted;

impl WebSearchBackend for DeclaresCredentialStatusExhausted {
    fn name(&self) -> &'static str {
        "exa"
    }
    fn app_key(&self) -> &'static str {
        ExaRestBackend.app_key()
    }
    fn action(&self) -> &'static str {
        ExaRestBackend.action()
    }
    fn capability(&self) -> crate::web_search::capability::WebSearchCapability {
        ExaRestBackend.capability()
    }
    fn vendor_args(&self, query: &WebSearchQuery, now_ms: i64) -> Value {
        ExaRestBackend.vendor_args(query, now_ms)
    }
    fn map_reply(
        &self,
        reply: &Value,
        max_results: usize,
        fetched_at_ms: i64,
    ) -> Result<Vec<WebSearchResult>, crate::web_search::backend::ReplyShapeError> {
        ExaRestBackend.map_reply(reply, max_results, fetched_at_ms)
    }
    fn exhausted_statuses(&self) -> &'static [u16] {
        &[401, 432]
    }
}

#[test]
fn a_declared_exhausted_401_is_still_a_credential_failure() {
    let classified = |code: &str| match classify(
        &DeclaresCredentialStatusExhausted,
        &dispatch(failed(code, "redacted"), None),
        QuotaSignal::Absent,
        5,
        0,
    ) {
        Classified::MoveOn {
            reason,
            cooldown_ms,
        } => (reason, cooldown_ms),
        _ => panic!("expected a failed attempt for {code}"),
    };
    assert_eq!(
        classified("http_401"),
        (SkipReason::Credential, 60_000),
        "a refused key stays a credential failure whatever the backend declares"
    );
    // The rest of the declaration still applies.
    assert_eq!(classified("http_432"), (SkipReason::Quota, 3_600_000));
}

#[test]
fn credential_excludes_quota_body() {
    assert_move(
        failed("http_401", "quota"),
        None,
        SkipReason::Credential,
        60_000,
    );
}

#[test]
fn forbidden_and_other_client_errors_are_unavailable() {
    for code in ["http_403", "http_404", "http_409"] {
        assert_move(
            failed(code, "permission refused"),
            None,
            SkipReason::Unavailable,
            60_000,
        );
    }
}

#[test]
fn default_errors_are_unavailable() {
    for outcome in [
        failed("http_503", "unavailable"),
        failed("timeout", "timed out"),
        TransportOutcome::NotSent {
            code: "transport_transient".into(),
            message: "no send".into(),
        },
        TransportOutcome::OutcomeUnknown,
        TransportOutcome::Completed { response: None },
        TransportOutcome::Completed {
            response: Some(json!({"malformed":true})),
        },
        failed("mcp_error", "tool failed"),
        TransportOutcome::Completed {
            response: Some(json!({"isError":true, "content":[]})),
        },
    ] {
        assert_move(outcome, None, SkipReason::Unavailable, 60_000);
    }
}

#[test]
fn zai_direct_is_error_bodies_classify_quota_without_scanning_successes() {
    let backend = crate::web_search::ZaiMcpBackend::default();
    for (body, reason, duration) in [
        (
            json!({"isError":true,"content":[{"type":"text","text":"No credits remain"}]}),
            SkipReason::Quota,
            3_600_000,
        ),
        (
            json!({"isError":true,"content":[{"type":"text","text":"Search unavailable"}]}),
            SkipReason::Unavailable,
            60_000,
        ),
    ] {
        let classified = classify(
            &backend,
            &dispatch(
                TransportOutcome::Completed {
                    response: Some(body),
                },
                None,
            ),
            QuotaSignal::Absent,
            5,
            0,
        );
        assert!(
            matches!(classified, Classified::MoveOn {reason: actual, cooldown_ms} if actual == reason && cooldown_ms == duration)
        );
    }
    assert!(
        matches!(classify(&backend, &dispatch(TransportOutcome::Completed { response:Some(json!({"results":[],"answer":"quota"})) }, None), QuotaSignal::Absent, 5, 0), Classified::Serve(results) if results.is_empty())
    );
}
