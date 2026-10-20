//! Transport seam and deterministic MockTransport for the substrate harness.
//!
//! The mock records a redacted request projection. The authorization header is
//! accepted as the one intentional secret sink, but it is kept in a separate
//! test-only inspection channel rather than in the request projection.

#[cfg(any(test, feature = "test-support"))]
use std::collections::{HashMap, VecDeque};
#[cfg(any(test, feature = "test-support"))]
use std::sync::{Arc, Mutex};

#[cfg(any(test, feature = "test-support"))]
use serde_json::Map;
use serde_json::Value;

use crate::credentials::ResolvedCredential;
#[cfg(any(test, feature = "test-support"))]
use crate::fingerprint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransmissionState {
    NotSent,
    /// The request was sent and has a definitive response, successful or not.
    Sent,
    OutcomeUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retryability {
    Terminal,
    AutoRetryable,
    Throttle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportRequest {
    pub request_id: String,
    pub connection_id: String,
    pub action: String,
    pub args: Value,
    pub credential_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TransportResponse {
    pub transmission: TransmissionState,
    pub retryability: Retryability,
    pub response: Option<Value>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub vendor_request_id: Option<String>,
    /// Route-plane success provenance. This stays absent for direct vendor transports.
    pub served_from: Option<String>,
    /// Epoch milliseconds when a route-plane adapter observed the response.
    pub observed_at_ms: Option<u64>,
    /// Adapter-supplied cooldown remaining before a request may be retried.
    pub retry_after_ms: Option<u64>,
    /// Fixed manifest-declared signal; never raw vendor diagnostics.
    pub error_signal: Option<crate::manifest::ErrorSignal>,
}

impl TransportResponse {
    /// Return the provider HTTP status encoded by an auth rejection without
    /// exposing any vendor response body. Without a reviewed credential signal,
    /// treat HTTP 403 as a permission refusal; it does not establish that the
    /// credential was rejected.
    pub fn provider_auth_status(&self) -> Option<u16> {
        if self.error_signal == Some(crate::manifest::ErrorSignal::CredentialRejected) {
            return Some(401);
        }
        let code = self.error_code.as_deref()?;
        code.strip_prefix("http_")
            .and_then(|status| status.parse::<u16>().ok())
            .filter(|status| *status == 401)
    }

    pub fn success(response: Value) -> Self {
        Self {
            transmission: TransmissionState::Sent,
            retryability: Retryability::Terminal,
            response: Some(response),
            error_code: None,
            error_message: None,
            vendor_request_id: None,
            served_from: None,
            observed_at_ms: None,
            retry_after_ms: None,
            error_signal: None,
        }
    }

    pub(crate) fn not_sent(mut self) -> Self {
        self.transmission = TransmissionState::NotSent;
        self
    }

    pub(crate) fn with_error_signal(
        mut self,
        signal: Option<crate::manifest::ErrorSignal>,
    ) -> Self {
        self.error_signal = signal;
        self
    }

    pub(crate) fn timeout(protocol: &str) -> Self {
        let mut response = Self::unknown();
        response.error_code = Some("timeout".to_string());
        response.error_message = Some(format!("{protocol} request timed out"));
        response
    }

    pub fn vendor_error(code: &str, message: &str) -> Self {
        Self {
            transmission: TransmissionState::Sent,
            retryability: Retryability::Terminal,
            response: None,
            error_code: Some(code.to_string()),
            error_message: Some(sanitize_message(message)),
            vendor_request_id: None,
            served_from: None,
            observed_at_ms: None,
            retry_after_ms: None,
            error_signal: None,
        }
    }

    pub fn unknown() -> Self {
        Self::unknown_with_error("outcome_unknown", "vendor response was not definitive")
    }

    pub fn unknown_with_error(code: &str, message: &str) -> Self {
        Self {
            transmission: TransmissionState::OutcomeUnknown,
            retryability: Retryability::Terminal,
            response: None,
            error_code: Some(code.to_string()),
            error_message: Some(sanitize_message(message)),
            vendor_request_id: None,
            served_from: None,
            observed_at_ms: None,
            retry_after_ms: None,
            error_signal: None,
        }
    }

    pub fn transient_not_sent(message: &str) -> Self {
        Self {
            transmission: TransmissionState::NotSent,
            retryability: Retryability::AutoRetryable,
            response: None,
            error_code: Some("transport_transient".to_string()),
            error_message: Some(sanitize_message(message)),
            vendor_request_id: None,
            served_from: None,
            observed_at_ms: None,
            retry_after_ms: None,
            error_signal: None,
        }
    }
}

/// Transport implementations receive a resolved credential only for the
/// duration of the call. Implementations must not retain it.
pub trait Transport: Send + Sync {
    /// Facade-only dispatch; non-REST transports retain their ordinary behavior.
    fn dispatch_github_facade(
        &self,
        request: TransportRequest,
        credential: &ResolvedCredential,
    ) -> TransportResponse {
        self.dispatch(request, credential)
    }

    fn dispatch(
        &self,
        request: TransportRequest,
        credential: &ResolvedCredential,
    ) -> TransportResponse;
}

/// Run a synchronous route request on its peer's existing runtime, without
/// nesting runtimes or creating an OS thread for every call. A panicking or
/// cancelled task drops the sender, allowing the caller to classify the outcome.
pub(crate) fn wait_on_runtime<F, T>(
    runtime: &std::sync::Arc<tokio::runtime::Runtime>,
    future: F,
) -> Result<T, ()>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    runtime.spawn(async move {
        let _ = send.send(future.await);
    });
    receive.recv().map_err(|_| ())
}

#[derive(Debug, Clone)]
#[cfg(any(test, feature = "test-support"))]
pub enum MockResponse {
    Success(Value),
    VendorError {
        code: String,
        message: String,
    },
    Throttled {
        retry_after_ms: Option<u64>,
        message: String,
    },
    OutcomeUnknown,
    TransientNotSent {
        message: String,
    },
}

#[cfg(any(test, feature = "test-support"))]
impl Default for MockResponse {
    fn default() -> Self {
        Self::Success(serde_json::json!({"ok": true}))
    }
}

/// Deterministic transport used by the harness and by facade wiring in this
/// slice. Received requests never include the credential payload.
#[derive(Clone, Default)]
#[cfg(any(test, feature = "test-support"))]
pub struct MockTransport {
    requests: Arc<Mutex<Vec<TransportRequest>>>,
    authorization_headers: Arc<Mutex<Vec<Vec<u8>>>>,
    response: Arc<Mutex<MockResponse>>,
    response_overrides: Arc<Mutex<HashMap<(String, String), MockResponse>>>,
    /// Per action/method response queues for tests that need a first attempt to
    /// fail and a retry to succeed. The last queued response repeats once the
    /// queue is down to one element, so a sequence never silently falls back to
    /// the default poll response mid-test.
    response_sequences: Arc<Mutex<HashMap<(String, String), ResponseSequence>>>,
}

/// A per action/method queue of responses consumed in order across successive
/// dispatches, used to model a transient failure followed by a success.
#[cfg(any(test, feature = "test-support"))]
type ResponseSequence = VecDeque<MockResponse>;

#[cfg(any(test, feature = "test-support"))]
impl MockTransport {
    pub fn set_response(&self, response: MockResponse) {
        if let Ok(mut current) = self.response.lock() {
            *current = response;
        }
    }

    /// Override the response for one action/method pair while leaving the
    /// default response in place for the poll that triggers a follow-up read.
    pub fn set_response_for_method(&self, action: &str, method: &str, response: MockResponse) {
        if let Ok(mut responses) = self.response_overrides.lock() {
            responses.insert((action.to_string(), method.to_string()), response);
        }
    }

    /// Queue a sequence of responses for one action/method pair, consumed in
    /// order across successive dispatches. The final element repeats, so a
    /// transient-then-success sequence yields the failure on the first attempt
    /// and the success on the retry.
    pub fn set_response_sequence_for_method(
        &self,
        action: &str,
        method: &str,
        responses: Vec<MockResponse>,
    ) {
        if let Ok(mut sequences) = self.response_sequences.lock() {
            sequences.insert(
                (action.to_string(), method.to_string()),
                responses.into_iter().collect(),
            );
        }
    }

    pub fn requests(&self) -> Vec<TransportRequest> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .unwrap_or_default()
    }

    /// This is the one intentional sink allowed to inspect the canary in the
    /// harness: the transport's Authorization header.
    pub fn authorization_headers(&self) -> Vec<Vec<u8>> {
        self.authorization_headers
            .lock()
            .map(|headers| headers.clone())
            .unwrap_or_default()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Transport for MockTransport {
    fn dispatch(
        &self,
        mut request: TransportRequest,
        credential: &ResolvedCredential,
    ) -> TransportResponse {
        let response_key = (
            request.action.clone(),
            request
                .args
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        );
        request.args = redact_args(&request.args);
        if let Ok(mut requests) = self.requests.lock() {
            requests.push(request);
        }
        if let Ok(mut headers) = self.authorization_headers.lock() {
            let mut header = b"Bearer ".to_vec();
            header.extend_from_slice(credential.payload());
            headers.push(header);
        }
        let response = self
            .response_sequences
            .lock()
            .ok()
            .and_then(|mut sequences| {
                let queue = sequences.get_mut(&response_key)?;
                let next = queue.pop_front()?;
                // Keep the last element so a sequence never runs dry and falls
                // back to the default poll response mid-test.
                if queue.is_empty() {
                    queue.push_back(next.clone());
                }
                Some(next)
            })
            .or_else(|| {
                self.response_overrides
                    .lock()
                    .ok()
                    .and_then(|responses| responses.get(&response_key).cloned())
            })
            .or_else(|| self.response.lock().ok().map(|response| response.clone()))
            .unwrap_or(MockResponse::TransientNotSent {
                message: "mock transport state unavailable".to_string(),
            });
        match response {
            // The response is returned verbatim, matching both real transports.
            // The mock previously redacted it, which made it diverge from the
            // thing it stands in for: a test could only see a vendor field whose
            // name avoided the secret-key list, so any test involving a field
            // like `nextSyncToken` silently exercised a fingerprint instead.
            // The REQUEST projection above stays redacted, because that is a
            // recorded diagnostic and the arguments are ours.
            MockResponse::Success(value) => TransportResponse {
                transmission: TransmissionState::Sent,
                retryability: Retryability::Terminal,
                response: Some(value),
                error_code: None,
                error_message: None,
                vendor_request_id: Some("mock-vendor-request".to_string()),
                served_from: None,
                observed_at_ms: None,
                retry_after_ms: None,
                error_signal: None,
            },
            MockResponse::VendorError { code, message } => {
                TransportResponse::vendor_error(&code, &message)
            }
            MockResponse::Throttled {
                retry_after_ms,
                message,
            } => TransportResponse {
                transmission: TransmissionState::Sent,
                retryability: Retryability::Throttle,
                response: None,
                error_code: Some("throttled".to_string()),
                error_message: Some(message),
                vendor_request_id: None,
                served_from: None,
                observed_at_ms: None,
                retry_after_ms: retry_after_ms.filter(|delay| *delay != 0),
                error_signal: None,
            },
            MockResponse::OutcomeUnknown => TransportResponse::unknown(),
            MockResponse::TransientNotSent { message } => {
                TransportResponse::transient_not_sent(&message)
            }
        }
    }
}

/// Replace a vendor's own words with a fixed phrase on the CALLER-FACING reply.
///
/// THE ARGUMENT IS DELIBERATELY IGNORED, and this comment exists because nothing
/// said so. `vendor_error(code, message)` reads as though the message is
/// delivered, so every call site writes a careful explanation that reaches
/// nobody, a trap that is easy to walk into even while auditing for exactly
/// this class.
///
/// The substitution is correct: this reply crosses the facade to an AGENT, and a
/// vendor error body is attacker-influenced text that can carry payload content
/// or provider-side secrets. Deciding per-vendor which bodies are safe to relay
/// is the guessing that rots.
///
/// So the detail belongs on the OPERATOR path instead, written to stderr where
/// the daemon log captures it — `rest_api::log_rest_error` and the MCP vendor
/// error logging are that path. A transport that discards detail on BOTH paths
/// leaves an operator with a status code and nothing else, and a bare 403
/// fits half a dozen causes equally well.
///
/// If a call site has something an operator needs, LOG IT; do not route it here.
pub(crate) const OPERATOR_DIAGNOSTIC_MESSAGE: &str =
    "vendor request failed; plexus logged the full diagnostic (see `ck module logs plexus`)";

fn sanitize_message(_message: &str) -> String {
    OPERATOR_DIAGNOSTIC_MESSAGE.to_string()
}

#[cfg(any(test, feature = "test-support"))]
fn redact_args(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut redacted = Map::new();
            for (key, value) in object {
                if crate::http_support::is_secret_key(key) {
                    let reference = serde_json::to_vec(value).unwrap_or_default();
                    redacted.insert(key.clone(), Value::String(fingerprint(&reference)));
                } else {
                    redacted.insert(key.clone(), redact_args(value));
                }
            }
            Value::Object(redacted)
        }
        Value::Array(values) => Value::Array(values.iter().map(redact_args).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_auth_status_is_limited_to_401() {
        let response = TransportResponse {
            transmission: TransmissionState::Sent,
            retryability: Retryability::Terminal,
            response: None,
            error_code: Some("http_401".to_string()),
            error_message: Some("redacted".to_string()),
            vendor_request_id: None,
            served_from: None,
            observed_at_ms: None,
            retry_after_ms: None,
            error_signal: None,
        };
        assert_eq!(response.provider_auth_status(), Some(401));

        for code in ["http_403", "http_429", "http_500", "network"] {
            let response = TransportResponse {
                transmission: TransmissionState::Sent,
                retryability: Retryability::Terminal,
                response: None,
                error_code: Some(code.to_string()),
                error_message: Some("redacted".to_string()),
                vendor_request_id: None,
                served_from: None,
                observed_at_ms: None,
                retry_after_ms: None,
                error_signal: None,
            };
            assert_eq!(response.provider_auth_status(), None);
        }
    }

    #[test]
    fn mock_request_projection_omits_credential_payload() {
        let mock = MockTransport::default();
        let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);
        mock.dispatch(
            TransportRequest {
                request_id: "req".to_string(),
                connection_id: "conn".to_string(),
                action: "call".to_string(),
                args: serde_json::json!({"token": "CANARY"}),
                credential_fingerprint: fingerprint(b"CANARY"),
            },
            &credential,
        );
        let requests = mock.requests();
        assert_eq!(requests.len(), 1);
        assert!(!requests[0].args.to_string().contains("CANARY"));
        assert_eq!(mock.authorization_headers()[0], b"Bearer CANARY");
    }

    /// Redaction must reach secrets NESTED inside the argument tree, and must
    /// leave ordinary arguments alone.
    ///
    /// The test above only ever places a secret at the top level, so removing
    /// the recursive call in `redact_args` — leaving nested values verbatim —
    /// passed the whole core suite. A caller who wraps a credential one level
    /// down, which is the ordinary shape for a structured argument, would have
    /// had it recorded in full.
    ///
    /// The second half matters just as much: a redactor that replaced
    /// EVERYTHING would satisfy an absence assertion perfectly while destroying
    /// the audit trail it exists to protect. Absence alone cannot distinguish
    /// correct redaction from total erasure.
    #[test]
    fn redaction_reaches_nested_secrets_and_spares_ordinary_arguments() {
        let mock = MockTransport::default();
        let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);
        mock.dispatch(
            TransportRequest {
                request_id: "req".to_string(),
                connection_id: "conn".to_string(),
                action: "call".to_string(),
                args: serde_json::json!({
                    "query": "ordinary-visible-value",
                    "auth": {"token": "NESTED_CANARY"},
                    "items": [{"api_key": "ARRAY_CANARY"}],
                }),
                credential_fingerprint: fingerprint(b"CANARY"),
            },
            &credential,
        );

        let recorded = mock.requests()[0].args.to_string();
        assert!(
            !recorded.contains("NESTED_CANARY"),
            "a secret nested one level down survived redaction: {recorded}"
        );
        assert!(
            !recorded.contains("ARRAY_CANARY"),
            "a secret inside an array survived redaction: {recorded}"
        );
        assert!(
            recorded.contains("ordinary-visible-value"),
            "redaction erased a non-secret argument, destroying the audit trail: {recorded}"
        );
    }

    /// The mock's request projection redacts every key that
    /// `http_support::is_secret_key` matches, including `Authorization`. The
    /// projection must use that one key list rather than a copy of its own,
    /// because copies drift.
    #[test]
    fn request_projection_redacts_every_shared_secret_key() {
        let mock = MockTransport::default();
        let keys = [
            "token",
            "Secret",
            "password",
            "handle",
            "payload",
            "credential",
            "api_key",
            "Authorization",
        ];
        let args = Value::Object(
            keys.iter()
                .map(|key| (key.to_string(), Value::String(format!("CANARY-{key}"))))
                .collect(),
        );
        mock.dispatch(
            TransportRequest {
                request_id: "req".to_string(),
                connection_id: "conn".to_string(),
                action: "call".to_string(),
                args,
                credential_fingerprint: fingerprint(b"CANARY"),
            },
            &ResolvedCredential::anonymous(),
        );
        let recorded = mock.requests()[0].args.to_string();
        for key in keys {
            assert!(
                !recorded.contains(&format!("CANARY-{key}")),
                "the value under `{key}` survived redaction: {recorded}"
            );
        }
    }
}
