//! Shared deterministic fixtures for the GitHub facade integration tests.
//! Include this module from each test binary rather than copying its assertions.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use plexus_core::credentials::{CredentialError, CredentialSource, ResolvedCredential};
use plexus_core::transport::{Transport, TransportRequest, TransportResponse};

/// One clock for receipt leases, approval deadlines and credential expiry.
#[derive(Clone)]
pub struct FixedClock(Arc<AtomicI64>);

impl FixedClock {
    pub fn new(now_ms: i64) -> Self {
        Self(Arc::new(AtomicI64::new(now_ms)))
    }

    pub fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    pub fn advance_ms(&self, delta_ms: i64) {
        assert!(delta_ms >= 0, "clock cannot move backwards");
        self.0.fetch_add(delta_ms, Ordering::SeqCst);
    }
}

/// Records GitHub API calls; the claustrum client records vault reads separately.
#[derive(Clone)]
pub struct RecordingTransport {
    repository_requests: Arc<Mutex<Vec<TransportRequest>>>,
    response: Arc<Mutex<TransportResponse>>,
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportResponse::success(serde_json::json!({})))
    }
}

impl RecordingTransport {
    pub fn new(response: TransportResponse) -> Self {
        Self {
            repository_requests: Arc::new(Mutex::new(Vec::new())),
            response: Arc::new(Mutex::new(response)),
        }
    }

    pub fn set_response(&self, response: TransportResponse) {
        *self.response.lock().unwrap() = response;
    }

    pub fn repository_requests(&self) -> Vec<TransportRequest> {
        self.repository_requests.lock().unwrap().clone()
    }

    pub fn assert_zero_requests_of_any_kind(&self, claustrum: &RecordingClaustrumClient) {
        assert_eq!(claustrum.secret_reads(), 0, "vault secret read occurred");
        assert!(
            self.repository_requests().is_empty(),
            "repository API contacted"
        );
    }
}

impl Transport for RecordingTransport {
    fn dispatch(
        &self,
        request: TransportRequest,
        _credential: &ResolvedCredential,
    ) -> TransportResponse {
        self.repository_requests.lock().unwrap().push(request);
        self.response.lock().unwrap().clone()
    }
}

/// Decorates a secret provider without retaining secret material in the recorder.
#[derive(Clone)]
pub struct RecordingClaustrumClient {
    inner: Arc<dyn CredentialSource>,
    reads: Arc<AtomicI64>,
}

impl RecordingClaustrumClient {
    pub fn new(inner: Arc<dyn CredentialSource>) -> Self {
        Self {
            inner,
            reads: Arc::new(AtomicI64::new(0)),
        }
    }

    pub fn secret_reads(&self) -> i64 {
        self.reads.load(Ordering::SeqCst)
    }
}

impl CredentialSource for RecordingClaustrumClient {
    fn get(&self, handle: &[u8]) -> Result<ResolvedCredential, CredentialError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.get(handle)
    }

    fn report_auth_failure(&self, handle: &[u8], status: u16, version: u64) {
        self.inner.report_auth_failure(handle, status, version);
    }
}

/// Counts reports independently of credential lookups and never records raw handles.
#[derive(Clone)]
pub struct RecordingCredentialSource {
    inner: Arc<dyn CredentialSource>,
    reports: Arc<AtomicI64>,
}

impl RecordingCredentialSource {
    pub fn new(inner: Arc<dyn CredentialSource>) -> Self {
        Self {
            inner,
            reports: Arc::new(AtomicI64::new(0)),
        }
    }

    pub fn auth_failure_reports(&self) -> i64 {
        self.reports.load(Ordering::SeqCst)
    }
}

impl CredentialSource for RecordingCredentialSource {
    fn get(&self, handle: &[u8]) -> Result<ResolvedCredential, CredentialError> {
        self.inner.get(handle)
    }

    fn report_auth_failure(&self, handle: &[u8], status: u16, version: u64) {
        self.reports.fetch_add(1, Ordering::SeqCst);
        self.inner.report_auth_failure(handle, status, version);
    }
}

/// Exact five-column assertion on one facade audit row, including SQL NULLs.
/// Querying the columns by name prevents an old agent_id/agent_handle column
/// from accidentally satisfying the new facade attribution contract.
pub fn assert_facade_audit_row(
    row: &rusqlite::Row<'_>,
    claimed_agent_id: Option<&str>,
    app_handle_id: Option<&str>,
    action: Option<&str>,
    request_id: Option<&str>,
    refusal_code: Option<&str>,
) {
    for (column, expected) in [
        ("claimed_agent_id", claimed_agent_id),
        ("app_handle_id", app_handle_id),
        ("action", action),
        ("request_id", request_id),
        ("refusal_code", refusal_code),
    ] {
        let actual: Option<String> = row
            .get(column)
            .unwrap_or_else(|error| panic!("{column}: {error}"));
        assert_eq!(actual.as_deref(), expected, "audit column {column}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plexus_core::credentials::StubCredentialSource;
    use serde_json::json;

    fn request(method: &str, path: &str) -> TransportRequest {
        TransportRequest {
            request_id: "req-1".into(),
            connection_id: "conn-1".into(),
            action: "github.issue.get".into(),
            args: json!({"method":method,"path":path}),
            credential_fingerprint: "sha256:fixture".into(),
        }
    }

    #[test]
    fn recording_transport_and_claustrum_count_separate_contacts() {
        let claustrum = RecordingClaustrumClient::new(Arc::new(
            StubCredentialSource::with_default_success(b"test-only".to_vec()),
        ));
        let transport = RecordingTransport::default();
        transport.assert_zero_requests_of_any_kind(&claustrum);
        claustrum.get(b"reference").unwrap();
        transport.dispatch(
            request("GET", "/repos/owner/repo/issues/1"),
            &ResolvedCredential::anonymous(),
        );
        assert_eq!(claustrum.secret_reads(), 1);
        assert_eq!(transport.repository_requests().len(), 1);
    }

    #[test]
    #[should_panic(expected = "vault secret read occurred")]
    fn zero_requests_assertion_checks_vault_reads() {
        let claustrum = RecordingClaustrumClient::new(Arc::new(
            StubCredentialSource::with_default_success(b"test-only".to_vec()),
        ));
        let transport = RecordingTransport::default();
        claustrum.get(b"reference").unwrap();
        transport.assert_zero_requests_of_any_kind(&claustrum);
    }

    #[test]
    #[should_panic(expected = "repository API contacted")]
    fn zero_requests_assertion_checks_repository_bucket() {
        let claustrum = RecordingClaustrumClient::new(Arc::new(
            StubCredentialSource::with_default_success(b"test-only".to_vec()),
        ));
        let transport = RecordingTransport::default();
        transport.dispatch(
            request("GET", "/repos/owner/repo"),
            &ResolvedCredential::anonymous(),
        );
        transport.assert_zero_requests_of_any_kind(&claustrum);
    }

    #[test]
    fn fixed_clock_advances_lease_time() {
        let clock = FixedClock::new(1_700_000_000_999);
        clock.advance_ms(60_001);
        assert_eq!(clock.now_ms(), 1_700_000_061_000);
    }

    #[test]
    fn secret_reads_and_auth_failure_reports_are_independently_counted() {
        let stub = Arc::new(StubCredentialSource::with_default_success(
            b"test-only".to_vec(),
        ));
        let claustrum = RecordingClaustrumClient::new(stub.clone());
        let source = RecordingCredentialSource::new(Arc::new(claustrum.clone()));
        assert_eq!(source.auth_failure_reports(), 0);
        assert_eq!(claustrum.secret_reads(), 0);
        source.get(b"reference").unwrap();
        source.report_auth_failure(b"reference", 401, 1);
        assert_eq!(claustrum.secret_reads(), 1);
        assert_eq!(source.auth_failure_reports(), 1);
        assert_eq!(stub.auth_failure_reports().len(), 1);
    }

    #[test]
    fn audit_helper_checks_all_five_columns_including_null() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE facade_audit (claimed_agent_id TEXT, app_handle_id TEXT, action TEXT, request_id TEXT, refusal_code TEXT); INSERT INTO facade_audit VALUES ('agent-1', 'app-1', 'github.bot_request', 'req-1', NULL);").unwrap();
        db.query_row("SELECT * FROM facade_audit", [], |row| {
            assert_facade_audit_row(
                row,
                Some("agent-1"),
                Some("app-1"),
                Some("github.bot_request"),
                Some("req-1"),
                None,
            );
            Ok(())
        })
        .unwrap();
    }
}
